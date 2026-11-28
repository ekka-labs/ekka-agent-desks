//! The installation's own certificate authority, the gateway's certificate and the gateway's token keys.
//!
//! The CA is EC P-256, five years, and name-constrained to the two names the gateway answers on: a stolen CA key
//! can vouch for nothing else. Its key stays with root (0600). The gateway's certificate is EC P-256 for one year
//! with DNS `host.docker.internal` (how desk supervisors in Docker's VM reach the Mac) and IP `127.0.0.1` (how the
//! Enclave and the adapter reach it); its key belongs to the developer, who runs the gateway. The Enclave trusts
//! the system's public roots plus this CA (one bundle), so Govern and the gateway are both verified. The gateway
//! signs its own tokens with an Ed25519 key the Enclave pins.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CidrSubnet, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints, SanType, PKCS_ECDSA_P256_SHA256, PKCS_ED25519,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::{failed, refused, Result};
use crate::net::{client_config, pem_certs, root_store};
use crate::util::{hex, random_bytes, sha256_hex};

/// The name desk supervisors in Docker Desktop's VM use for the Mac.
pub const GATEWAY_DNS: &str = "host.docker.internal";
/// The address host clients use: numeric IPv4, never `localhost` (which macOS resolves to ::1 first).
pub const GATEWAY_IP: Ipv4Addr = Ipv4Addr::LOCALHOST;
const CA_DAYS: i64 = 1826;
const LEAF_DAYS: i64 = 365;
/// A certificate this close to its end is made again.
pub const RENEW_DAYS: i64 = 30;

fn rc(what: &str) -> impl Fn(rcgen::Error) -> crate::error::Error + '_ {
    move |e| failed(format!("{what}: {e}"))
}

fn ca_params(installation_id: &str, now: OffsetDateTime) -> Result<CertificateParams> {
    let mut p = CertificateParams::new(Vec::<String>::new()).map_err(rc("the CA"))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("EKKA desk host CA {installation_id}"));
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DnsName(GATEWAY_DNS.to_string()),
            GeneralSubtree::IpAddress(CidrSubnet::V4(GATEWAY_IP.octets(), [255, 255, 255, 255])),
        ],
        excluded_subtrees: vec![],
    });
    p.not_before = now - time::Duration::hours(1);
    p.not_after = now + time::Duration::days(CA_DAYS);
    Ok(p)
}

/// A CA able to sign: its key, and its certificate as a signer (only its name and key are used to sign).
pub struct Ca {
    key: KeyPair,
    signer: Certificate,
}

impl Ca {
    /// A new CA for this installation: (CA, key PEM, certificate PEM).
    pub fn generate(installation_id: &str) -> Result<(Self, String, String)> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(rc("the CA key"))?;
        let cert = ca_params(installation_id, OffsetDateTime::now_utc())?.self_signed(&key).map_err(rc("the CA"))?;
        let (key_pem, cert_pem) = (key.serialize_pem(), cert.pem());
        Ok((Ca { key, signer: cert }, key_pem, cert_pem))
    }

    /// The installation's existing CA, from its key. Its certificate on disk is kept as it is: the signer made here
    /// has the same name and key, so what it signs chains to that certificate.
    pub fn load(installation_id: &str, key_pem: &str) -> Result<Self> {
        let key = KeyPair::from_pem(key_pem).map_err(|_| refused("the installation's CA key is not a key"))?;
        let signer = ca_params(installation_id, OffsetDateTime::now_utc())?.self_signed(&key).map_err(rc("the CA"))?;
        Ok(Ca { key, signer })
    }

    /// This CA's certificate, made again from its key and name (for a certificate file that went missing).
    pub fn cert_pem(&self) -> String {
        self.signer.pem()
    }

    /// A new gateway certificate: (certificate PEM, key PEM, what it says).
    pub fn leaf(&self, ca_cert_pem: &str) -> Result<(String, String, LeafMeta)> {
        let now = OffsetDateTime::now_utc();
        let mut p = CertificateParams::new(Vec::<String>::new()).map_err(rc("the gateway certificate"))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, GATEWAY_DNS);
        p.distinguished_name = dn;
        p.subject_alt_names = vec![
            SanType::DnsName(GATEWAY_DNS.try_into().map_err(rc("the gateway name"))?),
            SanType::IpAddress(IpAddr::V4(GATEWAY_IP)),
        ];
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyAgreement];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        p.not_before = now - time::Duration::minutes(5);
        p.not_after = now + time::Duration::days(LEAF_DAYS);
        let not_after = p.not_after.unix_timestamp();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(rc("the gateway key"))?;
        let cert = p.signed_by(&key, &self.signer, &self.key).map_err(rc("the gateway certificate"))?;
        Ok((cert.pem(), key.serialize_pem(), LeafMeta::current(not_after, ca_cert_pem)))
    }
}

/// What the gateway certificate says, kept beside it (world-readable) so a check needs no key and no parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafMeta {
    pub schema: String,
    pub not_after_unix: i64,
    pub dns: Vec<String>,
    pub ips: Vec<String>,
    /// sha256 of the CA certificate file it chains to.
    pub ca_sha256: String,
}

impl LeafMeta {
    const SCHEMA: &'static str = "ekka-desk-host.gateway-certificate/v1";

    fn current(not_after_unix: i64, ca_cert_pem: &str) -> Self {
        LeafMeta {
            schema: Self::SCHEMA.into(),
            not_after_unix,
            dns: vec![GATEWAY_DNS.into()],
            ips: vec![GATEWAY_IP.to_string()],
            ca_sha256: sha256_hex(ca_cert_pem.as_bytes()),
        }
    }

    /// Whether a gateway certificate described by `meta` must be made again: none, other names, another CA, or
    /// within `RENEW_DAYS` of its end.
    pub fn needs_renewal(meta: Option<&LeafMeta>, ca_cert_pem: &[u8], now_unix: i64) -> bool {
        match meta {
            None => true,
            Some(m) => {
                m.schema != Self::SCHEMA
                    || m.dns != [GATEWAY_DNS]
                    || m.ips != [GATEWAY_IP.to_string()]
                    || m.ca_sha256 != sha256_hex(ca_cert_pem)
                    || m.not_after_unix - now_unix < RENEW_DAYS * 86_400
            }
        }
    }
}

/// The gateway's token signing keys: PKCS#8 private key, SPKI public key and a 32-hex-character key id.
pub struct JwtKeys {
    pub signing_pem: String,
    pub public_pem: String,
    pub kid: String,
}

impl JwtKeys {
    pub fn generate() -> Result<Self> {
        let key = KeyPair::generate_for(&PKCS_ED25519).map_err(rc("the gateway's token key"))?;
        Ok(JwtKeys {
            signing_pem: key.serialize_pem(),
            public_pem: key.public_key_pem(),
            kid: hex(&random_bytes::<16>()?),
        })
    }

    /// The public halves of an existing signing key.
    pub fn public_of(signing_pem: &str) -> Result<(String, String)> {
        let key = KeyPair::from_pem(signing_pem).map_err(|_| refused("the gateway's token key is not a key"))?;
        if key.algorithm() != &PKCS_ED25519 {
            return Err(refused("the gateway's token key is not Ed25519"));
        }
        Ok((key.public_key_pem(), base64::engine::general_purpose::STANDARD.encode(key.public_key_raw())))
    }
}

/// The raw Ed25519 key in an SPKI PEM, in base64, as the Enclave's `EKKA_OPENSHELL_GATEWAY_KEY_B64` holds it.
pub fn public_b64_of_pem(public_pem: &str) -> Result<String> {
    let body: String = public_pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|_| refused("the gateway's public token key is not PEM"))?;
    // An Ed25519 SPKI is a fixed 12-byte prefix and the 32-byte key.
    const PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    if der.len() != 44 || der[..12] != PREFIX {
        return Err(refused("the gateway's public token key is not an Ed25519 key"));
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(&der[12..]))
}

/// The system's public roots and this CA, in one PEM bundle: what the Enclave's `SSL_CERT_FILE` names.
pub fn bundle(system_roots: &[u8], ca_cert_pem: &[u8]) -> Result<Vec<u8>> {
    pem_certs(system_roots, "the system's public roots")?;
    pem_certs(ca_cert_pem, "the installation CA")?;
    let mut out = system_roots.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.extend_from_slice(b"# EKKA desk host: this installation's CA\n");
    out.extend_from_slice(ca_cert_pem);
    Ok(out)
}

/// A TLS handshake with the gateway at `addr`, trusting only `ca_pem` and checking the certificate names
/// `server_name`. Ok means a verified session was set up; nothing is sent over it.
pub fn probe(addr: SocketAddr, server_name: &str, ca_pem: &[u8]) -> Result<()> {
    let config = client_config(root_store(&pem_certs(ca_pem, "the installation CA")?));
    let name = ServerName::try_from(server_name.to_string()).map_err(|_| refused("not a server name"))?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| failed(format!("connecting to {addr}: {e}")))?;
    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let conn = ClientConnection::new(Arc::clone(&config), name).map_err(|e| failed(format!("TLS: {e}")))?;
    let mut s = StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock).map_err(|e| refused(format!("TLS to {addr} as {server_name}: {e}")))?;
    }
    let _ = s.flush();
    let _ = s.sock.read(&mut [0u8; 0]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    use std::net::TcpListener;

    fn serve(cert_pem: String, key_pem: String, connections: usize) -> SocketAddr {
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<std::result::Result<_, _>>().unwrap();
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap(),
        );
        let l = TcpListener::bind((GATEWAY_IP, 0)).unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in l.incoming().take(connections) {
                let Ok(mut sock) = s else { continue };
                let mut conn = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
                while conn.is_handshaking() {
                    if conn.complete_io(&mut sock).is_err() {
                        break;
                    }
                }
            }
        });
        addr
    }

    #[test]
    fn the_gateway_certificate_verifies_for_both_names_and_nothing_else() {
        let (ca, _ca_key_pem, ca_pem) = Ca::generate("11111111-2222-4333-8444-555555555555").unwrap();
        let (leaf_pem, leaf_key_pem, meta) = ca.leaf(&ca_pem).unwrap();
        assert_eq!(meta.dns, [GATEWAY_DNS]);
        assert_eq!(meta.ips, ["127.0.0.1"]);
        let addr = serve(leaf_pem, leaf_key_pem, 4);
        probe(addr, GATEWAY_DNS, ca_pem.as_bytes()).expect("a desk supervisor's name verifies");
        probe(addr, "127.0.0.1", ca_pem.as_bytes()).expect("the host clients' numeric address verifies");
        let e = probe(addr, "gateway.example.com", ca_pem.as_bytes()).unwrap_err();
        assert!(e.reason.contains("TLS to"), "a wrong host name must fail: {e}");
        let (_, _, other_ca) = Ca::generate("99999999-2222-4333-8444-555555555555").unwrap();
        assert!(probe(addr, GATEWAY_DNS, other_ca.as_bytes()).is_err(), "a wrong CA must fail");
    }

    #[test]
    fn a_reloaded_ca_signs_certificates_that_chain_to_the_ca_on_disk() {
        let id = "11111111-2222-4333-8444-555555555555";
        let (_, key_pem, ca_pem) = Ca::generate(id).unwrap();
        let reloaded = Ca::load(id, &key_pem).unwrap();
        let (leaf_pem, leaf_key_pem, _) = reloaded.leaf(&ca_pem).unwrap();
        let addr = serve(leaf_pem, leaf_key_pem, 1);
        probe(addr, GATEWAY_DNS, ca_pem.as_bytes()).unwrap();
    }

    #[test]
    fn a_certificate_is_renewed_near_its_end_or_on_a_new_ca() {
        let (ca, _, ca_pem) = Ca::generate("11111111-2222-4333-8444-555555555555").unwrap();
        let (_, _, meta) = ca.leaf(&ca_pem).unwrap();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        assert!(!LeafMeta::needs_renewal(Some(&meta), ca_pem.as_bytes(), now));
        assert!(LeafMeta::needs_renewal(Some(&meta), ca_pem.as_bytes(), meta.not_after_unix - 29 * 86_400));
        assert!(LeafMeta::needs_renewal(Some(&meta), b"another CA", now));
        assert!(LeafMeta::needs_renewal(None, ca_pem.as_bytes(), now));
    }

    #[test]
    fn the_token_key_the_enclave_pins_is_the_gateways_public_key() {
        let k = JwtKeys::generate().unwrap();
        assert_eq!(k.kid.len(), 32);
        let b64 = public_b64_of_pem(&k.public_pem).unwrap();
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(&b64).unwrap().len(), 32);
        let (pem, from_signing) = JwtKeys::public_of(&k.signing_pem).unwrap();
        assert_eq!((pem, from_signing), (k.public_pem.clone(), b64));
        assert!(k.signing_pem.contains("PRIVATE KEY") && !k.public_pem.contains("PRIVATE"));
    }

    #[test]
    fn the_enclave_bundle_is_the_system_roots_plus_the_ca() {
        let roots = std::fs::read(crate::net::system_roots_path()).unwrap();
        let (_, _, ca_pem) = Ca::generate("11111111-2222-4333-8444-555555555555").unwrap();
        let b = bundle(&roots, ca_pem.as_bytes()).unwrap();
        assert!(b.starts_with(&roots));
        assert!(b.ends_with(ca_pem.as_bytes()));
        assert_eq!(pem_certs(&b, "b").unwrap().len(), pem_certs(&roots, "r").unwrap().len() + 1);
        assert!(bundle(b"", ca_pem.as_bytes()).is_err(), "no system roots is refused, never a CA-only bundle");
    }
}

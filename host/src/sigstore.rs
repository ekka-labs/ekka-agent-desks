//! Who built a release: Sigstore keyless signatures, checked here without cosign.
//!
//! A keyless signature is a short-lived certificate from Sigstore's Fulcio CA that names the workflow which signed,
//! a signature over the file by that certificate's key, and an entry in Sigstore's Rekor transparency log that
//! proves when it was signed. This checks all three: the certificate chains to Fulcio (pinned in the kit,
//! `deploy/macos/sigstore-trusted-root.json`) and is for code signing; it names exactly the expected workflow and
//! the expected OIDC issuer; the signature verifies over the exact bytes; and Rekor holds an entry for exactly this
//! file, signature and certificate, whose signed timestamp (verified with Rekor's pinned key) falls inside the
//! certificate's ten minutes. The chain is checked at that time. What is not checked: Rekor's Merkle inclusion
//! proof (the signed entry timestamp is Rekor's promise of inclusion), and certificate transparency for Fulcio.

use std::time::Duration;

use base64::Engine;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use rustls::pki_types::{pem::PemObject, CertificateDer, TrustAnchor, UnixTime};
use serde_json::Value;

use crate::error::{failed, refused, Result};
use crate::util::sha256_hex;

/// GitHub Actions' OIDC issuer, the only one a release workflow's certificate may name.
pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

const CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_ISSUER_V1: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01, 0x01];
const OID_ISSUER_V2: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01, 0x08];

fn b64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s.trim()).map_err(|_| refused("a signature part is not base64"))
}

/// One Fulcio certificate authority: its root, its intermediates, and the interval Sigstore says it was valid for.
pub struct Authority {
    root: CertificateDer<'static>,
    intermediates: Vec<CertificateDer<'static>>,
    start: i64,
    end: Option<i64>,
}

impl Authority {
    fn valid_at(&self, t: i64) -> bool {
        self.start <= t && self.end.is_none_or(|e| t <= e)
    }
}

/// Fulcio's certificate authorities and Rekor's keys.
pub struct Trust {
    authorities: Vec<Authority>,
    /// Rekor logs: (log id in hex, the P-256 public key point).
    rekor: Vec<(String, Vec<u8>)>,
}

impl Trust {
    pub fn embedded() -> Result<Self> {
        Self::parse(crate::kit::SIGSTORE_TRUSTED_ROOT)
    }

    /// Sigstore's `trusted_root.json`: every Fulcio chain (its last certificate the anchor) and every Rekor log
    /// with a P-256 key.
    pub fn parse(json: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(json).map_err(|_| failed("the Sigstore trusted root is not JSON"))?;
        let mut t = Trust { authorities: Vec::new(), rekor: Vec::new() };
        for ca in v["certificateAuthorities"].as_array().into_iter().flatten() {
            let mut chain: Vec<CertificateDer<'static>> = Vec::new();
            for c in ca["certChain"]["certificates"].as_array().into_iter().flatten() {
                chain.push(CertificateDer::from(b64(c["rawBytes"].as_str().unwrap_or(""))?));
            }
            let start = rfc3339(ca["validFor"]["start"].as_str().unwrap_or(""))?;
            let end = match ca["validFor"]["end"].as_str() {
                Some(e) => Some(rfc3339(e)?),
                None => None,
            };
            if let Some(root) = chain.pop() {
                t.authorities.push(Authority { root, intermediates: chain, start, end });
            }
        }
        for log in v["tlogs"].as_array().into_iter().flatten() {
            if log["publicKey"]["keyDetails"] != "PKIX_ECDSA_P256_SHA_256" {
                continue;
            }
            let spki = b64(log["publicKey"]["rawBytes"].as_str().unwrap_or(""))?;
            t.rekor.push((sha256_hex(&spki), spki_point(&spki)?));
        }
        if t.authorities.is_empty() || t.rekor.is_empty() {
            return Err(failed("the Sigstore trusted root names no Fulcio CA or no Rekor key"));
        }
        Ok(t)
    }

    #[cfg(test)]
    pub fn new(anchors: Vec<CertificateDer<'static>>, rekor: Vec<(String, Vec<u8>)>) -> Self {
        let authorities = anchors
            .into_iter()
            .map(|root| Authority { root, intermediates: Vec::new(), start: 0, end: None })
            .collect();
        Trust { authorities, rekor }
    }

    /// The authorities Sigstore says were valid at `t`: only these may anchor a signature made then.
    pub fn valid_at(&self, t: i64) -> Vec<&Authority> {
        self.authorities.iter().filter(|a| a.valid_at(t)).collect()
    }
}

/// An RFC 3339 UTC time as Sigstore's trusted root writes it (`2022-04-13T20:06:15Z`, fractions ignored).
fn rfc3339(s: &str) -> Result<i64> {
    let bad = || failed("the Sigstore trusted root has a time that is not RFC 3339 UTC");
    if s.len() < 20 || !s.ends_with('Z') || s.as_bytes()[10] != b'T' {
        return Err(bad());
    }
    let n = |r: std::ops::Range<usize>| s.get(r).and_then(|x| x.parse::<u32>().ok()).ok_or_else(bad);
    let date = time::Date::from_calendar_date(
        n(0..4)? as i32,
        time::Month::try_from(n(5..7)? as u8).map_err(|_| bad())?,
        n(8..10)? as u8,
    )
    .map_err(|_| bad())?;
    let t = time::Time::from_hms(n(11..13)? as u8, n(14..16)? as u8, n(17..19)? as u8).map_err(|_| bad())?;
    Ok(time::PrimitiveDateTime::new(date, t).assume_utc().unix_timestamp())
}

/// One DER element: (tag, contents, the rest after it).
fn tlv(d: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let bad = || refused("a certificate is not well-formed DER");
    let (&tag, rest) = d.split_first().ok_or_else(bad)?;
    let (&first, mut rest) = rest.split_first().ok_or_else(bad)?;
    let len = if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 3 || rest.len() < n {
            return Err(bad());
        }
        let len = rest[..n].iter().fold(0usize, |a, b| (a << 8) | *b as usize);
        rest = &rest[n..];
        len
    };
    if rest.len() < len {
        return Err(bad());
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn expect(d: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    let (t, v, rest) = tlv(d)?;
    if t != tag {
        return Err(refused("a certificate is not shaped like an X.509 certificate"));
    }
    Ok((v, rest))
}

/// The uncompressed point of a P-256 SubjectPublicKeyInfo.
fn spki_point(spki: &[u8]) -> Result<Vec<u8>> {
    let (inner, _) = expect(spki, 0x30)?;
    let (_alg, rest) = expect(inner, 0x30)?;
    let (bits, _) = expect(rest, 0x03)?;
    match bits.split_first() {
        Some((0, point)) if point.len() == 65 && point[0] == 4 => Ok(point.to_vec()),
        _ => Err(refused("a key is not an uncompressed P-256 point")),
    }
}

/// The whole SubjectPublicKeyInfo of a certificate (DER), as a key's `public_key_der` writes it.
pub fn spki_of(cert_der: &[u8]) -> Result<Vec<u8>> {
    let (cert, _) = expect(cert_der, 0x30)?;
    let (tbs, _) = expect(cert, 0x30)?;
    let mut r = tbs;
    if r.first() == Some(&0xa0) {
        r = tlv(r)?.2;
    }
    for _ in 0..5 {
        r = tlv(r)?.2; // serial, signature algorithm, issuer, validity, subject
    }
    let (_, _, rest) = tlv(r)?;
    Ok(r[..r.len() - rest.len()].to_vec())
}

fn time_of(tag: u8, v: &[u8]) -> Result<i64> {
    let s = std::str::from_utf8(v).map_err(|_| refused("a certificate time is not text"))?;
    let digits = |r: std::ops::Range<usize>| s.get(r).and_then(|x| x.parse::<i32>().ok());
    let (year, off) = match (tag, s.len()) {
        (0x17, 13) => (digits(0..2).map(|y| if y >= 50 { 1900 + y } else { 2000 + y }), 2),
        (0x18, 15) => (digits(0..4), 4),
        _ => (None, 0),
    };
    let bad = || refused("a certificate time is not a UTC time");
    let (y, mo, d, h, mi, se) = (
        year.ok_or_else(bad)?,
        digits(off..off + 2).ok_or_else(bad)?,
        digits(off + 2..off + 4).ok_or_else(bad)?,
        digits(off + 4..off + 6).ok_or_else(bad)?,
        digits(off + 6..off + 8).ok_or_else(bad)?,
        digits(off + 8..off + 10).ok_or_else(bad)?,
    );
    if !s.ends_with('Z') {
        return Err(bad());
    }
    let month = time::Month::try_from(mo as u8).map_err(|_| bad())?;
    let date = time::Date::from_calendar_date(y, month, d as u8).map_err(|_| bad())?;
    let t = time::Time::from_hms(h as u8, mi as u8, se as u8).map_err(|_| bad())?;
    Ok(time::PrimitiveDateTime::new(date, t).assume_utc().unix_timestamp())
}

/// What a signing certificate says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Leaf {
    pub not_before: i64,
    pub not_after: i64,
    pub point: Vec<u8>,
    pub uris: Vec<String>,
    pub issuer: Option<String>,
}

pub fn parse_leaf(der: &[u8]) -> Result<Leaf> {
    let (cert, _) = expect(der, 0x30)?;
    let (tbs, _) = expect(cert, 0x30)?;
    let mut r = tbs;
    if r.first() == Some(&0xa0) {
        r = tlv(r)?.2;
    }
    r = expect(r, 0x02)?.1; // serial
    r = expect(r, 0x30)?.1; // signature algorithm
    r = expect(r, 0x30)?.1; // issuer
    let (validity, rest) = expect(r, 0x30)?;
    let (t1, v1, after1) = tlv(validity)?;
    let (t2, v2, _) = tlv(after1)?;
    let mut leaf = Leaf { not_before: time_of(t1, v1)?, not_after: time_of(t2, v2)?, ..Default::default() };
    r = expect(rest, 0x30)?.1; // subject
    let spki_len = tlv(r)?;
    let spki_whole = &r[..r.len() - spki_len.2.len()];
    leaf.point = spki_point(spki_whole)?;
    r = spki_len.2;
    while let Ok((tag, v, rest)) = tlv(r) {
        r = rest;
        if tag != 0xa3 {
            continue;
        }
        let (mut exts, _) = expect(v, 0x30)?;
        while !exts.is_empty() {
            let (ext, more) = expect(exts, 0x30)?;
            exts = more;
            let (oid, mut e) = expect(ext, 0x06)?;
            if e.first() == Some(&0x01) {
                e = tlv(e)?.2;
            }
            let (value, _) = expect(e, 0x04)?;
            if oid == OID_SAN {
                let (mut names, _) = expect(value, 0x30)?;
                while !names.is_empty() {
                    let (t, n, more) = tlv(names)?;
                    names = more;
                    if t == 0x86 {
                        leaf.uris.push(String::from_utf8(n.to_vec()).map_err(|_| refused("a URI is not text"))?);
                    }
                }
            } else if oid == OID_ISSUER_V2 {
                let (s, _) = expect(value, 0x0c)?;
                leaf.issuer = Some(String::from_utf8(s.to_vec()).map_err(|_| refused("an issuer is not text"))?);
            } else if oid == OID_ISSUER_V1 && leaf.issuer.is_none() {
                leaf.issuer = Some(String::from_utf8(value.to_vec()).map_err(|_| refused("an issuer is not text"))?);
            }
        }
    }
    Ok(leaf)
}

/// Rekor's entries for a file, by its sha256.
pub trait RekorSource {
    fn entries(&self, sha256_hex: &str) -> Result<Vec<Value>>;
}

/// The public Rekor log.
pub struct PublicRekor;

impl RekorSource for PublicRekor {
    fn entries(&self, sha256_hex: &str) -> Result<Vec<Value>> {
        let body = serde_json::json!({ "hash": format!("sha256:{sha256_hex}") }).to_string();
        let ids: Vec<String> = serde_json::from_slice(&crate::net::post_json(
            "https://rekor.sigstore.dev/api/v1/index/retrieve",
            &body,
            64 * 1024,
        )?)
        .map_err(|_| refused("Rekor's search answer is not a list"))?;
        let mut out = Vec::new();
        for id in ids.iter().take(16) {
            if !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(refused("Rekor named an entry that is not hex"));
            }
            let e = crate::net::get(&format!("https://rekor.sigstore.dev/api/v1/log/entries/{id}"), 256 * 1024)?;
            out.push(serde_json::from_slice(&e).map_err(|_| refused("a Rekor entry is not JSON"))?);
        }
        Ok(out)
    }
}

/// A signed release file: its bytes, the `.sig` (base64 DER signature) and the `.crt` (base64 of a PEM).
pub struct Signed<'a> {
    pub blob: &'a [u8],
    pub sig_b64: &'a str,
    pub crt_b64: &'a str,
}

/// The entry's signed timestamp, when it is a Rekor entry for exactly this file, signature and certificate,
/// signed by a pinned Rekor key.
fn entry_time(entry: &Value, sha: &str, sig: &[u8], cert_der: &[u8], trust: &Trust) -> Option<i64> {
    let (_, e) = entry.as_object()?.iter().next()?;
    let body_b64 = e["body"].as_str()?;
    let body: Value = serde_json::from_slice(&b64(body_b64).ok()?).ok()?;
    let spec = &body["spec"];
    if body["kind"] != "hashedrekord"
        || spec["data"]["hash"]["algorithm"] != "sha256"
        || spec["data"]["hash"]["value"] != sha
    {
        return None;
    }
    if b64(spec["signature"]["content"].as_str()?).ok()? != sig {
        return None;
    }
    let pem = b64(spec["signature"]["publicKey"]["content"].as_str()?).ok()?;
    if CertificateDer::from_pem_slice(&pem).ok()?.as_ref() != cert_der {
        return None;
    }
    let (time, index, log_id) = (e["integratedTime"].as_i64()?, e["logIndex"].as_i64()?, e["logID"].as_str()?);
    let (_, point) = trust.rekor.iter().find(|(id, _)| id == log_id)?;
    let canonical = format!(r#"{{"body":"{body_b64}","integratedTime":{time},"logID":"{log_id}","logIndex":{index}}}"#);
    let set = b64(e["verification"]["signedEntryTimestamp"].as_str()?).ok()?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point).verify(canonical.as_bytes(), &set).ok()?;
    Some(time)
}

/// The file was signed by exactly `identity` (the certificate's URI), through `issuer`, and Rekor recorded it while
/// the certificate was valid. Returns when it was signed (Rekor's time).
pub fn verify(signed: &Signed, identity: &str, issuer: &str, trust: &Trust, rekor: &dyn RekorSource) -> Result<i64> {
    let pem = b64(signed.crt_b64)?;
    let cert = CertificateDer::from_pem_slice(&pem).map_err(|_| refused("the signing certificate is not PEM"))?;
    let leaf = parse_leaf(&cert)?;
    if leaf.uris != [identity] {
        return Err(refused(format!(
            "the release was signed by {}, not {identity}",
            leaf.uris.first().map(String::as_str).unwrap_or("no named identity")
        )));
    }
    if leaf.issuer.as_deref() != Some(issuer) {
        return Err(refused("the release's signing certificate names another sign-in issuer"));
    }
    let sig = b64(signed.sig_b64)?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &leaf.point)
        .verify(signed.blob, &sig)
        .map_err(|_| refused("the release's signature does not verify over these bytes"))?;
    let sha = sha256_hex(signed.blob);
    let time = rekor
        .entries(&sha)?
        .iter()
        .find_map(|e| entry_time(e, &sha, &sig, &cert, trust))
        .ok_or_else(|| refused("Sigstore's transparency log holds no signed entry for this exact release"))?;
    if time < leaf.not_before || time > leaf.not_after {
        return Err(refused("the release was logged outside its signing certificate's lifetime"));
    }
    // Only an authority valid when the release was logged may anchor it: a root past its end anchors nothing.
    let valid = trust.valid_at(time);
    if valid.is_empty() {
        return Err(refused("no Sigstore certificate authority was valid when this release was logged"));
    }
    let anchors: Vec<TrustAnchor> = valid
        .iter()
        .map(|a| webpki::anchor_from_trusted_cert(&a.root).map(|t| t.to_owned()))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| failed("a pinned Fulcio CA certificate does not parse"))?;
    let intermediates: Vec<CertificateDer> = valid.iter().flat_map(|a| a.intermediates.iter().cloned()).collect();
    let ee = webpki::EndEntityCert::try_from(&cert).map_err(|e| refused(format!("the signing certificate: {e}")))?;
    ee.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &anchors,
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(time as u64)),
        webpki::KeyUsage::required(CODE_SIGNING),
        None,
        None,
    )
    .map_err(|e| refused(format!("the signing certificate does not chain to Sigstore's CA: {e}")))?;
    Ok(time)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_ASN1_SIGNING};

    pub(crate) const ID: &str = "https://github.com/example/release/.github/workflows/release.yml@refs/tags/v1.2.3";

    /// A whole keyless signing world in memory: a Fulcio CA, a Rekor key, and a release signed through them.
    pub(crate) struct World {
        pub trust: Trust,
        pub sig_b64: String,
        pub crt_b64: String,
        pub entry: Value,
    }

    pub(crate) fn sign(blob: &[u8], identity: &str, issuer: &str, logged_at: i64) -> World {
        let now = time::OffsetDateTime::now_utc();
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test fulcio");
        ca.distinguished_name = dn;
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ca.not_before = now - time::Duration::days(1);
        ca.not_after = now + time::Duration::days(1);
        let ca_cert = ca.self_signed(&ca_key).unwrap();

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let leaf_key = KeyPair::try_from(pkcs8.as_ref()).unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name = DistinguishedName::new();
        p.subject_alt_names = vec![SanType::URI(identity.try_into().unwrap())];
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        p.custom_extensions =
            vec![CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 57264, 1, 1], issuer.as_bytes().to_vec())];
        p.not_before = now - time::Duration::minutes(1);
        p.not_after = now + time::Duration::minutes(9);
        let leaf = p.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        let signer = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let sig = signer.sign(&rng, blob).unwrap();
        let e64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let crt_b64 = e64(leaf.pem().as_bytes());

        let rekor_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let rekor = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, rekor_pkcs8.as_ref(), &rng).unwrap();
        let log_id = "ab".repeat(32);
        let body = serde_json::json!({"apiVersion": "0.0.1", "kind": "hashedrekord", "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": sha256_hex(blob)}},
            "signature": {"content": e64(sig.as_ref()), "publicKey": {"content": crt_b64}}}});
        let body_b64 = e64(body.to_string().as_bytes());
        let canonical =
            format!(r#"{{"body":"{body_b64}","integratedTime":{logged_at},"logID":"{log_id}","logIndex":7}}"#);
        let set = rekor.sign(&rng, canonical.as_bytes()).unwrap();
        let entry = serde_json::json!({"0123": {"body": body_b64, "integratedTime": logged_at, "logID": log_id,
            "logIndex": 7, "verification": {"signedEntryTimestamp": e64(set.as_ref())}}});
        World {
            trust: Trust::new(vec![ca_cert.der().clone()], vec![(log_id, rekor.public_key().as_ref().to_vec())]),
            sig_b64: e64(sig.as_ref()),
            crt_b64,
            entry,
        }
    }

    pub(crate) struct Fixed(pub Vec<Value>);
    impl RekorSource for Fixed {
        fn entries(&self, _: &str) -> Result<Vec<Value>> {
            Ok(self.0.clone())
        }
    }

    fn now() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }

    #[test]
    fn a_release_signed_and_logged_by_the_named_workflow_verifies() {
        let blob = b"a release";
        let w = sign(blob, ID, GITHUB_ISSUER, now());
        let s = Signed { blob, sig_b64: &w.sig_b64, crt_b64: &w.crt_b64 };
        verify(&s, ID, GITHUB_ISSUER, &w.trust, &Fixed(vec![w.entry.clone()])).unwrap();
    }

    #[test]
    fn another_identity_issuer_file_ca_log_or_time_is_refused() {
        let blob = b"a release";
        let w = sign(blob, ID, GITHUB_ISSUER, now());
        let rekor = Fixed(vec![w.entry.clone()]);
        let s = Signed { blob, sig_b64: &w.sig_b64, crt_b64: &w.crt_b64 };
        let other_id = ID.replace("v1.2.3", "v1.2.4");
        assert!(verify(&s, &other_id, GITHUB_ISSUER, &w.trust, &rekor).unwrap_err().reason.contains("signed by"));
        assert!(verify(&s, ID, "https://issuer.example.com", &w.trust, &rekor).is_err());
        let swapped = Signed { blob: b"a releasf", ..s };
        assert!(verify(&swapped, ID, GITHUB_ISSUER, &w.trust, &rekor).unwrap_err().reason.contains("does not verify"));
        let s = Signed { blob, sig_b64: &w.sig_b64, crt_b64: &w.crt_b64 };
        let stranger = sign(blob, ID, GITHUB_ISSUER, now());
        let anchors = |t: &Trust| t.authorities.iter().map(|a| a.root.clone()).collect::<Vec<_>>();
        let untrusted = Trust::new(anchors(&stranger.trust), w.trust.rekor.clone());
        assert!(verify(&s, ID, GITHUB_ISSUER, &untrusted, &rekor).unwrap_err().reason.contains("chain"));
        let other_log = Trust::new(anchors(&w.trust), stranger.trust.rekor.clone());
        assert!(verify(&s, ID, GITHUB_ISSUER, &other_log, &rekor).unwrap_err().reason.contains("transparency log"));
        assert!(verify(&s, ID, GITHUB_ISSUER, &w.trust, &Fixed(vec![])).is_err(), "no log entry");
        let late = sign(blob, ID, GITHUB_ISSUER, now() + 3600);
        let s = Signed { blob, sig_b64: &late.sig_b64, crt_b64: &late.crt_b64 };
        assert!(verify(&s, ID, GITHUB_ISSUER, &late.trust, &Fixed(vec![late.entry.clone()]))
            .unwrap_err()
            .reason
            .contains("lifetime"));
    }

    #[test]
    fn a_certificate_authority_anchors_only_inside_its_validity() {
        // The pinned trusted root: the first Fulcio CA ended on 2022-12-31; the second began on 2022-04-13.
        let t = Trust::embedded().unwrap();
        let at = |s: &str| t.valid_at(rfc3339(s).unwrap()).len();
        assert_eq!(at("2021-06-01T00:00:00Z"), 1);
        assert_eq!(at("2022-06-01T00:00:00Z"), 2);
        assert_eq!(at("2026-11-28T00:00:00Z"), 1, "the first CA is past its end");
        assert_eq!(at("2020-01-01T00:00:00Z"), 0, "before any CA");
        // A release logged while its only CA was not valid is refused, though everything else verifies.
        let blob = b"a release";
        let w = sign(blob, ID, GITHUB_ISSUER, now());
        let mut expired =
            Trust::new(w.trust.authorities.iter().map(|a| a.root.clone()).collect(), w.trust.rekor.clone());
        expired.authorities[0].end = Some(now() - 60);
        let s = Signed { blob, sig_b64: &w.sig_b64, crt_b64: &w.crt_b64 };
        let e = verify(&s, ID, GITHUB_ISSUER, &expired, &Fixed(vec![w.entry.clone()])).unwrap_err();
        assert!(e.reason.contains("no Sigstore certificate authority was valid"), "{e}");
    }

    #[test]
    fn the_pinned_trusted_root_names_fulcio_and_rekor() {
        let t = Trust::embedded().unwrap();
        assert!(!t.authorities.is_empty() && t.authorities.iter().any(|a| !a.intermediates.is_empty()));
        assert!(t.rekor.iter().any(|(id, _)| id == "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"));
    }
}

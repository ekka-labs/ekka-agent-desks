//! HTTPS downloads, https only, verified against the system's public roots, following at most five redirects
//! (GitHub sends release assets from another host). Whatever arrives is only bytes: every download is checked
//! against a pin before it is used.

use std::io::BufReader;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::error::{failed, refused, Result};
use crate::http1;

/// The public roots macOS ships for command-line clients, by their real path.
pub const MAC_SYSTEM_ROOTS: &str = "/private/etc/ssl/cert.pem";
const LINUX_SYSTEM_ROOTS: &str = "/etc/ssl/certs/ca-certificates.crt";
const TIMEOUT: Duration = Duration::from_secs(60);

pub fn system_roots_path() -> &'static Path {
    if cfg!(target_os = "macos") {
        Path::new(MAC_SYSTEM_ROOTS)
    } else {
        Path::new(LINUX_SYSTEM_ROOTS)
    }
}

/// The certificates in a PEM bundle; refused when it holds none.
pub fn pem_certs(pem: &[u8], what: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<_> = CertificateDer::pem_slice_iter(pem)
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| refused(format!("{what} is not a PEM certificate bundle")))?;
    if certs.is_empty() {
        return Err(refused(format!("{what} holds no certificate")));
    }
    Ok(certs)
}

pub fn root_store(certs: &[CertificateDer<'static>]) -> RootCertStore {
    let mut store = RootCertStore::empty();
    let _ = store.add_parsable_certificates(certs.iter().cloned());
    store
}

pub fn client_config(roots: RootCertStore) -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

struct Url {
    host: String,
    port: u16,
    target: String,
}

fn parse(url: &str) -> Result<Url> {
    let rest = url.strip_prefix("https://").ok_or_else(|| refused(format!("{url} is not an https address")))?;
    let (authority, target) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.contains('@') || authority.is_empty() {
        return Err(refused("a download address names a user or no host"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| refused("a download address has a bad port"))?),
        None => (authority, 443),
    };
    if !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
        return Err(refused("a download address's host is not a plain name"));
    }
    if target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(refused("a download address holds a space or control character"));
    }
    Ok(Url { host: host.to_ascii_lowercase(), port, target })
}

/// The body of `url`, at most `max` bytes, over https only.
pub fn get(url: &str, max: usize) -> Result<Vec<u8>> {
    request(url, "GET", None, max)
}

/// A JSON POST to `url` (no redirects followed), its answer at most `max` bytes, over https only.
pub fn post_json(url: &str, body: &str, max: usize) -> Result<Vec<u8>> {
    request(url, "POST", Some((body.as_bytes(), "application/json")), max)
}

/// An `application/x-www-form-urlencoded` POST and its answer, whatever its status: what an OAuth token endpoint
/// takes. A fake stands in for it in tests.
pub trait FormPost {
    /// The answer's status and body (at most 64 KiB). The body is zeroed when dropped: it may hold a token.
    fn post_form(&mut self, url: &str, form: &[(&str, &str)]) -> Result<(u16, zeroize::Zeroizing<Vec<u8>>)>;
}

/// The form body for `form`, every value percent-encoded; zeroed when dropped, as it may hold a secret.
pub fn form_body(form: &[(&str, &str)]) -> zeroize::Zeroizing<String> {
    let mut out = zeroize::Zeroizing::new(String::new());
    for (i, (k, v)) in form.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(&http1::query_escape(k));
        out.push('=');
        out.push_str(&http1::query_escape(v));
    }
    out
}

/// The real one: https only, verified against the system's public roots, no redirect followed.
pub struct Https;

impl FormPost for Https {
    fn post_form(&mut self, url: &str, form: &[(&str, &str)]) -> Result<(u16, zeroize::Zeroizing<Vec<u8>>)> {
        let body = form_body(form);
        let (status, bytes) =
            exchange(url, "POST", Some((body.as_bytes(), "application/x-www-form-urlencoded")), 64 * 1024, false)?;
        Ok((status, zeroize::Zeroizing::new(bytes)))
    }
}

fn request(url: &str, method: &str, body: Option<(&[u8], &str)>, max: usize) -> Result<Vec<u8>> {
    match exchange(url, method, body, max, body.is_none())? {
        (200, bytes) => Ok(bytes),
        (s, _) => {
            Err(failed(format!("{} answered {s} for a download", parse(url).map(|u| u.host).unwrap_or_default())))
        }
    }
}

/// One request and its answer's status and body (at most `max` bytes), following up to five https redirects when
/// `follow` is set.
fn exchange(url: &str, method: &str, body: Option<(&[u8], &str)>, max: usize, follow: bool) -> Result<(u16, Vec<u8>)> {
    let roots = pem_certs(
        &std::fs::read(system_roots_path()).map_err(|e| {
            failed(format!("reading the system's public roots ({}): {e}", system_roots_path().display()))
        })?,
        "the system's public roots",
    )?;
    let config = client_config(root_store(&roots));
    let mut url = url.to_string();
    for _ in 0..6 {
        let u = parse(&url)?;
        let addr = (u.host.as_str(), u.port)
            .to_socket_addrs()
            .map_err(|e| failed(format!("finding {}: {e}", u.host)))?
            .next()
            .ok_or_else(|| failed(format!("{} has no address", u.host)))?;
        let tcp =
            TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| failed(format!("reaching {}: {e}", u.host)))?;
        tcp.set_read_timeout(Some(TIMEOUT)).ok();
        tcp.set_write_timeout(Some(TIMEOUT)).ok();
        let name = ServerName::try_from(u.host.clone()).map_err(|_| refused("a download host is not a name"))?;
        let conn =
            ClientConnection::new(config.clone(), name).map_err(|e| failed(format!("TLS to {}: {e}", u.host)))?;
        let mut tls = StreamOwned::new(conn, tcp);
        let agent = concat!("ekka-desk-host/", env!("CARGO_PKG_VERSION"));
        let mut headers = vec![("User-Agent", agent), ("Accept", "*/*")];
        if let Some((_, kind)) = body {
            headers.push(("Content-Type", kind));
        }
        http1::write_request(&mut tls, method, &u.target, &u.host, &headers, body.map_or(&[][..], |(b, _)| b))
            .map_err(|e| failed(format!("asking {}: {e}", u.host)))?;
        let resp = http1::read_response(BufReader::new(tls))?;
        match resp.status {
            301 | 302 | 303 | 307 | 308 if follow => {
                url = resp
                    .header("Location")
                    .filter(|l| l.starts_with("https://"))
                    .ok_or_else(|| refused(format!("{} redirected somewhere that is not https", u.host)))?
                    .to_string();
            }
            s => return Ok((s, resp.bytes(max)?)),
        }
    }
    Err(failed("a download redirected too many times"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_https_addresses_are_fetched() {
        assert!(parse("http://github.com/x").is_err());
        assert!(parse("https://user@example.com/x").is_err());
        assert!(parse("https://github.com/a b").is_err());
        let u = parse("https://GitHub.com:8443/NVIDIA/x?y=1").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.target.as_str()), ("github.com", 8443, "/NVIDIA/x?y=1"));
    }

    #[test]
    fn a_form_is_percent_encoded_field_by_field() {
        let body = form_body(&[("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"), ("a b", "x&y=z")]);
        assert_eq!(&*body, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&a%20b=x%26y%3Dz");
    }

    #[test]
    fn the_system_roots_are_a_bundle() {
        let roots = pem_certs(&std::fs::read(system_roots_path()).unwrap(), "roots").unwrap();
        assert!(roots.len() > 50, "{}", roots.len());
        assert!(pem_certs(b"not a certificate", "x").is_err());
    }
}

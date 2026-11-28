//! The backend adapter's own signing key: one ES256 (P-256) key per installation, made on this Mac, kept at
//! `D/backend/adapter-key.pem` as unencrypted PKCS#8 PEM, owned by the developer who runs the adapter, mode 0600,
//! and never leaving the Mac. Its public half is registered with Govern (`adapter_public_jwk`); the adapter proves
//! it is this installation's with an assertion signed by it (Govern's desk-pass contract, section 3c).
//!
//! It is made once, when there is none, written whole beside and linked into place, so it is never half written
//! and never written over one made meanwhile. A key that is there is never replaced silently: one that is not safe
//! to use (another owner, a wider mode, an access control list, a link, not a P-256 key) or not the one Govern
//! registered is reported and left as it is; only `install --rotate-adapter-key` replaces it. What anyone may see
//! of it is its public JWK and its RFC 7638 thumbprint (`kid`), never the key.

use std::os::fd::OwnedFd;
use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::apply::Owners;
use crate::error::{failed, refused, Result};
use crate::fsx::{self, Walk, Wrote};
use crate::platform::macos::Layout;

pub const KEY_FILE: &str = "adapter-key.pem";
const MAX_KEY: u64 = 16 * 1024;

/// The public half, as Govern's registration takes it (`adapter_public_jwk`): only these four members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl PublicJwk {
    /// From an uncompressed P-256 point, `0x04 || x || y`.
    pub fn from_point(raw: &[u8]) -> Result<Self> {
        if raw.len() != 65 || raw[0] != 0x04 {
            return Err(refused("the adapter key's public half is not an uncompressed P-256 point"));
        }
        Ok(PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode(&raw[1..33]),
            y: URL_SAFE_NO_PAD.encode(&raw[33..65]),
        })
    }

    /// The RFC 7638 thumbprint: SHA-256 over the required members in lexicographic order with no whitespace,
    /// base64url without padding. Govern names the registered key by it (`adapter_kid`).
    pub fn thumbprint(&self) -> String {
        let canonical = serde_json::json!({"crv": self.crv, "kty": self.kty, "x": self.x, "y": self.y});
        // serde_json writes an object's members sorted by name (no `preserve_order`), with no whitespace.
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.to_string().as_bytes()))
    }
}

/// A thumbprint as Govern writes one: 43 base64url characters (256 bits).
pub fn is_kid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 43
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        && b"AEIMQUYcgkosw048".contains(&b[42])
}

/// What is at `D/backend/adapter-key.pem`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyState {
    /// `D/backend` is not there yet: the first install's root step makes it.
    NoFolder,
    Absent,
    Usable {
        jwk: PublicJwk,
        kid: String,
    },
    /// There, and never used: the reason says why.
    NotUsed(String),
}

impl KeyState {
    pub fn kid(&self) -> Option<&str> {
        match self {
            KeyState::Usable { kid, .. } => Some(kid),
            _ => None,
        }
    }
    pub fn jwk(&self) -> Option<&PublicJwk> {
        match self {
            KeyState::Usable { jwk, .. } => Some(jwk),
            _ => None,
        }
    }
}

/// `D/backend`, reached from the top through root's folders without a link, and the developer's alone
/// (`fsx::private_dir`). `None` when not there yet.
fn backend_dir(l: &Layout, owners: Owners) -> Result<Option<OwnedFd>> {
    match fsx::walk_trusted(&l.d(), &l.top, owners.root.uid, None)? {
        Walk::Found(d, _) => fsx::private_dir(&d, "backend", &l.backend_dir(), owners.dev.uid),
        Walk::Missing(_) => Ok(None),
    }
}

/// The public JWK of an ES256 key in unencrypted PKCS#8 PEM, as the adapter reads it.
fn public_of(pem: &[u8]) -> Result<PublicJwk> {
    let text = std::str::from_utf8(pem).map_err(|_| refused("it is not PEM text"))?;
    if !text.trim_start().starts_with("-----BEGIN PRIVATE KEY-----") || text.matches("-----BEGIN ").count() != 1 {
        return Err(refused("it is not one unencrypted PKCS#8 key (BEGIN PRIVATE KEY)"));
    }
    let key = KeyPair::from_pem(text).map_err(|_| refused("it is not a key this tool can read"))?;
    if key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
        return Err(refused("it is not an ES256 (P-256) key"));
    }
    PublicJwk::from_point(key.public_key_raw())
}

fn read_key(dir: &OwnedFd, path: &Path, dev_uid: u32) -> KeyState {
    let what = path.display().to_string();
    let fd = match fsx::open_file_at(dir, KEY_FILE) {
        Ok(None) => return KeyState::Absent,
        Ok(Some(fd)) => fd,
        Err(e) => return KeyState::NotUsed(format!("{what}: {}", e.reason)),
    };
    if let Err(e) = fsx::check_secret(&fd, &what, dev_uid, 0o600) {
        return KeyState::NotUsed(e.reason);
    }
    let pem = match fsx::read_regular(fd, &what, MAX_KEY) {
        Ok(b) => Zeroizing::new(b),
        Err(e) => return KeyState::NotUsed(e.reason),
    };
    match public_of(&pem) {
        Ok(jwk) => KeyState::Usable { kid: jwk.thumbprint(), jwk },
        Err(e) => KeyState::NotUsed(format!("{what}: {}", e.reason)),
    }
}

/// What is there now, read only: for `status`, and for the root plan before anything is written.
pub fn inspect(l: &Layout, owners: Owners) -> KeyState {
    match backend_dir(l, owners) {
        Ok(Some(dir)) => read_key(&dir, &l.backend_dir().join(KEY_FILE), owners.dev.uid),
        Ok(None) => KeyState::NoFolder,
        Err(e) => KeyState::NotUsed(e.reason),
    }
}

/// A new key: its PEM (zeroed when dropped) and its public JWK, read back from that same PEM.
fn generate() -> Result<(Zeroizing<String>, PublicJwk)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| failed(format!("making the adapter's signing key: {e}")))?;
    let pem = Zeroizing::new(key.serialize_pem());
    let jwk = PublicJwk::from_point(key.public_key_raw())?;
    if public_of(pem.as_bytes())? != jwk {
        return Err(failed("the adapter's new signing key does not read back as itself"));
    }
    Ok((pem, jwk))
}

/// What `ensure` did and found. No field holds the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ensured {
    pub state: KeyState,
    pub changed: Option<String>,
    /// Something the developer must act on: the key is not used as it is.
    pub problem: Option<String>,
}

/// The adapter key after install: made when there is none; replaced only when `rotate` asks for it; otherwise left
/// as it is, with a problem named when it is not safe to use or not the key Govern registered (`registered_kid`).
pub fn ensure(l: &Layout, owners: Owners, rotate: bool, registered_kid: Option<&str>) -> Result<Ensured> {
    let dir = backend_dir(l, owners)?
        .ok_or_else(|| failed(format!("{} is not there; install's root step makes it", l.backend_dir().display())))?;
    let path = l.backend_dir().join(KEY_FILE);
    let now = read_key(&dir, &path, owners.dev.uid);
    let register = "register it with Govern (ekka desk setup --local), then run install again";
    if rotate || now == KeyState::Absent {
        let (pem, jwk) = generate()?;
        let kid = jwk.thumbprint();
        let wrote = if rotate {
            fsx::write_at(&dir, KEY_FILE, pem.as_bytes(), 0o600, owners.dev)?
        } else {
            fsx::create_at(&dir, KEY_FILE, pem.as_bytes(), 0o600, owners.dev)?
        };
        if wrote == Wrote::Unchanged {
            // Another install made one meanwhile: that one stands.
            return Ok(Ensured { state: read_key(&dir, &path, owners.dev.uid), changed: None, problem: None });
        }
        let state = read_key(&dir, &path, owners.dev.uid);
        if state.kid() != Some(kid.as_str()) {
            return Err(failed(format!("{} does not read back as the key just written", path.display())));
        }
        let changed = if rotate {
            format!("replaced the adapter's signing key {} (kid {kid})", path.display())
        } else {
            format!("made the adapter's signing key {} (kid {kid})", path.display())
        };
        let problem = registered_kid
            .filter(|r| *r != kid)
            .map(|_| format!("the adapter's signing key is new (kid {kid}) and Govern registered another; {register}"));
        return Ok(Ensured { state, changed: Some(changed), problem });
    }
    let problem = match &now {
        KeyState::Usable { kid, .. } => registered_kid.filter(|r| r != kid).map(|r| {
            format!(
                "{} (kid {kid}) is not the adapter key Govern registered (kid {}); the adapter's sign-in is not \
                 written. Put the registered key back, or run install again with --rotate-adapter-key and {register}",
                path.display(),
                if is_kid(r) { r } else { "not a thumbprint" }
            )
        }),
        KeyState::NotUsed(why) => Some(format!(
            "{why}: the adapter key is not used as it is, and the adapter's sign-in is not written. Run install \
             again with --rotate-adapter-key to make a new key, then {register}"
        )),
        KeyState::NoFolder | KeyState::Absent => None,
    };
    Ok(Ensured { state: now, changed: None, problem })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::tests::{me, owners, rig};
    use crate::apply::{root_apply, Ctx};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// RFC 7638 for an EC key, computed independently of this module: the canonical JSON is written out by hand.
    #[test]
    fn the_thumbprint_is_rfc_7638_over_the_four_members_in_order() {
        let jwk = PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".into(),
            y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".into(),
        };
        let by_hand = r#"{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
        assert_eq!(jwk.thumbprint(), URL_SAFE_NO_PAD.encode(Sha256::digest(by_hand.as_bytes())));
        assert_eq!(jwk.thumbprint(), "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U");
        assert!(is_kid(&jwk.thumbprint()));
        assert!(!is_kid("x") && !is_kid(&"A".repeat(44)) && !is_kid(&format!("{}B", "A".repeat(42))));
        let point = [vec![0x04], vec![1u8; 32], vec![2u8; 32]].concat();
        let j = PublicJwk::from_point(&point).unwrap();
        assert_eq!((j.kty.as_str(), j.crv.as_str(), j.x.len(), j.y.len()), ("EC", "P-256", 43, 43));
        assert!(PublicJwk::from_point(&point[1..]).is_err(), "a point without 0x04 is refused");
    }

    fn installed() -> crate::apply::tests::Rig {
        let r = rig();
        root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        r
    }

    fn key_path(r: &crate::apply::tests::Rig) -> std::path::PathBuf {
        r.layout.backend_dir().join(KEY_FILE)
    }

    #[test]
    fn a_missing_key_is_made_once_private_to_the_developer_and_a_second_run_keeps_it() {
        let r = installed();
        assert_eq!(inspect(&r.layout, owners()), KeyState::Absent);
        let first = ensure(&r.layout, owners(), false, None).unwrap();
        let kid = first.state.kid().unwrap().to_string();
        assert!(first.changed.as_deref().unwrap().starts_with("made the adapter's signing key"));
        assert_eq!(first.problem, None);
        let p = key_path(&r);
        let m = std::fs::symlink_metadata(&p).unwrap();
        assert_eq!((m.uid(), m.permissions().mode() & 0o7777), (me().uid, 0o600));
        let pem = std::fs::read_to_string(&p).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"), "unencrypted PKCS#8, as the adapter reads it");
        let again = ensure(&r.layout, owners(), false, Some(&kid)).unwrap();
        assert_eq!((again.changed, again.problem), (None, None));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), pem, "never made twice");
        assert_eq!(inspect(&r.layout, owners()).kid(), Some(kid.as_str()));
        // The public half is what status shows; nothing printed holds the key.
        let shown = format!("{:?} {:?}", again.state, first);
        assert!(!shown.contains("PRIVATE") && !shown.contains(pem.lines().nth(1).unwrap()), "{shown}");
    }

    #[test]
    fn a_key_govern_did_not_register_is_reported_and_kept_until_rotate_is_asked() {
        let r = installed();
        let kid = ensure(&r.layout, owners(), false, None).unwrap().state.kid().unwrap().to_string();
        let pem = std::fs::read(key_path(&r)).unwrap();
        let other = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U";
        let e = ensure(&r.layout, owners(), false, Some(other)).unwrap();
        let problem = e.problem.unwrap();
        assert!(
            problem.contains(&kid) && problem.contains(other) && problem.contains("--rotate-adapter-key"),
            "{problem}"
        );
        assert_eq!(e.changed, None);
        assert_eq!(std::fs::read(key_path(&r)).unwrap(), pem, "never replaced silently");
        let rotated = ensure(&r.layout, owners(), true, Some(other)).unwrap();
        assert!(rotated.changed.as_deref().unwrap().starts_with("replaced the adapter's signing key"));
        assert!(
            rotated.problem.as_deref().unwrap().contains("ekka desk setup --local"),
            "the new key needs registering"
        );
        assert_ne!(rotated.state.kid(), Some(kid.as_str()));
        assert_ne!(std::fs::read(key_path(&r)).unwrap(), pem);
    }

    #[test]
    fn a_key_that_is_not_safe_or_not_a_p256_key_is_never_used_nor_replaced_silently() {
        let r = installed();
        ensure(&r.layout, owners(), false, None).unwrap();
        let p = key_path(&r);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let st = inspect(&r.layout, owners());
        assert!(matches!(&st, KeyState::NotUsed(why) if why.contains("mode 644")), "{st:?}");
        let e = ensure(&r.layout, owners(), false, None).unwrap();
        assert!(e.problem.as_deref().unwrap().contains("--rotate-adapter-key"), "{e:?}");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o644, "left as it is");
        // An Ed25519 key, and a link, in its place.
        let ed = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap().serialize_pem();
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, ed).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(inspect(&r.layout, owners()), KeyState::NotUsed(why) if why.contains("not an ES256")));
        std::fs::remove_file(&p).unwrap();
        std::fs::write(r.dir.path().join("elsewhere.pem"), b"x").unwrap();
        std::os::unix::fs::symlink(r.dir.path().join("elsewhere.pem"), &p).unwrap();
        assert!(matches!(inspect(&r.layout, owners()), KeyState::NotUsed(why) if why.contains("link")));
        let e = ensure(&r.layout, owners(), false, None).unwrap();
        assert!(e.problem.is_some() && e.changed.is_none());
        assert_eq!(std::fs::read(r.dir.path().join("elsewhere.pem")).unwrap(), b"x", "nothing written through it");
        // Even asked for by name, nothing replaces a link: it is refused, and the developer removes it.
        let e = ensure(&r.layout, owners(), true, None).unwrap_err();
        assert!(e.reason.contains("it was not replaced"), "{e}");
        assert_eq!(std::fs::read(r.dir.path().join("elsewhere.pem")).unwrap(), b"x");
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, b"not a key").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let rotated = ensure(&r.layout, owners(), true, None).unwrap();
        assert!(rotated.state.kid().is_some(), "a file that is not a key is replaced when asked by name");
    }

    #[test]
    fn before_the_first_root_step_there_is_no_folder_and_nothing_is_made() {
        let r = rig();
        assert_eq!(inspect(&r.layout, owners()), KeyState::NoFolder);
        assert!(ensure(&r.layout, owners(), false, None).is_err());
    }
}

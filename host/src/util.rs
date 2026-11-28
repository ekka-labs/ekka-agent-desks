//! Small shared helpers: hashing, hex, random identifiers and the checks on plain names.

use sha2::{Digest, Sha256};

use crate::error::{failed, Result};

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// 64 lowercase hex digits.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `sha256:` and 64 lowercase hex digits.
pub fn is_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(is_sha256_hex)
}

/// A lowercase UUID in its 8-4-4-4-12 form.
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|e| failed(format!("the system's random source failed: {e}")))?;
    Ok(buf)
}

/// A random (version 4) UUID, lowercase.
pub fn new_uuid() -> Result<String> {
    let mut b = random_bytes::<16>()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    Ok(format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]))
}

/// A plain file name this tool writes: letters, digits, `.`, `_` and `-`, not starting with a dot.
pub fn is_plain_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// An absolute path of plain components (no `.`, `..`, empty part or unusual character): what the adapter's
/// configuration schema and the rendered service files accept.
pub fn is_plain_absolute_path(s: &str) -> bool {
    s.len() <= 255
        && s.starts_with('/')
        && s.len() > 1
        && s[1..].split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_uuid_is_a_lowercase_version_4_uuid() {
        let u = new_uuid().unwrap();
        assert!(is_uuid(&u), "{u}");
        assert_eq!(&u[14..15], "4");
        assert_ne!(new_uuid().unwrap(), u);
    }

    #[test]
    fn digests_and_names_are_held_to_their_shape() {
        assert!(is_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!is_digest(&format!("sha256:{}", "A".repeat(64))));
        assert!(!is_digest(&format!("sha256:{}\n", "a".repeat(64))));
        assert!(is_plain_name("baseline-policy.json"));
        assert!(!is_plain_name(".hidden"));
        assert!(!is_plain_name("a/b"));
        assert!(is_plain_absolute_path("/private/var/db/ekka-dev/501/run"));
        assert!(!is_plain_absolute_path("/private/var/../etc"));
        assert!(!is_plain_absolute_path("relative/path"));
        assert!(!is_plain_absolute_path("/a//b"));
    }
}

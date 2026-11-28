//! The programs this host runs, downloaded and verified before anything is installed.
//!
//! Each archive must equal the sha256 embedded in this binary (deploy/pins.json) AND the publisher's own checksum
//! entry for it; NVIDIA hashes the archive, not the program. The program is then taken out of the archive (its one
//! regular member, nothing else accepted) and hashed separately against its own pin, and it must be an arm64
//! Mach-O. A swapped byte anywhere is refused before activation. The checked program is staged in the developer's
//! cache; root copies it again and hashes the copy it made before it is installed (`apply`).

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{failed, refused, Result};
use crate::kit;
use crate::util::{is_sha256_hex, sha256_hex};

const MAX_ARCHIVE: usize = 256 * 1024 * 1024;
const MAX_BINARY: u64 = 256 * 1024 * 1024;
const MAX_CHECKSUMS: usize = 64 * 1024;

/// One pinned program: where its archive is, what it must hash to, and the program inside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pinned {
    /// The name it is installed under, and the archive member that holds it.
    pub binary: String,
    pub archive_url: String,
    pub checksums_url: String,
    pub release_asset: String,
    pub archive_sha256: String,
    pub binary_sha256: String,
}

/// Every pin the Mac host uses, read from the embedded pins.
#[derive(Debug, Clone)]
pub struct Pins {
    pub gateway: Pinned,
    /// `None` while the adapter's Darwin release is not pinned: the host then installs no adapter and says so.
    pub adapter: Option<Pinned>,
    pub supervisor: ImagePin,
    pub sandbox: ImagePin,
    pub meter_image: String,
    pub openshell_version: String,
}

/// An image pinned by digest, and the program inside it with its own sha256 for linux/arm64.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePin {
    pub image: String,
    pub binary_in_image: String,
    pub binary_sha256: String,
}

fn text(v: &Value, what: &str) -> Result<String> {
    v.as_str().map(str::to_string).ok_or_else(|| failed(format!("deploy/pins.json: {what} is missing")))
}

/// An image pinned by digest, named as `<repository>@<digest>` (a tag beside the digest is dropped: the digest is
/// what is pulled, run and compared).
fn image_ref(s: &str, what: &str) -> Result<String> {
    let (repo, digest) = crate::runtime::docker::split_ref(s)
        .map_err(|_| failed(format!("deploy/pins.json: {what} is not pinned by digest")))?;
    Ok(format!("{repo}@{digest}"))
}

fn sha(v: &Value, what: &str) -> Result<String> {
    let s = text(v, what)?;
    if !is_sha256_hex(&s) {
        return Err(failed(format!("deploy/pins.json: {what} is not 64 lowercase hex")));
    }
    Ok(s)
}

impl Pins {
    pub fn embedded() -> Result<Self> {
        Self::parse(kit::PINS_JSON)
    }

    pub fn parse(json: &str) -> Result<Self> {
        let p: Value = serde_json::from_str(json).map_err(|e| failed(format!("deploy/pins.json: {e}")))?;
        let os = &p["openshell"];
        let version = text(&os["version"], "openshell.version")?;
        let release = text(&os["release"], "openshell.release")?;
        let g = &p["macos"]["gateway"];
        let asset = text(&g["release_asset"], "macos.gateway.release_asset")?;
        let gateway = Pinned {
            binary: text(&g["binary"], "macos.gateway.binary")?,
            archive_url: format!("{release}/{asset}"),
            checksums_url: format!("{release}/{}", text(&g["release_checksums"], "macos.gateway.release_checksums")?),
            release_asset: asset,
            archive_sha256: sha(&g["archive_sha256"], "macos.gateway.archive_sha256")?,
            binary_sha256: sha(&g["binary_sha256"], "macos.gateway.binary_sha256")?,
        };
        let a = &p["macos"]["ekka_backend"];
        // TODO(adapter release): the Darwin adapter is not published yet; its pins are null until it is.
        let adapter = match (a["version"].as_str(), a["archive_sha256"].as_str(), a["binary_sha256"].as_str()) {
            (Some(v), Some(_), Some(_)) => {
                let release = text(&a["release"], "macos.ekka_backend.release")?;
                let asset = text(&a["release_asset"], "macos.ekka_backend.release_asset")?;
                Some(Pinned {
                    binary: text(&a["binary"], "macos.ekka_backend.binary")?,
                    archive_url: format!("{release}/v{v}/{asset}"),
                    checksums_url: format!(
                        "{release}/v{v}/{}",
                        text(&a["release_checksums"], "macos.ekka_backend.release_checksums")?
                    ),
                    release_asset: asset,
                    archive_sha256: sha(&a["archive_sha256"], "macos.ekka_backend.archive_sha256")?,
                    binary_sha256: sha(&a["binary_sha256"], "macos.ekka_backend.binary_sha256")?,
                })
            }
            (None, None, None) => None,
            _ => return Err(failed("deploy/pins.json: macos.ekka_backend is half pinned")),
        };
        let img = |name: &str| -> Result<ImagePin> {
            let c = &os[name];
            Ok(ImagePin {
                image: image_ref(&text(&c["image"], &format!("openshell.{name}.image"))?, name)?,
                binary_in_image: text(&c["binary_in_image"], &format!("openshell.{name}.binary_in_image"))?,
                binary_sha256: sha(&c["platforms"]["aarch64"]["binary_sha256"], &format!("openshell.{name} aarch64"))?,
            })
        };
        Ok(Pins {
            gateway,
            adapter,
            supervisor: img("supervisor")?,
            sandbox: img("sandbox")?,
            meter_image: image_ref(&text(&p["macos"]["meter"]["image"], "macos.meter.image")?, "the meter image")?,
            openshell_version: version,
        })
    }

    /// The release name: this tool's version and a digest of every program it installs, so the same pins always
    /// make the same release and a changed pin makes a new one.
    pub fn release_id(&self) -> String {
        let mut basis = format!("gateway {}\n", self.gateway.binary_sha256);
        if let Some(a) = &self.adapter {
            basis.push_str(&format!("adapter {}\n", a.binary_sha256));
        }
        format!("{}-{}", env!("CARGO_PKG_VERSION"), &sha256_hex(basis.as_bytes())[..12])
    }
}

/// The one entry for `asset` in a `sha256sum`-style checksum file. Every line must be `<64 hex>  <name>` (or
/// `<64 hex> *<name>`); a malformed line, or no entry or two for the asset, is refused.
pub fn checksum_entry(text: &str, asset: &str) -> Result<String> {
    let mut found = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (hash, name) = line
            .split_once("  ")
            .or_else(|| line.split_once(" *"))
            .ok_or_else(|| refused("the publisher's checksum file has a line that is not `<sha256>  <name>`"))?;
        if !is_sha256_hex(hash) {
            return Err(refused("the publisher's checksum file has an entry that is not 64 lowercase hex"));
        }
        if name == asset {
            found.push(hash.to_string());
        }
    }
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(refused(format!("the publisher's checksum file has no entry for {asset}"))),
        _ => Err(refused(format!("the publisher's checksum file has more than one entry for {asset}"))),
    }
}

/// The archive is exactly what both the embedded pin and the publisher's entry say.
pub fn verify_archive(pin: &Pinned, archive: &[u8], checksums: &str) -> Result<()> {
    let upstream = checksum_entry(checksums, &pin.release_asset)?;
    if upstream != pin.archive_sha256 {
        return Err(refused(format!(
            "{}: the publisher's checksum ({upstream}) is not the pinned one ({}); nothing was installed",
            pin.release_asset, pin.archive_sha256
        )));
    }
    let got = sha256_hex(archive);
    if got != pin.archive_sha256 {
        return Err(refused(format!(
            "{}: the download hashes to {got}, not the pinned {}; nothing was installed",
            pin.release_asset, pin.archive_sha256
        )));
    }
    Ok(())
}

/// The one program in a `.tar.gz`: the archive must hold exactly one entry, a regular file named `member` at its
/// top, at most 256 MiB. Links, folders, other files and unsafe names are refused.
pub fn extract_member(archive: &[u8], member: &str) -> Result<Vec<u8>> {
    let gz = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(gz);
    let mut out = None;
    for entry in tar.entries().map_err(|e| refused(format!("the archive is not a tar.gz: {e}")))? {
        let mut entry = entry.map_err(|e| refused(format!("the archive is damaged: {e}")))?;
        let path = entry.path().map_err(|_| refused("the archive holds a name that is not text"))?.into_owned();
        let name = path.to_string_lossy().trim_start_matches("./").to_string();
        if name != member || !entry.header().entry_type().is_file() {
            return Err(refused(format!("the archive holds {name:?}; only the program {member:?} is accepted")));
        }
        if out.is_some() {
            return Err(refused(format!("the archive holds {member:?} twice")));
        }
        let mut bytes = Vec::new();
        (&mut entry)
            .take(MAX_BINARY + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| refused(format!("the archive is damaged: {e}")))?;
        if bytes.len() as u64 > MAX_BINARY {
            return Err(refused(format!("{member} is larger than 256 MiB")));
        }
        out = Some(bytes);
    }
    out.ok_or_else(|| refused(format!("the archive does not hold {member:?}")))
}

/// A 64-bit arm64 Mach-O program (thin, not universal): what launchd can start on Apple Silicon.
pub fn check_macho_arm64(bytes: &[u8]) -> Result<()> {
    const MH_MAGIC_64: [u8; 4] = [0xcf, 0xfa, 0xed, 0xfe];
    const CPU_TYPE_ARM64: [u8; 4] = [0x0c, 0x00, 0x00, 0x01];
    const MH_EXECUTE: [u8; 4] = [0x02, 0x00, 0x00, 0x00];
    if bytes.len() < 16 || bytes[0..4] != MH_MAGIC_64 || bytes[4..8] != CPU_TYPE_ARM64 || bytes[12..16] != MH_EXECUTE {
        return Err(refused("the program is not an arm64 Mach-O executable"));
    }
    Ok(())
}

/// The program equals its own pin and is an arm64 Mach-O.
pub fn verify_binary(pin: &Pinned, bytes: &[u8]) -> Result<()> {
    let got = sha256_hex(bytes);
    if got != pin.binary_sha256 {
        return Err(refused(format!(
            "{}: the program hashes to {got}, not the pinned {}; nothing was installed",
            pin.binary, pin.binary_sha256
        )));
    }
    check_macho_arm64(bytes)
}

/// Downloads, verifies and stages one program in the developer's cache folder `staging` (0700), as the
/// developer. A program already staged that still verifies is used again without a download.
pub fn stage(pin: &Pinned, staging: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(staging)
        .map_err(|e| failed(format!("making {}: {e}", staging.display())))?;
    std::fs::set_permissions(staging, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| failed(format!("setting the mode of {}: {e}", staging.display())))?;
    let path = staging.join(&pin.binary);
    if let Ok(have) = std::fs::read(&path) {
        if verify_binary(pin, &have).is_ok() {
            return Ok(path);
        }
    }
    let checksums = crate::net::get(&pin.checksums_url, MAX_CHECKSUMS)?;
    let checksums = String::from_utf8(checksums).map_err(|_| refused("the publisher's checksum file is not text"))?;
    let archive = crate::net::get(&pin.archive_url, MAX_ARCHIVE)?;
    verify_archive(pin, &archive, &checksums)?;
    let program = extract_member(&archive, &pin.binary)?;
    verify_binary(pin, &program)?;
    let tmp = staging.join(format!(".{}.tmp", pin.binary));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| failed(format!("staging {}: {e}", pin.binary)))?;
    std::io::Write::write_all(&mut f, &program).map_err(|e| failed(format!("staging {}: {e}", pin.binary)))?;
    f.sync_all().map_err(|e| failed(format!("staging {}: {e}", pin.binary)))?;
    std::fs::rename(&tmp, &path).map_err(|e| failed(format!("staging {}: {e}", pin.binary)))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin_for(program: &[u8], archive: &[u8]) -> Pinned {
        Pinned {
            binary: "openshell-gateway".into(),
            archive_url: "https://example.com/a.tar.gz".into(),
            checksums_url: "https://example.com/sums.txt".into(),
            release_asset: "openshell-gateway-aarch64-apple-darwin.tar.gz".into(),
            archive_sha256: sha256_hex(archive),
            binary_sha256: sha256_hex(program),
        }
    }

    fn macho() -> Vec<u8> {
        let mut b = vec![0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x02, 0, 0, 0];
        b.extend_from_slice(b"the rest of a program");
        b
    }

    fn targz(entries: &[(&str, &[u8], tar::EntryType)]) -> Vec<u8> {
        let mut b = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
        for (name, data, kind) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(*kind);
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            h.set_path(name).unwrap();
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    fn sums(pin: &Pinned) -> String {
        format!(
            "{}  openshell-gateway-x86_64-unknown-linux-gnu.tar.gz\n{}  {}\n",
            "1".repeat(64),
            pin.archive_sha256,
            pin.release_asset
        )
    }

    #[test]
    fn the_embedded_pins_name_nvidias_darwin_gateway_in_full() {
        let p = Pins::embedded().unwrap();
        assert_eq!(p.gateway.release_asset, "openshell-gateway-aarch64-apple-darwin.tar.gz");
        assert!(p.gateway.archive_url.starts_with("https://github.com/NVIDIA/OpenShell/releases/download/v0.1.9/"));
        assert_eq!(p.gateway.archive_sha256, "b348a57b97dc755d6a668631d328dd03fa88dc1b3565f16a094c9c59a420c51a");
        assert!(p.adapter.is_none(), "the Darwin adapter is not published yet; pin it when it is");
        assert_eq!(
            p.meter_image,
            "docker.io/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
        );
        assert!(p.release_id().starts_with(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn a_verified_archive_yields_its_program() {
        let program = macho();
        let archive = targz(&[("openshell-gateway", &program, tar::EntryType::Regular)]);
        let pin = pin_for(&program, &archive);
        verify_archive(&pin, &archive, &sums(&pin)).unwrap();
        let out = extract_member(&archive, "openshell-gateway").unwrap();
        verify_binary(&pin, &out).unwrap();
    }

    #[test]
    fn a_swapped_byte_in_the_archive_is_refused() {
        let program = macho();
        let archive = targz(&[("openshell-gateway", &program, tar::EntryType::Regular)]);
        let pin = pin_for(&program, &archive);
        let mut swapped = archive.clone();
        let i = swapped.len() / 2;
        swapped[i] ^= 0x01;
        let e = verify_archive(&pin, &swapped, &sums(&pin)).unwrap_err();
        assert!(e.reason.contains("the download hashes to"), "{e}");
    }

    #[test]
    fn a_swapped_byte_in_the_program_is_refused() {
        let program = macho();
        let archive = targz(&[("openshell-gateway", &program, tar::EntryType::Regular)]);
        let pin = pin_for(&program, &archive);
        let mut swapped = program.clone();
        *swapped.last_mut().unwrap() ^= 0x01;
        let e = verify_binary(&pin, &swapped).unwrap_err();
        assert!(e.reason.contains("the program hashes to"), "{e}");
    }

    #[test]
    fn the_publishers_entry_must_agree_with_the_pin() {
        let program = macho();
        let archive = targz(&[("openshell-gateway", &program, tar::EntryType::Regular)]);
        let pin = pin_for(&program, &archive);
        let other = format!("{}  {}\n", "2".repeat(64), pin.release_asset);
        assert!(verify_archive(&pin, &archive, &other).unwrap_err().reason.contains("not the pinned one"));
        let none = format!("{}  something-else.tar.gz\n", pin.archive_sha256);
        assert!(verify_archive(&pin, &archive, &none).unwrap_err().reason.contains("no entry"));
        let twice = format!("{0}  {1}\n{0}  {1}\n", pin.archive_sha256, pin.release_asset);
        assert!(verify_archive(&pin, &archive, &twice).unwrap_err().reason.contains("more than one"));
        assert!(checksum_entry("not a checksum line\n", "x").is_err());
        assert!(checksum_entry(&format!("{}  x\n", "A".repeat(64)), "x").is_err());
    }

    #[test]
    fn an_archive_holding_anything_but_the_program_is_refused() {
        let p = macho();
        for bad in [
            targz(&[("openshell-gateway", &p, tar::EntryType::Regular), ("extra", b"x", tar::EntryType::Regular)]),
            targz(&[("openshell-gateway", b"", tar::EntryType::Symlink)]),
            targz(&[("other-name", &p, tar::EntryType::Regular)]),
            targz(&[]),
        ] {
            assert!(extract_member(&bad, "openshell-gateway").is_err());
        }
        assert!(extract_member(b"not gzip", "openshell-gateway").is_err());
    }

    #[test]
    fn only_a_thin_arm64_executable_is_accepted() {
        check_macho_arm64(&macho()).unwrap();
        let mut x86 = macho();
        x86[4] = 0x07;
        assert!(check_macho_arm64(&x86).is_err());
        assert!(check_macho_arm64(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(check_macho_arm64(b"\x7fELF").is_err());
    }

    #[test]
    fn a_half_pinned_adapter_is_refused() {
        let mut p: Value = serde_json::from_str(kit::PINS_JSON).unwrap();
        p["macos"]["ekka_backend"]["version"] = "0.2.0".into();
        assert!(Pins::parse(&p.to_string()).is_err());
        p["macos"]["ekka_backend"]["archive_sha256"] = "a".repeat(64).into();
        p["macos"]["ekka_backend"]["binary_sha256"] = "b".repeat(64).into();
        let pins = Pins::parse(&p.to_string()).unwrap();
        let a = pins.adapter.clone().unwrap();
        assert_eq!(
            a.archive_url,
            "https://github.com/ekka-labs/ekka-backend/releases/download/v0.2.0/ekka-backend-aarch64-apple-darwin.tar.gz"
        );
        assert_ne!(pins.release_id(), Pins::embedded().unwrap().release_id(), "a new pin makes a new release");
    }

    /// NVIDIA's real v0.1.9 Darwin gateway, downloaded over https (GitHub redirects the asset) into a temporary
    /// folder: the archive matches the pin and NVIDIA's checksum entry, and the program its own pin. Online.
    #[test]
    #[ignore = "online: downloads NVIDIA's release"]
    fn online_nvidias_darwin_gateway_stages_and_verifies() {
        let pins = Pins::embedded().unwrap();
        let t = tempfile::tempdir().unwrap();
        let staged = stage(&pins.gateway, &t.path().join("staging")).unwrap();
        verify_binary(&pins.gateway, &std::fs::read(&staged).unwrap()).unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&staged).unwrap().permissions());
        assert_eq!(mode & 0o777, 0o600, "staged, never executable in the developer's cache");
    }
}

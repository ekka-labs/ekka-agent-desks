//! The `ekka` program the Enclave's LaunchAgent runs, checked to be EKKA's own release, byte for byte.
//!
//! Owning a file is not being EKKA. So the program is asked its version, that version's release is fetched from
//! EKKA's download host (its manifest, its archive for Apple Silicon, the archive's signature and certificate), the
//! archive's sha256 must equal the manifest's, the archive must be signed by EKKA's runner release workflow for
//! exactly that version tag (Sigstore, `sigstore`), and the `ekka` inside the archive must hash to exactly the
//! program on this Mac. The LaunchAgent then names that program by its real path, never a link. A program that does
//! not report an ekka version, or is not that release's `ekka`, is refused.

use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::error::{failed, refused, usage, Result};
use crate::sigstore::{self, RekorSource, Signed, Trust};
use crate::util::{is_plain_absolute_path, sha256_hex};

/// The identity that signs EKKA's runner releases, as EKKA publishes it; the version tag follows.
pub const SIGNER: &str = "https://github.com/ekka-ai/ekka-runner/.github/workflows/release-binaries.yml@refs/tags/v";
/// Where EKKA's runner releases are published.
pub const DOWNLOADS: &str = "https://get.ekka.ai/runner";
const TARGET: &str = "aarch64-apple-darwin";
const MAX_ARCHIVE: usize = 128 * 1024 * 1024;

/// A runner release's files, by version and name.
pub trait RunnerRelease {
    fn get(&self, version: &str, name: &str, max: usize) -> Result<Vec<u8>>;
}

/// EKKA's public download host.
pub struct PublicRelease;

impl RunnerRelease for PublicRelease {
    fn get(&self, version: &str, name: &str, max: usize) -> Result<Vec<u8>> {
        crate::net::get(&format!("{DOWNLOADS}/v{version}/{name}"), max)
    }
}

/// A checked `ekka`: its real path, its version, its sha256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub path: PathBuf,
    pub version: String,
    pub sha256: String,
}

fn is_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.len() <= 6 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The version the program reports for `--version` (`ekka X.Y.Z`), run as the developer for at most 10 seconds.
pub fn reported_version(program: &Path) -> Result<String> {
    let mut child = Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| refused(format!("{} could not be run: {e}", program.display())))?;
    let start = Instant::now();
    while child.try_wait().map_err(|e| failed(e.to_string()))?.is_none() {
        if start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            return Err(refused(format!("{} did not answer --version", program.display())));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut out = String::new();
    child.stdout.take().map(|mut s| s.by_ref().take(4096).read_to_string(&mut out));
    let first = out.lines().next().unwrap_or("");
    match first.split_whitespace().collect::<Vec<_>>().as_slice() {
        ["ekka", v] if is_version(v) => Ok(v.to_string()),
        _ => Err(refused(format!("{} does not report an ekka version; it is not EKKA's ekka", program.display()))),
    }
}

/// The program named, or the first `ekka` on PATH.
pub fn find(given: Option<&Path>) -> Result<PathBuf> {
    match given {
        Some(p) if p.is_absolute() => Ok(p.to_path_buf()),
        Some(_) => Err(usage("--ekka must be an absolute path")),
        None => std::env::var_os("PATH")
            .into_iter()
            .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
            .filter(|d| d.is_absolute())
            .map(|d| d.join("ekka"))
            .find(|p| p.exists())
            .ok_or_else(|| {
                refused("the ekka program is not on PATH; install EKKA, or name it with --ekka <absolute path>")
            }),
    }
}

/// Before it is run, even to ask its version: the program's real path, and the program and every folder above it, up
/// to /, owned by root or this developer, writable by nobody else, with no ACL letting anyone else change them.
/// Returns its real path and its bytes.
fn checked(program: &Path) -> Result<(PathBuf, Vec<u8>)> {
    let real = program.canonicalize().map_err(|e| refused(format!("{}: {e}", program.display())))?;
    if !is_plain_absolute_path(&real.display().to_string()) {
        return Err(refused(format!("ekka's real path {} is not a plain absolute path", real.display())));
    }
    // Before it is run, even to ask its version: the program and every folder above it, up to /, are owned by root
    // or this developer, writable by nobody else, with no ACL letting anyone else change them.
    let me = rustix::process::getuid().as_raw();
    let meta = std::fs::symlink_metadata(&real).map_err(|e| refused(format!("{}: {e}", real.display())))?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        return Err(refused(format!("{} is not a program", real.display())));
    }
    for p in real.ancestors() {
        let m = std::fs::symlink_metadata(p).map_err(|e| refused(format!("{}: {e}", p.display())))?;
        let owner_ok = m.uid() == 0 || m.uid() == me;
        if !owner_ok || m.permissions().mode() & 0o022 != 0 || m.file_type().is_symlink() {
            return Err(refused(format!(
                "{} is uid {} mode {:o}: ekka and every folder above it must be root's or yours and writable by \
                 nobody else; it was not run",
                p.display(),
                m.uid(),
                m.permissions().mode() & 0o7777
            )));
        }
        let f = std::fs::File::open(p).map_err(|e| refused(format!("{}: {e}", p.display())))?;
        if let Some(why) = crate::acl::unsafe_grant(&f, crate::acl::Guard::Writes)? {
            return Err(refused(format!("{}: {why}; it was not run", p.display())));
        }
    }
    let installed = std::fs::read(&real).map_err(|e| refused(format!("reading {}: {e}", real.display())))?;
    Ok((real, installed))
}

/// A developer's local build of `ekka` (`--local-build`, dev only): every check `verify` makes before it runs the
/// program, and then, in place of EKKA's signed release, its sha256 must be the manifest's. Only then is it run.
pub fn verify_local(program: &Path, sha256: &str) -> Result<Verified> {
    let (real, installed) = checked(program)?;
    let have = sha256_hex(&installed);
    if have != sha256 {
        return Err(refused(format!(
            "{} hashes to {have}, not the local build manifest's {sha256}; it was not run, and nothing was changed",
            real.display()
        )));
    }
    let version = reported_version(&real)?;
    Ok(Verified { path: real, version, sha256: have })
}

/// `program` is EKKA's runner release for the version it reports, byte for byte (module doc). Returns its real path.
pub fn verify(program: &Path, release: &dyn RunnerRelease, trust: &Trust, rekor: &dyn RekorSource) -> Result<Verified> {
    let (real, installed) = checked(program)?;
    let version = reported_version(&real)?;

    let manifest: Value = serde_json::from_slice(&release.get(&version, "manifest.json", 64 * 1024)?)
        .map_err(|_| refused(format!("ekka {version}'s release manifest is not JSON")))?;
    if manifest["version"] != version.as_str() {
        return Err(refused(format!("ekka {version}'s release manifest names another version")));
    }
    let artifact = manifest["artifacts"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["target"] == TARGET)
        .ok_or_else(|| refused(format!("ekka {version} has no Apple Silicon release")))?;
    let name = format!("ekka-{version}-{TARGET}.tar.gz");
    if artifact["filename"] != name.as_str() {
        return Err(refused(format!("ekka {version}'s manifest names an unexpected archive")));
    }
    let archive = release.get(&version, &name, MAX_ARCHIVE)?;
    if Some(sha256_hex(&archive).as_str()) != artifact["sha256"].as_str() {
        return Err(refused(format!("ekka {version}'s archive is not the one its manifest names")));
    }
    let sig = String::from_utf8(release.get(&version, &format!("{name}.sig"), 4096)?)
        .map_err(|_| refused("the release signature is not text"))?;
    let crt = String::from_utf8(release.get(&version, &format!("{name}.crt"), 64 * 1024)?)
        .map_err(|_| refused("the release certificate is not text"))?;
    sigstore::verify(
        &Signed { blob: &archive, sig_b64: &sig, crt_b64: &crt },
        &format!("{SIGNER}{version}"),
        sigstore::GITHUB_ISSUER,
        trust,
        rekor,
    )?;
    let member = format!("ekka-{version}-{TARGET}/bin/ekka");
    let released = archive_member(&archive, &member)?;
    let sha256 = sha256_hex(&installed);
    if sha256 != sha256_hex(&released) {
        return Err(refused(format!(
            "{} reports ekka {version} but is not that release's ekka (sha256 {sha256}); reinstall EKKA",
            real.display()
        )));
    }
    Ok(Verified { path: real, version, sha256 })
}

/// The one regular file `member` in a `.tar.gz`, in memory.
fn archive_member(archive: &[u8], member: &str) -> Result<Vec<u8>> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in tar.entries().map_err(|e| refused(format!("the ekka archive: {e}")))? {
        let mut e = entry.map_err(|e| refused(format!("the ekka archive: {e}")))?;
        let path = e.path().map_err(|_| refused("the ekka archive holds a name that is not text"))?.into_owned();
        if path.to_string_lossy() == member && e.header().entry_type().is_file() {
            let mut out = Vec::new();
            (&mut e).take(MAX_ARCHIVE as u64).read_to_end(&mut out).map_err(|e| refused(e.to_string()))?;
            return Ok(out);
        }
    }
    Err(refused(format!("the ekka archive holds no {member}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigstore::tests::{sign, Fixed};
    use std::collections::HashMap;

    struct Release(HashMap<String, Vec<u8>>);
    impl RunnerRelease for Release {
        fn get(&self, version: &str, name: &str, _: usize) -> Result<Vec<u8>> {
            self.0.get(&format!("{version}/{name}")).cloned().ok_or_else(|| refused("not published"))
        }
    }

    const V: &str = "1.2.3";

    fn program(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// A release of `ekka_bytes` for version V, signed by `identity`, in memory.
    fn release(ekka_bytes: &[u8], identity: &str) -> (Release, Trust, Fixed) {
        let mut b = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
        let mut h = tar::Header::new_gnu();
        h.set_size(ekka_bytes.len() as u64);
        h.set_mode(0o755);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_path(format!("ekka-{V}-{TARGET}/bin/ekka")).unwrap();
        h.set_cksum();
        b.append(&h, ekka_bytes).unwrap();
        let archive = b.into_inner().unwrap().finish().unwrap();
        let w = sign(&archive, identity, sigstore::GITHUB_ISSUER, time::OffsetDateTime::now_utc().unix_timestamp());
        let name = format!("ekka-{V}-{TARGET}.tar.gz");
        let manifest = serde_json::json!({"version": V, "artifacts": [
            {"os": "darwin", "arch": "arm64", "target": TARGET, "filename": name, "sha256": sha256_hex(&archive)}]});
        let files = HashMap::from([
            (format!("{V}/manifest.json"), manifest.to_string().into_bytes()),
            (format!("{V}/{name}"), archive),
            (format!("{V}/{name}.sig"), w.sig_b64.into_bytes()),
            (format!("{V}/{name}.crt"), w.crt_b64.into_bytes()),
        ]);
        (Release(files), w.trust, Fixed(vec![w.entry]))
    }

    #[test]
    fn a_root_owned_program_that_is_not_ekka_is_refused() {
        let (r, t, k) = release(b"x", &format!("{SIGNER}{V}"));
        let e = verify(Path::new("/bin/ls"), &r, &t, &k).unwrap_err();
        assert!(e.reason.contains("does not report an ekka version"), "{e}");
    }

    #[test]
    fn only_the_exact_bytes_of_the_signed_release_pass_and_by_their_real_path() {
        let d = tempfile::tempdir().unwrap();
        let real = program(d.path(), "ekka-real", &format!("echo 'ekka {V}'"));
        let (r, t, k) = release(&std::fs::read(&real).unwrap(), &format!("{SIGNER}{V}"));
        let link = d.path().join("ekka");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let v = verify(&link, &r, &t, &k).unwrap();
        assert_eq!(v.path, real.canonicalize().unwrap(), "the real path, never the link");
        assert_eq!(v.version, V);

        // The same version string, other bytes: not the release's ekka.
        let other = program(d.path(), "other", &format!("echo 'ekka {V}' # other"));
        assert!(verify(&other, &r, &t, &k).unwrap_err().reason.contains("is not that release's ekka"));
    }

    #[test]
    fn a_program_below_a_folder_others_can_write_is_never_run() {
        let d = tempfile::tempdir().unwrap();
        let open = d.path().join("open");
        let inner = open.join("bin");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let marker = d.path().join("ran");
        let p = program(&inner, "ekka", &format!("touch '{}'; echo 'ekka {V}'", marker.display()));
        let (r, t, k) = release(b"x", &format!("{SIGNER}{V}"));
        let e = verify(&p, &r, &t, &k).unwrap_err();
        assert!(e.reason.contains("it was not run"), "{e}");
        assert!(!marker.exists(), "the program was run before it was checked");
    }

    #[test]
    fn a_local_build_of_ekka_keeps_every_check_before_it_runs_and_must_hash_to_the_manifest() {
        let d = tempfile::tempdir().unwrap();
        let marker = d.path().join("ran");
        let p = program(d.path(), "ekka", &format!("touch '{}'; echo 'ekka {V}'", marker.display()));
        let sha = sha256_hex(&std::fs::read(&p).unwrap());
        let e = verify_local(&p, &"0".repeat(64)).unwrap_err();
        assert!(e.reason.contains("not the local build manifest's") && e.reason.contains("it was not run"), "{e}");
        assert!(!marker.exists(), "a program that is not the manifest's is never run");
        let v = verify_local(&p, &sha).unwrap();
        assert_eq!((v.version.as_str(), v.sha256.as_str()), (V, sha.as_str()));
        // The checks made before running it stay: a folder others can write refuses even the right bytes.
        let open = d.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let q = program(&open, "ekka", &format!("echo 'ekka {V}'"));
        let e = verify_local(&q, &sha256_hex(&std::fs::read(&q).unwrap())).unwrap_err();
        assert!(e.reason.contains("it was not run"), "{e}");
    }

    #[test]
    fn a_release_signed_by_anyone_but_ekkas_workflow_for_that_tag_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = program(d.path(), "ekka", &format!("echo 'ekka {V}'"));
        let bytes = std::fs::read(&p).unwrap();
        for identity in [
            format!("{SIGNER}9.9.9"),
            "https://github.com/example/fork/.github/workflows/x.yml@refs/tags/v1.2.3".into(),
        ] {
            let (r, t, k) = release(&bytes, &identity);
            assert!(verify(&p, &r, &t, &k).unwrap_err().reason.contains("signed by"), "{identity}");
        }
    }

    /// This Mac's own ekka against EKKA's real release, Fulcio and Rekor. Online.
    #[test]
    #[ignore = "online: EKKA's release, Sigstore's log, and an ekka installed on this Mac"]
    fn online_the_installed_ekka_is_ekkas_signed_release() {
        let p = find(None).unwrap();
        let v = verify(&p, &PublicRelease, &Trust::embedded().unwrap(), &sigstore::PublicRekor).unwrap();
        eprintln!("{} is ekka {} ({})", v.path.display(), v.version, v.sha256);
    }
}

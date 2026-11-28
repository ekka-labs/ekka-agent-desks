//! `install --env dev --local-build <dir>`: a developer's own builds in place of EKKA's signed releases, for proving
//! a change on a Mac against dev Govern before anything is released. Dev only: staging and prod are refused, before
//! anything is read.
//!
//! `<dir>/local-build.json` names any of three parts; a part it leaves out is the normal pinned release:
//!
//! ```json
//! { "ekka":         { "path": "/abs/ekka",         "sha256": "<64 hex>" },
//!   "ekka_backend": { "path": "/abs/ekka-backend", "sha256": "<64 hex>" },
//!   "desk_image":   { "image_id": "sha256:<64 hex>" } }
//! ```
//!
//! Only the release proof changes. `ekka` keeps every check made before it is run (its real path, every folder
//! above it root's or the developer's, writable by nobody else, no link, no access control list); only the Sigstore
//! release check becomes "its sha256 is the manifest's". The adapter is read by root one folder at a time from `/`
//! (no link, each folder root's or the developer's and writable by nobody else, a regular file, at most 256 MiB),
//! hashed by root, refused on any difference, and installed into the release folder like a release. The desk
//! image is `ekka-desk:local` (the name the runner's records accept) whose content id must be the manifest's.
//!
//! Nothing may mistake it for a release: root keeps `local-build.json` (`"source": "local-build"`) beside the
//! records and in `release.json`, and `status` and `doctor` print `LOUD` for each replaced part. The desk image
//! record itself stays exactly `{image, id}`: the runner refuses any other field in it.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{refused, Result};
use crate::release::Pinned;
use crate::util::{is_digest, is_plain_absolute_path, is_sha256_hex};

pub const MANIFEST: &str = "local-build.json";
/// Root's marker, beside the records, while a local build is installed.
pub const MARKER: &str = "local-build.json";
pub const MARKER_SCHEMA: &str = "ekka-desk-host.local-build/v1";
pub const SOURCE: &str = "local-build";
/// The desk image name the runner's records accept for an image built on this Mac.
pub const LOCAL_IMAGE: &str = "ekka-desk:local";
pub const LOUD: &str = "LOCAL BUILD, NOT A SIGNED RELEASE (dev only)";
const ADAPTER_BINARY: &str = "ekka-backend";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub image_id: String,
}

/// The parts a local build replaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalBuild {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ekka: Option<Program>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ekka_backend: Option<Program>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desk_image: Option<Image>,
}

/// A local build is for `--env dev` only.
pub fn only_dev(env: &str) -> Result<()> {
    if env != "dev" {
        return Err(refused(format!(
            "--local-build is for --env dev only; {env} installs EKKA's signed releases and nothing else. Nothing \
             was changed"
        )));
    }
    Ok(())
}

impl LocalBuild {
    /// For `env` only when it is dev, and every part well-formed: absolute plain paths, sha256s, a content id.
    pub fn check(&self, env: &str) -> Result<()> {
        only_dev(env)?;
        if self.ekka.is_none() && self.ekka_backend.is_none() && self.desk_image.is_none() {
            return Err(refused("local-build.json names no part (ekka, ekka_backend, desk_image)"));
        }
        for (name, p) in [("ekka", &self.ekka), ("ekka_backend", &self.ekka_backend)] {
            if let Some(p) = p {
                if !is_plain_absolute_path(&p.path) || !is_sha256_hex(&p.sha256) {
                    return Err(refused(format!(
                        "local-build.json: {name} needs an absolute plain path and a lowercase sha256"
                    )));
                }
            }
        }
        if self.desk_image.as_ref().is_some_and(|i| !is_digest(&i.image_id)) {
            return Err(refused("local-build.json: desk_image.image_id is not sha256:<64 lowercase hex>"));
        }
        Ok(())
    }

    /// `<dir>/local-build.json`, refused unless `env` is dev (checked before anything is read).
    pub fn load(dir: &Path, env: &str) -> Result<Self> {
        only_dev(env)?;
        let path = dir.join(MANIFEST);
        let meta = std::fs::symlink_metadata(&path).map_err(|e| refused(format!("{}: {e}", path.display())))?;
        if !meta.file_type().is_file() || meta.len() > 64 * 1024 {
            return Err(refused(format!("{} is not a regular file of at most 64 KiB", path.display())));
        }
        let text = std::fs::read(&path).map_err(|e| refused(format!("{}: {e}", path.display())))?;
        let lb: LocalBuild = serde_json::from_slice(&text)
            .map_err(|e| refused(format!("{} is not a local build manifest: {e}", path.display())))?;
        lb.check(env)?;
        Ok(lb)
    }

    /// The adapter as root installs it: by the manifest's sha256, in place of the pinned release.
    pub fn adapter_pin(&self) -> Option<Pinned> {
        self.ekka_backend.as_ref().map(|p| Pinned {
            binary: ADAPTER_BINARY.into(),
            archive_url: String::new(),
            checksums_url: String::new(),
            release_asset: String::new(),
            archive_sha256: String::new(),
            binary_sha256: p.sha256.clone(),
        })
    }

    /// One loud line per replaced part, for people.
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(p) = &self.ekka {
            out.push(format!("{LOUD}: ekka {} (sha256 {})", p.path, p.sha256));
        }
        if let Some(p) = &self.ekka_backend {
            out.push(format!("{LOUD}: the backend adapter (sha256 {}, from {})", p.sha256, p.path));
        }
        if let Some(i) = &self.desk_image {
            out.push(format!("{LOUD}: the desk image {LOCAL_IMAGE} ({})", i.image_id));
        }
        out
    }
}

/// Root's marker beside the records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Marker {
    pub schema: String,
    pub source: String,
    pub env: String,
    pub parts: LocalBuild,
}

pub fn marker_bytes(lb: &LocalBuild) -> Vec<u8> {
    let m = Marker { schema: MARKER_SCHEMA.into(), source: SOURCE.into(), env: "dev".into(), parts: lb.clone() };
    let mut v = serde_json::to_vec_pretty(&m).unwrap_or_default();
    v.push(b'\n');
    v
}

/// The local build root recorded, if any; `None` when there is no marker. A marker that is not one is reported.
pub fn read_marker(bytes: Option<Vec<u8>>) -> std::result::Result<Option<LocalBuild>, String> {
    let Some(bytes) = bytes else { return Ok(None) };
    let m: Marker = serde_json::from_slice(&bytes).map_err(|_| format!("{MARKER} is not a local build marker"))?;
    if m.schema != MARKER_SCHEMA || m.source != SOURCE || m.env != "dev" {
        return Err(format!("{MARKER} is not a local build marker"));
    }
    Ok(Some(m.parts))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn manifest(dir: &Path, body: &serde_json::Value) {
        std::fs::write(dir.join(MANIFEST), body.to_string()).unwrap();
    }

    #[test]
    fn a_local_build_is_refused_for_staging_and_prod_before_anything_is_read() {
        let t = tempfile::tempdir().unwrap();
        // Not even a manifest is needed to be refused.
        for env in ["staging", "prod"] {
            let e = LocalBuild::load(t.path(), env).unwrap_err();
            assert_eq!(e.kind, crate::error::Kind::Refused);
            assert!(e.reason.contains("--env dev only") && e.reason.contains("Nothing was changed"), "{e}");
        }
        manifest(t.path(), &serde_json::json!({"desk_image": {"image_id": format!("sha256:{}", "a".repeat(64))}}));
        assert!(LocalBuild::load(t.path(), "dev").unwrap().desk_image.is_some());
        assert!(LocalBuild::load(t.path(), "prod").is_err());
    }

    #[test]
    fn a_manifest_must_name_parts_well_formed_and_nothing_else() {
        let t = tempfile::tempdir().unwrap();
        for bad in [
            serde_json::json!({}),
            serde_json::json!({"ekka": {"path": "relative/ekka", "sha256": "a".repeat(64)}}),
            serde_json::json!({"ekka": {"path": "/x/ekka", "sha256": "A".repeat(64)}}),
            serde_json::json!({"desk_image": {"image_id": "ekka-desk:local"}}),
            serde_json::json!({"ekka_backend": {"path": "/x/b", "sha256": "a".repeat(64), "signed": true}}),
            serde_json::json!({"gateway": {"path": "/x/g", "sha256": "a".repeat(64)}}),
        ] {
            manifest(t.path(), &bad);
            assert!(LocalBuild::load(t.path(), "dev").is_err(), "{bad}");
        }
    }

    #[test]
    fn the_marker_says_local_build_and_reads_back() {
        let lb = LocalBuild {
            ekka: None,
            ekka_backend: Some(Program { path: "/x/ekka-backend".into(), sha256: "b".repeat(64) }),
            desk_image: None,
        };
        let v: serde_json::Value = serde_json::from_slice(&marker_bytes(&lb)).unwrap();
        assert_eq!((v["source"].as_str(), v["env"].as_str()), (Some("local-build"), Some("dev")));
        assert_eq!(read_marker(Some(marker_bytes(&lb))).unwrap(), Some(lb.clone()));
        assert_eq!(read_marker(None).unwrap(), None);
        assert!(read_marker(Some(b"{}".to_vec())).is_err());
        assert!(lb.lines()[0].starts_with(LOUD));
    }
}

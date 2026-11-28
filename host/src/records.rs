//! The root-owned records EKKA's desk commands read to build a desks grant's limits: the reviewed baseline policy,
//! the desk image by its content id, and the provider ceiling with the largest CPU and memory one desk may have.
//!
//! The Enclave's own user runs those commands, so it must be able to read the records and must never be able to
//! change them: root owns every folder from `/` down, nobody else can write any of them, and each record is
//! replaced whole (`fsx`). The folder is `/private/var/lib/ekka-agent-desks/backend`, the real path the `ekka`
//! runner reads on macOS (its walk from `/` refuses every link, and `/var` is a link on a Mac).

use std::path::Path;

use serde::Serialize;

use crate::apply::Ctx;
use crate::error::{refused, Result};
use crate::fsx::Owner;
use crate::kit;
use crate::release::DeskImagePin;
use crate::util::is_digest;

/// Where the records live on a Mac, by their real path.
pub const RECORDS_DIR: &str = "/private/var/lib/ekka-agent-desks/backend";
pub const BASELINE: &str = "baseline-policy.json";
pub const IMAGE: &str = "desk-image.json";
pub const CEILING: &str = "provider-ceiling.json";
const MAX_POLICY: usize = 1024 * 1024;

/// The largest CPU and memory a single desk may be given. The runner refuses a ceiling outside these ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub max_cpu_millicores: u64,
    pub max_memory_mib: u64,
}

/// The most one desk may ever be given on a developer Mac, compiled in and enforced by the root step: a request
/// above these is refused, whatever the VM has.
pub const MAX_DESK_CPU_MILLICORES: u64 = 8_000;
pub const MAX_DESK_MEMORY_MIB: u64 = 16_384;

impl Resources {
    pub fn check(&self) -> Result<()> {
        if !(100..=MAX_DESK_CPU_MILLICORES).contains(&self.max_cpu_millicores) {
            return Err(refused(format!(
                "the desk CPU ceiling must be 100 to {MAX_DESK_CPU_MILLICORES} millicores on a developer Mac"
            )));
        }
        if !(256..=MAX_DESK_MEMORY_MIB).contains(&self.max_memory_mib) {
            return Err(refused(format!(
                "the desk memory ceiling must be 256 to {MAX_DESK_MEMORY_MIB} MiB on a developer Mac"
            )));
        }
        Ok(())
    }

    /// Half of what Docker's VM has, so one desk can never take the whole VM, and never above the compiled-in
    /// maxima.
    pub fn half_of(vm_cpus: u64, vm_memory_bytes: u64) -> Result<Self> {
        let r = Resources {
            max_cpu_millicores: (vm_cpus.saturating_mul(1000) / 2).min(MAX_DESK_CPU_MILLICORES),
            max_memory_mib: (vm_memory_bytes / (1024 * 1024) / 2).min(MAX_DESK_MEMORY_MIB),
        };
        r.check().map_err(|e| refused(format!("Docker's VM is too small for one desk: {}", e.reason)))?;
        Ok(r)
    }

    /// An explicit ceiling must fit in the VM it runs on.
    pub fn fits(&self, vm_cpus: u64, vm_memory_bytes: u64) -> Result<()> {
        self.check()?;
        if self.max_cpu_millicores > vm_cpus.saturating_mul(1000) {
            return Err(refused(format!(
                "the desk CPU ceiling ({} millicores) is more than Docker's VM has ({vm_cpus} CPUs)",
                self.max_cpu_millicores
            )));
        }
        if self.max_memory_mib > vm_memory_bytes / (1024 * 1024) {
            return Err(refused(format!(
                "the desk memory ceiling ({} MiB) is more than Docker's VM has ({} MiB)",
                self.max_memory_mib,
                vm_memory_bytes / (1024 * 1024)
            )));
        }
        Ok(())
    }
}

/// A host the runner's ceiling accepts: two or more labels of lowercase letters, digits and inner hyphens.
pub fn is_host(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    labels.len() >= 2
        && labels.iter().all(|l| {
            let b = l.as_bytes();
            (1..=63).contains(&b.len())
                && edge(b[0])
                && edge(b[b.len() - 1])
                && b.iter().all(|c| edge(*c) || *c == b'-')
        })
}

/// A profile name the runner accepts.
fn is_profile_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=63).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
}

/// The endpoint hosts one YAML profile names, sorted and unique: each line that is `host: <name>` (optionally a
/// list item), the same lines the Linux installer reads. A named host the runner would refuse is refused here.
pub fn profile_hosts(name: &str, yaml: &str) -> Result<Vec<String>> {
    let mut hosts = std::collections::BTreeSet::new();
    for line in yaml.lines() {
        let t = line.trim_start();
        let t = t.strip_prefix('-').map(str::trim_start).unwrap_or(t);
        let Some(rest) = t.strip_prefix("host:") else { continue };
        let value = rest.trim();
        if value.is_empty() || value.contains(char::is_whitespace) || value.contains('#') {
            continue;
        }
        let host = value.trim_matches(|c| c == '\'' || c == '"');
        if !is_host(host) {
            return Err(refused(format!("{name}.yaml names a host the limits cannot hold: {host:?}")));
        }
        hosts.insert(host.to_string());
    }
    Ok(hosts.into_iter().collect())
}

pub fn baseline_bytes() -> Result<Vec<u8>> {
    let data = kit::BASELINE_POLICY;
    if data.len() > MAX_POLICY {
        return Err(refused("the baseline policy is larger than 1 MiB"));
    }
    match serde_json::from_slice::<serde_json::Value>(data) {
        Ok(serde_json::Value::Object(_)) => Ok(data.to_vec()),
        _ => Err(refused("the baseline policy is not a JSON object")),
    }
}

/// The desk image record, from a published image pinned by digest: never from an image built on this Mac.
pub fn image_bytes(pin: &DeskImagePin) -> Result<Vec<u8>> {
    if !is_digest(&pin.image_id) || !pin.image.rsplit_once('@').is_some_and(|(_, d)| is_digest(d)) {
        return Err(refused("the desk image pin is not an image pinned by digest with its content id"));
    }
    #[derive(Serialize)]
    struct Image<'a> {
        image: &'a str,
        id: &'a str,
    }
    pretty(&Image { image: &pin.image, id: &pin.image_id })
}

/// The desk image record for a developer's local build (`--local-build`, dev only): `ekka-desk:local` by its
/// content id, exactly the two fields the runner reads (it refuses any other, so the record carries no `source`;
/// root's `local-build.json` beside it says this is a local build).
pub fn local_image_bytes(image_id: &str) -> Result<Vec<u8>> {
    if !is_digest(image_id) {
        return Err(refused("the local desk image id is not sha256:<64 lowercase hex>"));
    }
    #[derive(Serialize)]
    struct Image<'a> {
        image: &'a str,
        id: &'a str,
    }
    pretty(&Image { image: crate::local_build::LOCAL_IMAGE, id: image_id })
}

/// The desk image record this installation should hold: a local build's image when it names one, otherwise the
/// published pinned image, otherwise none (desks wait, closed).
pub fn expected_image(
    pin: Option<&DeskImagePin>,
    local: Option<&crate::local_build::LocalBuild>,
) -> Result<Option<Vec<u8>>> {
    match (local.and_then(|l| l.desk_image.as_ref()), pin) {
        (Some(i), _) => local_image_bytes(&i.image_id).map(Some),
        (None, Some(pin)) => image_bytes(pin).map(Some),
        (None, None) => Ok(None),
    }
}

#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CeilingProfile {
    pub name: String,
    pub hosts: Vec<String>,
}

#[derive(Debug, Serialize, serde::Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Ceiling {
    pub profiles: Vec<CeilingProfile>,
    pub hosts: Vec<String>,
    /// The largest CPU and memory one desk may have, when the profile sets one. Left out (never `null`) when it
    /// does not: the runner reads an absent ceiling as none, and a developer's Mac has none in this release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,
}

impl Ceiling {
    /// The runner's own rules: unique valid names, sorted unique hosts, the hosts the sorted union of the
    /// profiles' (1 to 64), and a resource ceiling within range.
    pub fn check(&self) -> Result<()> {
        let mut names = std::collections::BTreeSet::new();
        let mut union = std::collections::BTreeSet::new();
        let sorted = |h: &[String]| h.iter().all(|x| is_host(x)) && h.windows(2).all(|w| w[0] < w[1]);
        for p in &self.profiles {
            if !is_profile_name(&p.name) || !names.insert(&p.name) || !sorted(&p.hosts) {
                return Err(refused("the provider ceiling needs unique valid profile names and sorted unique hosts"));
            }
            union.extend(p.hosts.iter().cloned());
        }
        if !(1..=64).contains(&self.hosts.len())
            || !sorted(&self.hosts)
            || self.hosts != union.into_iter().collect::<Vec<_>>()
        {
            return Err(refused("the provider ceiling's hosts must be the sorted union of its profiles' (1 to 64)"));
        }
        match &self.resources {
            Some(r) => r.check(),
            None => Ok(()),
        }
    }
}

/// The provider ceiling: every profile this install puts in the gateway, the hosts each names, all of them, and
/// the largest CPU and memory one desk may be given. Without a resource ceiling a desks grant carries none, and
/// desks run with no CPU or memory limit at all.
pub fn ceiling(resources: Option<Resources>) -> Result<Ceiling> {
    let mut profiles = Vec::new();
    for p in &kit::PROVIDERS {
        profiles.push(CeilingProfile { name: p.name.to_string(), hosts: profile_hosts(p.name, p.yaml)? });
    }
    profiles.sort_by(|a, b| a.name.cmp(&b.name));
    let hosts: std::collections::BTreeSet<String> = profiles.iter().flat_map(|p| p.hosts.iter().cloned()).collect();
    let c = Ceiling { profiles, hosts: hosts.into_iter().collect(), resources };
    c.check()?;
    Ok(c)
}

pub fn ceiling_bytes(resources: Option<Resources>) -> Result<Vec<u8>> {
    pretty(&ceiling(resources)?)
}

fn pretty<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    let mut out = serde_json::to_vec_pretty(v).map_err(|e| refused(format!("a record could not be written: {e}")))?;
    out.push(b'\n');
    Ok(out)
}

/// Writes (or, checking, compares) the records under `dir`, reached from `top`, all owned by `root`. Without a
/// desk image record (`expected_image`), none is written: desks wait, closed, until there is one.
pub fn write(
    ctx: &mut Ctx,
    top: &Path,
    dir: &Path,
    root: Owner,
    desk_image: Option<&[u8]>,
    resources: Option<Resources>,
) -> Result<()> {
    let mut files = vec![(BASELINE, baseline_bytes()?), (CEILING, ceiling_bytes(resources)?)];
    if let Some(record) = desk_image {
        files.push((IMAGE, record.to_vec()));
    }
    let fd = ctx.trusted_dir(top, dir, root.uid, 0o755)?;
    for (name, data) in files {
        ctx.file(fd.as_ref(), dir, name, &data, 0o644, root)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::Ctx;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn me() -> Owner {
        Owner { uid: rustix::process::getuid().as_raw(), gid: rustix::process::getgid().as_raw() }
    }

    const ID: &str = "sha256:e1063b44e1063b44e1063b44e1063b44e1063b44e1063b44e1063b44e1063b44";

    fn pin() -> DeskImagePin {
        DeskImagePin { image: format!("ghcr.io/example/desk@sha256:{}", "1".repeat(64)), image_id: ID.into() }
    }
    const RES: Resources = Resources { max_cpu_millicores: 4000, max_memory_mib: 8192 };

    #[test]
    fn the_ceiling_names_every_imported_profile_with_positive_cpu_and_memory() {
        let c = ceiling(Some(RES)).unwrap();
        let names: Vec<_> = c.profiles.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["bitbucket", "claude-code", "codex", "github"]);
        assert!(c.hosts.contains(&"github.com".to_string()));
        let r = c.resources.unwrap();
        assert!(r.max_cpu_millicores > 0 && r.max_memory_mib > 0);
        // The same hosts the gateway's JSON forms name: the ceiling and the gateway can never disagree.
        for p in &kit::PROVIDERS {
            let json: serde_json::Value = serde_json::from_str(p.json).unwrap();
            let mut from_json: Vec<String> =
                json["endpoints"].as_array().unwrap().iter().map(|e| e["host"].as_str().unwrap().to_string()).collect();
            from_json.sort();
            from_json.dedup();
            assert_eq!(from_json, profile_hosts(p.name, p.yaml).unwrap(), "{}", p.name);
        }
        let text = String::from_utf8(ceiling_bytes(Some(RES)).unwrap()).unwrap();
        assert!(text.contains("\"max_cpu_millicores\": 4000") && text.ends_with("}\n"), "{text}");
    }

    #[test]
    fn a_ceiling_outside_the_runners_ranges_is_refused() {
        assert!(ceiling(Some(Resources { max_cpu_millicores: 0, max_memory_mib: 8192 })).is_err());
        assert!(ceiling(Some(Resources { max_cpu_millicores: 4000, max_memory_mib: 0 })).is_err());
        assert!(Resources::half_of(1, 256 * 1024 * 1024).is_err(), "a VM too small for one desk is refused");
        let half = Resources::half_of(8, 16 * 1024 * 1024 * 1024).unwrap();
        assert_eq!(half, Resources { max_cpu_millicores: 4000, max_memory_mib: 8192 });
        assert!(Resources { max_cpu_millicores: 9000, max_memory_mib: 1024 }.fits(8, 16 << 30).is_err());
        // The compiled-in maxima hold whatever the VM has.
        let big = Resources::half_of(64, 512 << 30).unwrap();
        assert_eq!((big.max_cpu_millicores, big.max_memory_mib), (MAX_DESK_CPU_MILLICORES, MAX_DESK_MEMORY_MIB));
        assert!(Resources { max_cpu_millicores: MAX_DESK_CPU_MILLICORES + 1, max_memory_mib: 1024 }.check().is_err());
        assert!(Resources { max_cpu_millicores: 1000, max_memory_mib: MAX_DESK_MEMORY_MIB + 1 }.check().is_err());
    }

    /// The runner's ceiling reader, field for field: `resources` may be absent, and nothing else may be added.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct RunnerCeiling {
        profiles: Vec<CeilingProfile>,
        #[serde(default)]
        resources: Option<Resources>,
        hosts: Vec<String>,
    }

    #[test]
    fn a_developer_mac_ceiling_has_no_resources_and_the_runner_reads_it() {
        let bytes = ceiling_bytes(None).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v.get("resources").is_none(), "left out, never null: {v}");
        let runner: RunnerCeiling = serde_json::from_slice(&bytes).unwrap();
        assert!(runner.resources.is_none() && !runner.hosts.is_empty());
        // A profile that sets one still writes it, in the shape the runner reads.
        let with: RunnerCeiling = serde_json::from_slice(&ceiling_bytes(Some(RES)).unwrap()).unwrap();
        assert_eq!(with.resources, Some(RES));
    }

    #[test]
    fn a_profile_host_the_runner_would_refuse_is_refused() {
        assert!(profile_hosts("x", "endpoints:\n  - host: Example.COM\n").is_err());
        assert!(profile_hosts("x", "endpoints:\n  - host: localhost\n").is_err());
        assert_eq!(profile_hosts("x", "  - host: 'a.example.com'\n  host: b.example.com\n").unwrap().len(), 2);
    }

    #[test]
    fn the_image_record_holds_only_a_pinned_image_and_its_content_id() {
        assert!(image_bytes(&DeskImagePin { image: "ekka-desk:local".into(), image_id: ID.into() }).is_err());
        assert!(image_bytes(&DeskImagePin { image: pin().image, image_id: format!("{ID}\n") }).is_err());
        let v: serde_json::Value = serde_json::from_slice(&image_bytes(&pin()).unwrap()).unwrap();
        assert_eq!(v, serde_json::json!({"image": pin().image, "id": ID}));
    }

    #[test]
    fn records_are_written_owner_only_writable_and_a_second_write_changes_nothing() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("private/var/lib/ekka-agent-desks/backend");
        let mut ctx = Ctx::apply();
        write(&mut ctx, t.path(), &dir, me(), Some(&image_bytes(&pin()).unwrap()), Some(RES)).unwrap();
        assert_eq!(ctx.changes.len(), 8, "{:?}", ctx.changes); // five folders made, three records
        for name in [BASELINE, IMAGE, CEILING] {
            let m = std::fs::metadata(dir.join(name)).unwrap();
            assert_eq!(m.permissions().mode() & 0o7777, 0o644, "{name}: only its owner may write it");
            assert_eq!(m.uid(), me().uid);
        }
        let d = std::fs::metadata(&dir).unwrap();
        assert_eq!(d.permissions().mode() & 0o7777, 0o755, "nobody else may add or rename a record");
        assert_eq!(std::fs::read(dir.join(BASELINE)).unwrap(), kit::BASELINE_POLICY);

        let mut again = Ctx::apply();
        write(&mut again, t.path(), &dir, me(), Some(&image_bytes(&pin()).unwrap()), Some(RES)).unwrap();
        assert!(again.changes.is_empty(), "{:?}", again.changes);
        let mut check = Ctx::check();
        write(
            &mut check,
            t.path(),
            &dir,
            me(),
            Some(&image_bytes(&pin()).unwrap()),
            Some(Resources { max_cpu_millicores: 2000, ..RES }),
        )
        .unwrap();
        assert_eq!(check.changes.len(), 1, "a changed ceiling is one change: {:?}", check.changes);
        assert_eq!(
            std::fs::read(dir.join(CEILING)).unwrap(),
            ceiling_bytes(Some(RES)).unwrap(),
            "checking wrote nothing"
        );
    }

    #[test]
    fn a_record_that_is_a_link_is_refused_and_its_target_untouched() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("backend");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(t.path().join("wide-open.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(t.path().join("wide-open.json"), dir.join(CEILING)).unwrap();
        let mut ctx = Ctx::apply();
        let e = write(&mut ctx, t.path(), &dir, me(), Some(&image_bytes(&pin()).unwrap()), Some(RES)).unwrap_err();
        assert!(e.reason.contains("provider-ceiling.json is a link"), "{e}");
        assert_eq!(std::fs::read(t.path().join("wide-open.json")).unwrap(), b"{}");
    }

    #[test]
    fn a_local_desk_image_is_recorded_exactly_as_the_runner_reads_it() {
        let lb = crate::local_build::LocalBuild {
            ekka: None,
            ekka_backend: None,
            desk_image: Some(crate::local_build::Image { image_id: ID.into() }),
        };
        let v: serde_json::Value =
            serde_json::from_slice(&expected_image(Some(&pin()), Some(&lb)).unwrap().unwrap()).unwrap();
        assert_eq!(v, serde_json::json!({"image": "ekka-desk:local", "id": ID}), "only the two fields, no source");
        assert_eq!(expected_image(Some(&pin()), None).unwrap().unwrap(), image_bytes(&pin()).unwrap());
        assert_eq!(expected_image(None, None).unwrap(), None);
        assert!(local_image_bytes("ekka-desk:local").is_err());
    }

    #[test]
    fn a_records_folder_reached_through_a_link_is_refused() {
        // /var is a link on a Mac: the records must be named by their real path, as the runner reads them.
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("private/var")).unwrap();
        std::os::unix::fs::symlink(t.path().join("private/var"), t.path().join("var")).unwrap();
        let mut ctx = Ctx::apply();
        let e = write(
            &mut ctx,
            t.path(),
            &t.path().join("var/lib/ekka-agent-desks/backend"),
            me(),
            Some(&image_bytes(&pin()).unwrap()),
            Some(RES),
        )
        .unwrap_err();
        assert!(e.reason.contains("is a link or not a folder"), "{e}");
        assert!(!t.path().join("private/var/lib").exists());
    }
}

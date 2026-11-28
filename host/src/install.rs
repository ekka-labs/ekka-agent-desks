//! `ekka-desk-host install --profile developer-native --runtime docker-desktop --env <env> --org <tenant id>
//! --identity-profile <file>`: one native Mac desk host for the developer running it.
//!
//! In order: refuse a foreign organization before any change; check every download and image as the developer;
//! work out what root must change, and ask for the password once only when something does; then, as the
//! developer, write the three LaunchAgents and start them in the login session (the gateway only after the
//! Enclave's interceptor answers), start the memory meter, and run the gateway's one-time setup when it can.
//! Every step reads first and changes only what differs, so running it again is safe and, when nothing changed,
//! a no-op. What cannot be done yet is named, with what it waits for.

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::adapter::{self, AdapterInputs};
use crate::apply::{self, Ctx, Owners, RootPlan, PLAN_SCHEMA};
use crate::binding::{Binding, Want};
use crate::bootstrap::{self, Desired, GatewayAdmin, GovernExchangeNotYetAvailable, Pass, Stop};
use crate::error::{failed, refused, usage, Result};
use crate::fsx::Owner;
use crate::identity::Profile;
use crate::kit;
use crate::meter;
use crate::platform::macos::{self, Layout, ServiceInputs, LABEL_BACKEND, LABEL_ENCLAVE, LABEL_GATEWAY};
use crate::records::{Resources, DESK_IMAGE_TAG};
use crate::release::{self, Pins};
use crate::runtime::docker::{recipe_source, Docker};
use crate::tls;
use crate::util::is_plain_absolute_path;

#[derive(Debug, Clone, Default)]
pub struct Args {
    pub profile: String,
    pub runtime: String,
    pub env: String,
    pub org: String,
    pub identity_profile: PathBuf,
    pub ekka: Option<PathBuf>,
    pub cpu_millicores: Option<u64>,
    pub memory_mib: Option<u64>,
}

/// What an install did and what it still waits for.
#[derive(Debug, Default)]
pub struct Outcome {
    pub changes: Vec<String>,
    pub pending: Vec<String>,
}

fn say(s: impl AsRef<str>) {
    println!("   {}", s.as_ref());
}

/// The `ekka` program the Enclave runs: an absolute path, a regular file (through any link) that only its owner
/// may change, in a folder only its owner may change.
pub fn resolve_ekka(given: Option<&Path>) -> Result<PathBuf> {
    let path = match given {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(_) => return Err(usage("--ekka must be an absolute path")),
        None => std::env::var_os("PATH")
            .into_iter()
            .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
            .filter(|d| d.is_absolute())
            .map(|d| d.join("ekka"))
            .find(|p| p.is_file())
            .ok_or_else(|| {
                refused("the ekka program is not on PATH; install EKKA, or name it with --ekka <absolute path>")
            })?,
    };
    if !is_plain_absolute_path(&path.display().to_string()) {
        return Err(refused(format!("{} is not a plain absolute path", path.display())));
    }
    let real = path.canonicalize().map_err(|e| refused(format!("{}: {e}", path.display())))?;
    for p in [real.as_path(), real.parent().unwrap_or(Path::new("/"))] {
        let m = std::fs::metadata(p).map_err(|e| refused(format!("{}: {e}", p.display())))?;
        if m.permissions().mode() & 0o022 != 0 {
            return Err(refused(format!("{} can be changed by users other than its owner", p.display())));
        }
    }
    if !std::fs::metadata(&real).map(|m| m.is_file() && m.mode() & 0o111 != 0).unwrap_or(false) {
        return Err(refused(format!("{} is not a program", path.display())));
    }
    Ok(path)
}

fn wait_for(what: &str, limit: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    say(format!("{what}: not yet, after {} s", limit.as_secs()));
    false
}

/// Puts the meter in place on the developer's Docker Desktop: unchanged when this release's meter already runs.
pub fn ensure_meter(docker: &Docker, pins: &Pins, out: &mut Outcome) -> Result<()> {
    docker.pull(&pins.meter_image)?;
    if let Some(c) = docker.container(meter::NAME)? {
        let id = c["Id"].as_str().unwrap_or(meter::NAME).to_string();
        if meter::differences(&c, &pins.meter_image).is_empty() {
            if c["State"]["Running"].as_bool() != Some(true) {
                docker.start(&id)?;
                out.changes.push("started the memory meter".into());
            }
            return Ok(());
        }
        docker.remove(&id)?;
        out.changes.push("removed a memory meter that was not this release's".into());
    }
    let id = docker.create(Some(meter::NAME), &meter::container(&pins.meter_image))?;
    docker.start(&id)?;
    out.changes.push(format!("started the memory meter ({})", meter::NAME));
    Ok(())
}

/// The gateway calls for setup are made with Govern's setup pass, which this release cannot obtain; until then
/// no call is ever made (the pass source stops first).
struct GatewayNotCalled;

impl GatewayAdmin for GatewayNotCalled {
    fn workspace_exists(&mut self, _: &Pass, _: &str) -> std::result::Result<bool, Stop> {
        Err(Stop::Pending("no gateway call without a setup pass".into()))
    }
    fn create_workspace(&mut self, _: &Pass, _: &str) -> std::result::Result<(), Stop> {
        Err(Stop::Pending("no gateway call without a setup pass".into()))
    }
    fn members(&mut self, _: &Pass, _: &str) -> std::result::Result<Vec<bootstrap::Member>, Stop> {
        Err(Stop::Pending("no gateway call without a setup pass".into()))
    }
    fn add_member(&mut self, _: &Pass, _: &str, _: &bootstrap::Member) -> std::result::Result<(), Stop> {
        Err(Stop::Pending("no gateway call without a setup pass".into()))
    }
    fn profiles(&mut self, _: &Pass) -> std::result::Result<Vec<bootstrap::ProviderProfile>, Stop> {
        Err(Stop::Pending("no gateway call without a setup pass".into()))
    }
    fn import_profiles(&mut self, _: &Pass, _: &[bootstrap::ProviderProfile]) -> std::result::Result<(), Stop> {
        Err(Stop::Pending("no gateway call without a setup pass".into()))
    }
}

pub fn run(args: &Args) -> Result<Outcome> {
    let mut out = Outcome::default();
    let user = macos::developer()?;
    let want = Want {
        org: args.org.clone(),
        uid: user.uid,
        env: args.env.clone(),
        profile: args.profile.clone(),
        runtime: args.runtime.clone(),
    };
    want.check()?;
    let profile = Profile::load(&args.identity_profile)?;
    if profile.org != want.org {
        return Err(refused(format!(
            "the identity profile is for organization {}, not --org {}; nothing was changed",
            profile.org, want.org
        )));
    }
    let l = Layout::system(user.uid, user.home.clone());

    println!("== the installation's binding");
    if let Some(b) = Binding::read(&l.binding())? {
        b.check_same(&want)?;
        say(format!("bound to organization {} (installation {}): the same, continuing", b.org, b.installation_id));
    }
    let enclave = adapter::read_enclave_values(&adapter::enclave_env_path(&l, &want.env))?;
    if let Some(e) = &enclave {
        if e.tenant_id != want.org {
            return Err(refused(format!(
                "the Enclave in {} is enrolled in organization {}, not {}; nothing was changed",
                l.enclave_home().display(),
                e.tenant_id,
                want.org
            )));
        }
    }
    let ekka = resolve_ekka(args.ekka.as_deref())?;
    say(format!("the Enclave runs {}", ekka.display()));

    println!("== Docker Desktop");
    let docker = Docker::new(&l.docker_socket());
    docker.ping()?;
    let info = docker.info()?;
    if info.os_type != "linux" || info.arch != "aarch64" {
        return Err(refused(format!("Docker's VM is {}/{}; desks need linux/aarch64", info.os_type, info.arch)));
    }
    say(format!(
        "{} {}, {} CPUs, {} MiB",
        info.operating_system,
        info.server_version,
        info.cpus,
        info.memory_bytes >> 20
    ));
    let resources = match (args.cpu_millicores, args.memory_mib) {
        (None, None) => Resources::half_of(info.cpus, info.memory_bytes)?,
        (Some(c), Some(m)) => {
            let r = Resources { max_cpu_millicores: c, max_memory_mib: m };
            r.fits(info.cpus, info.memory_bytes)?;
            r
        }
        _ => return Err(usage("give both --desk-cpu-millicores and --desk-memory-mib, or neither")),
    };
    say(format!(
        "one desk may have at most {} millicores and {} MiB",
        resources.max_cpu_millicores, resources.max_memory_mib
    ));

    println!("== verified downloads");
    let pins = Pins::embedded()?;
    let staging = l.staging(&pins.release_id());
    let gateway_staged = release::stage(&pins.gateway, &staging)?;
    say(format!("NVIDIA OpenShell gateway {}: archive and program match their pins", pins.openshell_version));
    let adapter_staged = match &pins.adapter {
        Some(pin) => {
            let p = release::stage(pin, &staging)?;
            say("EKKA backend adapter: archive and program match their pins");
            Some(p)
        }
        None => {
            out.pending.push("the backend adapter: its macOS release is not pinned in this release yet".into());
            None
        }
    };

    println!("== images, by digest");
    docker.verify_image(&pins.supervisor)?;
    docker.verify_image(&pins.sandbox)?;
    say("the supervisor and sandbox runtime hold their pinned programs");
    let source = recipe_source(&kit::DESK_IMAGE);
    let have = docker.image(DESK_IMAGE_TAG)?;
    let desk_image_id = match have {
        Some(img) if img["Config"]["Labels"]["ekka.desk.source"].as_str() == Some(source.as_str()) => {
            img["Id"].as_str().unwrap_or("").to_string()
        }
        _ => {
            say("building the desk image on this Mac (several minutes the first time)");
            let labels = BTreeMap::from([("ekka.desk.source".to_string(), source.clone())]);
            let id = docker.build(&kit::DESK_IMAGE, DESK_IMAGE_TAG, &labels)?;
            out.changes.push(format!("built the desk image {DESK_IMAGE_TAG} ({source})"));
            id
        }
    };
    say(format!("desk image {DESK_IMAGE_TAG} is {desk_image_id}"));

    let adapter_inputs = match (&adapter_staged, &enclave) {
        (Some(_), Some(e)) => {
            Some(AdapterInputs { node_id: e.node_id.clone(), govern_keys: adapter::fetch_govern_keys(&e.govern_url)? })
        }
        (Some(_), None) => {
            out.pending.push("the backend adapter's configuration: it needs the enrolled Enclave's node id".into());
            None
        }
        _ => None,
    };

    println!("== what root owns");
    let plan = RootPlan {
        schema: PLAN_SCHEMA.into(),
        want: want.clone(),
        gateway_staged,
        adapter_staged: adapter_staged.filter(|_| adapter_inputs.is_some()),
        desk_image_id,
        resources,
        oidc: profile.gateway.clone(),
        adapter: adapter_inputs,
    };
    let roots = std::fs::read(crate::net::system_roots_path())
        .map_err(|e| failed(format!("reading the system's public roots: {e}")))?;
    let owners = Owners { root: Owner { uid: 0, gid: 0 }, dev: Owner { uid: user.uid, gid: user.gid } };
    let mut check = Ctx::check();
    apply::root_apply(&plan, &l, owners, &pins, &roots, &mut check)?;
    if check.changes.is_empty() {
        say("nothing root owns needs to change: no password asked");
    } else {
        for c in &check.changes {
            say(format!("to do as root: {c}"));
        }
        let plan_json = serde_json::to_vec(&plan).map_err(|e| failed(e.to_string()))?;
        let done = macos::run_elevated(&plan_json)?;
        let done: serde_json::Value =
            serde_json::from_slice(&done).map_err(|_| failed("the root step did not report what it did"))?;
        for c in done["changes"].as_array().into_iter().flatten().filter_map(|c| c.as_str()) {
            out.changes.push(c.to_string());
        }
    }

    println!("== the services, in your login session");
    let public = std::fs::read_to_string(l.jwt_dir().join(macos::JWT_PUBLIC))
        .map_err(|e| failed(format!("reading the gateway's public token key: {e}")))?;
    let key_b64 = tls::public_b64_of_pem(&public)?;
    std::fs::create_dir_all(l.logs()).map_err(|e| failed(format!("making {}: {e}", l.logs().display())))?;
    std::fs::set_permissions(l.logs(), std::fs::Permissions::from_mode(0o700)).ok();
    let inputs = ServiceInputs { ekka: &ekka, env: &want.env, gateway_key_b64: &key_b64, profile: &profile };
    let mut agents = vec![macos::enclave_agent(&l, &inputs), macos::gateway_agent(&l)];
    if plan.adapter.is_some() {
        agents.push(macos::backend_agent(&l));
    }
    let mut changed = BTreeMap::new();
    for a in &agents {
        let c = macos::write_plist(&l.plist(a.label), &macos::render_plist(a))?;
        if c {
            out.changes.push(format!("wrote {}", l.plist(a.label).display()));
        }
        changed.insert(a.label, c);
    }
    if enclave.is_none() {
        out.pending.push(format!(
            "the Enclave: not enrolled in {} yet. Enroll it (ekka desk setup --local), then run install again",
            l.enclave_home().display()
        ));
    } else {
        macos::bootstrap(user.uid, LABEL_ENCLAVE, &l.plist(LABEL_ENCLAVE), changed[LABEL_ENCLAVE])?;
        let interceptor = l.interceptor_socket();
        let answers = wait_for("the Enclave's interceptor", Duration::from_secs(60), || {
            std::os::unix::net::UnixStream::connect(&interceptor).is_ok()
        });
        if answers {
            say("the Enclave's interceptor answers");
            macos::bootstrap(user.uid, LABEL_GATEWAY, &l.plist(LABEL_GATEWAY), changed[LABEL_GATEWAY])?;
            let ca = std::fs::read(l.tls_dir().join(macos::CA_CERT)).unwrap_or_default();
            let addr = std::net::SocketAddr::from((tls::GATEWAY_IP, macos::GATEWAY_PORT));
            if wait_for("the gateway", Duration::from_secs(60), || tls::probe(addr, tls::GATEWAY_DNS, &ca).is_ok()) {
                say("the gateway answers with verified TLS on 127.0.0.1");
                if plan.adapter.is_some() {
                    macos::bootstrap(user.uid, LABEL_BACKEND, &l.plist(LABEL_BACKEND), changed[LABEL_BACKEND])?;
                }
            } else {
                out.pending.push(format!("the gateway did not answer; see {}", l.logs().join("gateway.log").display()));
            }
        } else {
            out.pending.push(format!(
                "the gateway waits for the Enclave's interceptor, which did not answer; see {}",
                l.logs().join("enclave.log").display()
            ));
        }
    }

    println!("== the memory meter");
    ensure_meter(&docker, &pins, &mut out)?;
    say(format!("{} runs on your Docker Desktop", meter::NAME));

    println!("== the gateway's one-time setup");
    match (&profile.callers.enclave, &profile.callers.adapter) {
        (Some(e), Some(a)) => {
            let want = Desired::for_subjects(&e.subject, &a.subject).map_err(|s| failed(format!("{s:?}")))?;
            match bootstrap::reconcile(
                &mut GovernExchangeNotYetAvailable,
                &mut GatewayNotCalled,
                &profile.gateway.audience,
                &want,
                &std::time::SystemTime::now,
            ) {
                Ok(r) if r.ready => out.changes.extend(r.changed),
                Ok(r) => out.pending.extend(r.problems),
                Err(Stop::Pending(why)) => out.pending.push(why),
                Err(Stop::Expired) => out.pending.push("the setup pass expired; run install again to resume".into()),
                Err(Stop::Failed(why)) => return Err(failed(format!("the gateway's setup: {why}"))),
            }
        }
        _ => {
            out.pending.push("the gateway's setup: the identity profile names no Enclave or adapter subject yet".into())
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ekka_program_must_be_absolute_and_owner_only() {
        assert!(resolve_ekka(Some(Path::new("relative/ekka"))).is_err());
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("ekka");
        std::fs::write(&p, b"#!/bin/false\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        // A temporary folder's own path may not be plain on every machine; only the rules below are checked.
        if is_plain_absolute_path(&p.display().to_string()) {
            assert_eq!(resolve_ekka(Some(&p)).unwrap(), p);
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o777)).unwrap();
            assert!(resolve_ekka(Some(&p)).unwrap_err().reason.contains("other than its owner"));
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(resolve_ekka(Some(&p)).unwrap_err().reason.contains("not a program"));
        }
    }
}

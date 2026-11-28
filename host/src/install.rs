//! `ekka-desk-host install --profile developer-native --runtime docker-desktop --env <env> --org <tenant id>
//! --identity-profile <file>`: one native Mac desk host for the developer running it.
//!
//! In order: run only from the root-owned copy of this program; refuse another organization, developer or
//! environment before any change (one installation per Mac); check every download and image as the developer;
//! work out what root must change, and ask for the password once only when something does; then, as the
//! developer, write the LaunchAgents and start them in the login session (the gateway only after the Enclave's
//! interceptor answers), start a fresh memory meter, and run the gateway's one-time setup when it can. Every
//! other step reads first and changes only what differs. What cannot be done yet is named, with what it waits for.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::adapter::{self, AdapterInputs};
use crate::apply::{self, Ctx, Owners, RootPlan, PLAN_SCHEMA};
use crate::binding::{Binding, Want};
use crate::bootstrap::{self, Desired, GatewayAdmin, GovernExchangeNotYetAvailable, Pass, Stop};
use crate::error::{failed, refused, usage, Result};
use crate::fsx::Owner;
use crate::identity::{self, Profile};
use crate::meter;
use crate::platform::macos::{self, Layout, ServiceInputs, LABEL_BACKEND, LABEL_ENCLAVE, LABEL_GATEWAY};
use crate::records::Resources;
use crate::registration::{finish, gateway_action, GatewayAction, Launchd, Registration, RestartPending};
use crate::release::{self, Pins};
use crate::runtime::docker::Docker;
use crate::tls;

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
    pub rotate_ca: bool,
    pub raise_ceiling: bool,
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

/// The gateway calls for setup are made with Govern's setup pass, which this release cannot obtain; until then
/// no call is ever made (the pass source stops first).
struct GatewayNotCalled;

fn no_pass<T>() -> std::result::Result<T, Stop> {
    Err(Stop::Pending("no gateway call without a setup pass".into()))
}

impl GatewayAdmin for GatewayNotCalled {
    fn workspace_exists(&mut self, _: &Pass, _: &str) -> std::result::Result<bool, Stop> {
        no_pass()
    }
    fn create_workspace(&mut self, _: &Pass, _: &str) -> std::result::Result<(), Stop> {
        no_pass()
    }
    fn members(&mut self, _: &Pass, _: &str) -> std::result::Result<Vec<bootstrap::Member>, Stop> {
        no_pass()
    }
    fn add_member(&mut self, _: &Pass, _: &str, _: &bootstrap::Member) -> std::result::Result<(), Stop> {
        no_pass()
    }
    fn profiles(&mut self, _: &Pass) -> std::result::Result<Vec<bootstrap::ProviderProfile>, Stop> {
        no_pass()
    }
    fn import_profiles(&mut self, _: &Pass, _: &[bootstrap::ProviderProfile]) -> std::result::Result<(), Stop> {
        no_pass()
    }
}

/// The gateway's LaunchAgent, as `registration::finish` drives it.
struct GatewayLaunchd {
    uid: u32,
    plist: PathBuf,
}

impl Launchd for GatewayLaunchd {
    fn state(&self) -> macos::ServiceState {
        macos::service_state(self.uid, LABEL_GATEWAY)
    }
    fn restart(&self) -> Result<()> {
        macos::kickstart(self.uid, LABEL_GATEWAY)
    }
    fn start(&self) -> Result<()> {
        macos::bootstrap(self.uid, LABEL_GATEWAY, &self.plist, false)
    }
    fn stop(&self) -> Result<()> {
        macos::bootout(self.uid, LABEL_GATEWAY)
    }
}

/// The restart marker, if there is one. Only "not there" is absence: a marker that cannot be read or is not one
/// stops the install, with the fix, rather than passing as "nothing pending".
pub fn read_pending(marker: &Path, uid: u32) -> Result<Option<RestartPending>> {
    let fix = |why: String| {
        refused(format!(
            "{} {why}. Restart the gateway yourself (launchctl kickstart -k gui/{uid}/{LABEL_GATEWAY}), remove the \
             file, and run install again",
            marker.display()
        ))
    };
    let meta = match std::fs::symlink_metadata(marker) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(fix(format!("cannot be read ({e})"))),
        Ok(m) => m,
    };
    if !meta.file_type().is_file() || meta.len() > 64 * 1024 {
        return Err(fix("is not a restart marker".into()));
    }
    let bytes = std::fs::read(marker).map_err(|e| fix(format!("cannot be read ({e})")))?;
    serde_json::from_slice(&bytes).map(Some).map_err(|_| fix("is not a restart marker".into()))
}

/// Removes the restart marker once launchd confirmed what it asked for, and only that marker: one a later install
/// wrote meanwhile (another digest or action) is left for its own confirmation.
fn clear_pending(marker: &Path, confirmed: &RestartPending, uid: u32) -> Result<bool> {
    match read_pending(marker, uid)? {
        Some(now) if &now == confirmed => match std::fs::remove_file(marker) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(failed(format!("removing {}: {e}", marker.display()))),
        },
        Some(_) => Ok(false),
        None => Ok(true),
    }
}

/// What status, doctor and install say about desk limits on a developer's Mac.
pub fn no_desk_limits(vm: Option<(u64, u64)>) -> String {
    let size = match vm {
        Some((cpus, mib)) => format!("{cpus} CPUs, {mib} MiB"),
        None => "unknown while Docker Desktop is not answering".to_string(),
    };
    format!(
        "desks on this Mac have no CPU or memory limit of their own; Docker Desktop's VM size ({size}) bounds them; the \
         room check still holds jobs when the VM is short of memory"
    )
}

/// The per-desk CPU and memory ceiling for `profile`. The developer-native profile has none in this release: the
/// adapter and the runner cannot apply one on a Mac yet (no cgroup files to read limits back from), so a limit would
/// only make every desk refuse. Asking for one there is refused, saying so; a later release adds it.
pub fn desk_limits(
    profile: &str,
    cpu_millicores: Option<u64>,
    memory_mib: Option<u64>,
    info: &crate::runtime::docker::Info,
) -> Result<Option<Resources>> {
    if profile == crate::binding::PROFILE {
        if cpu_millicores.is_some() || memory_mib.is_some() {
            return Err(usage(format!(
                "{}. --desk-cpu-millicores and --desk-memory-mib are not taken on a developer's Mac; a later release \
                 gives a desk on a Mac its own CPU and memory limit",
                no_desk_limits(Some((info.cpus, info.memory_bytes >> 20)))
            )));
        }
        return Ok(None);
    }
    match (cpu_millicores, memory_mib) {
        (None, None) => Resources::half_of(info.cpus, info.memory_bytes).map(Some),
        (Some(c), Some(m)) => {
            let r = Resources { max_cpu_millicores: c, max_memory_mib: m };
            r.fits(info.cpus, info.memory_bytes)?;
            Ok(Some(r))
        }
        _ => Err(usage("give both --desk-cpu-millicores and --desk-memory-mib, or neither")),
    }
}

pub fn run(args: &Args) -> Result<Outcome> {
    let mut out = Outcome::default();
    // Before anything else: the program that will ask for the password is the root-owned copy, and nothing the
    // developer's processes can change.
    let exe = std::env::current_exe().map_err(|e| failed(format!("finding this program: {e}")))?;
    macos::trusted_self(&exe, Path::new(macos::HOST_BINARY), Path::new("/"), 0)?;
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
    let origin = identity::govern_origin(&want.env)?;
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
        if e.govern_url.trim_end_matches('/') != origin {
            return Err(refused(format!(
                "the Enclave in {} is enrolled with another Govern than {}'s ({origin}); nothing was changed",
                l.enclave_home().display(),
                want.env
            )));
        }
    }
    let ekka = crate::ekka::verify(
        &crate::ekka::find(args.ekka.as_deref())?,
        &crate::ekka::PublicRelease,
        &crate::sigstore::Trust::embedded()?,
        &crate::sigstore::PublicRekor,
    )?;
    say(format!(
        "the Enclave runs {}: EKKA's signed ekka {} release, byte for byte",
        ekka.path.display(),
        ekka.version
    ));
    let ekka = ekka.path;
    say(format!("the gateway trusts sign-in from {} only", identity::issuer(&want.env, &want.org)?));

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
    // A developer's Mac sets no CPU or memory limit for a desk in this release (`desk_limits`).
    let resources = desk_limits(&want.profile, args.cpu_millicores, args.memory_mib, &info)?;
    say(no_desk_limits(Some((info.cpus, info.memory_bytes >> 20))));

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
    match &pins.desk_image {
        Some(pin) => {
            docker.pull(&pin.image)?;
            let img = docker.image(&pin.image)?.ok_or_else(|| failed(format!("Docker does not have {}", pin.image)))?;
            if img["Id"].as_str() != Some(pin.image_id.as_str()) {
                return Err(refused(format!("{} is not the pinned desk image {}", pin.image, pin.image_id)));
            }
            say(format!("the desk image {} is the pinned one", pin.image));
        }
        None => out.pending.push(
            "desks: no published desk image is pinned for a Mac yet, so no desk-image record is written and desks \
             wait (closed). An image built on this Mac is never recorded"
                .into(),
        ),
    }

    let adapter_inputs = match (&adapter_staged, &enclave) {
        (Some(_), Some(e)) => {
            Some(AdapterInputs { node_id: e.node_id.clone(), govern_keys: adapter::fetch_govern_keys(origin)? })
        }
        (Some(_), None) => {
            out.pending.push("the backend adapter's configuration: it needs the enrolled Enclave's node id".into());
            None
        }
        _ => None,
    };
    // A registration that is not well-formed is no registration: the gateway is stopped and its trust removed.
    let registration = match profile.registration.as_ref().map(Registration::from_answer) {
        Some(Ok(r)) => Some(r),
        Some(Err(e)) => {
            out.pending.push(format!("the gateway: {}; it is stopped and its configuration removed", e.reason));
            None
        }
        None => None,
    };

    println!("== what root owns");
    let plan = RootPlan {
        schema: PLAN_SCHEMA.into(),
        want: want.clone(),
        gateway_staged,
        adapter_staged: adapter_staged.filter(|_| adapter_inputs.is_some()),
        resources,
        registration: registration.clone(),
        adapter: adapter_inputs,
        rotate_ca: args.rotate_ca,
        raise_ceiling: args.raise_ceiling,
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
    let binding = Binding::read(&l.binding())?.ok_or_else(|| failed("the root step left no binding"))?;
    // The same check root made: only this installation's registration makes a gateway.
    let registered = match registration.as_ref().map(|r| r.verify(&binding)) {
        Some(Ok(_)) => true,
        Some(Err(e)) => {
            out.pending.push(format!("the gateway: {}; it is stopped and its configuration removed", e.reason));
            false
        }
        None => {
            out.pending.push(
                "the gateway: not registered yet. Register it (ekka desk setup --local), put Govern's answer in \
                 the identity profile's registration, then run install again"
                    .into(),
            );
            false
        }
    };

    println!("== the services, in your login session");
    let public = std::fs::read_to_string(l.jwt_dir().join(macos::JWT_PUBLIC))
        .map_err(|e| failed(format!("reading the gateway's public token key: {e}")))?;
    let key_b64 = tls::public_b64_of_pem(&public)?;
    std::fs::create_dir_all(l.logs()).map_err(|e| failed(format!("making {}: {e}", l.logs().display())))?;
    std::fs::set_permissions(l.logs(), std::fs::Permissions::from_mode(0o700)).ok();
    let inputs = ServiceInputs {
        ekka: &ekka,
        env: &want.env,
        gateway_key_b64: &key_b64,
        installation_id: &binding.installation_id,
    };
    // A restart (or stop) the root step asked for, now or in an earlier install that did not finish it.
    let marker = l.run_dir().join(crate::registration::RESTART_PENDING);
    let mut pending: Option<RestartPending> = read_pending(&marker, user.uid)?;
    let mut agents = vec![macos::enclave_agent(&l, &inputs)];
    if registered {
        agents.push(macos::gateway_agent(&l));
    } else {
        // Not registered, or not this installation's: never leave a gateway running on an old configuration.
        let launchd = GatewayLaunchd { uid: user.uid, plist: l.plist(LABEL_GATEWAY) };
        let stop = RestartPending::new(true, String::new());
        if macos::service_state(user.uid, LABEL_GATEWAY).loaded || pending.is_some() {
            if finish(&launchd, &stop, Duration::from_secs(30))? {
                out.changes.push("stopped the gateway: it has no registration for this installation".into());
                if let Some(p) = pending.take() {
                    if !clear_pending(&marker, &p, user.uid)? {
                        pending = read_pending(&marker, user.uid)?;
                    }
                }
            } else {
                out.pending
                    .push("the gateway: launchd did not confirm it stopped; install finishes it next time".into());
            }
        }
        if std::fs::symlink_metadata(l.plist(LABEL_GATEWAY)).is_ok() {
            std::fs::remove_file(l.plist(LABEL_GATEWAY))
                .map_err(|e| failed(format!("removing {}: {e}", l.plist(LABEL_GATEWAY).display())))?;
            out.changes.push(format!("removed {}", l.plist(LABEL_GATEWAY).display()));
        }
    }
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
    out.pending.push(
        "desk jobs: the Enclave's executor stays off until an ekka release can exchange its runner session for \
         Govern's gateway pass"
            .into(),
    );
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
        if !answers {
            out.pending.push(format!(
                "the gateway waits for the Enclave's interceptor, which did not answer; see {}",
                l.logs().join("enclave.log").display()
            ));
        } else if registered {
            say("the Enclave's interceptor answers");
            let loaded = macos::service_state(user.uid, LABEL_GATEWAY).loaded;
            match gateway_action(true, loaded, changed[LABEL_GATEWAY], pending.is_some()) {
                GatewayAction::Start => {
                    macos::bootstrap(user.uid, LABEL_GATEWAY, &l.plist(LABEL_GATEWAY), changed[LABEL_GATEWAY])?;
                    if pending.is_some()
                        && wait_for("the gateway", Duration::from_secs(30), || {
                            macos::service_state(user.uid, LABEL_GATEWAY).running
                        })
                    {
                        let p = pending.take().expect("checked just above");
                        if !clear_pending(&marker, &p, user.uid)? {
                            pending = read_pending(&marker, user.uid)?;
                        }
                    }
                }
                GatewayAction::Reload => {
                    let launchd = GatewayLaunchd { uid: user.uid, plist: l.plist(LABEL_GATEWAY) };
                    let restart = pending.clone().expect("a reload is for a pending restart");
                    if finish(&launchd, &restart, Duration::from_secs(30))? {
                        out.changes.push("restarted the gateway on its new trust configuration".into());
                        pending = if clear_pending(&marker, &restart, user.uid)? {
                            None
                        } else {
                            read_pending(&marker, user.uid)?
                        };
                    }
                }
                GatewayAction::Unload | GatewayAction::Keep => {}
            }
            if pending.is_some() {
                out.pending
                    .push("the gateway: launchd did not confirm its restart; install finishes it next time".into());
            }
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
        }
    }

    println!("== the memory meter");
    out.changes.extend(meter::replace(&docker, &pins.meter_image)?);
    say(format!("a fresh {} runs on your Docker Desktop", meter::NAME));

    println!("== the gateway's one-time setup");
    match (registration.as_ref().filter(|_| registered).map(|r| &r.gateway_id), &enclave) {
        (Some(gateway_id), Some(e)) => {
            let want = Desired::for_subjects(
                &format!("enclave/{}", e.node_id),
                &format!("adapter/{}", binding.installation_id),
            )
            .map_err(|s| failed(format!("{s:?}")))?;
            match bootstrap::reconcile(
                &mut GovernExchangeNotYetAvailable,
                &mut GatewayNotCalled,
                gateway_id,
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
        _ => out.pending.push("the gateway's setup: it needs the registered gateway and the enrolled Enclave".into()),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm() -> crate::runtime::docker::Info {
        crate::runtime::docker::Info {
            os_type: "linux".into(),
            arch: "aarch64".into(),
            cpus: 8,
            memory_bytes: 16 << 30,
            server_version: "29".into(),
            operating_system: "Docker Desktop".into(),
        }
    }

    #[test]
    fn a_developer_mac_gets_no_desk_limit_and_asking_for_one_is_refused_plainly() {
        assert_eq!(desk_limits(crate::binding::PROFILE, None, None, &vm()).unwrap(), None);
        let e = desk_limits(crate::binding::PROFILE, Some(2000), Some(4096), &vm()).unwrap_err();
        assert!(e.reason.contains("desks on this Mac have no CPU or memory limit of their own"), "{e}");
        assert!(e.reason.contains("(8 CPUs, 16384 MiB)") && e.reason.contains("a later release"), "{e}");
        // The same shape stays for a profile that sets one.
        assert!(desk_limits("server", None, None, &vm()).unwrap().is_some());
    }

    #[test]
    fn only_a_missing_marker_is_no_marker_and_only_the_confirmed_one_is_removed() {
        let t = tempfile::tempdir().unwrap();
        let m = t.path().join("gateway-restart.pending");
        assert_eq!(read_pending(&m, 501).unwrap(), None);
        std::fs::write(&m, b"not a marker").unwrap();
        let e = read_pending(&m, 501).unwrap_err();
        assert!(e.reason.contains("is not a restart marker") && e.reason.contains("kickstart -k"), "{e}");
        std::fs::remove_file(&m).unwrap();
        std::fs::create_dir(&m).unwrap();
        assert!(read_pending(&m, 501).is_err(), "a folder is not absence");
        std::fs::remove_dir(&m).unwrap();
        // Confirmed A, while a second install wrote B: B stays for its own confirmation.
        let a = RestartPending::new(false, "a".into());
        let b = RestartPending::new(false, "b".into());
        std::fs::write(&m, b.bytes()).unwrap();
        assert!(!clear_pending(&m, &a, 501).unwrap());
        assert_eq!(read_pending(&m, 501).unwrap(), Some(b.clone()));
        assert!(clear_pending(&m, &b, 501).unwrap());
        assert!(!m.exists());
    }
}

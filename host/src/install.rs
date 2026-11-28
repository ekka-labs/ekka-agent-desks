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
use crate::registration::{gateway_action, GatewayAction, Registration};
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

/// A digest of everything the gateway trusts, as anyone may read it: its configuration, its registration record,
/// its certificate, the CA and its token key. A change means a running gateway must restart to use it.
fn trust_digest(l: &Layout) -> String {
    let files = [
        l.gateway_toml(),
        l.d().join(crate::registration::RECORD),
        l.tls_dir().join(macos::LEAF_CERT),
        l.tls_dir().join(macos::CA_CERT),
        l.jwt_dir().join(macos::JWT_PUBLIC),
    ];
    let mut all = Vec::new();
    for f in files {
        all.extend_from_slice(f.display().to_string().as_bytes());
        all.push(0);
        all.extend(std::fs::read(&f).unwrap_or_default());
        all.push(0);
    }
    crate::util::sha256_hex(&all)
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
    // The ceiling already recorded, if any: a default never raises it (only --raise-ceiling with values does).
    let recorded: Option<crate::records::Ceiling> =
        std::fs::read(l.records().join(crate::records::CEILING)).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let resources = match (args.cpu_millicores, args.memory_mib) {
        (None, None) => {
            let half = Resources::half_of(info.cpus, info.memory_bytes)?;
            match &recorded {
                Some(c) => Resources {
                    max_cpu_millicores: half.max_cpu_millicores.min(c.resources.max_cpu_millicores),
                    max_memory_mib: half.max_memory_mib.min(c.resources.max_memory_mib),
                },
                None => half,
            }
        }
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
    let registration = profile.registration.as_ref().map(Registration::from_answer).transpose()?;

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
    let trust_before = trust_digest(&l);
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
    let trust_changed = trust_digest(&l) != trust_before;
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
    let mut agents = vec![macos::enclave_agent(&l, &inputs)];
    if registered {
        agents.push(macos::gateway_agent(&l));
    } else {
        // Not registered, or not this installation's: never leave a gateway running on an old configuration.
        if macos::service_state(user.uid, LABEL_GATEWAY).loaded {
            macos::bootout(user.uid, LABEL_GATEWAY)?;
            out.changes.push("stopped the gateway: it has no registration for this installation".into());
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
            match gateway_action(true, loaded, changed[LABEL_GATEWAY], trust_changed) {
                GatewayAction::Start => {
                    macos::bootstrap(user.uid, LABEL_GATEWAY, &l.plist(LABEL_GATEWAY), changed[LABEL_GATEWAY])?
                }
                GatewayAction::Reload => {
                    macos::kickstart(user.uid, LABEL_GATEWAY)?;
                    out.changes.push("restarted the gateway on its new trust configuration".into());
                }
                GatewayAction::Unload | GatewayAction::Keep => {}
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

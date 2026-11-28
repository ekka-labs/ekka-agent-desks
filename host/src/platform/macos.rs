//! macOS: where everything lives, the developer's identity, the three per-user LaunchAgents, and the one
//! elevation.
//!
//! Let `D` be `/var/db/ekka-dev/<uid>`, named by its real path `/private/var/db/ekka-dev/<uid>` everywhere (on a
//! Mac `/var` is a link, and the checks that walk these paths refuse links). Root owns `D`, the installation
//! binding, the gateway configuration, the certificates and the records. The developer owns `D/enclave`,
//! `D/gateway`, `D/backend` and `D/run`, each 0700; the services make their sockets there, 0600. Programs are
//! under `/opt/ekka-desk-host/releases/<release>/` with a root-managed `current` link.

use std::ffi::CStr;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{failed, refused, usage, Result};
use crate::identity::{EnclaveToken, Profile};
use crate::kit;
use crate::tls::GATEWAY_IP;
use crate::util::is_plain_absolute_path;

pub const LABEL_ENCLAVE: &str = "com.ekka.desks.enclave";
pub const LABEL_GATEWAY: &str = "com.ekka.desks.gateway";
pub const LABEL_BACKEND: &str = "com.ekka.desks.backend";
/// The gateway's name, as the Enclave and the gateway's own config call it.
pub const GATEWAY_NAME: &str = "ekka-desks";
/// The gateway workspace that holds this organization's desks.
pub const WORKSPACE: &str = "desks";
pub const GATEWAY_PORT: u16 = 8080;
pub const HEALTH_PORT: u16 = 8081;
pub const INTERCEPTOR_AUDIENCE: &str = "urn:ekka:openshell:interceptor";

pub const CA_KEY: &str = "ca.key";
pub const CA_CERT: &str = "ca.crt";
pub const BUNDLE: &str = "ca-bundle.crt";
pub const LEAF_CERT: &str = "gateway.crt";
pub const LEAF_KEY: &str = "gateway.key";
pub const LEAF_META: &str = "gateway.json";
pub const JWT_SIGNING: &str = "signing.pem";
pub const JWT_PUBLIC: &str = "public.pem";
pub const JWT_KID: &str = "kid";

/// Where one installation's files are. `top` is `/` on a real install; tests use a folder of their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub top: PathBuf,
    pub uid: u32,
    pub home: PathBuf,
}

impl Layout {
    pub fn system(uid: u32, home: PathBuf) -> Self {
        Layout { top: PathBuf::from("/"), uid, home }
    }
    pub fn ekka_dev(&self) -> PathBuf {
        self.top.join("private/var/db/ekka-dev")
    }
    pub fn d(&self) -> PathBuf {
        self.ekka_dev().join(self.uid.to_string())
    }
    pub fn binding(&self) -> PathBuf {
        self.d().join("binding.json")
    }
    pub fn enclave_home(&self) -> PathBuf {
        self.d().join("enclave")
    }
    pub fn gateway_dir(&self) -> PathBuf {
        self.d().join("gateway")
    }
    pub fn gateway_db_url(&self) -> String {
        format!("sqlite:{}?mode=rwc", self.gateway_dir().join("state/gateway.db").display())
    }
    pub fn backend_dir(&self) -> PathBuf {
        self.d().join("backend")
    }
    pub fn permits_dir(&self) -> PathBuf {
        self.backend_dir().join("permits")
    }
    pub fn run_dir(&self) -> PathBuf {
        self.d().join("run")
    }
    pub fn backend_socket_dir(&self) -> PathBuf {
        self.run_dir().join("backend")
    }
    pub fn adapter_socket(&self) -> PathBuf {
        self.backend_socket_dir().join("backend.sock")
    }
    pub fn claim_socket(&self) -> PathBuf {
        self.backend_socket_dir().join("enclave.sock")
    }
    pub fn interceptor_socket(&self) -> PathBuf {
        self.run_dir().join("openshell-interceptor.sock")
    }
    pub fn tls_dir(&self) -> PathBuf {
        self.d().join("tls")
    }
    pub fn jwt_dir(&self) -> PathBuf {
        self.tls_dir().join("jwt")
    }
    pub fn gateway_toml(&self) -> PathBuf {
        self.d().join("gateway.toml")
    }
    pub fn adapter_config(&self) -> PathBuf {
        self.d().join("backend-config.json")
    }
    pub fn opt(&self) -> PathBuf {
        self.top.join("opt/ekka-desk-host")
    }
    pub fn release_dir(&self, release: &str) -> PathBuf {
        self.opt().join("releases").join(release)
    }
    pub fn current_bin(&self, name: &str) -> PathBuf {
        self.opt().join("current/bin").join(name)
    }
    pub fn records(&self) -> PathBuf {
        self.top.join(crate::records::RECORDS_DIR.trim_start_matches('/'))
    }
    pub fn launch_agents(&self) -> PathBuf {
        self.home.join("Library/LaunchAgents")
    }
    pub fn plist(&self, label: &str) -> PathBuf {
        self.launch_agents().join(format!("{label}.plist"))
    }
    pub fn logs(&self) -> PathBuf {
        self.home.join("Library/Logs/ekka-desk-host")
    }
    pub fn staging(&self, release: &str) -> PathBuf {
        self.home.join("Library/Caches/ekka-desk-host").join(release)
    }
    /// Docker Desktop's socket for this user: the Enclave, the gateway and the meter all use this one.
    pub fn docker_socket(&self) -> PathBuf {
        self.home.join(".docker/run/docker.sock")
    }
    /// The developer's default XDG folders, which must never acquire gateway state.
    pub fn default_xdg_gateway_dirs(&self) -> Vec<PathBuf> {
        ["config", "local/share", "local/state", "cache"]
            .iter()
            .map(|d| self.home.join(format!(".{d}/openshell")))
            .collect()
    }
}

/// The developer this install is for, from the system's account database (never from the environment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub home: PathBuf,
}

pub fn user_by_uid(uid: u32) -> Result<User> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is to memory owned here and sized as passed; `out` is checked before use.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() {
        return Err(refused(format!("uid {uid} has no account on this Mac")));
    }
    // SAFETY: getpwuid_r succeeded, so these are NUL-terminated strings inside `buf`.
    let (name, home) = unsafe { (CStr::from_ptr(pwd.pw_name), CStr::from_ptr(pwd.pw_dir)) };
    let user = User {
        uid,
        gid: pwd.pw_gid,
        name: name.to_string_lossy().into_owned(),
        home: PathBuf::from(home.to_string_lossy().into_owned()),
    };
    if !is_plain_absolute_path(&user.home.to_string_lossy()) {
        return Err(refused("the account's home folder is not a plain absolute path"));
    }
    Ok(user)
}

/// The uid that owns the Mac's console: the user logged in at the screen, whose session the LaunchAgents join.
pub fn console_uid() -> Option<u32> {
    std::fs::metadata("/dev/console").ok().map(|m| m.uid())
}

/// The developer running this command: never root (install elevates once, by itself), and the user logged in at
/// the screen (the LaunchAgents run in that login session).
pub fn developer() -> Result<User> {
    let uid = rustix::process::getuid().as_raw();
    if uid == 0 || rustix::process::geteuid().as_raw() == 0 {
        return Err(usage("run ekka-desk-host as yourself, not with sudo: it asks for your password once, itself"));
    }
    if console_uid().is_some_and(|c| c != uid) {
        return Err(refused(format!(
            "uid {uid} is not the user logged in at this Mac's screen; the services run in that user's login session"
        )));
    }
    user_by_uid(uid)
}

/// One LaunchAgent's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    pub label: &'static str,
    pub program: Vec<String>,
    pub env: Vec<(String, String)>,
    pub working_dir: PathBuf,
    pub log: PathBuf,
}

/// What the services are given.
pub struct ServiceInputs<'a> {
    pub ekka: &'a Path,
    pub env: &'a str,
    pub gateway_key_b64: &'a str,
    pub profile: &'a Profile,
}

fn s(p: impl AsRef<Path>) -> String {
    p.as_ref().display().to_string()
}

/// The Enclave: `ekka enclave start`, with every desk setting explicit.
pub fn enclave_agent(l: &Layout, i: &ServiceInputs) -> Agent {
    let mut env = vec![
        ("EKKA_HOME".into(), s(l.enclave_home())),
        ("EKKA_ENV".into(), i.env.to_string()),
        // The system's public roots plus this installation's CA: Govern and the gateway both verify.
        ("SSL_CERT_FILE".into(), s(l.tls_dir().join(BUNDLE))),
        ("EKKA_BACKEND_SOCKET_DIR".into(), s(l.backend_socket_dir())),
        ("EKKA_OPENSHELL_GATEWAY".into(), GATEWAY_NAME.into()),
        ("EKKA_OPENSHELL_GATEWAY_KEY_B64".into(), i.gateway_key_b64.into()),
        ("EKKA_OPENSHELL_INTERCEPTOR_SOCKET".into(), s(l.interceptor_socket())),
        ("EKKA_OPENSHELL_INTERCEPTOR_SOCKET_MODE".into(), "0600".into()),
        ("EKKA_OPENSHELL_INTERCEPTOR_AUDIENCE".into(), INTERCEPTOR_AUDIENCE.into()),
        ("EKKA_OPENSHELL_DISCOVERY_PERMITS_DIR".into(), s(l.permits_dir())),
    ];
    if let Some(e) = &i.profile.callers.enclave {
        let EnclaveToken::ClientCredentials { client_id, secret_name } = &e.token;
        env.extend([
            ("EKKA_OPENSHELL_EXECUTOR_URL".into(), format!("https://{GATEWAY_IP}:{GATEWAY_PORT}")),
            ("EKKA_OPENSHELL_EXECUTOR_CA_PEM_PATH".into(), s(l.tls_dir().join(CA_CERT))),
            ("EKKA_OPENSHELL_EXECUTOR_WORKSPACE".into(), WORKSPACE.into()),
            ("EKKA_OPENSHELL_EXECUTOR_SUBJECT".into(), format!("user:oidc:{}", e.subject)),
            ("EKKA_OPENSHELL_EXECUTOR_ISSUER".into(), i.profile.gateway.issuer.clone()),
            ("EKKA_OPENSHELL_EXECUTOR_CLIENT_ID".into(), client_id.clone()),
            ("EKKA_OPENSHELL_EXECUTOR_CLIENT_SECRET_NAME".into(), secret_name.clone()),
            // Desks made through EKKA register on their own, with no `ekka desk add` (needs the executor).
            ("EKKA_DESKS_AUTO".into(), "true".into()),
        ]);
    }
    if let Some(a) = &i.profile.callers.adapter {
        env.push(("EKKA_OPENSHELL_BACKEND_SUBJECT".into(), format!("user:oidc:{}", a.subject)));
    }
    Agent {
        label: LABEL_ENCLAVE,
        program: vec![s(i.ekka), "enclave".into(), "start".into()],
        env,
        working_dir: l.enclave_home(),
        log: l.logs().join("enclave.log"),
    }
}

/// NVIDIA's gateway: loopback only, its state and every XDG folder under `D/gateway`.
pub fn gateway_agent(l: &Layout) -> Agent {
    let g = l.gateway_dir();
    Agent {
        label: LABEL_GATEWAY,
        program: vec![s(l.current_bin("openshell-gateway"))],
        env: vec![
            ("OPENSHELL_GATEWAY_CONFIG".into(), s(l.gateway_toml())),
            ("OPENSHELL_TELEMETRY_ENABLED".into(), "false".into()),
            ("OPENSHELL_DB_URL".into(), l.gateway_db_url()),
            ("HOME".into(), s(&g)),
            ("XDG_CONFIG_HOME".into(), s(g.join("config"))),
            ("XDG_DATA_HOME".into(), s(g.join("data"))),
            ("XDG_STATE_HOME".into(), s(g.join("state"))),
            ("XDG_CACHE_HOME".into(), s(g.join("cache"))),
            ("SSL_CERT_FILE".into(), s(l.tls_dir().join(BUNDLE))),
        ],
        working_dir: g,
        log: l.logs().join("gateway.log"),
    }
}

/// EKKA's backend adapter: `serve --config`, its socket beside the Enclave's backend folder.
pub fn backend_agent(l: &Layout) -> Agent {
    Agent {
        label: LABEL_BACKEND,
        program: vec![s(l.current_bin("ekka-backend")), "serve".into(), "--config".into(), s(l.adapter_config())],
        env: vec![("HOME".into(), s(l.backend_dir())), ("SSL_CERT_FILE".into(), s(l.tls_dir().join(BUNDLE)))],
        working_dir: l.backend_dir(),
        log: l.logs().join("backend.log"),
    }
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

pub fn render_plist(a: &Agent) -> String {
    let args: Vec<String> = a.program.iter().map(|p| format!("    <string>{}</string>", xml(p))).collect();
    let env: Vec<String> =
        a.env.iter().map(|(k, v)| format!("    <key>{}</key>\n    <string>{}</string>", xml(k), xml(v))).collect();
    kit::LAUNCH_AGENT_TEMPLATE
        .replace("@@LABEL@@", &xml(a.label))
        .replace("@@ARGUMENTS@@", &args.join("\n"))
        .replace("@@ENVIRONMENT@@", &env.join("\n"))
        .replace("@@WORKING_DIRECTORY@@", &xml(&s(&a.working_dir)))
        .replace("@@LOG@@", &xml(&s(&a.log)))
}

/// What launchd says about one of this user's services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceState {
    pub loaded: bool,
    pub running: bool,
    pub pid: Option<u32>,
}

const LAUNCHCTL: &str = "/bin/launchctl";

pub fn service_state(uid: u32, label: &str) -> ServiceState {
    let out = Command::new(LAUNCHCTL).arg("print").arg(format!("gui/{uid}/{label}")).output();
    match out {
        Ok(o) if o.status.success() => parse_print(&String::from_utf8_lossy(&o.stdout)),
        _ => ServiceState { loaded: false, running: false, pid: None },
    }
}

/// `launchctl print` output: the service's `state` and `pid` lines at its top level.
pub fn parse_print(text: &str) -> ServiceState {
    let mut running = false;
    let mut pid = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("state = ") {
            running = running || v == "running";
        } else if let Some(v) = t.strip_prefix("pid = ") {
            pid = pid.or(v.parse().ok());
        }
    }
    ServiceState { loaded: true, running, pid }
}

fn launchctl(args: &[&str], what: &str) -> Result<()> {
    let o = Command::new(LAUNCHCTL)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| failed(format!("{what}: launchctl could not run: {e}")))?;
    if !o.status.success() {
        let err = String::from_utf8_lossy(&o.stderr);
        return Err(failed(format!("{what}: launchctl said: {}", err.trim())));
    }
    Ok(())
}

/// Loads (or reloads, when its file changed) one service in the developer's login session.
pub fn bootstrap(uid: u32, label: &str, plist: &Path, changed: bool) -> Result<()> {
    let domain = format!("gui/{uid}");
    let target = format!("{domain}/{label}");
    let state = service_state(uid, label);
    if state.loaded && !changed {
        return Ok(());
    }
    if state.loaded {
        launchctl(&["bootout", &target], &format!("stopping {label}"))?;
    }
    let _ = launchctl(&["enable", &target], &format!("enabling {label}"));
    // A service just stopped can take a moment to leave the session; try again briefly before giving up.
    let mut last = Ok(());
    for _ in 0..5 {
        last = launchctl(&["bootstrap", &domain, &plist.display().to_string()], &format!("starting {label}"));
        if last.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    last
}

/// Writes one LaunchAgent file as the developer, 0644, replacing it whole; a link in its place is refused.
/// Returns whether it changed.
pub fn write_plist(path: &Path, text: &str) -> Result<bool> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = path.parent().ok_or_else(|| failed("a LaunchAgent path has no folder"))?;
    std::fs::create_dir_all(dir).map_err(|e| failed(format!("making {}: {e}", dir.display())))?;
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_file() => {
            return Err(refused(format!("{} is a link or not a file; it was not replaced", path.display())))
        }
        Ok(m) => {
            if std::fs::read(path).ok().as_deref() == Some(text.as_bytes()) && m.permissions().mode() & 0o7777 == 0o644
            {
                return Ok(false);
            }
        }
        Err(_) => {}
    }
    let tmp = dir.join(format!(".{}.tmp", path.file_name().and_then(|n| n.to_str()).unwrap_or("agent")));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)
        .map_err(|e| failed(format!("writing {}: {e}", path.display())))?;
    f.write_all(text.as_bytes()).map_err(|e| failed(format!("writing {}: {e}", path.display())))?;
    f.set_permissions(std::fs::Permissions::from_mode(0o644)).ok();
    f.sync_all().map_err(|e| failed(format!("writing {}: {e}", path.display())))?;
    std::fs::rename(&tmp, path).map_err(|e| failed(format!("writing {}: {e}", path.display())))?;
    Ok(true)
}

/// Runs this same binary once as root (`sudo`), with the root plan on its standard input; sudo asks for the
/// password on the terminal. Returns what the root step printed (its changes, as JSON).
pub fn run_elevated(plan_json: &[u8]) -> Result<Vec<u8>> {
    let me = std::env::current_exe().map_err(|e| failed(format!("finding this program: {e}")))?;
    let me = me.canonicalize().map_err(|e| failed(format!("finding this program: {e}")))?;
    let mut child = Command::new("/usr/bin/sudo")
        .arg("--prompt=ekka-desk-host needs your password once, for the files root owns: ")
        .arg("--")
        .arg(&me)
        .arg("__apply-root")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| failed(format!("asking for root with sudo: {e}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| failed("sudo took no input"))?
        .write_all(plan_json)
        .map_err(|e| failed(format!("handing the plan to the root step: {e}")))?;
    let out = child.wait_with_output().map_err(|e| failed(format!("waiting for the root step: {e}")))?;
    if !out.status.success() {
        return Err(failed(format!(
            "the root step did not finish (exit {}); see its reason above. Nothing after it was done",
            out.status.code().unwrap_or(-1)
        )));
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Profile;

    pub(crate) fn sample_layout() -> Layout {
        Layout::system(501, PathBuf::from("/Users/dev"))
    }

    fn inputs(p: &Profile) -> ServiceInputs<'_> {
        ServiceInputs { ekka: Path::new("/usr/local/bin/ekka"), env: "prod", gateway_key_b64: "AAAA", profile: p }
    }

    fn env_of<'a>(a: &'a Agent, k: &str) -> Option<&'a str> {
        a.env.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str())
    }

    #[test]
    fn every_socket_path_fits_the_mac_limit() {
        let l = sample_layout();
        for p in [l.adapter_socket(), l.claim_socket(), l.interceptor_socket()] {
            assert!(p.as_os_str().len() <= 103, "{}", p.display());
            assert!(p.starts_with("/private/var/db/ekka-dev/501/run"), "{}", p.display());
        }
    }

    #[test]
    fn the_enclave_and_the_adapter_meet_in_one_owner_only_folder() {
        let l = sample_layout();
        let p = Profile::parse(include_str!("../../../deploy/macos/identity-profile.sample.json")).unwrap();
        let e = enclave_agent(&l, &inputs(&p));
        assert_eq!(env_of(&e, "EKKA_BACKEND_SOCKET_DIR"), Some("/private/var/db/ekka-dev/501/run/backend"));
        assert_eq!(l.adapter_socket().parent().unwrap(), Path::new(env_of(&e, "EKKA_BACKEND_SOCKET_DIR").unwrap()));
    }

    #[test]
    fn the_enclave_registers_desks_by_itself_behind_an_owner_only_interceptor() {
        let l = sample_layout();
        let p = Profile::parse(include_str!("../../../deploy/macos/identity-profile.sample.json")).unwrap();
        let e = enclave_agent(&l, &inputs(&p));
        assert_eq!(env_of(&e, "EKKA_DESKS_AUTO"), Some("true"));
        assert_eq!(env_of(&e, "EKKA_OPENSHELL_INTERCEPTOR_SOCKET_MODE"), Some("0600"));
        assert_eq!(
            env_of(&e, "EKKA_OPENSHELL_INTERCEPTOR_SOCKET"),
            Some("/private/var/db/ekka-dev/501/run/openshell-interceptor.sock")
        );
        assert_eq!(env_of(&e, "EKKA_OPENSHELL_INTERCEPTOR_AUDIENCE"), Some(INTERCEPTOR_AUDIENCE));
        assert_eq!(env_of(&e, "EKKA_OPENSHELL_GATEWAY_KEY_B64"), Some("AAAA"));
        assert!(e.env.iter().all(|(k, _)| k != "EKKA_OPENSHELL_INTERCEPTOR_GROUP"), "never a group on a Mac");
        assert_eq!(env_of(&e, "EKKA_OPENSHELL_EXECUTOR_URL"), Some("https://127.0.0.1:8080"));
        assert_eq!(env_of(&e, "EKKA_OPENSHELL_EXECUTOR_ISSUER"), Some(p.gateway.issuer.as_str()));
        assert!(env_of(&e, "EKKA_OPENSHELL_BACKEND_SUBJECT").unwrap().starts_with("user:oidc:adapter/"));
        // Without the Enclave's caller the executor keys (and auto registration, which needs them) are left out.
        let mut bare = p.clone();
        bare.callers.enclave = None;
        let e = enclave_agent(&l, &inputs(&bare));
        assert!(e.env.iter().all(|(k, _)| !k.starts_with("EKKA_OPENSHELL_EXECUTOR_") && k != "EKKA_DESKS_AUTO"));
    }

    #[test]
    fn the_enclave_trusts_the_system_roots_plus_the_installation_ca() {
        let l = sample_layout();
        let p = Profile::parse(include_str!("../../../deploy/macos/identity-profile.sample.json")).unwrap();
        let e = enclave_agent(&l, &inputs(&p));
        assert_eq!(env_of(&e, "SSL_CERT_FILE"), Some("/private/var/db/ekka-dev/501/tls/ca-bundle.crt"));
    }

    #[test]
    fn the_gateway_keeps_every_state_folder_in_d() {
        let l = sample_layout();
        let g = gateway_agent(&l);
        for k in ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"] {
            assert!(env_of(&g, k).unwrap().starts_with("/private/var/db/ekka-dev/501/gateway"), "{k}");
        }
        assert_eq!(
            env_of(&g, "OPENSHELL_DB_URL"),
            Some("sqlite:/private/var/db/ekka-dev/501/gateway/state/gateway.db?mode=rwc")
        );
        assert!(g.env.iter().all(|(_, v)| !v.starts_with("/Users/dev")), "nothing in the developer's home");
        assert!(g.env.iter().all(|(_, v)| !v.contains("localhost")), "numeric IPv4 or the VM name, never localhost");
    }

    #[test]
    fn a_plist_is_rendered_escaped_and_runs_in_the_login_session_only() {
        let a = Agent {
            label: LABEL_GATEWAY,
            program: vec!["/opt/x".into()],
            env: vec![("K".into(), "a<b&\"c\"".into())],
            working_dir: PathBuf::from("/w"),
            log: PathBuf::from("/l.log"),
        };
        let x = render_plist(&a);
        assert!(x.contains("<string>a&lt;b&amp;&quot;c&quot;</string>"), "{x}");
        assert!(x.contains("<key>LimitLoadToSessionType</key>\n  <string>Aqua</string>"));
        assert!(!x.contains("@@"), "every placeholder is filled");
        assert!(!x.contains("UserName"), "a LaunchAgent runs as the user who logs in, never as another");
    }

    #[test]
    fn launchctl_print_is_read_for_state_and_pid() {
        let st =
            parse_print("gui/501/com.ekka.desks.gateway = {\n\tactive count = 1\n\tstate = running\n\tpid = 4242\n}\n");
        assert_eq!(st, ServiceState { loaded: true, running: true, pid: Some(4242) });
        assert!(!parse_print("x = {\n\tstate = waiting\n}\n").running);
    }
}

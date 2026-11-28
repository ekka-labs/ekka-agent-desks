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
use crate::kit;
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
    /// The machine-wide installation binding (one installation per Mac).
    pub fn binding(&self) -> PathBuf {
        self.ekka_dev().join("binding.json")
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
    /// This installation's id: the adapter's subject is `adapter/<installation id>`, as Govern issues it.
    pub installation_id: &'a str,
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
    // The one caller the interceptor lets create a desk: the adapter, by the subject Govern gives this
    // installation's adapter. Derived, never configured.
    env.push(("EKKA_OPENSHELL_BACKEND_SUBJECT".into(), format!("user:oidc:adapter/{}", i.installation_id)));
    // No executor keys, and so no EKKA_DESKS_AUTO (it needs the executor): the gateway's issuer is Govern's, which
    // issues the Enclave's own pass only in exchange for its runner session, and the shipped Enclave cannot make
    // that exchange yet. Install says so; the keys come with the ekka release that can.
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

/// Stops one service and takes it out of the developer's login session.
pub fn bootout(uid: u32, label: &str) -> Result<()> {
    launchctl(&["bootout", &format!("gui/{uid}/{label}")], &format!("stopping {label}"))
}

/// Restarts a running service, so it reads its configuration again.
pub fn kickstart(uid: u32, label: &str) -> Result<()> {
    launchctl(&["kickstart", "-k", &format!("gui/{uid}/{label}")], &format!("restarting {label}"))
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

/// Where `ekka-desk-host` must be, root's, before it may ask for root. sudo runs this path and nothing else.
pub const HOST_BINARY: &str = "/usr/local/libexec/ekka-desk-host/ekka-desk-host";

/// The one root command that places this program, for `version`. Everything happens as root inside a folder root
/// makes for it (mode 0700), using only the system's own programs and a cosign fetched into that same folder and
/// checked against its pinned sha256: the release archive is checked against its sha256 file and its keyless
/// signature by this kit's release workflow for exactly that tag, and the program is installed from those very
/// bytes, atomically. Nothing the developer can write is hashed, run or installed by root.
pub fn bootstrap_command(version: &str) -> String {
    format!(
        "sudo /bin/sh -euc '\n\
         v={version}\n\
         d=$(/usr/bin/mktemp -d /private/tmp/ekka-desk-host.XXXXXXXX); cd \"$d\"\n\
         r=https://github.com/ekka-labs/ekka-agent-desks/releases/download/host-v$v\n\
         f=ekka-desk-host-$v-aarch64-apple-darwin.tar.gz\n\
         for x in \"$f\" \"$f.sha256\" \"$f.sig\" \"$f.crt\"; do /usr/bin/curl -fsSLo \"$x\" \"$r/$x\"; done\n\
         /usr/bin/curl -fsSLo cosign https://github.com/sigstore/cosign/releases/download/{COSIGN_VERSION}/cosign-darwin-arm64\n\
         echo \"{COSIGN_SHA256}  cosign\" | /usr/bin/shasum -a 256 -c -\n\
         /bin/chmod 0700 cosign\n\
         /usr/bin/shasum -a 256 -c \"$f.sha256\"\n\
         ./cosign verify-blob --certificate \"$f.crt\" --signature \"$f.sig\" \\\n\
         \x20 --certificate-oidc-issuer https://token.actions.githubusercontent.com \\\n\
         \x20 --certificate-identity \"{HOST_SIGNER}$v\" \"$f\"\n\
         /usr/bin/tar -xzf \"$f\" ekka-desk-host\n\
         /usr/bin/install -d -o root -g wheel -m 0755 /usr/local/libexec/ekka-desk-host\n\
         /usr/bin/install -o root -g wheel -m 0755 ekka-desk-host /usr/local/libexec/ekka-desk-host/.ekka-desk-host.new\n\
         /bin/mv -f /usr/local/libexec/ekka-desk-host/.ekka-desk-host.new {HOST_BINARY}\n\
         cd /; /bin/rm -rf \"$d\"'"
    )
}

/// The identity that signs this kit's ekka-desk-host releases; the version tag follows.
pub const HOST_SIGNER: &str =
    "https://github.com/ekka-labs/ekka-agent-desks/.github/workflows/release-host.yml@refs/tags/host-v";
/// The cosign the bootstrap command fetches, by version and by its published sha256 (darwin-arm64).
const COSIGN_VERSION: &str = "v2.6.5";
const COSIGN_SHA256: &str = "4d41cc18f0563907c0c785b51db76e1d1af10db4422b605ba876b1758e1771ab";

fn place_it(why: &str) -> String {
    format!(
        "ekka-desk-host asks for root only when it runs from {HOST_BINARY}, a root-owned copy nobody else can change \
         ({why}). Nothing was changed. Place it with this one root command (it checks the signed release itself, \
         inside a folder only root can write), then run it from there:\n\n{}\n\n    {HOST_BINARY} install ...",
        bootstrap_command(env!("CARGO_PKG_VERSION"))
    )
}

/// The running program is `fixed` (after resolving links), a regular file owned by `owner` in folders that only
/// `owner` can change, from `top` down: no link, no group or other write, no ACL grant. On a real install
/// `fixed` is `HOST_BINARY`, `top` is `/` and `owner` is root, so code running as the developer cannot replace
/// the program the password prompt will authorize.
pub fn trusted_self(exe: &Path, fixed: &Path, top: &Path, owner: u32) -> Result<()> {
    let real = exe.canonicalize().map_err(|e| refused(place_it(&format!("this program cannot be found: {e}"))))?;
    if real != fixed {
        return Err(refused(place_it(&format!("this program is {}", real.display()))));
    }
    let (Some(parent), Some(name)) = (fixed.parent(), fixed.file_name().and_then(|n| n.to_str())) else {
        return Err(refused(place_it("its path has no folder")));
    };
    let dir = crate::fsx::open_trusted_dir(parent, top, owner, None).map_err(|e| refused(place_it(&e.reason)))?;
    let fd = crate::fsx::open_file_at(&dir, name)?.ok_or_else(|| refused(place_it("it is not there")))?;
    let st = rustix::fs::fstat(&fd).map_err(|e| refused(place_it(&e.to_string())))?;
    if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::RegularFile
        || st.st_uid != owner
        || crate::fsx::mode_bits(st.st_mode) & 0o022 != 0
    {
        return Err(refused(place_it("it is not a regular file that only root can change")));
    }
    if let Some(why) = crate::acl::unsafe_grant(&fd, crate::acl::Guard::Writes)? {
        return Err(refused(place_it(&why)));
    }
    Ok(())
}

/// The one command that asks for root: sudo, then `HOST_BINARY` by its fixed path. Never this process's own path.
fn elevation() -> Command {
    let mut c = Command::new("/usr/bin/sudo");
    c.arg("--prompt=ekka-desk-host needs your password once, for the files root owns: ")
        .arg("--")
        .arg(HOST_BINARY)
        .arg("__apply-root");
    c
}

/// Runs `HOST_BINARY` once as root (`sudo`), with the root plan on its standard input; sudo asks for the
/// password on the terminal. Returns what the root step printed (its changes, as JSON). The caller has checked
/// `trusted_self` first.
pub fn run_elevated(plan_json: &[u8]) -> Result<Vec<u8>> {
    let mut child = elevation()
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

    pub(crate) fn sample_layout() -> Layout {
        Layout::system(501, PathBuf::from("/Users/dev"))
    }

    fn me() -> u32 {
        rustix::process::getuid().as_raw()
    }

    #[test]
    fn a_host_program_anywhere_the_developer_can_change_is_refused_before_sudo() {
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("ekka-desk-host");
        std::fs::write(&exe, b"x").unwrap();
        let e = trusted_self(&exe, Path::new(HOST_BINARY), Path::new("/"), 0).unwrap_err();
        assert_eq!(e.kind, crate::error::Kind::Refused);
        assert!(e.reason.contains(HOST_BINARY), "{e}");
        assert!(e.reason.contains(&bootstrap_command(env!("CARGO_PKG_VERSION"))), "{e}");
    }

    #[test]
    fn the_placement_command_verifies_and_installs_only_bytes_root_fetched_into_its_own_folder() {
        let c = bootstrap_command("1.2.3");
        // Root makes the folder (mktemp -d: root's, 0700) and everything is fetched into it as root.
        assert!(c.starts_with("sudo /bin/sh -euc '") && c.contains("/usr/bin/mktemp -d /private/tmp/"), "{c}");
        assert!(!c.contains("<downloaded"), "never a developer's file by name: {c}");
        // cosign is pinned by sha256 before it runs; the archive by its sha256 file and its signature, by exactly
        // this kit's release workflow for exactly this tag; the program comes out of those very bytes.
        let pos = |needle: &str| c.find(needle).unwrap_or_else(|| panic!("{needle} missing in {c}"));
        assert!(pos(COSIGN_SHA256) < pos("./cosign verify-blob"));
        assert!(pos("shasum -a 256 -c \"$f.sha256\"") < pos("/usr/bin/tar -xzf"));
        assert!(pos("./cosign verify-blob") < pos("/usr/bin/tar -xzf"));
        assert!(c.contains(&format!("--certificate-identity \"{HOST_SIGNER}$v\"")) && c.contains("v=1.2.3"));
        // Atomic: installed beside, then renamed over the program.
        assert!(
            pos(".ekka-desk-host.new")
                < pos(&format!("/bin/mv -f /usr/local/libexec/ekka-desk-host/.ekka-desk-host.new {HOST_BINARY}"))
        );
        // Only the system's own programs run as root, and the cosign root fetched and checked itself.
        for line in c.lines().skip(1) {
            let first = line.split_whitespace().next().unwrap_or("");
            assert!(
                first.starts_with("/usr/bin/")
                    || first.starts_with("/bin/")
                    || first.starts_with("./cosign")
                    || ["v=", "d=", "r=", "f=", "for", "echo", "cd", "--cert"].iter().any(|ok| first.starts_with(ok)),
                "{line}"
            );
        }
    }

    #[test]
    fn the_docs_give_the_same_placement_command_as_the_refusal() {
        let readme = include_str!("../../README.md");
        assert!(readme.contains(&bootstrap_command(env!("CARGO_PKG_VERSION"))), "host/README.md is out of date");
    }

    #[test]
    fn only_the_fixed_root_owned_path_passes_and_sudo_runs_that_path_only() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let top = t.path().canonicalize().unwrap();
        let dir = top.join("usr/local/libexec/ekka-desk-host");
        std::fs::create_dir_all(&dir).unwrap();
        for d in ["usr", "usr/local", "usr/local/libexec", "usr/local/libexec/ekka-desk-host"] {
            std::fs::set_permissions(top.join(d), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::set_permissions(&top, std::fs::Permissions::from_mode(0o755)).unwrap();
        let fixed = dir.join("ekka-desk-host");
        std::fs::write(&fixed, b"x").unwrap();
        std::fs::set_permissions(&fixed, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The owner stands in for root here: the same rules, on a tree this test owns.
        trusted_self(&fixed, &fixed, &top, me()).unwrap();
        let link = top.join("link");
        std::os::unix::fs::symlink(&fixed, &link).unwrap();
        trusted_self(&link, &fixed, &top, me()).unwrap();
        std::fs::set_permissions(&fixed, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(trusted_self(&fixed, &fixed, &top, me()).is_err(), "group-writable program");
        std::fs::set_permissions(&fixed, std::fs::Permissions::from_mode(0o755)).unwrap();
        crate::acl::tests::plant(&dir, "everyone allow add_file,delete_child");
        assert!(trusted_self(&fixed, &fixed, &top, me()).is_err(), "a folder an ACL lets others change");

        let c = elevation();
        assert_eq!(c.get_program(), "/usr/bin/sudo");
        let args: Vec<_> = c.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args[2..], [HOST_BINARY.to_string(), "__apply-root".to_string()]);
        let me_path = std::env::current_exe().unwrap().display().to_string();
        assert!(!args.contains(&me_path), "never this process's own path");
    }

    const INSTALLATION: &str = "5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d";

    fn inputs() -> ServiceInputs<'static> {
        ServiceInputs {
            ekka: Path::new("/usr/local/bin/ekka"),
            env: "prod",
            gateway_key_b64: "AAAA",
            installation_id: INSTALLATION,
        }
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
        let e = enclave_agent(&l, &inputs());
        assert_eq!(env_of(&e, "EKKA_BACKEND_SOCKET_DIR"), Some("/private/var/db/ekka-dev/501/run/backend"));
        assert_eq!(l.adapter_socket().parent().unwrap(), Path::new(env_of(&e, "EKKA_BACKEND_SOCKET_DIR").unwrap()));
    }

    #[test]
    fn the_enclave_serves_an_owner_only_interceptor_and_names_the_adapter_by_derivation() {
        let l = sample_layout();
        let e = enclave_agent(&l, &inputs());
        assert_eq!(env_of(&e, "EKKA_OPENSHELL_INTERCEPTOR_SOCKET_MODE"), Some("0600"));
        assert_eq!(
            env_of(&e, "EKKA_OPENSHELL_INTERCEPTOR_SOCKET"),
            Some("/private/var/db/ekka-dev/501/run/openshell-interceptor.sock")
        );
        assert_eq!(env_of(&e, "EKKA_OPENSHELL_INTERCEPTOR_AUDIENCE"), Some(INTERCEPTOR_AUDIENCE));
        assert_eq!(env_of(&e, "EKKA_OPENSHELL_GATEWAY_KEY_B64"), Some("AAAA"));
        assert!(e.env.iter().all(|(k, _)| k != "EKKA_OPENSHELL_INTERCEPTOR_GROUP"), "never a group on a Mac");
        assert_eq!(
            env_of(&e, "EKKA_OPENSHELL_BACKEND_SUBJECT").unwrap(),
            format!("user:oidc:adapter/{INSTALLATION}"),
            "the adapter's subject is derived from this installation, never configured"
        );
        // No executor, and no auto registration (it needs the executor), until the Enclave can get Govern's pass.
        assert!(e.env.iter().all(|(k, _)| !k.starts_with("EKKA_OPENSHELL_EXECUTOR_") && k != "EKKA_DESKS_AUTO"));
    }

    #[test]
    fn the_enclave_trusts_the_system_roots_plus_the_installation_ca() {
        let l = sample_layout();
        let e = enclave_agent(&l, &inputs());
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

//! `status` and `doctor`: what this host observes, as versioned, secret-free JSON with a reason for each failure.
//!
//! `status` reads state: the binding, the release, the records, the folders, the certificates' files, the
//! services and the meter. `doctor` adds live probes that change nothing: the interceptor and the adapter answer
//! on their sockets, the gateway completes verified TLS for both its names and refuses a wrong one, the gateway
//! cannot be reached on this Mac's network address, its configuration has no unsafe setting, and the developer's
//! own XDG folders hold no gateway state. No value printed is a key, a token or a password: only paths, owners,
//! modes, public hashes, booleans and reasons.

use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::adapter;
use crate::binding::Binding;
use crate::fsx;
use crate::gateway_config;
use crate::meter;
use crate::platform::macos::{
    self, Layout, BUNDLE, CA_CERT, CA_KEY, GATEWAY_PORT, LABEL_BACKEND, LABEL_ENCLAVE, LABEL_GATEWAY, LEAF_KEY,
    LEAF_META,
};
use crate::records::{self, Ceiling};
use crate::release::{verify_binary, Pins};
use crate::runtime::docker::Docker;
use crate::tls::{self, LeafMeta, GATEWAY_DNS, GATEWAY_IP};

pub const STATUS_SCHEMA: &str = "ekka-desk-host.status/v1";
pub const DOCTOR_SCHEMA: &str = "ekka-desk-host.doctor/v1";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Check {
    pub id: &'static str,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn pass(id: &'static str) -> Check {
    Check { id, ok: true, reason: None }
}

fn fail(id: &'static str, reason: impl Into<String>) -> Check {
    Check { id, ok: false, reason: Some(reason.into()) }
}

fn from(id: &'static str, r: Result<(), String>) -> Check {
    match r {
        Ok(()) => pass(id),
        Err(e) => fail(id, e),
    }
}

#[derive(Debug, Serialize)]
pub struct Service {
    pub label: &'static str,
    pub loaded: bool,
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub schema: &'static str,
    pub host_version: &'static str,
    pub ok: bool,
    pub binding: Option<Binding>,
    pub release: String,
    pub adapter_pinned: bool,
    pub enclave_enrolled: bool,
    pub services: Vec<Service>,
    pub bootstrap: Check,
    pub checks: Vec<Check>,
}

#[derive(Debug, Serialize)]
pub struct Doctor {
    pub schema: &'static str,
    pub host_version: &'static str,
    pub ok: bool,
    pub checks: Vec<Check>,
}

fn mode_of(p: &Path) -> Result<(u32, u32), String> {
    let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok((m.uid(), m.permissions().mode() & 0o7777))
}

fn expect(p: &Path, uid: u32, mode: u32) -> Result<(), String> {
    let (u, m) = mode_of(p)?;
    if u != uid || m != mode {
        return Err(format!("{} is uid {u} mode {m:o}; it must be uid {uid} mode {mode:o}", p.display()));
    }
    Ok(())
}

fn check_binding(l: &Layout) -> (Check, Option<Binding>) {
    match Binding::read(&l.binding()) {
        Ok(Some(b)) => match expect(&l.binding(), 0, 0o644) {
            Ok(()) if b.uid == l.uid => (pass("binding"), Some(b)),
            Ok(()) => (
                fail(
                    "binding",
                    format!("this Mac's desk host is installed for uid {}, not {} (one per Mac)", b.uid, l.uid),
                ),
                Some(b),
            ),
            Err(e) => (fail("binding", e), Some(b)),
        },
        Ok(None) => (fail("binding", "not installed: run ekka-desk-host install"), None),
        Err(e) => (fail("binding", e.reason), None),
    }
}

fn check_release(l: &Layout, pins: &Pins) -> Check {
    let want = format!("releases/{}", pins.release_id());
    match std::fs::read_link(l.opt().join("current")) {
        Ok(t) if t == Path::new(&want) => {}
        Ok(t) => return fail("release", format!("current is {}, not {want}", t.display())),
        Err(_) => return fail("release", "no current release"),
    }
    if let Err(e) = expect(&l.opt(), 0, 0o755) {
        return fail("release", e);
    }
    let mut programs = vec![&pins.gateway];
    programs.extend(pins.adapter.as_ref());
    for p in programs {
        let path = l.release_dir(&pins.release_id()).join("bin").join(&p.binary);
        if let Err(e) = expect(&path, 0, 0o755) {
            return fail("release", e);
        }
        match std::fs::read(&path) {
            Ok(b) => {
                if let Err(e) = verify_binary(p, &b) {
                    return fail("release", e.reason);
                }
            }
            Err(e) => return fail("release", format!("{}: {e}", path.display())),
        }
    }
    pass("release")
}

/// The records as the runner reads them: a walk from `/` that refuses links, root-owned, nobody else may write.
fn check_records(l: &Layout, pins: &Pins) -> Check {
    from(
        "records",
        (|| {
            let dir = fsx::open_trusted_dir(&l.records(), &l.top, 0, None).map_err(|e| e.reason)?;
            for name in [records::BASELINE, records::CEILING] {
                expect(&l.records().join(name), 0, 0o644)?;
            }
            let baseline = fsx::read_at(&dir, records::BASELINE, 1 << 20).map_err(|e| e.reason)?.unwrap_or_default();
            if baseline != records::baseline_bytes().map_err(|e| e.reason)? {
                return Err("baseline-policy.json is not this release's reviewed baseline".into());
            }
            let ceiling = fsx::read_at(&dir, records::CEILING, 64 * 1024).map_err(|e| e.reason)?.unwrap_or_default();
            let c: Ceiling = serde_json::from_slice(&ceiling).map_err(|e| format!("provider-ceiling.json: {e}"))?;
            c.check().map_err(|e| e.reason)?;
            if c != records::ceiling(c.resources).map_err(|e| e.reason)? {
                return Err("provider-ceiling.json does not name exactly this release's profiles".into());
            }
            // The desk image only by a published, pinned digest; without one, desks wait (closed).
            match (fsx::read_at(&dir, records::IMAGE, 4096).map_err(|e| e.reason)?, &pins.desk_image) {
                (None, None) => {
                    return Err("waiting: no published desk image is pinned for a Mac yet; desks wait, closed".into())
                }
                (Some(_), None) => return Err("desk-image.json names an image this release did not pin".into()),
                (None, Some(_)) => return Err("desk-image.json is missing: run install again".into()),
                (Some(have), Some(pin)) => {
                    expect(&l.records().join(records::IMAGE), 0, 0o644)?;
                    if have != records::image_bytes(pin).map_err(|e| e.reason)? {
                        return Err("desk-image.json is not the pinned published desk image".into());
                    }
                }
            }
            Ok(())
        })(),
    )
}

fn check_folders(l: &Layout) -> Check {
    from(
        "folders",
        (|| {
            expect(&l.d(), 0, 0o755)?;
            for p in [
                l.enclave_home(),
                l.gateway_dir(),
                l.backend_dir(),
                l.run_dir(),
                l.backend_socket_dir(),
                l.permits_dir(),
            ] {
                expect(&p, l.uid, 0o700)?;
            }
            Ok(())
        })(),
    )
}

fn check_tls(l: &Layout) -> Check {
    from(
        "certificates",
        (|| {
            let t = l.tls_dir();
            expect(&t.join(CA_KEY), 0, 0o600)?;
            if let Some(why) = crate::acl::unsafe_grant_path(&t.join(CA_KEY), crate::acl::Guard::ReadsAndWrites)
                .map_err(|e| e.reason)?
            {
                return Err(format!("{}: {why}; run install --rotate-ca", t.join(CA_KEY).display()));
            }
            expect(&t.join(CA_CERT), 0, 0o644)?;
            expect(&t.join(LEAF_KEY), l.uid, 0o600)?;
            expect(&t.join(BUNDLE), 0, 0o644)?;
            let ca = std::fs::read(t.join(CA_CERT)).map_err(|e| e.to_string())?;
            let meta: Option<LeafMeta> =
                std::fs::read(t.join(LEAF_META)).ok().and_then(|m| serde_json::from_slice(&m).ok());
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
            if LeafMeta::needs_renewal(meta.as_ref(), &ca, now) {
                return Err(
                    "the gateway certificate is missing, near its end, or not from this CA: run install again".into()
                );
            }
            Ok(())
        })(),
    )
}

fn check_gateway_config(l: &Layout, binding: Option<&Binding>) -> Check {
    from(
        "gateway_config",
        (|| {
            if std::fs::symlink_metadata(l.gateway_toml()).is_err() {
                return Err("waiting: the gateway is not registered for this installation yet".into());
            }
            expect(&l.gateway_toml(), 0, 0o644)?;
            let record = l.d().join(crate::registration::RECORD);
            expect(&record, 0, 0o644)?;
            let r: crate::registration::Record =
                serde_json::from_slice(&std::fs::read(&record).map_err(|e| e.to_string())?)
                    .map_err(|_| "the gateway's registration record is unreadable".to_string())?;
            let ours = binding.is_some_and(|b| {
                r.installation_id == b.installation_id
                    && crate::identity::issuer(&b.env, &b.org).is_ok_and(|i| i == r.issuer)
            });
            if !ours {
                return Err("the gateway's registration is not this installation's".into());
            }
            let text = std::fs::read_to_string(l.gateway_toml()).map_err(|e| e.to_string())?;
            let found = gateway_config::findings_of_text(&text);
            if found.is_empty() {
                Ok(())
            } else {
                Err(found.join("; "))
            }
        })(),
    )
}

fn services(l: &Layout, pins: &Pins) -> Vec<Service> {
    let mut labels = vec![LABEL_ENCLAVE, LABEL_GATEWAY];
    if pins.adapter.is_some() {
        labels.push(LABEL_BACKEND);
    }
    labels
        .into_iter()
        .map(|label| {
            let s = macos::service_state(l.uid, label);
            Service { label, loaded: s.loaded, running: s.running, pid: s.pid }
        })
        .collect()
}

fn check_socket(id: &'static str, p: &Path, uid: u32) -> Check {
    from(
        id,
        (|| {
            let m = std::fs::symlink_metadata(p)
                .map_err(|_| format!("{} does not exist (is its service running?)", p.display()))?;
            if !m.file_type().is_socket() {
                return Err(format!("{} is not a socket", p.display()));
            }
            if m.uid() != uid || m.permissions().mode() & 0o777 != 0o600 {
                return Err(format!("{} must be owned by uid {uid} with mode 600", p.display()));
            }
            Ok(())
        })(),
    )
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// The meter: running, sealed as this release makes it, no TTY, and its newest sample fresh and complete.
pub fn check_meter(docker: &Docker, pins: &Pins) -> Check {
    from(
        "meter",
        (|| {
            let c =
                docker.container(meter::NAME).map_err(|e| e.reason)?.ok_or("the meter is not there: run install")?;
            if c["State"]["Running"].as_bool() != Some(true) {
                return Err("the meter is not running".into());
            }
            let diff = meter::differences(&c, &pins.meter_image);
            if !diff.is_empty() {
                return Err(format!("the meter is not this release's: {}", diff.join(", ")));
            }
            let lines = docker.stdout_tail(meter::NAME, meter::READER_LINES).map_err(|e| e.reason)?;
            let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
            let s = meter::newest_sample(&refs)?;
            if !s.errors.is_empty() {
                return Err(format!("the meter cannot read {}", s.errors.join(", ")));
            }
            meter::fresh(s.unix_seconds, now_secs())
        })(),
    )
}

fn check_docker(docker: &Docker) -> Check {
    from(
        "docker",
        (|| {
            let i = docker.info().map_err(|e| e.reason)?;
            if i.os_type != "linux" || i.arch != "aarch64" {
                return Err(format!("Docker's VM is {}/{}, not linux/aarch64", i.os_type, i.arch));
            }
            Ok(())
        })(),
    )
}

/// The program itself: the root-owned copy at its fixed path, the only one that may ask for root.
fn check_host_binary() -> Check {
    from(
        "host_binary",
        std::env::current_exe().map_err(|e| e.to_string()).and_then(|exe| {
            macos::trusted_self(&exe, Path::new(macos::HOST_BINARY), Path::new("/"), 0).map_err(|e| e.reason)
        }),
    )
}

/// The status of this Mac's desk host for the developer `l.uid`.
pub fn status(l: &Layout, pins: &Pins, env: Option<&str>) -> Status {
    let (b, binding) = check_binding(l);
    let mut checks = vec![check_host_binary(), b];
    if binding.is_some() {
        checks.extend([
            check_release(l, pins),
            check_records(l, pins),
            check_folders(l),
            check_tls(l),
            check_gateway_config(l, binding.as_ref()),
        ]);
    }
    let docker = Docker::new(&l.docker_socket());
    checks.push(check_docker(&docker));
    checks.push(check_meter(&docker, pins));
    let env = env.or(binding.as_ref().map(|b| b.env.as_str())).unwrap_or("prod");
    let enrolled = adapter::read_enclave_values(&adapter::enclave_env_path(l, env)).ok().flatten();
    if let (Some(e), Some(b)) = (&enrolled, &binding) {
        if e.tenant_id != b.org {
            checks.push(fail("enclave", "the Enclave is enrolled in another organization than this host is bound to"));
        }
    }
    let services = services(l, pins);
    let stopped: Vec<&str> = services.iter().filter(|s| !s.running).map(|s| s.label).collect();
    checks.push(if stopped.is_empty() {
        pass("services")
    } else {
        fail("services", format!("not running: {}", stopped.join(", ")))
    });
    let bootstrap = fail(
        "bootstrap",
        "pending: the gateway's one-time setup needs an EKKA setup pass from Govern, which this release cannot obtain yet",
    );
    let ok = checks.iter().all(|c| c.ok) && bootstrap.ok;
    Status {
        schema: STATUS_SCHEMA,
        host_version: env!("CARGO_PKG_VERSION"),
        ok,
        binding,
        release: pins.release_id(),
        adapter_pinned: pins.adapter.is_some(),
        enclave_enrolled: enrolled.is_some(),
        services,
        bootstrap,
        checks,
    }
}

/// This Mac's address on its network, if it has one (no packet is sent).
fn lan_ipv4() -> Option<std::net::IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// Everything `status` checks, and the live probes.
pub fn doctor(l: &Layout, pins: &Pins) -> Doctor {
    let mut checks = status(l, pins, None).checks;
    checks.push(check_socket("interceptor_socket", &l.interceptor_socket(), l.uid));
    checks.push(from(
        "interceptor_answers",
        std::os::unix::net::UnixStream::connect(l.interceptor_socket())
            .map(|_| ())
            .map_err(|e| format!("the Enclave's interceptor does not answer: {e}")),
    ));
    if pins.adapter.is_some() {
        checks.push(check_socket("adapter_socket", &l.adapter_socket(), l.uid));
        checks.push(check_socket("claim_socket", &l.claim_socket(), l.uid));
    }
    let gw = SocketAddr::from((GATEWAY_IP, GATEWAY_PORT));
    checks.push(from(
        "gateway_tls",
        (|| {
            let ca = std::fs::read(l.tls_dir().join(CA_CERT)).map_err(|e| format!("the installation CA: {e}"))?;
            tls::probe(gw, GATEWAY_DNS, &ca).map_err(|e| e.reason)?;
            tls::probe(gw, &GATEWAY_IP.to_string(), &ca).map_err(|e| e.reason)?;
            if tls::probe(gw, "wrong-name.invalid", &ca).is_ok() {
                return Err("the gateway's certificate was accepted for a wrong name".into());
            }
            Ok(())
        })(),
    ));
    checks.push(from(
        "gateway_loopback_only",
        match lan_ipv4() {
            None => Ok(()),
            Some(ip) => match TcpStream::connect_timeout(&SocketAddr::new(ip, GATEWAY_PORT), Duration::from_secs(1)) {
                Ok(_) => Err(format!("the gateway answers on this Mac's network address {ip}")),
                Err(_) => Ok(()),
            },
        },
    ));
    checks.push(from("gateway_state_in_d", {
        let found: Vec<String> = l
            .default_xdg_gateway_dirs()
            .into_iter()
            .flat_map(|d| std::fs::read_dir(&d).into_iter().flatten().flatten().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "db" || x == "sqlite"))
            .map(|p| p.display().to_string())
            .collect();
        if found.is_empty() {
            Ok(())
        } else {
            Err(format!("gateway state outside D: {}", found.join(", ")))
        }
    }));
    let ok = checks.iter().all(|c| c.ok);
    Doctor { schema: DOCTOR_SCHEMA, host_version: env!("CARGO_PKG_VERSION"), ok, checks }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::{root_apply, tests as apply_tests, Ctx};

    #[test]
    fn status_of_a_mac_with_nothing_installed_says_so_with_a_reason() {
        let t = tempfile::tempdir().unwrap();
        let l = Layout { top: t.path().to_path_buf(), uid: 501, home: t.path().join("home") };
        let s = status(&l, &Pins::embedded().unwrap(), None);
        assert!(!s.ok);
        assert_eq!(s.schema, STATUS_SCHEMA);
        assert!(s.checks.iter().all(|c| c.ok || c.reason.is_some()), "every failure has a reason");
        let by_id = |id: &str| s.checks.iter().find(|c| c.id == id).unwrap();
        assert_eq!(by_id("binding").reason.as_deref(), Some("not installed: run ekka-desk-host install"));
        assert!(by_id("host_binary").reason.as_deref().unwrap().contains(macos::HOST_BINARY));
        assert!(!s.bootstrap.ok && s.bootstrap.reason.as_deref().unwrap().starts_with("pending"));
    }

    #[test]
    fn the_status_of_an_installed_tree_names_each_failure_and_holds_no_secret() {
        let r = apply_tests::rig();
        root_apply(&r.plan, &r.layout, apply_tests::owners(), &r.pins, &r.roots, &mut Ctx::apply()).unwrap();
        let s = status(&r.layout, &r.pins, None);
        let json = serde_json::to_string(&s).unwrap();
        for secret in ["PRIVATE KEY", "BEGIN", "client_secret", "setup-pass"] {
            assert!(!json.contains(secret), "status must hold no secret ({secret})");
        }
        // Not root here, so every root-owned part is reported as not root's: each with a reason.
        let records = s.checks.iter().find(|c| c.id == "records").unwrap();
        assert!(!records.ok && records.reason.as_deref().unwrap().contains("uid 0"), "{records:?}");
        assert!(s.checks.iter().all(|c| c.ok || c.reason.as_deref().is_some_and(|r| !r.is_empty())));
    }

    #[test]
    fn a_socket_must_be_owner_only() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("s.sock");
        let _l = std::os::unix::net::UnixListener::bind(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let me = rustix::process::getuid().as_raw();
        assert!(check_socket("s", &p, me).ok);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!check_socket("s", &p, me).ok);
        assert!(!check_socket("s", &t.path().join("none.sock"), me).ok);
    }
}

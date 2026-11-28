//! The gateway's registration with Govern, bound to this installation before it is trusted.
//!
//! Govern answers a gateway registration (`POST /govern/desk-gateways`) with the gateway's id and its sign-in
//! settings. Root uses that answer only when it is this installation's: its installation id is the binding's, its
//! organization is the bound one, its class is development, its issuer is the one computed for the environment and
//! organization, and every sign-in value is what that id implies. Root then records the gateway id, the
//! installation id and the issuer beside the gateway's configuration, in the same step. Without a registration, or
//! with one that is not this installation's, the gateway's trust configuration is removed and its LaunchAgent
//! unloaded: an old configuration is never left running.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::binding::Binding;
use crate::error::{refused, Result};
use crate::identity::{self, Gateway};
use crate::platform::macos::{GATEWAY_PORT, WORKSPACE};
use crate::tls::GATEWAY_DNS;

/// The sign-in part of Govern's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oidc {
    pub issuer: String,
    pub audience: String,
    pub roles_claim: String,
    pub scopes_claim: String,
    pub admin_role: String,
    pub user_role: String,
    pub jwks_ttl_secs: u64,
}

/// What root reads of Govern's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub gateway_id: String,
    pub tenant_id: String,
    pub installation_id: String,
    pub class: String,
    pub endpoint: String,
    pub workspace: String,
    pub oidc: Oidc,
    /// The RFC 7638 thumbprint of the adapter key Govern registered (`gateway.adapter_kid`). The adapter's
    /// desk-pass sign-in is written only when this installation's key has this thumbprint (`adapter::signin`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_kid: Option<String>,
}

impl Registration {
    /// From Govern's answer as it was given: the whole answer (`{"gateway": {...}, "created": ...}`) or its
    /// `gateway` object. Fields this release does not use are left out.
    pub fn from_answer(v: &Value) -> Result<Self> {
        let g = if v.get("gateway").is_some() { &v["gateway"] } else { v };
        let text = |k: &str| g[k].as_str().map(str::to_string);
        let o = &g["oidc"];
        let otext = |k: &str| o[k].as_str().map(str::to_string);
        let bad = || refused("the gateway registration is not Govern's answer to a registration");
        Ok(Registration {
            gateway_id: text("gateway_id").ok_or_else(bad)?,
            tenant_id: text("tenant_id").ok_or_else(bad)?,
            installation_id: text("installation_id").ok_or_else(bad)?,
            class: text("class").ok_or_else(bad)?,
            endpoint: text("endpoint").ok_or_else(bad)?,
            workspace: text("workspace").ok_or_else(bad)?,
            oidc: Oidc {
                issuer: otext("issuer").ok_or_else(bad)?,
                audience: otext("audience").ok_or_else(bad)?,
                roles_claim: otext("roles_claim").ok_or_else(bad)?,
                scopes_claim: otext("scopes_claim").ok_or_else(bad)?,
                admin_role: otext("admin_role").ok_or_else(bad)?,
                user_role: otext("user_role").ok_or_else(bad)?,
                jwks_ttl_secs: o["jwks_ttl_secs"].as_u64().ok_or_else(bad)?,
            },
            adapter_kid: text("adapter_kid"),
        })
    }

    /// The gateway's sign-in settings, when this registration is this installation's in every respect.
    pub fn verify(&self, binding: &Binding) -> Result<Gateway> {
        let want = identity::gateway_oidc(&binding.env, &binding.org, &self.gateway_id)?;
        let checks = [
            (self.installation_id == binding.installation_id, "it is another installation's"),
            (self.tenant_id == binding.org, "it is another organization's"),
            (self.class == "development", "it is not a development gateway"),
            (self.oidc.issuer == want.issuer, "it names another issuer than EKKA's for this organization"),
            (self.oidc.audience == self.gateway_id, "its audience is not its gateway id"),
            (self.oidc.roles_claim == want.roles_claim, "its roles claim does not follow its class"),
            (self.oidc.scopes_claim == want.scopes_claim, "its scope claim is not Govern's"),
            (
                self.oidc.admin_role == want.admin_role && self.oidc.user_role == want.user_role,
                "its roles are not Govern's",
            ),
            (self.oidc.jwks_ttl_secs == want.jwks_ttl_secs, "its key-set lifetime is not Govern's"),
            (self.endpoint == format!("https://{GATEWAY_DNS}:{GATEWAY_PORT}"), "it names another gateway address"),
            (self.workspace == WORKSPACE, "it names another workspace"),
        ];
        match checks.iter().find(|(ok, _)| !ok) {
            Some((_, why)) => Err(refused(format!("the gateway registration is not used: {why}"))),
            None => Ok(want),
        }
    }
}

/// The record root keeps beside `gateway.toml`: which registration it was made from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema: String,
    pub gateway_id: String,
    pub installation_id: String,
    pub issuer: String,
}

pub const RECORD: &str = "gateway-registration.json";

impl Record {
    pub fn of(r: &Registration) -> Self {
        Record {
            schema: "ekka-desk-host.gateway-registration/v1".into(),
            gateway_id: r.gateway_id.clone(),
            installation_id: r.installation_id.clone(),
            issuer: r.oidc.issuer.clone(),
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut v = serde_json::to_vec_pretty(self).unwrap_or_default();
        v.push(b'\n');
        v
    }
}

/// A digest of everything the gateway trusts: its configuration, its registration record, its certificate, the CA
/// and its token key, read through the folders root has already checked (`d`, `tls`, `jwt`): never through a link,
/// only regular files, at most 1 MiB each. When the root step changes it, a running gateway must restart (or stop).
pub fn trust_digest_at(
    d: Option<&std::os::fd::OwnedFd>,
    tls: Option<&std::os::fd::OwnedFd>,
    jwt: Option<&std::os::fd::OwnedFd>,
) -> Result<String> {
    use crate::platform::macos::{CA_CERT, JWT_PUBLIC, LEAF_CERT};
    let files = [(d, "gateway.toml"), (d, RECORD), (tls, LEAF_CERT), (tls, CA_CERT), (jwt, JWT_PUBLIC)];
    let mut all = Vec::new();
    for (dir, name) in files {
        all.extend_from_slice(name.as_bytes());
        all.push(0);
        if let Some(dir) = dir {
            all.extend(crate::fsx::read_at(dir, name, 1024 * 1024)?.unwrap_or_default());
        }
        all.push(0);
    }
    Ok(crate::util::sha256_hex(&all))
}

/// Root writes this, root-owned, into the developer's `D/run` in the same step that changes what the gateway
/// trusts. The developer's side removes it only once launchd confirms the gateway restarted (or stopped); every
/// later install finishes a pending one first.
pub const RESTART_PENDING: &str = "gateway-restart.pending";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartPending {
    pub schema: String,
    /// `restart` when the gateway has a configuration to run, `stop` when it has none.
    pub action: String,
    pub trust_digest: String,
}

impl RestartPending {
    pub fn new(stop: bool, trust_digest: String) -> Self {
        RestartPending {
            schema: "ekka-desk-host.gateway-restart/v1".into(),
            action: if stop { "stop" } else { "restart" }.into(),
            trust_digest,
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut v = serde_json::to_vec_pretty(self).unwrap_or_default();
        v.push(b'\n');
        v
    }

    pub fn stops(&self) -> bool {
        self.action == "stop"
    }
}

/// What finishing a restart needs from launchd, so it can be checked without one.
pub trait Launchd {
    fn state(&self) -> crate::platform::macos::ServiceState;
    fn restart(&self) -> Result<()>;
    fn start(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
}

/// Restarts (or stops) the gateway as the pending marker asks, and says whether launchd confirmed it: a restart is
/// confirmed only by the service running under a new process id, a stop only by the service being gone.
pub fn finish(launchd: &dyn Launchd, pending: &RestartPending, wait: std::time::Duration) -> Result<bool> {
    let before = launchd.state();
    if pending.stops() {
        if before.loaded {
            launchd.stop()?;
        }
    } else if before.loaded {
        launchd.restart()?;
    } else {
        launchd.start()?;
    }
    let deadline = std::time::Instant::now() + wait;
    loop {
        let now = launchd.state();
        let done = if pending.stops() {
            !now.loaded
        } else {
            now.running && now.pid.is_some() && (now.pid != before.pid || !before.running)
        };
        if done {
            return Ok(true);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// What the developer's side does with the gateway's LaunchAgent after the root step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayAction {
    /// Not registered, or not this installation's: stop it and take its LaunchAgent away.
    Unload,
    /// Registered and not running, or its LaunchAgent changed: (re)load it.
    Start,
    /// Running, and what it trusts changed: restart it so it reads the new configuration.
    Reload,
    Keep,
}

pub fn gateway_action(registered: bool, loaded: bool, plist_changed: bool, trust_changed: bool) -> GatewayAction {
    match (registered, loaded) {
        (false, true) => GatewayAction::Unload,
        (false, false) => GatewayAction::Keep,
        (true, false) => GatewayAction::Start,
        (true, true) if plist_changed => GatewayAction::Start,
        (true, true) if trust_changed => GatewayAction::Reload,
        (true, true) => GatewayAction::Keep,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::binding::Want;

    pub(crate) const GATEWAY: &str = "urn:ekka:desk-gateway:development:0b6f4a52-1c3d-4e5f-8a9b-0c1d2e3f4a5b";

    /// Govern's answer for `b`'s installation, as its contract writes it.
    pub(crate) fn answer(b: &Binding) -> Value {
        let issuer = identity::issuer(&b.env, &b.org).unwrap();
        serde_json::json!({"gateway": {
            "gateway_id": GATEWAY, "tenant_id": b.org, "node_id": "2f8e7d6c-5b4a-4392-8170-6e5d4c3b2a19",
            "installation_id": b.installation_id, "class": "development", "endpoint": "https://host.docker.internal:8080",
            "workspace": "desks", "adapter_kid": "x", "registered_at": "2026-11-28T00:00:00Z",
            "oidc": {"issuer": issuer, "audience": GATEWAY, "jwks_uri": "x", "token_endpoint": "x",
                     "roles_claim": "ekka_roles.development", "scopes_claim": "scope", "admin_role": "openshell-admin",
                     "user_role": "openshell-user", "jwks_ttl_secs": 300}}, "created": true})
    }

    fn binding() -> Binding {
        Want {
            org: "7c1e2a3b-4d5e-4f60-8a71-92b3c4d5e6f7".into(),
            uid: 501,
            env: "prod".into(),
            profile: crate::binding::PROFILE.into(),
            runtime: crate::binding::RUNTIME.into(),
        }
        .new_binding()
        .unwrap()
    }

    #[test]
    fn this_installations_registration_is_used_and_any_other_is_not() {
        let b = binding();
        let good = Registration::from_answer(&answer(&b)).unwrap();
        assert_eq!(good.verify(&b).unwrap().audience, GATEWAY);
        assert_eq!(good.adapter_kid.as_deref(), Some("x"), "the registered adapter key's thumbprint is kept");
        for (path, value) in [
            ("/gateway/installation_id", serde_json::json!("5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d")),
            ("/gateway/tenant_id", serde_json::json!("0d0e0f10-1112-4314-8516-171819202122")),
            ("/gateway/oidc/issuer", serde_json::json!("https://attacker.example.com/oidc/orgs/x")),
            ("/gateway/oidc/audience", serde_json::json!("urn:ekka:desk-gateway:development:other")),
            ("/gateway/oidc/roles_claim", serde_json::json!("ekka_roles.production")),
            ("/gateway/endpoint", serde_json::json!("https://0.0.0.0:8080")),
        ] {
            let mut a = answer(&b);
            *a.pointer_mut(path).unwrap() = value;
            let r = Registration::from_answer(&a).unwrap();
            assert!(r.verify(&b).is_err(), "{path} must not be used");
        }
    }

    use crate::platform::macos::ServiceState;
    use std::cell::RefCell;

    /// A launchd in memory: what `state` answers after each call.
    struct FakeLaunchd {
        states: RefCell<Vec<ServiceState>>,
        calls: RefCell<Vec<&'static str>>,
    }
    impl FakeLaunchd {
        fn new(states: Vec<ServiceState>) -> Self {
            FakeLaunchd { states: RefCell::new(states), calls: RefCell::new(Vec::new()) }
        }
    }
    impl Launchd for FakeLaunchd {
        fn state(&self) -> ServiceState {
            let mut s = self.states.borrow_mut();
            if s.len() > 1 {
                s.remove(0)
            } else {
                s[0].clone()
            }
        }
        fn restart(&self) -> Result<()> {
            self.calls.borrow_mut().push("restart");
            Ok(())
        }
        fn start(&self) -> Result<()> {
            self.calls.borrow_mut().push("start");
            Ok(())
        }
        fn stop(&self) -> Result<()> {
            self.calls.borrow_mut().push("stop");
            Ok(())
        }
    }

    fn st(loaded: bool, running: bool, pid: Option<u32>) -> ServiceState {
        ServiceState { loaded, running, pid }
    }

    #[test]
    fn a_pending_restart_is_done_only_when_launchd_shows_a_new_process() {
        let wait = std::time::Duration::from_millis(600);
        let restart = RestartPending::new(false, "d".into());
        let l = FakeLaunchd::new(vec![st(true, true, Some(10)), st(true, true, Some(11))]);
        assert!(finish(&l, &restart, wait).unwrap());
        assert_eq!(*l.calls.borrow(), ["restart"]);
        let same = FakeLaunchd::new(vec![st(true, true, Some(10))]);
        assert!(!finish(&same, &restart, wait).unwrap(), "the same process is not a restart: the marker stays");
        let stopped = FakeLaunchd::new(vec![st(false, false, None), st(true, true, Some(12))]);
        assert!(finish(&stopped, &restart, wait).unwrap());
        assert_eq!(*stopped.calls.borrow(), ["start"]);
        let stop = RestartPending::new(true, "d".into());
        let l = FakeLaunchd::new(vec![st(true, true, Some(10)), st(false, false, None)]);
        assert!(finish(&l, &stop, wait).unwrap());
        assert_eq!(*l.calls.borrow(), ["stop"]);
        let stuck = FakeLaunchd::new(vec![st(true, true, Some(10))]);
        assert!(!finish(&stuck, &stop, wait).unwrap(), "still loaded: the marker stays");
    }

    #[test]
    fn an_unregistered_gateway_is_unloaded_and_a_trust_change_restarts_a_running_one() {
        assert_eq!(gateway_action(false, true, false, false), GatewayAction::Unload);
        assert_eq!(gateway_action(true, true, false, true), GatewayAction::Reload);
        assert_eq!(gateway_action(true, true, true, true), GatewayAction::Start);
        assert_eq!(gateway_action(true, false, false, false), GatewayAction::Start);
        assert_eq!(gateway_action(true, true, false, false), GatewayAction::Keep);
    }
}

//! The gateway's one-time setup: the `desks` workspace, the Enclave and the adapter as ordinary members, and
//! the provider profiles the ceiling record names, each read back before the host is called ready.
//!
//! It runs on a one-time EKKA setup pass held in memory only: never written, never printed, never passed to
//! another program. Two small traits keep the two outside parties apart: `SetupPass` obtains the pass (Govern's
//! exchange of a setup authorization, `gateway_setup`), and `GatewayAdmin` makes the gateway calls with it. Every step reads first and changes only what is
//! missing, so running it twice, or again after an interruption, ends in the same state. A member already present
//! with another role, or a profile that differs at the gateway, is reported and left alone, never changed
//! silently. When the pass has expired the run stops and asks for a fresh authorization.

use std::fmt;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use serde_json::Value;

use crate::kit;
use crate::platform::macos::WORKSPACE;

/// A one-time setup pass. Its token is never shown: `Debug` prints only its lifetime.
pub struct Pass {
    token: String,
    expires_at: SystemTime,
}

impl Pass {
    pub fn new(token: String, expires_at: SystemTime) -> Self {
        Pass { token, expires_at }
    }
    /// The bearer, for the gateway call that needs it and nothing else (`gateway_grpc`).
    pub fn bearer(&self) -> &str {
        &self.token
    }
    pub fn expired(&self, now: SystemTime) -> bool {
        // A margin, so a call never starts on a pass about to end.
        now + Duration::from_secs(10) >= self.expires_at
    }
}

impl fmt::Debug for Pass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pass")
            .field("token", &"<held in memory, never shown>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Drop for Pass {
    fn drop(&mut self) {
        // Overwrite the bearer before its memory is released.
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}

/// Why a setup step stopped. Never carries the pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// Waiting on something outside this host (no issuer yet, no subject yet); nothing was changed.
    Pending(String),
    /// The pass ended part way: what is done stays done; a fresh authorization resumes.
    Expired,
    /// The gateway refused or failed; the reason names the step.
    Failed(String),
    /// Govern refused the authorization (used, closed, expired, or its opener no longer may); nothing was changed
    /// at the gateway. A fresh authorization is needed.
    Refused(String),
}

/// Obtains the one-time setup pass. Govern's exchange implements this when it is available.
pub trait SetupPass {
    fn obtain(&mut self, gateway_audience: &str) -> Result<Pass, Stop>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub subject: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderProfile {
    pub name: String,
    pub definition: Value,
}

/// The gateway calls setup makes, each with the pass.
pub trait GatewayAdmin {
    /// Whether this client can reach the gateway's admin API at all; asked before any authorization is redeemed,
    /// so one is never spent on a client that cannot use the pass.
    fn available(&self) -> Result<(), String> {
        Ok(())
    }
    fn workspace_exists(&mut self, pass: &Pass, name: &str) -> Result<bool, Stop>;
    fn create_workspace(&mut self, pass: &Pass, name: &str) -> Result<(), Stop>;
    fn members(&mut self, pass: &Pass, workspace: &str) -> Result<Vec<Member>, Stop>;
    fn add_member(&mut self, pass: &Pass, workspace: &str, member: &Member) -> Result<(), Stop>;
    fn profiles(&mut self, pass: &Pass) -> Result<Vec<ProviderProfile>, Stop>;
    fn import_profiles(&mut self, pass: &Pass, profiles: &[ProviderProfile]) -> Result<(), Stop>;
    /// Whether a profile the gateway holds (`have`, as `profiles` gave it) is this release's (`want`).
    fn same_definition(&self, have: &Value, want: &Value) -> bool {
        have == want
    }
}

/// The state setup brings the gateway to.
#[derive(Debug, Clone, PartialEq)]
pub struct Desired {
    pub workspace: String,
    pub members: Vec<Member>,
    pub profiles: Vec<ProviderProfile>,
}

impl Desired {
    /// The `desks` workspace, the two subjects as ordinary members, and every profile the ceiling names.
    pub fn for_subjects(enclave: &str, adapter: &str) -> Result<Self, Stop> {
        let mut profiles = Vec::new();
        for p in &kit::PROVIDERS {
            let definition: Value = serde_json::from_str(p.json)
                .map_err(|e| Stop::Failed(format!("the {} profile is not JSON: {e}", p.name)))?;
            profiles.push(ProviderProfile { name: p.name.to_string(), definition });
        }
        Ok(Desired {
            workspace: WORKSPACE.into(),
            members: vec![
                Member { subject: enclave.into(), role: "user".into() },
                Member { subject: adapter.into(), role: "user".into() },
            ],
            profiles,
        })
    }
}

impl Desired {
    /// A digest of everything setup brings the gateway to: the record of a finished setup names it, so `status`
    /// can tell a setup made for another Enclave, installation or set of profiles from this one.
    pub fn digest(&self) -> String {
        let doc = serde_json::json!({
            "workspace": self.workspace,
            "members": self.members.iter().map(|m| serde_json::json!({"subject": m.subject, "role": m.role}))
                .collect::<Vec<_>>(),
            "profiles": self.profiles.iter().map(|p| serde_json::json!({"name": p.name, "definition": p.definition}))
                .collect::<Vec<_>>(),
        });
        crate::util::sha256_hex(doc.to_string().as_bytes())
    }
}

/// What setup did and found, secret-free.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub changed: Vec<String>,
    pub ready: bool,
    pub problems: Vec<String>,
}

fn live<'a>(pass: &'a Pass, now: &dyn Fn() -> SystemTime) -> Result<&'a Pass, Stop> {
    if pass.expired(now()) {
        Err(Stop::Expired)
    } else {
        Ok(pass)
    }
}

/// Brings the gateway to `want` with one setup pass, then reads everything back.
pub fn reconcile(
    passes: &mut dyn SetupPass,
    gateway: &mut dyn GatewayAdmin,
    audience: &str,
    want: &Desired,
    now: &dyn Fn() -> SystemTime,
) -> Result<Report, Stop> {
    let pass = passes.obtain(audience)?;
    let mut r = Report::default();

    if !gateway.workspace_exists(live(&pass, now)?, &want.workspace)? {
        gateway.create_workspace(live(&pass, now)?, &want.workspace)?;
        r.changed.push(format!("created the {} workspace", want.workspace));
    }
    for m in &want.members {
        let have = gateway.members(live(&pass, now)?, &want.workspace)?;
        match have.iter().find(|h| h.subject == m.subject) {
            Some(h) if h.role == m.role => {}
            Some(h) => r.problems.push(format!(
                "{} is a {} member of {}, not {}; it was left as it is",
                m.subject, h.role, want.workspace, m.role
            )),
            None => {
                gateway.add_member(live(&pass, now)?, &want.workspace, m)?;
                r.changed.push(format!("added {} to {}", m.subject, want.workspace));
            }
        }
    }
    let have = gateway.profiles(live(&pass, now)?)?;
    let missing: Vec<ProviderProfile> =
        want.profiles.iter().filter(|p| !have.iter().any(|h| h.name == p.name)).cloned().collect();
    for p in &want.profiles {
        if let Some(h) = have.iter().find(|h| h.name == p.name) {
            if !gateway.same_definition(&h.definition, &p.definition) {
                r.problems.push(format!(
                    "the {} profile at the gateway differs from this release's; it was left as it is",
                    p.name
                ));
            }
        }
    }
    if !missing.is_empty() {
        gateway.import_profiles(live(&pass, now)?, &missing)?;
        r.changed.extend(missing.iter().map(|p| format!("imported the {} profile", p.name)));
    }

    // Read everything back: ready only when the gateway holds exactly what was wanted.
    if !gateway.workspace_exists(live(&pass, now)?, &want.workspace)? {
        r.problems.push(format!("the {} workspace is not there on reading back", want.workspace));
    }
    let members = gateway.members(live(&pass, now)?, &want.workspace)?;
    for m in &want.members {
        if !members.contains(m) {
            r.problems.push(format!("{} is not a {} member on reading back", m.subject, m.role));
        }
    }
    let profiles = gateway.profiles(live(&pass, now)?)?;
    for p in &want.profiles {
        if !profiles.iter().any(|h| h.name == p.name && gateway.same_definition(&h.definition, &p.definition)) {
            r.problems.push(format!("the {} profile does not read back exactly", p.name));
        }
    }
    r.problems.dedup();
    r.ready = r.problems.is_empty();
    Ok(r)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    /// A gateway in memory, with failures to inject.
    #[derive(Default)]
    pub(crate) struct FakeGateway {
        pub workspaces: Vec<String>,
        pub members: Vec<Member>,
        pub profiles: Vec<ProviderProfile>,
        pub fail_add_after: Option<usize>,
        pub adds: usize,
        pub bearers_seen: Vec<String>,
    }

    impl FakeGateway {
        fn saw(&mut self, p: &Pass) {
            self.bearers_seen.push(p.bearer().to_string());
        }
    }

    impl GatewayAdmin for FakeGateway {
        fn workspace_exists(&mut self, p: &Pass, name: &str) -> Result<bool, Stop> {
            self.saw(p);
            Ok(self.workspaces.iter().any(|w| w == name))
        }
        fn create_workspace(&mut self, p: &Pass, name: &str) -> Result<(), Stop> {
            self.saw(p);
            self.workspaces.push(name.into());
            Ok(())
        }
        fn members(&mut self, p: &Pass, _ws: &str) -> Result<Vec<Member>, Stop> {
            self.saw(p);
            Ok(self.members.clone())
        }
        fn add_member(&mut self, p: &Pass, _ws: &str, m: &Member) -> Result<(), Stop> {
            self.saw(p);
            if self.fail_add_after == Some(self.adds) {
                return Err(Stop::Failed("the gateway went away".into()));
            }
            self.adds += 1;
            self.members.push(m.clone());
            Ok(())
        }
        fn profiles(&mut self, p: &Pass) -> Result<Vec<ProviderProfile>, Stop> {
            self.saw(p);
            Ok(self.profiles.clone())
        }
        fn import_profiles(&mut self, p: &Pass, profiles: &[ProviderProfile]) -> Result<(), Stop> {
            self.saw(p);
            self.profiles.extend(profiles.iter().cloned());
            Ok(())
        }
    }

    /// Issues passes that live `ttl`, counting how many it issued.
    pub(crate) struct FakeGovern {
        pub issued: Rc<Cell<usize>>,
        pub ttl: Duration,
    }

    impl SetupPass for FakeGovern {
        fn obtain(&mut self, audience: &str) -> Result<Pass, Stop> {
            assert!(audience.starts_with("urn:ekka:desk-gateway:"));
            self.issued.set(self.issued.get() + 1);
            Ok(Pass::new(format!("setup-pass-{}", self.issued.get()), SystemTime::now() + self.ttl))
        }
    }

    fn want() -> Desired {
        Desired::for_subjects(
            "enclave/2f8e7d6c-5b4a-4392-8170-6e5d4c3b2a19",
            "adapter/5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d",
        )
        .unwrap()
    }

    const AUD: &str = "urn:ekka:desk-gateway:development:0b6f4a52-1c3d-4e5f-8a9b-0c1d2e3f4a5b";

    fn govern() -> FakeGovern {
        FakeGovern { issued: Rc::new(Cell::new(0)), ttl: Duration::from_secs(120) }
    }

    #[test]
    fn setup_twice_reads_back_one_workspace_both_subjects_and_the_exact_profiles() {
        let mut gw = FakeGateway::default();
        let r1 = reconcile(&mut govern(), &mut gw, AUD, &want(), &SystemTime::now).unwrap();
        assert!(r1.ready, "{:?}", r1.problems);
        assert_eq!(r1.changed.len(), 1 + 2 + 4);
        let r2 = reconcile(&mut govern(), &mut gw, AUD, &want(), &SystemTime::now).unwrap();
        assert!(r2.ready && r2.changed.is_empty(), "{r2:?}");
        assert_eq!(gw.workspaces, ["desks"]);
        assert_eq!(gw.members, want().members);
        assert_eq!(gw.profiles, want().profiles);
    }

    #[test]
    fn an_interruption_after_the_first_member_resumes_to_the_same_state() {
        let mut gw = FakeGateway { fail_add_after: Some(1), ..Default::default() };
        let stop = reconcile(&mut govern(), &mut gw, AUD, &want(), &SystemTime::now).unwrap_err();
        assert!(matches!(stop, Stop::Failed(_)));
        assert_eq!(gw.members.len(), 1, "the first member was added before the interruption");
        gw.fail_add_after = None;
        let r = reconcile(&mut govern(), &mut gw, AUD, &want(), &SystemTime::now).unwrap();
        assert!(r.ready, "{:?}", r.problems);
        assert_eq!(
            r.changed,
            [format!("added {} to desks", want().members[1].subject)]
                .iter()
                .cloned()
                .chain(want().profiles.iter().map(|p| format!("imported the {} profile", p.name)))
                .collect::<Vec<_>>()
        );
        assert_eq!(gw.workspaces.len(), 1, "never a second workspace");
        assert_eq!(gw.members, want().members, "never a duplicate member");
    }

    #[test]
    fn an_expired_pass_stops_and_needs_fresh_authorization() {
        let mut gw = FakeGateway::default();
        let mut g = FakeGovern { issued: Rc::new(Cell::new(0)), ttl: Duration::from_secs(120) };
        let later = || SystemTime::now() + Duration::from_secs(600);
        assert_eq!(reconcile(&mut g, &mut gw, AUD, &want(), &later).unwrap_err(), Stop::Expired);
        assert!(gw.workspaces.is_empty(), "nothing is done on an expired pass");
        let r = reconcile(&mut g, &mut gw, AUD, &want(), &SystemTime::now).unwrap();
        assert!(r.ready);
        assert_eq!(g.issued.get(), 2, "resuming took a fresh pass");
    }

    #[test]
    fn a_wrong_role_or_a_changed_profile_is_reported_never_changed() {
        let w = want();
        let mut changed = w.profiles[0].clone();
        changed.definition["description"] = "edited at the gateway".into();
        let mut gw = FakeGateway {
            workspaces: vec!["desks".into()],
            members: vec![Member { subject: w.members[0].subject.clone(), role: "admin".into() }],
            profiles: vec![changed.clone()],
            ..Default::default()
        };
        let r = reconcile(&mut govern(), &mut gw, AUD, &w, &SystemTime::now).unwrap();
        assert!(!r.ready);
        assert!(r.problems.iter().any(|p| p.contains("is a admin member")), "{:?}", r.problems);
        assert!(r.problems.iter().any(|p| p.contains("differs")), "{:?}", r.problems);
        assert_eq!(gw.members[0].role, "admin", "left as it is");
        assert_eq!(gw.profiles[0], changed, "left as it is");
    }

    #[test]
    fn the_digest_names_the_subjects_and_the_profiles() {
        let a = want();
        assert_eq!(a.digest(), want().digest());
        let other = Desired::for_subjects(
            "enclave/0d0e0f10-1112-4314-8516-171819202122",
            "adapter/5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d",
        )
        .unwrap();
        assert_ne!(a.digest(), other.digest(), "another Enclave");
        let mut edited = want();
        edited.profiles[0].definition["description"] = "edited".into();
        assert_ne!(a.digest(), edited.digest(), "another profile");
    }

    #[test]
    fn the_pass_is_held_in_memory_and_never_shown() {
        let p = Pass::new("secret-bearer".into(), SystemTime::now() + Duration::from_secs(60));
        assert!(!format!("{p:?}").contains("secret-bearer"));
        let report = reconcile(&mut govern(), &mut FakeGateway::default(), AUD, &want(), &SystemTime::now).unwrap();
        assert!(!serde_json::to_string(&report).unwrap().contains("setup-pass"));
    }
}

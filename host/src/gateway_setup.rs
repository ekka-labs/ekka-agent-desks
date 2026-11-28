//! `ekka-desk-host gateway-setup [--json]`: the gateway's one-time setup, run as the developer, with a one-time
//! setup authorization from Govern on stdin.
//!
//! An owner or admin opens a setup transaction at Govern (`POST /govern/desk-gateways/{id}/setup`; `ekka desk
//! setup --local` does it) and gets an authorization `ekds_...`, said once. It reaches this command on stdin only:
//! never as an argument or an environment variable, where other processes on the Mac could read it, and never typed
//! at a terminal. This command checks it can use a pass before it spends the authorization: the gateway's admin
//! client (`gateway_grpc`, OpenShell's gRPC) is made and the gateway answers with verified TLS. It then redeems the authorization once at
//! `{issuer}/token` (RFC 8693, Govern's desk-pass contract section 3d) for a setup pass of at most 120 s, held in
//! memory, and brings the gateway to the desired state (`bootstrap::reconcile`): the `desks` workspace, the Enclave
//! and the adapter as ordinary members, the provider profiles, each read back. A second run changes nothing; a run
//! the pass outlived stops and resumes with a fresh authorization. Neither the authorization nor the pass is ever
//! printed, logged, written or passed to another program.
//!
//! The issuer is never taken from a file the developer can change: it is Govern's for the environment and the
//! organization, compiled in (`identity::issuer`), so the authorization is only ever sent to Govern. The gateway
//! is the one root recorded for this installation (`D/gateway-registration.json`).
//!
//! What the last setup read back is kept in `D/gateway/setup.json` (no secret in it), so `status` can say whether
//! the gateway was set up for this installation, this Enclave and this release's profiles, and when.

use std::ffi::OsString;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::adapter;
use crate::apply::Owners;
use crate::binding::Binding;
use crate::bootstrap::{self, Desired, GatewayAdmin, Member, Pass, ProviderProfile, SetupPass, Stop};
use crate::error::{failed, refused, usage, Result};
use crate::fsx::{self, Owner, Walk};
use crate::net::FormPost;
use crate::platform::macos::{self, Layout};
use crate::registration;

pub const RECORD: &str = "setup.json";
pub const RECORD_SCHEMA: &str = "ekka-desk-host.gateway-setup/v1";
pub const RESULT_SCHEMA: &str = "ekka-desk-host.gateway-setup-result/v1";
pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const SETUP_TOKEN_TYPE: &str = "urn:ekka:params:oauth:token-type:desk-setup-authorization";
const PREFIX: &str = "ekds_";
/// A setup pass lives at most this long (Govern's contract); a longer `expires_in` is not believed.
const PASS_SECONDS: u64 = 120;
const MAX_STDIN: u64 = 512;

/// The one-time setup authorization, zeroed when dropped. `Debug` never shows it.
pub struct Authorization(Zeroizing<String>);

impl Authorization {
    fn secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Authorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Authorization(<held in memory, never shown>)")
    }
}

fn is_authorization(s: &str) -> bool {
    s.strip_prefix(PREFIX).is_some_and(|rest| {
        rest.len() == 43 && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// `gateway-setup` takes only `--json`. An argument is never echoed back: it may be an authorization.
pub fn parse_args(args: &[String]) -> Result<bool> {
    match args {
        [] => Ok(false),
        [j] if j == "--json" => Ok(true),
        _ if args.iter().any(|a| a.contains(PREFIX)) => Err(refused(
            "the setup authorization is read from stdin only, never from the command line, where every process on \
             this Mac can read it; nothing was sent. Open a new one, it may have been seen",
        )),
        _ => Err(usage("gateway-setup takes only --json; the setup authorization comes on stdin")),
    }
}

/// The authorization, from stdin only: refused when an environment variable holds one (named, never shown), when
/// stdin is a terminal (it would be on the screen), and unless stdin holds exactly one, with at most a newline.
pub fn read_authorization(
    env: impl Iterator<Item = (OsString, OsString)>,
    stdin: &mut dyn Read,
    terminal: bool,
) -> Result<Authorization> {
    let found: Vec<String> = env
        .filter(|(_, v)| v.as_encoded_bytes().windows(PREFIX.len()).any(|w| w == PREFIX.as_bytes()))
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    if !found.is_empty() {
        return Err(refused(format!(
            "the environment variable {} holds what looks like a setup authorization; it is read from stdin only. \
             Unset it, and open a new authorization: it may have been seen. Nothing was sent",
            found.join(", ")
        )));
    }
    if terminal {
        return Err(refused(
            "the setup authorization comes on stdin from a pipe, never typed at a terminal: ekka desk setup --local \
             passes it",
        ));
    }
    let mut raw = Zeroizing::new(Vec::new());
    stdin.take(MAX_STDIN + 1).read_to_end(&mut raw).map_err(|e| failed(format!("reading stdin: {e}")))?;
    let mut text = Zeroizing::new(String::from_utf8(raw.to_vec()).unwrap_or_default());
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    if raw.len() as u64 > MAX_STDIN || !is_authorization(&text) {
        return Err(refused(
            "stdin does not hold one setup authorization (ekds_ and 43 base64url characters); nothing was sent",
        ));
    }
    Ok(Authorization(text))
}

/// What setup needs to know about this installation, read and checked before the authorization is touched.
#[derive(Debug, Clone)]
pub struct Context {
    pub binding: Binding,
    pub gateway_id: String,
    /// Govern's token endpoint for this organization: computed, never read from a file.
    pub token_endpoint: String,
    pub want: Desired,
}

fn d_dir(l: &Layout, owners: Owners) -> Result<OwnedFd> {
    match fsx::walk_trusted(&l.d(), &l.top, owners.root.uid, None)? {
        Walk::Found(fd, _) => Ok(fd),
        Walk::Missing(_) => Err(refused("this Mac's desk host is not installed for you: run ekka-desk-host install")),
    }
}

impl Context {
    pub fn load(l: &Layout, owners: Owners) -> Result<Self> {
        let binding = Binding::read(&l.binding())?
            .ok_or_else(|| refused("this Mac's desk host is not installed: run ekka-desk-host install"))?;
        if binding.uid != owners.dev.uid {
            return Err(refused(format!("this Mac's desk host is installed for uid {}, not you", binding.uid)));
        }
        let d = d_dir(l, owners)?;
        let not_registered = || {
            refused(
                "the gateway is not registered for this installation: register it (ekka desk setup --local), put \
                 Govern's answer in the identity profile, and run install again",
            )
        };
        let record = fsx::read_at(&d, registration::RECORD, 64 * 1024)?.ok_or_else(not_registered)?;
        let record: registration::Record = serde_json::from_slice(&record).map_err(|_| not_registered())?;
        let issuer = crate::identity::issuer(&binding.env, &binding.org)?;
        if record.installation_id != binding.installation_id || record.issuer != issuer {
            return Err(not_registered());
        }
        crate::identity::gateway_class(&record.gateway_id)?;
        let enclave = adapter::read_enclave_values(&adapter::enclave_env_path(l, &binding.env))?.ok_or_else(|| {
            refused("the Enclave is not enrolled yet: enroll it (ekka desk setup --local), then run install again")
        })?;
        if enclave.tenant_id != binding.org {
            return Err(refused("the Enclave is enrolled in another organization than this host is bound to"));
        }
        let want = Desired::for_subjects(
            &format!("enclave/{}", enclave.node_id),
            &format!("adapter/{}", binding.installation_id),
        )
        .map_err(|s| failed(format!("{s:?}")))?;
        Ok(Context { token_endpoint: format!("{issuer}/token"), gateway_id: record.gateway_id, binding, want })
    }
}

/// Govern's side of setup: redeems the one authorization, once, for one pass.
pub struct GovernExchange<'a> {
    post: &'a mut dyn FormPost,
    token_endpoint: String,
    authorization: Option<Authorization>,
    now: &'a dyn Fn() -> SystemTime,
    /// The authorization was sent: whatever the answer, it may have been redeemed.
    pub sent: bool,
    /// A pass was issued, so the gateway may have been called.
    pub issued: bool,
}

impl<'a> GovernExchange<'a> {
    pub fn new(
        post: &'a mut dyn FormPost,
        token_endpoint: String,
        authorization: Authorization,
        now: &'a dyn Fn() -> SystemTime,
    ) -> Self {
        GovernExchange { post, token_endpoint, authorization: Some(authorization), now, sent: false, issued: false }
    }
}

/// A code from a refusal's body, only when it is one (capitals and underscores): nothing else of it is repeated.
fn code_of(body: &[u8]) -> String {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    v["code"]
        .as_str()
        .filter(|c| (1..=64).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'))
        .unwrap_or("no code")
        .to_string()
}

#[derive(Deserialize)]
struct TokenAnswer {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

/// Govern's answer as a pass, or why there is none. The pass ends `expires_in` (at most 120 s) after `sent_at`.
pub fn pass_from(status: u16, body: &[u8], sent_at: SystemTime) -> std::result::Result<Pass, Stop> {
    // Only a refusal's body is read for its code: an answer holding a pass is read once, into the pass.
    let code = if status == 200 { String::new() } else { code_of(body) };
    let fresh = "open a new setup authorization (ekka desk setup --local)";
    match status {
        200 => {}
        400 => {
            return Err(Stop::Failed(format!(
                "Govern refused the exchange as malformed (400, {code}); this is a fault in ekka-desk-host"
            )))
        }
        401 => {
            return Err(Stop::Refused(format!(
                "Govern refused the setup authorization (401, {code}): it was used, closed or expired. Nothing was \
                 changed; {fresh}"
            )))
        }
        403 => {
            return Err(Stop::Refused(format!(
                "Govern refused (403, {code}): no desk access for this gateway. Whoever opened the setup must still \
                 hold org.manage, and the gateway must be registered and not retired. Nothing was changed"
            )))
        }
        409 => {
            return Err(Stop::Failed(format!(
                "Govern refused (409, {code}): the Enclave's class is no longer the gateway's; retire the \
                 registration and register again. Nothing was changed"
            )))
        }
        503 => {
            return Err(Stop::Pending(format!(
                "Govern cannot issue a pass now (503, {code}); nothing was changed. Try again later and {fresh}"
            )))
        }
        s => return Err(Stop::Failed(format!("Govern answered {s} ({code}); nothing was changed"))),
    }
    let bad = || Stop::Failed("Govern's answer is not a token answer; nothing was changed".into());
    let a: TokenAnswer = serde_json::from_slice(body).map_err(|_| bad())?;
    let well_formed = !a.access_token.is_empty()
        && a.access_token.len() <= 16 * 1024
        && a.access_token.bytes().all(|b| (b'!'..=b'~').contains(&b))
        && a.token_type.eq_ignore_ascii_case("Bearer")
        && a.expires_in >= 1;
    if !well_formed {
        return Err(bad());
    }
    let lifetime = a.expires_in.min(PASS_SECONDS);
    Ok(Pass::new(a.access_token, sent_at + Duration::from_secs(lifetime)))
}

impl SetupPass for GovernExchange<'_> {
    fn obtain(&mut self, gateway_audience: &str) -> std::result::Result<Pass, Stop> {
        // One authorization, one pass: asking again means a fresh authorization.
        let auth = self.authorization.take().ok_or(Stop::Expired)?;
        let form = [
            ("grant_type", GRANT_TYPE),
            ("audience", gateway_audience),
            ("subject_token", auth.secret()),
            ("subject_token_type", SETUP_TOKEN_TYPE),
        ];
        let sent_at = (self.now)();
        self.sent = true;
        let answer = self.post.post_form(&self.token_endpoint, &form);
        drop(auth);
        let (status, body) = answer.map_err(|e| {
            Stop::Pending(format!(
                "Govern's token endpoint did not answer ({}); nothing was changed at the gateway. The authorization \
                 may have been used: open a new one (ekka desk setup --local)",
                e.reason
            ))
        })?;
        let pass = pass_from(status, &body, sent_at)?;
        self.issued = true;
        Ok(pass)
    }
}

/// A gateway admin client that could not be made (its CA unreadable, say): no call is ever made, and `available`
/// says why before any authorization is redeemed.
pub struct Unavailable(pub String);

impl GatewayAdmin for Unavailable {
    fn available(&self) -> std::result::Result<(), String> {
        Err(self.0.clone())
    }
    fn workspace_exists(&mut self, _: &Pass, _: &str) -> std::result::Result<bool, Stop> {
        Err(Stop::Pending(self.0.clone()))
    }
    fn create_workspace(&mut self, _: &Pass, _: &str) -> std::result::Result<(), Stop> {
        Err(Stop::Pending(self.0.clone()))
    }
    fn members(&mut self, _: &Pass, _: &str) -> std::result::Result<Vec<Member>, Stop> {
        Err(Stop::Pending(self.0.clone()))
    }
    fn add_member(&mut self, _: &Pass, _: &str, _: &Member) -> std::result::Result<(), Stop> {
        Err(Stop::Pending(self.0.clone()))
    }
    fn profiles(&mut self, _: &Pass) -> std::result::Result<Vec<ProviderProfile>, Stop> {
        Err(Stop::Pending(self.0.clone()))
    }
    fn import_profiles(&mut self, _: &Pass, _: &[ProviderProfile]) -> std::result::Result<(), Stop> {
        Err(Stop::Pending(self.0.clone()))
    }
}

/// What the last setup that reached the gateway read back. No secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupRecord {
    pub schema: String,
    pub gateway_id: String,
    pub installation_id: String,
    /// `Desired::digest` of what this setup brought the gateway to.
    pub desired_sha256: String,
    /// The gateway read back exactly what was wanted.
    pub ready: bool,
    pub changed: Vec<String>,
    pub problems: Vec<String>,
    pub finished_at_unix: u64,
}

/// How a setup ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// The gateway read back exactly what was wanted.
    Done,
    /// The gateway holds something other than what was wanted (named in `problems`), left as it is.
    NotReady,
    /// Nothing more can be done now (named in `reason`); run again, with a fresh authorization if it was used.
    Waiting,
    /// Govern or this host refused (named in `reason`); nothing was changed at the gateway.
    Refused,
    /// A step failed part way (named in `reason`); what was done stays done.
    Failed,
}

/// What `gateway-setup` prints: no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupResult {
    pub schema: &'static str,
    pub ok: bool,
    pub state: State,
    pub gateway_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub changed: Vec<String>,
    pub problems: Vec<String>,
    /// The authorization was sent to Govern: a run after this one needs a fresh authorization.
    pub authorization_used: bool,
}

impl SetupResult {
    pub fn exit_code(&self) -> u8 {
        match self.state {
            State::Done => 0,
            State::Failed | State::NotReady => 1,
            State::Refused => 3,
            State::Waiting => 4,
        }
    }
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The gateway's one-time setup with one authorization. `gateway_answers` probes the gateway before the
/// authorization is spent; `keep` saves the record of a setup that reached the gateway.
pub fn setup(
    ctx: &Context,
    authorization: Authorization,
    govern: &mut dyn FormPost,
    gateway: &mut dyn GatewayAdmin,
    gateway_answers: &mut dyn FnMut() -> std::result::Result<(), String>,
    keep: &mut dyn FnMut(&SetupRecord) -> Result<()>,
    now: &dyn Fn() -> SystemTime,
) -> SetupResult {
    let mut out = SetupResult {
        schema: RESULT_SCHEMA,
        ok: false,
        state: State::Waiting,
        gateway_id: ctx.gateway_id.clone(),
        reason: None,
        changed: Vec::new(),
        problems: Vec::new(),
        authorization_used: false,
    };
    let unused = "the authorization was not used";
    if let Err(why) = gateway.available() {
        out.reason = Some(format!("{why}; {unused}"));
        return out;
    }
    if let Err(why) = gateway_answers() {
        out.reason = Some(format!(
            "the gateway does not answer with verified TLS on 127.0.0.1:8080 ({why}); start it with \
             ekka-desk-host install; {unused}"
        ));
        return out;
    }
    let mut exchange = GovernExchange::new(govern, ctx.token_endpoint.clone(), authorization, now);
    let result = bootstrap::reconcile(&mut exchange, gateway, &ctx.gateway_id, &ctx.want, now);
    out.authorization_used = exchange.sent;
    let reached = exchange.issued;
    let (ready, changed, problems) = match result {
        Ok(r) => {
            out.state = if r.ready { State::Done } else { State::NotReady };
            (r.ready, r.changed, r.problems)
        }
        Err(stop) => {
            let (state, why) = match stop {
                Stop::Expired => (
                    State::Waiting,
                    "the setup pass ended part way; what was done stays done. Run setup again with a fresh \
                     authorization (ekka desk setup --local) to finish it"
                        .to_string(),
                ),
                Stop::Pending(why) => (State::Waiting, why),
                Stop::Refused(why) => (State::Refused, why),
                Stop::Failed(why) => (State::Failed, format!("the gateway's setup: {why}")),
            };
            out.state = state;
            out.reason = Some(why.clone());
            (false, Vec::new(), vec![why])
        }
    };
    out.changed = changed.clone();
    out.problems = problems.clone();
    out.ok = out.state == State::Done;
    if reached {
        let record = SetupRecord {
            schema: RECORD_SCHEMA.into(),
            gateway_id: ctx.gateway_id.clone(),
            installation_id: ctx.binding.installation_id.clone(),
            desired_sha256: ctx.want.digest(),
            ready,
            changed,
            problems,
            finished_at_unix: secs(now()),
        };
        if let Err(e) = keep(&record) {
            out.ok = false;
            out.state = State::Failed;
            out.reason = Some(format!("the setup ran, and its record was not saved: {}", e.reason));
        }
    }
    out
}

/// `D/gateway`, the developer's own folder.
fn gateway_dir(l: &Layout, owners: Owners) -> Result<OwnedFd> {
    fsx::private_dir(&d_dir(l, owners)?, "gateway", &l.gateway_dir(), owners.dev.uid)?
        .ok_or_else(|| refused(format!("{} is not there: run ekka-desk-host install", l.gateway_dir().display())))
}

/// Saves the record in `D/gateway/setup.json`, the developer's, 0600, atomically.
pub fn keep_record(l: &Layout, owners: Owners, r: &SetupRecord) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(r).map_err(|e| failed(e.to_string()))?;
    bytes.push(b'\n');
    fsx::write_at(&gateway_dir(l, owners)?, RECORD, &bytes, 0o600, owners.dev).map(|_| ())
}

/// Whether the gateway was set up for this installation, its Enclave and this release's profiles, by what the last
/// setup read back; why not when it was not.
pub fn check(l: &Layout, owners: Owners) -> std::result::Result<(), String> {
    let ctx = Context::load(l, owners).map_err(|e| format!("not done: {}", e.reason))?;
    let again = "run it again (ekka desk setup --local)";
    let bytes = fsx::read_at(&gateway_dir(l, owners).map_err(|e| e.reason)?, RECORD, 256 * 1024)
        .map_err(|e| e.reason)?
        .ok_or("not done: the gateway's one-time setup has not run; ekka desk setup --local runs it")?;
    let r: SetupRecord =
        serde_json::from_slice(&bytes).map_err(|_| format!("{} is not a setup record; {again}", RECORD))?;
    if r.schema != RECORD_SCHEMA || r.gateway_id != ctx.gateway_id || r.installation_id != ctx.binding.installation_id {
        return Err(format!("the recorded setup was for another gateway or installation; {again}"));
    }
    if r.desired_sha256 != ctx.want.digest() {
        return Err(format!("the recorded setup is for another Enclave or other provider profiles; {again}"));
    }
    if !r.ready {
        return Err(format!("the last setup did not finish: {}; {again}", r.problems.join("; ")));
    }
    Ok(())
}

/// The command: as the developer, never root.
pub fn command(args: &[String]) -> Result<ExitCode> {
    let json = parse_args(args)?;
    let uid = rustix::process::getuid().as_raw();
    if uid == 0 || rustix::process::geteuid().as_raw() == 0 {
        return Err(usage("run gateway-setup as yourself, not as root"));
    }
    let user = macos::user_by_uid(uid)?;
    let l = Layout::system(uid, user.home.clone());
    let owners = Owners { root: Owner { uid: 0, gid: 0 }, dev: Owner { uid, gid: user.gid } };
    let terminal = std::io::IsTerminal::is_terminal(&std::io::stdin());
    // Everything about this installation is checked before the authorization is read.
    let ctx = Context::load(&l, owners)?;
    let authorization = read_authorization(std::env::vars_os(), &mut std::io::stdin().lock(), terminal)?;
    let ca = std::fs::read(l.tls_dir().join(macos::CA_CERT)).unwrap_or_default();
    let addr = std::net::SocketAddr::from((crate::tls::GATEWAY_IP, macos::GATEWAY_PORT));
    // The gateway's admin API over TLS that trusts this installation's CA only, by the gateway's own name.
    let mut gateway: Box<dyn GatewayAdmin> =
        match crate::gateway_grpc::GatewayGrpc::new(&format!("https://{addr}"), &ca, crate::tls::GATEWAY_DNS) {
            Ok(g) => Box::new(g),
            Err(e) => Box::new(Unavailable(format!("the gateway's admin client: {}", e.reason))),
        };
    let result = setup(
        &ctx,
        authorization,
        &mut crate::net::Https,
        gateway.as_mut(),
        &mut || crate::tls::probe(addr, crate::tls::GATEWAY_DNS, &ca).map_err(|e| e.reason),
        &mut |r| keep_record(&l, owners, r),
        &SystemTime::now,
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&result).map_err(|e| failed(e.to_string()))?);
    } else {
        for c in &result.changed {
            println!("   changed: {c}");
        }
        for p in &result.problems {
            println!("   problem: {p}");
        }
        if let Some(r) = &result.reason {
            println!("   {r}");
        }
        println!("{}", if result.ok { "the gateway is set up" } else { "the gateway is not set up" });
    }
    Ok(ExitCode::from(result.exit_code()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::tests::{owners, registered, rig, Rig};
    use crate::bootstrap::tests::FakeGateway;
    use std::cell::RefCell;

    const AUTH: &str = "ekds_Q2xhdWRlIGRvZXMgbm90IGtub3cgdGhpcyBvbmUuIEd";

    fn auth() -> Authorization {
        read_authorization(std::iter::empty(), &mut format!("{AUTH}\n").as_bytes(), false).unwrap()
    }

    /// Govern's token endpoint: the answers it gives, in order, and every form it was sent.
    struct FakeGovern {
        answers: Vec<(u16, String)>,
        forms: Vec<Vec<(String, String)>>,
        urls: Vec<String>,
    }

    impl FakeGovern {
        fn passes(n: usize) -> Self {
            let ok = r#"{"access_token":"the-setup-pass-NEVER-SHOWN","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":120,"scope":"workspace:read workspace:write provider:read provider:write"}"#;
            FakeGovern { answers: vec![(200, ok.into()); n], forms: Vec::new(), urls: Vec::new() }
        }
        fn answering(status: u16, body: &str) -> Self {
            FakeGovern { answers: vec![(status, body.into())], forms: Vec::new(), urls: Vec::new() }
        }
    }

    impl FormPost for FakeGovern {
        fn post_form(&mut self, url: &str, form: &[(&str, &str)]) -> Result<(u16, Zeroizing<Vec<u8>>)> {
            self.urls.push(url.into());
            self.forms.push(form.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect());
            let (s, b) = self.answers.remove(0);
            Ok((s, Zeroizing::new(b.into_bytes())))
        }
    }

    const NODE: &str = "2f8e7d6c-5b4a-4392-8170-6e5d4c3b2a19";

    /// An installed, registered tree with an enrolled Enclave, as setup finds one.
    fn installed() -> (Rig, Context) {
        let mut r = rig();
        let b = registered(&mut r, owners());
        std::fs::write(
            adapter::enclave_env_path(&r.layout, &b.env),
            format!(
                "EKKA_TENANT_ID={}\nEKKA_NODE_ID={NODE}\nEKKA_GOVERN_URL=https://govern.ekka.ai\n",
                crate::apply::tests::ORG
            ),
        )
        .unwrap();
        let ctx = Context::load(&r.layout, owners()).unwrap();
        (r, ctx)
    }

    fn run(r: &Rig, ctx: &Context, govern: &mut FakeGovern, gw: &mut dyn GatewayAdmin) -> SetupResult {
        setup(
            ctx,
            auth(),
            govern,
            gw,
            &mut || Ok(()),
            &mut |rec| keep_record(&r.layout, owners(), rec),
            &SystemTime::now,
        )
    }

    #[test]
    fn the_authorization_comes_on_stdin_only_and_is_never_echoed() {
        let e = parse_args(&[AUTH.to_string()]).unwrap_err();
        assert_eq!(e.kind, crate::error::Kind::Refused);
        assert!(e.reason.contains("stdin only") && !e.reason.contains(AUTH), "{e}");
        let e = parse_args(&["--authorization".into(), AUTH.into()]).unwrap_err();
        assert!(!e.reason.contains(AUTH));
        assert_eq!(parse_args(&["--yes".into()]).unwrap_err().kind, crate::error::Kind::Usage);
        assert!(parse_args(&["--json".into()]).unwrap());
        let env =
            vec![(OsString::from("PATH"), OsString::from("/usr/bin")), (OsString::from("EKDS"), OsString::from(AUTH))];
        let e = read_authorization(env.into_iter(), &mut format!("{AUTH}\n").as_bytes(), false).unwrap_err();
        assert!(e.reason.contains("EKDS") && !e.reason.contains(AUTH), "{e}");
        let e = read_authorization(std::iter::empty(), &mut format!("{AUTH}\n").as_bytes(), true).unwrap_err();
        assert!(e.reason.contains("never typed at a terminal"), "{e}");
        for bad in [
            String::new(),
            format!("{AUTH}\n{AUTH}\n"),
            format!(" {AUTH}"),
            AUTH.replace("ekds_", "ekda_"),
            format!("{AUTH}x"),
            "x".repeat(600),
        ] {
            let e = read_authorization(std::iter::empty(), &mut bad.as_bytes(), false).unwrap_err();
            assert!(e.reason.contains("does not hold one setup authorization") && !e.reason.contains(AUTH), "{e}");
        }
        let a = read_authorization(std::iter::empty(), &mut format!("{AUTH}\r\n").as_bytes(), false).unwrap();
        assert_eq!(a.secret(), AUTH);
        assert!(!format!("{a:?}").contains(AUTH));
    }

    #[test]
    fn the_exchange_sends_exactly_the_four_fields_to_governs_issuer_for_this_gateway() {
        let (r, ctx) = installed();
        let mut govern = FakeGovern::passes(1);
        let res = run(&r, &ctx, &mut govern, &mut FakeGateway::default());
        assert!(res.ok, "{res:?}");
        assert_eq!(
            govern.urls,
            [format!("https://govern.ekka.ai/oidc/orgs/{}/token", crate::apply::tests::ORG)],
            "Govern's issuer for the organization, compiled in"
        );
        let form: Vec<(&str, &str)> = govern.forms[0].iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        assert_eq!(
            form,
            [
                ("grant_type", GRANT_TYPE),
                ("audience", crate::registration::tests::GATEWAY),
                ("subject_token", AUTH),
                ("subject_token_type", SETUP_TOKEN_TYPE),
            ]
        );
    }

    #[test]
    fn setup_twice_with_fresh_authorizations_changes_nothing_the_second_time() {
        let (r, ctx) = installed();
        let mut gw = FakeGateway::default();
        let first = run(&r, &ctx, &mut FakeGovern::passes(1), &mut gw);
        assert_eq!((first.state, first.changed.len()), (State::Done, 1 + 2 + 4), "{first:?}");
        assert_eq!(check(&r.layout, owners()), Ok(()));
        let second = run(&r, &ctx, &mut FakeGovern::passes(1), &mut gw);
        assert_eq!(second.state, State::Done);
        assert!(second.changed.is_empty(), "a second run is a no-op: {:?}", second.changed);
        assert_eq!(gw.workspaces, ["desks"]);
        assert_eq!(gw.members, ctx.want.members);
        assert!(gw.bearers_seen.iter().all(|b| b == "the-setup-pass-NEVER-SHOWN"));
        assert_eq!(check(&r.layout, owners()), Ok(()));
    }

    #[test]
    fn an_interrupted_setup_is_recorded_unfinished_and_resumes_with_a_fresh_authorization() {
        let (r, ctx) = installed();
        let mut gw = FakeGateway { fail_add_after: Some(1), ..Default::default() };
        let cut = run(&r, &ctx, &mut FakeGovern::passes(1), &mut gw);
        assert_eq!((cut.state, cut.authorization_used, cut.exit_code()), (State::Failed, true, 1), "{cut:?}");
        let why = check(&r.layout, owners()).unwrap_err();
        assert!(why.starts_with("the last setup did not finish"), "{why}");
        gw.fail_add_after = None;
        let resumed = run(&r, &ctx, &mut FakeGovern::passes(1), &mut gw);
        assert_eq!(resumed.state, State::Done, "{resumed:?}");
        assert_eq!(gw.members, ctx.want.members, "never a duplicate member");
        assert_eq!(check(&r.layout, owners()), Ok(()));
    }

    #[test]
    fn a_pass_that_ends_part_way_stops_for_a_fresh_authorization() {
        let (r, ctx) = installed();
        let mut gw = FakeGateway::default();
        // Govern says 120 s, the clock runs ten minutes on between calls.
        let start = SystemTime::now();
        let calls = RefCell::new(0u64);
        let clock = || {
            *calls.borrow_mut() += 1;
            start + Duration::from_secs(if *calls.borrow() <= 2 { 0 } else { 600 })
        };
        let res = setup(
            &ctx,
            auth(),
            &mut FakeGovern::passes(1),
            &mut gw,
            &mut || Ok(()),
            &mut |rec| keep_record(&r.layout, owners(), rec),
            &clock,
        );
        assert_eq!((res.state, res.exit_code()), (State::Waiting, 4), "{res:?}");
        assert!(res.reason.as_deref().unwrap().contains("fresh authorization"));
        assert!(check(&r.layout, owners()).unwrap_err().starts_with("the last setup did not finish"));
        // One authorization is one pass: a second obtain on it is refused before anything is sent.
        let mut govern = FakeGovern::passes(2);
        let now = SystemTime::now;
        let mut x = GovernExchange::new(&mut govern, ctx.token_endpoint.clone(), auth(), &now);
        x.obtain(&ctx.gateway_id).unwrap();
        assert_eq!(x.obtain(&ctx.gateway_id).unwrap_err(), Stop::Expired);
        assert_eq!(govern.forms.len(), 1);
    }

    #[test]
    fn governs_refusals_change_nothing_and_say_what_to_do() {
        let (r, ctx) = installed();
        for (status, body, state, says) in [
            (
                401,
                r#"{"error":"invalid_grant","code":"DESK_PASS_PROOF_INVALID"}"#,
                State::Refused,
                "used, closed or expired",
            ),
            (403, r#"{"error":"access_denied","code":"DESK_ACCESS_DENIED"}"#, State::Refused, "org.manage"),
            (
                503,
                r#"{"error":"temporarily_unavailable","code":"DESK_PASS_KEY_NOT_CONFIGURED"}"#,
                State::Waiting,
                "503",
            ),
            (400, r#"{"error":"invalid_request","code":"<script>"}"#, State::Failed, "no code"),
            (200, r#"{"access_token":"","token_type":"Bearer","expires_in":120}"#, State::Failed, "not a token answer"),
            (200, r#"{"access_token":"x","token_type":"DPoP","expires_in":120}"#, State::Failed, "not a token answer"),
            (200, r#"{"access_token":"x","token_type":"Bearer"}"#, State::Failed, "not a token answer"),
        ] {
            let mut gw = FakeGateway::default();
            let res = run(&r, &ctx, &mut FakeGovern::answering(status, body), &mut gw);
            assert_eq!(res.state, state, "{status}: {res:?}");
            assert!(res.reason.as_deref().unwrap().contains(says), "{status}: {res:?}");
            assert!(res.authorization_used, "it was sent");
            assert!(gw.bearers_seen.is_empty() && gw.workspaces.is_empty(), "{status}: no gateway call");
            assert!(check(&r.layout, owners()).unwrap_err().starts_with("not done"), "no record: nothing was set up");
        }
        // A pass longer than Govern's 120 s is not believed.
        let p =
            pass_from(200, br#"{"access_token":"t","token_type":"bearer","expires_in":3600}"#, SystemTime::UNIX_EPOCH)
                .unwrap();
        assert!(p.expired(SystemTime::UNIX_EPOCH + Duration::from_secs(111)));
        assert!(!p.expired(SystemTime::UNIX_EPOCH + Duration::from_secs(100)));
    }

    #[test]
    fn without_an_admin_client_or_a_gateway_the_authorization_is_never_spent() {
        let (r, ctx) = installed();
        let mut govern = FakeGovern::passes(1);
        let res = run(&r, &ctx, &mut govern, &mut Unavailable("no CA to trust".into()));
        assert_eq!((res.state, res.authorization_used, res.exit_code()), (State::Waiting, false, 4));
        assert!(
            res.reason.as_deref().unwrap().contains("no CA to trust")
                && res.reason.as_deref().unwrap().contains("not used")
        );
        let down = setup(
            &ctx,
            auth(),
            &mut govern,
            &mut FakeGateway::default(),
            &mut || Err("refused".into()),
            &mut |_| panic!("nothing to record"),
            &SystemTime::now,
        );
        assert_eq!((down.state, down.authorization_used), (State::Waiting, false));
        assert!(govern.forms.is_empty(), "Govern was never asked");
    }

    #[test]
    fn neither_the_authorization_nor_the_pass_is_ever_printed_or_written() {
        let (r, ctx) = installed();
        let mut gw = FakeGateway { fail_add_after: Some(0), ..Default::default() };
        let mut out = vec![serde_json::to_string(&run(&r, &ctx, &mut FakeGovern::passes(1), &mut gw)).unwrap()];
        gw.fail_add_after = None;
        out.push(serde_json::to_string(&run(&r, &ctx, &mut FakeGovern::passes(1), &mut gw)).unwrap());
        out.push(std::fs::read_to_string(r.layout.gateway_dir().join(RECORD)).unwrap());
        for text in out {
            assert!(!text.contains(AUTH) && !text.contains("NEVER-SHOWN"), "{text}");
        }
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(r.layout.gateway_dir().join(RECORD)).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
    }

    /// The whole command's path with its real parts: Govern's exchange (faked at its token endpoint), the gRPC client,
    /// and a fake OpenShell gateway over TLS from an installation CA.
    #[test]
    fn gateway_setup_completes_over_grpc_and_a_second_run_changes_nothing() {
        let (r, ctx) = installed();
        let served = crate::gateway_grpc::tests::serve();
        let mut govern = FakeGovern {
            answers: vec![
                (
                    200,
                    r#"{"access_token":"setup-pass-for-the-fake-gateway","token_type":"Bearer","expires_in":120}"#
                        .into()
                );
                2
            ],
            forms: Vec::new(),
            urls: Vec::new(),
        };
        for round in 0..2 {
            let mut gw =
                crate::gateway_grpc::GatewayGrpc::new(&served.uri, &served.ca_pem, crate::tls::GATEWAY_DNS).unwrap();
            let res = setup(
                &ctx,
                auth(),
                &mut govern,
                &mut gw,
                &mut || Ok(()),
                &mut |rec| keep_record(&r.layout, owners(), rec),
                &SystemTime::now,
            );
            assert_eq!((res.state, res.exit_code(), res.authorization_used), (State::Done, 0, true), "{res:?}");
            assert_eq!(res.changed.is_empty(), round == 1, "{round}: {:?}", res.changed);
            assert_eq!(check(&r.layout, owners()), Ok(()));
        }
        let st = served.fake.0.lock().unwrap();
        assert_eq!((st.workspaces.len(), st.members.len(), st.profiles.len()), (1, 2, 4));
    }

    #[test]
    fn setup_needs_this_installations_registration_and_its_enrolled_enclave() {
        let r = rig();
        crate::apply::root_apply(&r.plan, &r.layout, owners(), &r.pins, &r.roots, &mut crate::apply::Ctx::apply())
            .unwrap();
        let e = Context::load(&r.layout, owners()).unwrap_err();
        assert!(e.reason.contains("not registered"), "{e}");
        let (r, _) = installed();
        std::fs::remove_file(adapter::enclave_env_path(&r.layout, "prod")).unwrap();
        assert!(Context::load(&r.layout, owners()).unwrap_err().reason.contains("not enrolled"));
    }

    #[test]
    fn status_says_a_setup_for_another_enclave_is_not_this_ones() {
        let (r, ctx) = installed();
        run(&r, &ctx, &mut FakeGovern::passes(1), &mut FakeGateway::default());
        assert_eq!(check(&r.layout, owners()), Ok(()));
        std::fs::write(
            adapter::enclave_env_path(&r.layout, "prod"),
            format!(
                "EKKA_TENANT_ID={}\nEKKA_NODE_ID=0d0e0f10-1112-4314-8516-171819202122\nEKKA_GOVERN_URL=https://govern.ekka.ai\n",
                crate::apply::tests::ORG
            ),
        )
        .unwrap();
        assert!(check(&r.layout, owners()).unwrap_err().contains("another Enclave"));
    }
}

//! The gateway's admin API, as the one-time setup calls it: NVIDIA OpenShell v0.1.9's gRPC (`openshell`), over TLS
//! that trusts this installation's CA only and expects the gateway's name, with the setup pass as the bearer.
//!
//! Six calls, the ones the Linux kit's administrator makes with OpenShell's own command line: `GetWorkspace` and
//! `CreateWorkspace` (the `desks` workspace), `ListWorkspaceMembers` and `AddWorkspaceMember` (the Enclave and the
//! adapter as `user` members), and `ListProviderProfiles` and `ImportProviderProfiles` at platform scope (the
//! provider profiles, from their protobuf JSON). "Already exists" is success: a second run, or one racing another,
//! ends in the same state, and `bootstrap::reconcile` reads everything back.
//!
//! A profile is compared as protobuf JSON made the same way from both sides (the vendored descriptor, default
//! fields left out), with what the gateway sets itself taken away first: `resource_version`, `source`, `scope` and
//! each credential's `token_grant_owners`.

use std::time::Duration;

use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor};
use serde_json::Value;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use zeroize::Zeroizing;

use crate::bootstrap::{GatewayAdmin, Member, Pass, ProviderProfile, Stop};
use crate::error::{failed, Result};
use crate::openshell::{api, datamodel, FILE_DESCRIPTOR_SET};

type Client = api::open_shell_client::OpenShellClient<Channel>;

const PAGE: i32 = 1000;
const MAX_PAGES: usize = 100;

/// The gateway's admin client. It makes no connection until its first call.
pub struct GatewayGrpc {
    rt: tokio::runtime::Runtime,
    client: Client,
    profile: MessageDescriptor,
}

/// The protobuf JSON of a provider profile, as both sides are compared: what the gateway sets itself removed.
pub fn canonical(mut m: DynamicMessage) -> std::result::Result<Value, String> {
    for f in ["resource_version", "source", "scope"] {
        m.clear_field_by_name(f);
    }
    if let Some(prost_reflect::Value::List(creds)) = m.get_field_by_name_mut("credentials") {
        for c in creds.iter_mut() {
            if let prost_reflect::Value::Message(c) = c {
                c.clear_field_by_name("token_grant_owners");
            }
        }
    }
    serde_json::to_value(&m).map_err(|e| format!("a provider profile is not protobuf JSON: {e}"))
}

/// A provider profile's protobuf JSON (as `providers/*.json` holds it) as the message, refusing any field the
/// vendored definition does not have.
pub fn profile_message(profile: &MessageDescriptor, json: &Value) -> std::result::Result<DynamicMessage, String> {
    DynamicMessage::deserialize(profile.clone(), json.clone())
        .map_err(|e| format!("a provider profile is not OpenShell v0.1.9's ProviderProfile: {e}"))
}

pub fn profile_descriptor() -> Result<MessageDescriptor> {
    DescriptorPool::decode(FILE_DESCRIPTOR_SET)
        .map_err(|e| failed(format!("the OpenShell descriptor: {e}")))?
        .get_message_by_name("openshell.v1.ProviderProfile")
        .ok_or_else(|| failed("the OpenShell descriptor has no ProviderProfile"))
}

fn named(workspace: &str) -> Option<datamodel::WorkspaceSelector> {
    Some(datamodel::WorkspaceSelector {
        selection: Some(datamodel::workspace_selector::Selection::Workspace(workspace.to_string())),
    })
}

/// The call with the setup pass as its bearer. The header is marked sensitive, and the text it is made from zeroed.
fn with_pass<T>(message: T, pass: &Pass) -> std::result::Result<tonic::Request<T>, Stop> {
    let mut r = tonic::Request::new(message);
    let text = Zeroizing::new(format!("Bearer {}", pass.bearer()));
    let mut v: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
        text.parse().map_err(|_| Stop::Failed("the setup pass is not a header value".into()))?;
    v.set_sensitive(true);
    r.metadata_mut().insert("authorization", v);
    Ok(r)
}

/// A refusal as a stop that names the call and its gRPC status code, in this tool's own words. The gateway's message
/// is never repeated: it reaches the output and `D/gateway/setup.json`, and it is the gateway's text, not ours.
fn refused_by(rpc: &str, what: &str, s: &tonic::Status) -> Stop {
    Stop::Failed(format!("{what}: the gateway refused {rpc} ({:?}); its log says why", s.code()))
}

fn role_name(r: i32) -> &'static str {
    match api::WorkspaceRole::try_from(r) {
        Ok(api::WorkspaceRole::User) => "user",
        Ok(api::WorkspaceRole::Admin) => "admin",
        _ => "unspecified",
    }
}

impl GatewayGrpc {
    /// A client for the gateway at `uri` (`https://127.0.0.1:8080`), trusting only `ca_pem` and expecting `name`.
    pub fn new(uri: &str, ca_pem: &[u8], name: &str) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| failed(format!("starting the gateway client: {e}")))?;
        let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca_pem)).domain_name(name);
        let endpoint = Endpoint::from_shared(uri.to_string())
            .map_err(|e| failed(format!("the gateway's address: {e}")))?
            .tls_config(tls)
            .map_err(|e| failed(format!("the gateway's TLS: {e}")))?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30));
        let channel = {
            let _in_runtime = rt.enter();
            endpoint.connect_lazy()
        };
        Ok(GatewayGrpc { rt, client: Client::new(channel), profile: profile_descriptor()? })
    }
}

impl GatewayAdmin for GatewayGrpc {
    fn workspace_exists(&mut self, pass: &Pass, name: &str) -> std::result::Result<bool, Stop> {
        let req = with_pass(api::GetWorkspaceRequest { name: name.into() }, pass)?;
        match self.rt.block_on(self.client.get_workspace(req)) {
            Ok(_) => Ok(true),
            Err(s) if s.code() == tonic::Code::NotFound => Ok(false),
            Err(s) => Err(refused_by("GetWorkspace", "reading the workspace", &s)),
        }
    }

    fn create_workspace(&mut self, pass: &Pass, name: &str) -> std::result::Result<(), Stop> {
        let req = with_pass(api::CreateWorkspaceRequest { name: name.into(), ..Default::default() }, pass)?;
        match self.rt.block_on(self.client.create_workspace(req)) {
            Ok(_) => Ok(()),
            Err(s) if s.code() == tonic::Code::AlreadyExists => Ok(()),
            Err(s) => Err(refused_by("CreateWorkspace", "making the workspace", &s)),
        }
    }

    fn members(&mut self, pass: &Pass, workspace: &str) -> std::result::Result<Vec<Member>, Stop> {
        let mut out = Vec::new();
        let mut token = String::new();
        for _ in 0..MAX_PAGES {
            let req = with_pass(
                api::ListWorkspaceMembersRequest {
                    workspace_scope: named(workspace),
                    page_size: PAGE,
                    page_token: token.clone(),
                },
                pass,
            )?;
            let page = self
                .rt
                .block_on(self.client.list_workspace_members(req))
                .map_err(|s| refused_by("ListWorkspaceMembers", "listing the workspace's members", &s))?
                .into_inner();
            out.extend(
                page.members
                    .iter()
                    .map(|m| Member { subject: m.principal_subject.clone(), role: role_name(m.role).into() }),
            );
            if page.next_page_token.is_empty() {
                return Ok(out);
            }
            token = page.next_page_token;
        }
        Err(Stop::Failed("the workspace's member list did not end".into()))
    }

    fn add_member(&mut self, pass: &Pass, workspace: &str, m: &Member) -> std::result::Result<(), Stop> {
        let role = match m.role.as_str() {
            "user" => api::WorkspaceRole::User,
            "admin" => api::WorkspaceRole::Admin,
            other => return Err(Stop::Failed(format!("{other} is not a workspace role"))),
        };
        let req = with_pass(
            api::AddWorkspaceMemberRequest {
                workspace_scope: named(workspace),
                principal_subject: m.subject.clone(),
                role: role as i32,
                ..Default::default()
            },
            pass,
        )?;
        match self.rt.block_on(self.client.add_workspace_member(req)) {
            Ok(_) => Ok(()),
            Err(s) if s.code() == tonic::Code::AlreadyExists => Ok(()),
            Err(s) => Err(refused_by("AddWorkspaceMember", &format!("adding {} to {workspace}", m.subject), &s)),
        }
    }

    fn profiles(&mut self, pass: &Pass) -> std::result::Result<Vec<ProviderProfile>, Stop> {
        let mut out = Vec::new();
        let mut token = String::new();
        for _ in 0..MAX_PAGES {
            // No workspace scope: the platform's profiles, as the Linux kit imports them (`--global`).
            let req = with_pass(
                api::ListProviderProfilesRequest { workspace_scope: None, page_size: PAGE, page_token: token },
                pass,
            )?;
            let page = self
                .rt
                .block_on(self.client.list_provider_profiles(req))
                .map_err(|s| refused_by("ListProviderProfiles", "listing the provider profiles", &s))?
                .into_inner();
            for p in &page.profiles {
                let m = DynamicMessage::decode(self.profile.clone(), p.encode_to_vec().as_slice())
                    .map_err(|e| Stop::Failed(format!("the gateway's {} profile: {e}", p.id)))?;
                let definition = canonical(m).map_err(Stop::Failed)?;
                out.push(ProviderProfile { name: p.id.clone(), definition });
            }
            if page.next_page_token.is_empty() {
                return Ok(out);
            }
            token = page.next_page_token;
        }
        Err(Stop::Failed("the gateway's profile list did not end".into()))
    }

    fn import_profiles(&mut self, pass: &Pass, profiles: &[ProviderProfile]) -> std::result::Result<(), Stop> {
        let mut items = Vec::new();
        for p in profiles {
            let m = profile_message(&self.profile, &p.definition).map_err(Stop::Failed)?;
            let profile: api::ProviderProfile =
                m.transcode_to().map_err(|e| Stop::Failed(format!("the {} profile: {e}", p.name)))?;
            items.push(api::ProviderProfileImportItem { profile: Some(profile), source: format!("{}.json", p.name) });
        }
        let req = with_pass(
            api::ImportProviderProfilesRequest { workspace_scope: None, profiles: items, ..Default::default() },
            pass,
        )?;
        let answer = self
            .rt
            .block_on(self.client.import_provider_profiles(req))
            .map_err(|s| refused_by("ImportProviderProfiles", "importing the provider profiles", &s))?
            .into_inner();
        if !answer.imported {
            return Err(Stop::Failed(format!(
                "importing the provider profiles: the gateway refused ImportProviderProfiles with {} diagnostic(s); \
                 its log says why",
                answer.diagnostics.len()
            )));
        }
        Ok(())
    }

    fn same_definition(&self, have: &Value, want: &Value) -> bool {
        // `have` is canonical already (`profiles`); `want` is the release's JSON, made canonical the same way.
        profile_message(&self.profile, want).and_then(canonical).is_ok_and(|w| &w == have)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bootstrap::{reconcile, Desired, SetupPass};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    const BEARER: &str = "setup-pass-for-the-fake-gateway";

    /// What the fake gateway holds, and every call it was asked, with the bearer each carried.
    #[derive(Default)]
    pub(crate) struct State {
        pub workspaces: Vec<String>,
        pub members: Vec<api::WorkspaceMember>,
        pub profiles: Vec<api::ProviderProfile>,
        pub calls: Vec<String>,
        pub bearers: Vec<String>,
        /// Refuse an import, as the gateway does with diagnostics.
        pub refuse_import: bool,
        /// Answer GetWorkspace with this error message (gateway text that must never be repeated).
        pub fail_get: Option<String>,
        pub next_version: u64,
    }

    #[derive(Clone, Default)]
    pub(crate) struct Fake(pub Arc<Mutex<State>>);

    impl Fake {
        fn auth<T>(&self, call: &str, r: &tonic::Request<T>) -> std::result::Result<(), tonic::Status> {
            let mut s = self.0.lock().unwrap();
            s.calls.push(call.into());
            let bearer = r.metadata().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            s.bearers.push(bearer.clone());
            if bearer != format!("Bearer {BEARER}") {
                return Err(tonic::Status::unauthenticated("no bearer"));
            }
            Ok(())
        }
    }

    fn scope_of(sel: &Option<datamodel::WorkspaceSelector>) -> Option<String> {
        match sel.as_ref().and_then(|s| s.selection.as_ref()) {
            Some(datamodel::workspace_selector::Selection::Workspace(w)) => Some(w.clone()),
            _ => None,
        }
    }

    #[tonic::async_trait]
    impl api::open_shell_server::OpenShell for Fake {
        async fn get_workspace(
            &self,
            r: tonic::Request<api::GetWorkspaceRequest>,
        ) -> std::result::Result<tonic::Response<api::GetWorkspaceResponse>, tonic::Status> {
            self.auth("GetWorkspace", &r)?;
            if let Some(text) = self.0.lock().unwrap().fail_get.clone() {
                return Err(tonic::Status::internal(text));
            }
            if self.0.lock().unwrap().workspaces.contains(&r.get_ref().name) {
                Ok(tonic::Response::new(api::GetWorkspaceResponse::default()))
            } else {
                Err(tonic::Status::not_found("workspace not found"))
            }
        }
        async fn create_workspace(
            &self,
            r: tonic::Request<api::CreateWorkspaceRequest>,
        ) -> std::result::Result<tonic::Response<api::CreateWorkspaceResponse>, tonic::Status> {
            self.auth("CreateWorkspace", &r)?;
            let mut s = self.0.lock().unwrap();
            if s.workspaces.contains(&r.get_ref().name) {
                return Err(tonic::Status::already_exists("workspace already exists"));
            }
            s.workspaces.push(r.get_ref().name.clone());
            Ok(tonic::Response::new(api::CreateWorkspaceResponse::default()))
        }
        async fn list_workspace_members(
            &self,
            r: tonic::Request<api::ListWorkspaceMembersRequest>,
        ) -> std::result::Result<tonic::Response<api::ListWorkspaceMembersResponse>, tonic::Status> {
            self.auth("ListWorkspaceMembers", &r)?;
            if scope_of(&r.get_ref().workspace_scope).as_deref() != Some("desks") {
                return Err(tonic::Status::invalid_argument("a named workspace is required"));
            }
            // One member per page, so paging is exercised.
            let s = self.0.lock().unwrap();
            let at: usize = r.get_ref().page_token.parse().unwrap_or(0);
            let members = s.members.iter().skip(at).take(1).cloned().collect();
            let next = if at + 1 < s.members.len() { (at + 1).to_string() } else { String::new() };
            Ok(tonic::Response::new(api::ListWorkspaceMembersResponse { members, next_page_token: next }))
        }
        async fn add_workspace_member(
            &self,
            r: tonic::Request<api::AddWorkspaceMemberRequest>,
        ) -> std::result::Result<tonic::Response<api::AddWorkspaceMemberResponse>, tonic::Status> {
            self.auth("AddWorkspaceMember", &r)?;
            let req = r.into_inner();
            if scope_of(&req.workspace_scope).as_deref() != Some("desks") {
                return Err(tonic::Status::invalid_argument("a named workspace is required"));
            }
            let mut s = self.0.lock().unwrap();
            if s.members.iter().any(|m| m.principal_subject == req.principal_subject) {
                return Err(tonic::Status::already_exists("member already exists in this workspace"));
            }
            s.members.push(api::WorkspaceMember {
                metadata: None,
                principal_subject: req.principal_subject,
                role: req.role,
            });
            Ok(tonic::Response::new(api::AddWorkspaceMemberResponse::default()))
        }
        async fn list_provider_profiles(
            &self,
            r: tonic::Request<api::ListProviderProfilesRequest>,
        ) -> std::result::Result<tonic::Response<api::ListProviderProfilesResponse>, tonic::Status> {
            self.auth("ListProviderProfiles", &r)?;
            if r.get_ref().workspace_scope.is_some() {
                return Err(tonic::Status::invalid_argument("the fake holds platform profiles only"));
            }
            let profiles = self.0.lock().unwrap().profiles.clone();
            Ok(tonic::Response::new(api::ListProviderProfilesResponse { profiles, next_page_token: String::new() }))
        }
        async fn import_provider_profiles(
            &self,
            r: tonic::Request<api::ImportProviderProfilesRequest>,
        ) -> std::result::Result<tonic::Response<api::ImportProviderProfilesResponse>, tonic::Status> {
            self.auth("ImportProviderProfiles", &r)?;
            let req = r.into_inner();
            let mut s = self.0.lock().unwrap();
            let clash = req.profiles.iter().find_map(|i| {
                let id = i.profile.as_ref().map(|p| p.id.clone()).unwrap_or_default();
                s.profiles.iter().any(|p| p.id == id).then_some(id)
            });
            if req.workspace_scope.is_some() || s.refuse_import || clash.is_some() {
                let d = api::ProviderProfileDiagnostic {
                    profile_id: clash.unwrap_or_else(|| "github".into()),
                    field: "id".into(),
                    message: "GATEWAY-TEXT custom provider profile already exists".into(),
                    severity: "error".into(),
                    ..Default::default()
                };
                return Ok(tonic::Response::new(api::ImportProviderProfilesResponse {
                    diagnostics: vec![d],
                    profiles: vec![],
                    imported: false,
                }));
            }
            for i in req.profiles {
                let mut p = i.profile.unwrap_or_default();
                // What the gateway sets itself on what it stores and answers.
                s.next_version += 1;
                p.resource_version = s.next_version;
                p.source = "user".into();
                p.scope = "platform".into();
                for c in &mut p.credentials {
                    c.token_grant_owners = vec!["api.example.com:443".into()];
                }
                s.profiles.push(p);
            }
            Ok(tonic::Response::new(api::ImportProviderProfilesResponse { imported: true, ..Default::default() }))
        }
    }

    /// The fake gateway on 127.0.0.1, over TLS with a certificate from a new installation CA, as the real one runs.
    pub(crate) struct Served {
        pub uri: String,
        pub ca_pem: Vec<u8>,
        pub fake: Fake,
        _stop: tokio::sync::oneshot::Sender<()>,
    }

    pub(crate) fn serve() -> Served {
        let (ca, _ca_key, ca_pem) = crate::tls::Ca::generate("5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d").unwrap();
        let (cert, key, _) = ca.leaf(&ca_pem).unwrap();
        let fake = Fake::default();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let served = fake.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                listener.set_nonblocking(true).unwrap();
                let incoming =
                    tonic::transport::server::TcpIncoming::from(tokio::net::TcpListener::from_std(listener).unwrap());
                tonic::transport::Server::builder()
                    .tls_config(
                        tonic::transport::ServerTlsConfig::new()
                            .identity(tonic::transport::Identity::from_pem(cert, key)),
                    )
                    .unwrap()
                    .add_service(api::open_shell_server::OpenShellServer::new(served))
                    .serve_with_incoming_shutdown(incoming, async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
            });
        });
        Served { uri: format!("https://127.0.0.1:{port}"), ca_pem: ca_pem.into_bytes(), fake, _stop: stop }
    }

    struct OnePass;
    impl SetupPass for OnePass {
        fn obtain(&mut self, _: &str) -> std::result::Result<Pass, Stop> {
            Ok(Pass::new(BEARER.into(), SystemTime::now() + Duration::from_secs(120)))
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

    fn client(s: &Served) -> GatewayGrpc {
        GatewayGrpc::new(&s.uri, &s.ca_pem, crate::tls::GATEWAY_DNS).unwrap()
    }

    #[test]
    fn every_profile_this_release_ships_is_openshell_v019s_provider_profile() {
        let d = profile_descriptor().unwrap();
        for p in &crate::kit::PROVIDERS {
            let json: Value = serde_json::from_str(p.json).unwrap();
            let m = profile_message(&d, &json).unwrap_or_else(|e| panic!("{}: {e}", p.name));
            let back = canonical(m).unwrap();
            assert_eq!(back["id"], p.name, "{}", p.name);
        }
        let mut extra: Value = serde_json::from_str(crate::kit::PROVIDERS[0].json).unwrap();
        extra["notAField"] = "x".into();
        assert!(profile_message(&d, &extra).is_err(), "a field v0.1.9 does not have is refused");
    }

    #[test]
    fn setup_over_grpc_makes_the_workspace_members_and_profiles_and_a_second_run_changes_nothing() {
        let s = serve();
        let mut gw = client(&s);
        let r1 = reconcile(&mut OnePass, &mut gw, AUD, &want(), &SystemTime::now).unwrap();
        assert!(r1.ready, "{:?}", r1.problems);
        assert_eq!(r1.changed.len(), 1 + 2 + 4, "{:?}", r1.changed);
        {
            let st = s.fake.0.lock().unwrap();
            assert_eq!(st.workspaces, ["desks"]);
            let subjects: Vec<(&str, i32)> =
                st.members.iter().map(|m| (m.principal_subject.as_str(), m.role)).collect();
            assert_eq!(
                subjects,
                [
                    ("enclave/2f8e7d6c-5b4a-4392-8170-6e5d4c3b2a19", api::WorkspaceRole::User as i32),
                    ("adapter/5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d", api::WorkspaceRole::User as i32),
                ]
            );
            assert_eq!(st.profiles.len(), 4);
            assert!(st.bearers.iter().all(|b| b == &format!("Bearer {BEARER}")), "every call carries the pass");
            for call in [
                "GetWorkspace",
                "CreateWorkspace",
                "ListWorkspaceMembers",
                "AddWorkspaceMember",
                "ListProviderProfiles",
                "ImportProviderProfiles",
            ] {
                assert!(st.calls.iter().any(|c| c == call), "{call}");
            }
        }
        // The gateway's own fields (resource_version, source, scope, token_grant_owners) do not make a difference.
        let r2 = reconcile(&mut OnePass, &mut client(&s), AUD, &want(), &SystemTime::now).unwrap();
        assert!(r2.ready && r2.changed.is_empty(), "{r2:?}");
        let st = s.fake.0.lock().unwrap();
        assert_eq!((st.workspaces.len(), st.members.len(), st.profiles.len()), (1, 2, 4), "nothing twice");
    }

    #[test]
    fn a_changed_profile_or_a_refused_import_is_reported_and_left_alone() {
        let s = serve();
        reconcile(&mut OnePass, &mut client(&s), AUD, &want(), &SystemTime::now).unwrap();
        s.fake.0.lock().unwrap().profiles[0].description = "edited at the gateway".into();
        let r = reconcile(&mut OnePass, &mut client(&s), AUD, &want(), &SystemTime::now).unwrap();
        assert!(!r.ready && r.problems.iter().any(|p| p.contains("differs")), "{r:?}");
        assert_eq!(s.fake.0.lock().unwrap().profiles[0].description, "edited at the gateway", "left as it is");
        let fresh = serve();
        fresh.fake.0.lock().unwrap().refuse_import = true;
        let e = reconcile(&mut OnePass, &mut client(&fresh), AUD, &want(), &SystemTime::now).unwrap_err();
        assert!(matches!(&e, Stop::Failed(why) if why.contains("ImportProviderProfiles")), "{e:?}");
    }

    /// What the gateway says in a refusal or a diagnostic is never repeated: it reaches the output and setup.json.
    /// Only the call's name and the gRPC status code are said, with this tool's own words.
    #[test]
    fn the_gateways_own_words_are_never_repeated() {
        let s = serve();
        s.fake.0.lock().unwrap().fail_get = Some("GATEWAY-TEXT something it chose to say".into());
        let e = reconcile(&mut OnePass, &mut client(&s), AUD, &want(), &SystemTime::now).unwrap_err();
        let Stop::Failed(why) = e else { panic!("{e:?}") };
        assert!(!why.contains("GATEWAY-TEXT"), "{why}");
        assert!(why.contains("GetWorkspace") && why.contains("Internal"), "{why}");
        let fresh = serve();
        fresh.fake.0.lock().unwrap().refuse_import = true;
        let e = reconcile(&mut OnePass, &mut client(&fresh), AUD, &want(), &SystemTime::now).unwrap_err();
        assert!(!format!("{e:?}").contains("GATEWAY-TEXT"), "{e:?}");
    }

    #[test]
    fn a_gateway_with_a_certificate_from_another_ca_is_never_sent_the_pass() {
        let s = serve();
        let (_, _, other_ca) = crate::tls::Ca::generate("0d0e0f10-1112-4314-8516-171819202122").unwrap();
        let mut gw = GatewayGrpc::new(&s.uri, other_ca.as_bytes(), crate::tls::GATEWAY_DNS).unwrap();
        let e = reconcile(&mut OnePass, &mut gw, AUD, &want(), &SystemTime::now).unwrap_err();
        assert!(matches!(e, Stop::Failed(_)), "{e:?}");
        assert!(s.fake.0.lock().unwrap().calls.is_empty(), "the TLS handshake failed before any call");
        let mut wrong_name = GatewayGrpc::new(&s.uri, &s.ca_pem, "wrong-name.invalid").unwrap();
        assert!(reconcile(&mut OnePass, &mut wrong_name, AUD, &want(), &SystemTime::now).is_err());
        assert!(s.fake.0.lock().unwrap().calls.is_empty());
    }
}

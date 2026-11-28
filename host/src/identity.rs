//! The identity profile an administrator approves for one gateway: who issues the gateway's tokens and what they
//! carry, and how each caller gets one. It holds no token, no secret and no command; secrets stay in the Enclave's
//! vault and are named only. Nothing about sign-in is hard-coded in this tool: the gateway's OIDC settings are
//! exactly the profile's.
//!
//! ```json
//! {
//!   "schema": "ekka-desk-host.identity-profile/v1",
//!   "org": "<the organization's tenant id>",
//!   "gateway": {
//!     "issuer": "https://<origin>/oidc/orgs/<tenant id>",
//!     "audience": "urn:ekka:desk-gateway:development:<gateway id>",
//!     "roles_claim": "ekka_roles.development",
//!     "admin_role": "openshell-admin",
//!     "user_role": "openshell-user",
//!     "scopes_claim": "scope",
//!     "jwks_ttl_secs": 300
//!   },
//!   "callers": {
//!     "enclave": { "subject": "...", "token": { "kind": "client_credentials", "client_id": "...", "secret_name": "..." } },
//!     "adapter": { "subject": "..." }
//!   }
//! }
//! ```
//!
//! `callers` may be left out until the gateway is registered; the steps that need a subject then wait and say so.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{failed, refused, Result};
use crate::util::is_uuid;

pub const SCHEMA: &str = "ekka-desk-host.identity-profile/v1";
const MAX_FILE: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema: String,
    pub org: String,
    pub gateway: Gateway,
    #[serde(default)]
    pub callers: Callers,
}

/// The gateway's `[openshell.gateway.oidc]` settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    pub issuer: String,
    pub audience: String,
    pub roles_claim: String,
    pub admin_role: String,
    pub user_role: String,
    pub scopes_claim: String,
    pub jwks_ttl_secs: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Callers {
    #[serde(default)]
    pub enclave: Option<EnclaveCaller>,
    #[serde(default)]
    pub adapter: Option<AdapterCaller>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnclaveCaller {
    /// The Enclave's subject as the issuer names it; the gateway sees it as `user:oidc:<subject>`.
    pub subject: String,
    pub token: EnclaveToken,
}

/// How the Enclave gets its gateway token. One kind today: the kind the shipped Enclave supports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnclaveToken {
    /// Client credentials at the issuer's token endpoint; the client secret is in the Enclave's vault under
    /// `secret_name`, never here.
    ClientCredentials { client_id: String, secret_name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterCaller {
    /// The backend adapter's subject; the one caller the Enclave lets create a desk.
    pub subject: String,
}

fn token_like(s: &str) -> bool {
    // A JWT, or anything long and opaque enough to be a bearer token, is never accepted in a profile.
    s.starts_with("eyJ") || (s.len() > 200 && !s.contains('/'))
}

fn plain(s: &str, max: usize, extra: &[u8]) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

/// An https issuer as the gateway and the adapter accept it: no user, query, fragment, dot segment or trailing
/// slash.
pub fn is_issuer(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else { return false };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let host_ok = |h: &str| plain(h, 253, b".-");
    let authority_ok = match authority.rsplit_once(':') {
        Some((h, p)) => host_ok(h) && !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()),
        None => host_ok(authority),
    };
    authority_ok
        && s.len() <= 512
        && (path.is_empty() || path[1..].split('/').all(|seg| plain(seg, 128, b"._~-") && seg != "." && seg != ".."))
}

impl Profile {
    pub fn load(path: &Path) -> Result<Self> {
        use std::io::Read;
        let f = std::fs::File::open(path).map_err(|e| refused(format!("reading {}: {e}", path.display())))?;
        let meta = f.metadata().map_err(|e| failed(format!("reading {}: {e}", path.display())))?;
        if !meta.is_file() {
            return Err(refused(format!("{} is not a file", path.display())));
        }
        let mut text = String::new();
        f.take(MAX_FILE + 1)
            .read_to_string(&mut text)
            .map_err(|e| refused(format!("reading {}: {e}", path.display())))?;
        if text.len() as u64 > MAX_FILE {
            return Err(refused(format!("{} is larger than 64 KiB", path.display())));
        }
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let p: Profile =
            serde_json::from_str(text).map_err(|e| refused(format!("the identity profile is not one: {e}")))?;
        p.check()?;
        Ok(p)
    }

    pub fn check(&self) -> Result<()> {
        if self.schema != SCHEMA {
            return Err(refused(format!("the identity profile's schema is not {SCHEMA}")));
        }
        if !is_uuid(&self.org) {
            return Err(refused("the identity profile's org is not a lowercase tenant id"));
        }
        self.gateway.check(&self.org)?;
        let subject_ok = |s: &str| plain(s, 128, b"._:/@-") && !token_like(s);
        if let Some(e) = &self.callers.enclave {
            if !subject_ok(&e.subject) {
                return Err(refused("the identity profile's enclave subject is not a plain subject"));
            }
            let EnclaveToken::ClientCredentials { client_id, secret_name } = &e.token;
            if !plain(client_id, 128, b"._-") || token_like(client_id) {
                return Err(refused("the identity profile's enclave client_id is not a plain name"));
            }
            let b = secret_name.as_bytes();
            if b.is_empty()
                || b.len() > 64
                || !b[0].is_ascii_uppercase()
                || !b.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
            {
                return Err(refused(
                    "the identity profile's enclave secret_name is not a vault secret name (A-Z, 0-9, _)",
                ));
            }
        }
        if let Some(a) = &self.callers.adapter {
            if !subject_ok(&a.subject) {
                return Err(refused("the identity profile's adapter subject is not a plain subject"));
            }
            if self.callers.enclave.as_ref().is_some_and(|e| e.subject == a.subject) {
                return Err(refused("the Enclave and the adapter must be distinct subjects"));
            }
        }
        Ok(())
    }
}

impl Gateway {
    /// The gateway's sign-in settings, for the organization `org`.
    pub fn check(&self, org: &str) -> Result<()> {
        let g = self;
        if !is_issuer(&g.issuer) {
            return Err(refused(
                "the identity profile's issuer is not a plain https address (no http, user, query or trailing slash)",
            ));
        }
        if let Some((_, tail)) = g.issuer.split_once("/oidc/orgs/") {
            if tail != org {
                return Err(refused("the identity profile's issuer names another organization than its org"));
            }
        }
        if !plain(&g.audience, 256, b":._-/") {
            return Err(refused("the identity profile's audience is not a plain name"));
        }
        if !g.roles_claim.split('.').all(|seg| plain(seg, 64, b"_-")) || g.roles_claim.len() > 128 {
            return Err(refused("the identity profile's roles_claim is not a dotted claim path"));
        }
        if !plain(&g.scopes_claim, 64, b"_-") {
            return Err(refused("the identity profile's scopes_claim is not a claim name"));
        }
        for r in [&g.admin_role, &g.user_role] {
            if !plain(r, 64, b"._:-") {
                return Err(refused("the identity profile's roles are not plain names"));
            }
        }
        if g.admin_role == g.user_role {
            return Err(refused("the identity profile's admin and user roles are the same"));
        }
        if !(60..=3600).contains(&g.jwks_ttl_secs) {
            return Err(refused("the identity profile's jwks_ttl_secs must be 60 to 3600"));
        }
        for v in [&g.issuer, &g.audience] {
            if token_like(v) {
                return Err(refused("the identity profile carries something shaped like a token; it must hold none"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../deploy/macos/identity-profile.sample.json");

    fn sample() -> serde_json::Value {
        serde_json::from_str(SAMPLE).unwrap()
    }

    #[test]
    fn the_sample_profile_is_accepted() {
        let p = Profile::parse(SAMPLE).unwrap();
        assert!(p.gateway.issuer.ends_with(&p.org));
        assert!(p.callers.enclave.is_some() && p.callers.adapter.is_some());
    }

    #[test]
    fn a_profile_without_callers_is_accepted_and_waits() {
        let mut v = sample();
        v.as_object_mut().unwrap().remove("callers");
        assert_eq!(Profile::parse(&v.to_string()).unwrap().callers, Callers::default());
    }

    #[test]
    fn insecure_or_foreign_or_token_bearing_profiles_are_refused() {
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("/gateway/issuer", "http://govern.example.com/oidc/orgs/x".into()),
            ("/gateway/issuer", "https://govern.example.com/oidc/orgs/7c1e2a3b-4d5e-4f60-8a71-92b3c4d5e6f8".into()),
            ("/gateway/issuer", "https://user@govern.example.com/x".into()),
            ("/gateway/issuer", "https://govern.example.com/x/".into()),
            ("/gateway/jwks_ttl_secs", 0.into()),
            ("/gateway/roles_claim", "a..b".into()),
            ("/gateway/user_role", "openshell-admin".into()),
            ("/org", "Not-A-Uuid".into()),
            ("/callers/enclave/subject", "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln".into()),
            ("/callers/enclave/token/secret_name", "lowercase".into()),
            ("/callers/adapter/subject", sample()["callers"]["enclave"]["subject"].clone()),
        ];
        for (ptr, value) in cases {
            let mut v = sample();
            *v.pointer_mut(ptr).unwrap() = value.clone();
            assert!(Profile::parse(&v.to_string()).is_err(), "{ptr} = {value} must be refused");
        }
        let mut v = sample();
        v["gateway"]["dangerously_allow_insecure_http"] = true.into();
        assert!(Profile::parse(&v.to_string()).is_err(), "an unknown setting is refused");
        let mut v = sample();
        v["callers"]["enclave"]["token"]["client_secret"] = "s3cret".into();
        assert!(Profile::parse(&v.to_string()).is_err(), "a secret is never accepted in the profile");
    }
}

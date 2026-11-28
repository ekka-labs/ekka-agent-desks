//! Who the gateway trusts for sign-in. Nothing here is taken from a file the developer can edit: the issuer is
//! EKKA's own for the organization, at the Govern origin compiled in for the environment; the audience is the
//! gateway's id from its registration, which names the machine class the roles claim follows; the role names, the
//! scope claim and the key-set lifetime are Govern's contract. A profile can say which registered gateway this is,
//! and nothing that widens what the gateway accepts.
//!
//! The identity profile, version 3:
//!
//! ```json
//! { "schema": "ekka-desk-host.identity-profile/v3",
//!   "org": "<the organization's tenant id>",
//!   "registration": <Govern's answer to the gateway's registration, as it was given> }
//! ```
//!
//! `registration` is left out until the gateway is registered; the gateway then waits and install says so. Root uses
//! it only when it is this installation's (`registration`). Any other field (an issuer, a role, a subject, a secret)
//! is refused.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{refused, Result};
use crate::util::is_uuid;

pub const SCHEMA: &str = "ekka-desk-host.identity-profile/v3";
const MAX_FILE: u64 = 64 * 1024;
const GATEWAY_ID_PREFIX: &str = "urn:ekka:desk-gateway:";

/// Govern's public origin for each environment a Mac desk host can join.
pub const GOVERN_ORIGINS: [(&str, &str); 3] = [
    ("dev", "https://govern.dev.ekka.ai"),
    ("staging", "https://govern.staging.ekka.ai"),
    ("prod", "https://govern.ekka.ai"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema: String,
    pub org: String,
    #[serde(default)]
    pub registration: Option<serde_json::Value>,
}

/// The gateway's `[openshell.gateway.oidc]` settings, every one computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gateway {
    pub issuer: String,
    pub audience: String,
    pub roles_claim: String,
    pub admin_role: String,
    pub user_role: String,
    pub scopes_claim: String,
    pub jwks_ttl_secs: u64,
}

/// Govern's origin for `env`; refused for any environment without one.
pub fn govern_origin(env: &str) -> Result<&'static str> {
    GOVERN_ORIGINS.iter().find(|(e, _)| *e == env).map(|(_, o)| *o).ok_or_else(|| {
        refused(format!("a Mac desk host joins dev, staging or prod; {env:?} has no Govern origin compiled in"))
    })
}

/// The organization's issuer: `{Govern origin}/oidc/orgs/{tenant id}`.
pub fn issuer(env: &str, org: &str) -> Result<String> {
    if !is_uuid(org) {
        return Err(refused("the organization is not a lowercase tenant id"));
    }
    Ok(format!("{}/oidc/orgs/{org}", govern_origin(env)?))
}

/// The machine class a gateway id names. A Mac is a development machine: a production gateway is refused.
pub fn gateway_class(gateway_id: &str) -> Result<&str> {
    let rest = gateway_id
        .strip_prefix(GATEWAY_ID_PREFIX)
        .ok_or_else(|| refused("the gateway id is not urn:ekka:desk-gateway:<class>:<uuid>"))?;
    let (class, id) =
        rest.split_once(':').ok_or_else(|| refused("the gateway id is not urn:ekka:desk-gateway:<class>:<uuid>"))?;
    if !is_uuid(id) {
        return Err(refused("the gateway id does not end in a lowercase uuid"));
    }
    match class {
        "development" => Ok(class),
        "production" => Err(refused("a production gateway is never installed on a developer Mac")),
        _ => Err(refused("the gateway id names no machine class this release knows")),
    }
}

/// The gateway's sign-in settings for this organization, environment and registered gateway.
pub fn gateway_oidc(env: &str, org: &str, gateway_id: &str) -> Result<Gateway> {
    let class = gateway_class(gateway_id)?;
    Ok(Gateway {
        issuer: issuer(env, org)?,
        audience: gateway_id.to_string(),
        roles_claim: format!("ekka_roles.{class}"),
        admin_role: "openshell-admin".into(),
        user_role: "openshell-user".into(),
        scopes_claim: "scope".into(),
        jwks_ttl_secs: 300,
    })
}

impl Profile {
    pub fn load(path: &Path) -> Result<Self> {
        use std::io::Read;
        let f = std::fs::File::open(path).map_err(|e| refused(format!("reading {}: {e}", path.display())))?;
        let meta = f.metadata().map_err(|e| refused(format!("reading {}: {e}", path.display())))?;
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
        let p: Profile = serde_json::from_str(text).map_err(|e| {
            refused(format!(
                "the identity profile is not one this release reads (it may hold only schema, org and gateway_id): {e}"
            ))
        })?;
        if p.schema != SCHEMA {
            return Err(refused(format!("the identity profile's schema is not {SCHEMA}")));
        }
        if !is_uuid(&p.org) {
            return Err(refused("the identity profile's org is not a lowercase tenant id"));
        }
        if let Some(r) = &p.registration {
            gateway_class(&crate::registration::Registration::from_answer(r)?.gateway_id)?;
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../deploy/macos/identity-profile.sample.json");
    const ORG: &str = "7c1e2a3b-4d5e-4f60-8a71-92b3c4d5e6f7";

    #[test]
    fn the_sample_profile_is_accepted() {
        let p = Profile::parse(SAMPLE).unwrap();
        assert_eq!(p.org, ORG);
        assert!(p.registration.is_some());
    }

    #[test]
    fn the_issuer_is_govern_for_the_environment_and_the_org_never_the_profile() {
        assert_eq!(issuer("prod", ORG).unwrap(), format!("https://govern.ekka.ai/oidc/orgs/{ORG}"));
        assert_eq!(issuer("dev", ORG).unwrap(), format!("https://govern.dev.ekka.ai/oidc/orgs/{ORG}"));
        assert!(issuer("local", ORG).is_err(), "no Govern origin for local");
        let id = "urn:ekka:desk-gateway:development:0b6f4a52-1c3d-4e5f-8a9b-0c1d2e3f4a5b";
        let g = gateway_oidc("staging", ORG, id).unwrap();
        assert_eq!(g.issuer, format!("https://govern.staging.ekka.ai/oidc/orgs/{ORG}"));
        assert_eq!((g.audience.as_str(), g.roles_claim.as_str()), (id, "ekka_roles.development"));
        assert_eq!(
            (g.admin_role.as_str(), g.user_role.as_str(), g.jwks_ttl_secs),
            ("openshell-admin", "openshell-user", 300)
        );
    }

    #[test]
    fn a_profile_naming_an_issuer_roles_or_subjects_is_refused() {
        for (k, v) in [
            ("issuer", serde_json::json!("https://attacker.example.com/oidc/orgs/x")),
            ("roles_claim", serde_json::json!("realm_access.roles")),
            ("gateway", serde_json::json!({"issuer": "https://attacker.example.com"})),
            ("callers", serde_json::json!({"adapter": {"subject": "attacker"}})),
        ] {
            let mut p: serde_json::Value = serde_json::from_str(SAMPLE).unwrap();
            p[k] = v;
            assert!(Profile::parse(&p.to_string()).is_err(), "{k} must be refused");
        }
    }

    #[test]
    fn only_a_development_gateway_is_accepted_on_a_mac() {
        assert!(gateway_class("urn:ekka:desk-gateway:production:0b6f4a52-1c3d-4e5f-8a9b-0c1d2e3f4a5b").is_err());
        assert!(gateway_class("urn:ekka:desk-gateway:development:not-a-uuid").is_err());
        assert!(gateway_class("ekka-desks").is_err());
        let mut p: serde_json::Value = serde_json::from_str(SAMPLE).unwrap();
        p.as_object_mut().unwrap().remove("registration");
        assert_eq!(Profile::parse(&p.to_string()).unwrap().registration, None, "before registration");
    }
}

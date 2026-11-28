//! The installation binding: which organization, developer, environment, profile and runtime this Mac's install
//! serves. Root writes it once and it never changes; an install for anything else is refused before any change.
//! A second install with the same binding is the same installation and changes nothing that is already right.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{refused, Result};
use crate::util::{is_uuid, new_uuid};

pub const SCHEMA: &str = "ekka-desk-host.binding/v1";
pub const PROFILE: &str = "developer-native";
pub const RUNTIME: &str = "docker-desktop";

/// What the binding must say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Want {
    pub org: String,
    pub uid: u32,
    pub env: String,
    pub profile: String,
    pub runtime: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub schema: String,
    pub installation_id: String,
    pub org: String,
    pub uid: u32,
    pub env: String,
    pub profile: String,
    pub runtime: String,
}

/// An environment name as the `ekka` CLI takes it.
pub fn is_env(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

impl Want {
    pub fn check(&self) -> Result<()> {
        if !is_uuid(&self.org) {
            return Err(refused("--org must be the organization's tenant id (a lowercase UUID), which never changes"));
        }
        if !is_env(&self.env) {
            return Err(refused("--env must be an environment name (lowercase letters, digits and -)"));
        }
        if self.profile != PROFILE {
            return Err(refused(format!("only --profile {PROFILE} is installed by this release")));
        }
        if self.runtime != RUNTIME {
            return Err(refused(format!("only --runtime {RUNTIME} is installed by this release")));
        }
        if self.uid == 0 {
            return Err(refused("an installation is never for root"));
        }
        Ok(())
    }

    /// A new binding for this want, with a new installation id.
    pub fn new_binding(&self) -> Result<Binding> {
        Ok(Binding {
            schema: SCHEMA.into(),
            installation_id: new_uuid()?,
            org: self.org.clone(),
            uid: self.uid,
            env: self.env.clone(),
            profile: self.profile.clone(),
            runtime: self.runtime.clone(),
        })
    }
}

impl Binding {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let b: Binding = serde_json::from_slice(data)
            .map_err(|_| refused("this Mac's installation binding is unreadable; it was not changed"))?;
        if b.schema != SCHEMA || !is_uuid(&b.installation_id) || !is_uuid(&b.org) {
            return Err(refused("this Mac's installation binding is not one this release reads; it was not changed"));
        }
        Ok(b)
    }

    /// The binding at `path`, read without following a link; `None` when there is none yet.
    pub fn read(path: &Path) -> Result<Option<Self>> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(refused(format!("reading {}: {e}", path.display()))),
            Ok(m) if !m.file_type().is_file() => {
                return Err(refused(format!("{} is not a regular file; nothing was changed", path.display())))
            }
            Ok(_) => {}
        }
        let data = std::fs::read(path).map_err(|e| refused(format!("reading {}: {e}", path.display())))?;
        Self::parse(&data).map(Some)
    }

    /// Refused, naming what differs, unless this binding is for exactly `want`.
    pub fn check_same(&self, want: &Want) -> Result<()> {
        if self.org != want.org {
            return Err(refused(format!(
                "this Mac's desk host for uid {} is bound to organization {}; refusing organization {} before any \
                 change. One installation serves one organization",
                self.uid, self.org, want.org
            )));
        }
        let mut differ = Vec::new();
        if self.uid != want.uid {
            differ.push(format!("uid {} (asked {})", self.uid, want.uid));
        }
        if self.env != want.env {
            differ.push(format!("environment {} (asked {})", self.env, want.env));
        }
        if self.profile != want.profile {
            differ.push(format!("profile {} (asked {})", self.profile, want.profile));
        }
        if self.runtime != want.runtime {
            differ.push(format!("runtime {} (asked {})", self.runtime, want.runtime));
        }
        if !differ.is_empty() {
            return Err(refused(format!(
                "this Mac's desk host is bound to {}; nothing was changed",
                differ.join(", ")
            )));
        }
        Ok(())
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut v = serde_json::to_vec_pretty(self).unwrap_or_default();
        v.push(b'\n');
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn want(org: &str) -> Want {
        Want { org: org.into(), uid: 501, env: "prod".into(), profile: PROFILE.into(), runtime: RUNTIME.into() }
    }

    const A: &str = "7c1e2a3b-4d5e-4f60-8a71-92b3c4d5e6f7";
    const B: &str = "0d0e0f10-1112-4314-8516-171819202122";

    #[test]
    fn the_same_binding_is_accepted_and_a_foreign_org_is_refused_by_name() {
        let b = want(A).new_binding().unwrap();
        b.check_same(&want(A)).unwrap();
        let e = b.check_same(&want(B)).unwrap_err();
        assert_eq!(e.kind, crate::error::Kind::Refused);
        assert!(e.reason.contains(A) && e.reason.contains(B) && e.reason.contains("before any change"), "{e}");
        let mut other_env = want(A);
        other_env.env = "dev".into();
        assert!(b.check_same(&other_env).unwrap_err().reason.contains("environment prod"));
    }

    #[test]
    fn a_binding_round_trips_and_garbage_is_refused() {
        let b = want(A).new_binding().unwrap();
        assert_eq!(Binding::parse(&b.bytes()).unwrap(), b);
        assert!(Binding::parse(b"{}").is_err());
        assert!(Binding::parse(b"not json").is_err());
    }

    #[test]
    fn only_this_releases_profile_and_runtime_are_accepted() {
        want(A).check().unwrap();
        let mut w = want(A);
        w.runtime = "podman".into();
        assert!(w.check().is_err());
        let mut w = want(A);
        w.org = "my-org-slug".into();
        assert!(w.check().unwrap_err().reason.contains("tenant id"));
        let mut w = want(A);
        w.uid = 0;
        assert!(w.check().is_err());
    }
}

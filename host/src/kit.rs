//! The kit files this binary carries, embedded at build time from this repository. Nothing is read from a checkout
//! at install: the reviewed bytes are the ones in the binary, so a changed file on disk changes nothing.

/// Every pin the installers share: NVIDIA's releases, the images and EKKA's adapter.
pub const PINS_JSON: &str = include_str!("../../deploy/pins.json");

/// The gateway configuration both installers start from (31 governed bindings).
pub const GATEWAY_TEMPLATE: &str = include_str!("../../deploy/gateway/gateway.toml.template");

/// The per-user LaunchAgent every Mac service is written from.
pub const LAUNCH_AGENT_TEMPLATE: &str = include_str!("../../deploy/macos/launch-agent.plist.template");

/// The reviewed baseline sandbox policy, recorded byte for byte.
pub const BASELINE_POLICY: &[u8] = include_bytes!("../../desk/policy.json");

/// NVIDIA's provider profiles as pinned, with EKKA's own changes listed in the pin file.
#[cfg(test)]
pub const PROVIDER_PIN: &str = include_str!("../../providers/PIN.json");

pub struct ProviderFiles {
    /// The profile's name at the gateway: its file's name.
    pub name: &'static str,
    /// The YAML form, which the ceiling record reads hosts from.
    pub yaml: &'static str,
    /// The JSON form the gateway imports (protobuf JSON).
    pub json: &'static str,
}

/// Every provider profile this install puts in the gateway. The ceiling record names exactly these.
pub const PROVIDERS: [ProviderFiles; 4] = [
    ProviderFiles {
        name: "bitbucket",
        yaml: include_str!("../../providers/bitbucket.yaml"),
        json: include_str!("../../providers/bitbucket.json"),
    },
    ProviderFiles {
        name: "claude-code",
        yaml: include_str!("../../providers/claude-code.yaml"),
        json: include_str!("../../providers/claude-code.json"),
    },
    ProviderFiles {
        name: "codex",
        yaml: include_str!("../../providers/codex.yaml"),
        json: include_str!("../../providers/codex.json"),
    },
    ProviderFiles {
        name: "github",
        yaml: include_str!("../../providers/github.yaml"),
        json: include_str!("../../providers/github.json"),
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::sha256_hex;
    use std::path::Path;

    fn repo() -> &'static Path {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
    }

    #[test]
    fn every_shipped_profile_is_embedded_and_matches_its_pin() {
        let mut on_disk: Vec<String> = std::fs::read_dir(repo().join("providers"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".yaml"))
            .map(|n| n.trim_end_matches(".yaml").to_string())
            .collect();
        on_disk.sort();
        let embedded: Vec<String> = PROVIDERS.iter().map(|p| p.name.to_string()).collect();
        assert_eq!(on_disk, embedded);
        let pin: serde_json::Value = serde_json::from_str(PROVIDER_PIN).unwrap();
        for p in &PROVIDERS {
            assert_eq!(pin["files"][format!("{}.yaml", p.name)].as_str(), Some(sha256_hex(p.yaml.as_bytes()).as_str()));
            assert_eq!(pin["files"][format!("{}.json", p.name)].as_str(), Some(sha256_hex(p.json.as_bytes()).as_str()));
        }
    }
}

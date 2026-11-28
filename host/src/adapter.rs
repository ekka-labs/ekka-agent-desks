//! EKKA's backend adapter's one configuration file (the vendored contract `backend/adapter-config.v1`), and the
//! enrolled Enclave's values it is built from. It holds no credential: the gateway credential stays in the
//! Enclave's vault and arrives with each call.
//!
//! Every value comes from this machine: the organization (the binding), the Enclave's API gate (from its node id),
//! Govern's gate-token keys (Govern's own published configuration), and the gateway as the adapter reaches it here
//! (`https://127.0.0.1:8080`, this installation's CA, EKKA's issuer for the organization).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{refused, Result};
use crate::platform::macos::{Layout, CA_CERT, GATEWAY_PORT, WORKSPACE};
use crate::tls::GATEWAY_IP;
use crate::util::{is_plain_absolute_path, is_uuid};

/// The adapter's sign-in client at the gateway's issuer (fixed by the contract).
pub const CLIENT_ID: &str = "ekka-desk-admin";

/// The enrolled Enclave's identity, from its `enclave.env`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclaveValues {
    pub tenant_id: String,
    pub node_id: String,
    pub govern_url: String,
}

/// The Enclave's `enclave.env` for `env`: at the top of its home for prod, in a folder named after any other.
pub fn enclave_env_path(l: &Layout, env: &str) -> PathBuf {
    if env == "prod" {
        l.enclave_home().join("enclave.env")
    } else {
        l.enclave_home().join(env).join("enclave.env")
    }
}

/// The three values from `enclave.env` lines; nothing else is read.
pub fn enclave_values(text: &str) -> Result<EnclaveValues> {
    let get = |k: &str| {
        text.lines()
            .filter_map(|l| l.split_once('='))
            .filter(|(key, _)| key.trim() == k)
            .map(|(_, v)| v.trim().to_string())
            .next_back()
            .filter(|v| !v.is_empty())
    };
    let (Some(tenant_id), Some(node_id), Some(govern_url)) =
        (get("EKKA_TENANT_ID"), get("EKKA_NODE_ID"), get("EKKA_GOVERN_URL"))
    else {
        return Err(refused(
            "the Enclave's enclave.env does not name its organization, node and Govern; is it enrolled?",
        ));
    };
    if !is_uuid(&tenant_id) || !is_uuid(&node_id) {
        return Err(refused("the Enclave's organization or node id is not a lowercase UUID"));
    }
    let origin = govern_url.trim_end_matches('/');
    if !origin.strip_prefix("https://").is_some_and(|h| {
        !h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':')
    }) {
        return Err(refused("the Enclave's Govern URL is not a plain https origin"));
    }
    Ok(EnclaveValues { tenant_id, node_id, govern_url })
}

/// The enrolled Enclave's values, or `None` when it is not enrolled yet (no `enclave.env`).
pub fn read_enclave_values(path: &Path) -> Result<Option<EnclaveValues>> {
    match std::fs::read_to_string(path) {
        Ok(text) => enclave_values(&text).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(refused(format!("{} cannot be read by this user", path.display())))
        }
        Err(e) => Err(refused(format!("reading {}: {e}", path.display()))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernKey {
    pub key_id: String,
    pub public_key_b64: String,
}

fn is_key_b64(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 44
        && b[..42].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/')
        && b"AEIMQUYcgkosw048".contains(&b[42])
        && b[43] == b'='
}

/// Govern's `verify_keys` with purpose `gate_token`: one, or two while a key rotates.
pub fn gate_token_keys(well_known: &Value) -> Result<Vec<GovernKey>> {
    let keys: Vec<GovernKey> = well_known["verify_keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|k| k["purpose"] == "gate_token")
        .map(|k| GovernKey {
            key_id: k["kid"].as_str().unwrap_or("").to_string(),
            public_key_b64: k["public_key_b64"].as_str().unwrap_or("").to_string(),
        })
        .collect();
    check_keys(&keys)?;
    Ok(keys)
}

pub fn check_keys(keys: &[GovernKey]) -> Result<()> {
    if !(1..=2).contains(&keys.len()) {
        return Err(refused(format!(
            "Govern published {} gate-token keys; the adapter takes one, or two while one rotates",
            keys.len()
        )));
    }
    for k in keys {
        if k.key_id.is_empty() || k.key_id.len() > 128 || !k.key_id.bytes().all(|b| (b'!'..=b'~').contains(&b)) {
            return Err(refused("a gate-token key has no usable kid"));
        }
        if !is_key_b64(&k.public_key_b64) {
            return Err(refused("a gate-token key is not a 32-byte Ed25519 key in standard base64"));
        }
    }
    Ok(())
}

/// Govern's gate-token keys, from its published configuration.
pub fn fetch_govern_keys(govern_url: &str) -> Result<Vec<GovernKey>> {
    let url = format!("{}/.well-known/ekka-configuration", govern_url.trim_end_matches('/'));
    let body = crate::net::get(&url, 256 * 1024)?;
    let v: Value = serde_json::from_slice(&body).map_err(|_| refused("Govern's configuration is not JSON"))?;
    gate_token_keys(&v)
}

/// What the adapter's configuration needs from the enrolled Enclave and Govern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterInputs {
    pub node_id: String,
    pub govern_keys: Vec<GovernKey>,
}

/// The adapter's configuration file for this installation.
pub fn config_bytes(l: &Layout, org: &str, inputs: &AdapterInputs, issuer: &str) -> Result<Vec<u8>> {
    if !is_uuid(org) || !is_uuid(&inputs.node_id) {
        return Err(refused("the adapter's organization or the Enclave's node id is not a lowercase UUID"));
    }
    check_keys(&inputs.govern_keys)?;
    if !issuer.starts_with("https://") || issuer.contains(char::is_whitespace) {
        return Err(refused("the adapter's issuer is not an https address"));
    }
    let paths = [l.tls_dir().join(CA_CERT), l.adapter_socket(), l.backend_dir()];
    if paths.iter().any(|p| !is_plain_absolute_path(&p.display().to_string())) {
        return Err(refused("an adapter path is not a plain absolute path"));
    }
    let node = inputs.node_id.replace('-', "");
    let doc = json!({
        "config_version": 1,
        "organization_id": org,
        "api_gate_instance": format!("enclave{}Api", &node[..8]),
        "govern_keys": inputs.govern_keys,
        "backend_gateway": {
            "url": format!("https://{GATEWAY_IP}:{GATEWAY_PORT}"),
            "client_id": CLIENT_ID,
            "workspace": WORKSPACE,
            "issuer": issuer,
            "ca_pem_path": paths[0].display().to_string(),
        },
        "deadline_seconds": 120,
        "socket_path": paths[1].display().to_string(),
        "state_dir": paths[2].display().to_string(),
    });
    let mut out = serde_json::to_vec_pretty(&doc).map_err(|e| refused(format!("the adapter's configuration: {e}")))?;
    out.push(b'\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENV: &str =
        "EKKA_TENANT_ID=7c1e2a3b-4d5e-4f60-8a71-92b3c4d5e6f7\nEKKA_NODE_ID=2f8e7d6c-5b4a-4392-8170-6e5d4c3b2a19\n\
EKKA_GOVERN_URL=https://govern.example.com\nOTHER=x\n";

    #[test]
    fn the_enclave_values_are_read_and_checked() {
        let v = enclave_values(ENV).unwrap();
        assert_eq!(v.node_id, "2f8e7d6c-5b4a-4392-8170-6e5d4c3b2a19");
        assert!(enclave_values("EKKA_TENANT_ID=x\n").is_err());
        assert!(enclave_values(&ENV.replace("https://", "http://")).is_err());
        let l = Layout::system(501, PathBuf::from("/Users/dev"));
        assert_eq!(enclave_env_path(&l, "prod"), PathBuf::from("/private/var/db/ekka-dev/501/enclave/enclave.env"));
        assert_eq!(enclave_env_path(&l, "dev"), PathBuf::from("/private/var/db/ekka-dev/501/enclave/dev/enclave.env"));
    }

    #[test]
    fn govern_gate_token_keys_are_taken_one_or_two() {
        let k = |kid: &str| json!({"kid": kid, "purpose": "gate_token", "public_key_b64": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="});
        let one = json!({"verify_keys": [k("a"), {"kid": "s", "purpose": "session", "public_key_b64": "x"}]});
        assert_eq!(gate_token_keys(&one).unwrap().len(), 1);
        assert!(gate_token_keys(&json!({"verify_keys": [k("a"), k("b"), k("c")]})).is_err());
        assert!(gate_token_keys(&json!({"verify_keys": []})).is_err());
        let mut bad = k("a");
        bad["public_key_b64"] = "short".into();
        assert!(gate_token_keys(&json!({"verify_keys": [bad]})).is_err());
    }

    #[test]
    fn the_adapter_config_follows_the_contract_and_meets_the_enclave_in_d_run() {
        let l = Layout::system(501, PathBuf::from("/Users/dev"));
        let inputs = AdapterInputs {
            node_id: "2f8e7d6c-5b4a-4392-8170-6e5d4c3b2a19".into(),
            govern_keys: vec![GovernKey {
                key_id: "govern-gate-token-v1".into(),
                public_key_b64: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".into(),
            }],
        };
        let issuer = "https://govern.example.com/oidc/orgs/7c1e2a3b-4d5e-4f60-8a71-92b3c4d5e6f7";
        let v: Value =
            serde_json::from_slice(&config_bytes(&l, "7c1e2a3b-4d5e-4f60-8a71-92b3c4d5e6f7", &inputs, issuer).unwrap())
                .unwrap();
        let schema: Value =
            serde_json::from_str(include_str!("../../vendor/ekka-contracts/backend/adapter-config.v1.schema.json"))
                .unwrap();
        let allowed: Vec<&String> = schema["properties"].as_object().unwrap().keys().collect();
        for k in v.as_object().unwrap().keys() {
            assert!(allowed.contains(&k), "{k} is not in the contract");
        }
        for k in schema["required"].as_array().unwrap() {
            assert!(v.get(k.as_str().unwrap()).is_some(), "{k} is required by the contract");
        }
        assert_eq!(v["api_gate_instance"], "enclave2f8e7d6cApi");
        assert_eq!(
            v["backend_gateway"]["client_id"],
            schema["properties"]["backend_gateway"]["properties"]["client_id"]["const"]
        );
        assert_eq!(v["socket_path"], "/private/var/db/ekka-dev/501/run/backend/backend.sock");
        assert_eq!(v["state_dir"], "/private/var/db/ekka-dev/501/backend");
        assert_eq!(v["backend_gateway"]["url"], "https://127.0.0.1:8080");
        assert!(config_bytes(&l, "not-a-uuid", &inputs, issuer).is_err());
    }
}

//! The Mac gateway's `gateway.toml`, rendered from the same template the Linux installer uses, so the 31 governed
//! bindings have one source. Only what a native Mac gateway needs differs: loopback addresses, this
//! installation's certificate and token-key paths, the identity profile's OIDC settings, Docker Desktop's
//! socket, and the Enclave's interceptor socket under `D/run`.
//!
//! `findings` names anything in a gateway configuration that would let the gateway hand credentials out, take an
//! unauthenticated caller, listen beyond this Mac, or let a desk change go through with EKKA down. Render refuses a
//! configuration with any finding; `doctor` reads the installed file again and reports them.

use std::net::SocketAddr;
use std::path::Path;

use toml::{Table, Value};

use crate::error::{failed, refused, Result};
use crate::identity::Gateway;
use crate::kit;
use crate::platform::macos::{
    Layout, CA_CERT, GATEWAY_PORT, HEALTH_PORT, JWT_KID, JWT_PUBLIC, JWT_SIGNING, LEAF_CERT, LEAF_KEY,
};
use crate::release::Pins;
use crate::tls::{GATEWAY_DNS, GATEWAY_IP};

const HEADER: &str = "# Written by ekka-desk-host from deploy/gateway/gateway.toml.template. Do not edit: install \
writes it again.\n# The governed bindings are the template's; this file changes only addresses, paths and sign-in.\n";

fn table<'a>(t: &'a mut Table, path: &[&str]) -> Result<&'a mut Table> {
    let mut cur = t;
    for key in path {
        cur = cur
            .get_mut(*key)
            .and_then(Value::as_table_mut)
            .ok_or_else(|| failed(format!("the gateway template has no [{}]", path.join("."))))?;
    }
    Ok(cur)
}

fn path(p: &Path) -> Value {
    Value::String(p.display().to_string())
}

/// The gateway's configuration for this installation.
pub fn render(l: &Layout, oidc: &Gateway, docker_socket: &Path, pins: &Pins) -> Result<String> {
    let mut t: Table = kit::GATEWAY_TEMPLATE.parse().map_err(|e| failed(format!("the gateway template: {e}")))?;
    let tls = l.tls_dir();
    {
        let g = table(&mut t, &["openshell", "gateway"])?;
        g.insert("bind_address".into(), format!("{GATEWAY_IP}:{GATEWAY_PORT}").into());
        g.insert("health_bind_address".into(), format!("{GATEWAY_IP}:{HEALTH_PORT}").into());
        g.insert("guest_tls_ca".into(), path(&tls.join(CA_CERT)));
    }
    {
        let t2 = table(&mut t, &["openshell", "gateway", "tls"])?;
        t2.insert("cert_path".into(), path(&tls.join(LEAF_CERT)));
        t2.insert("key_path".into(), path(&tls.join(LEAF_KEY)));
    }
    {
        let o = table(&mut t, &["openshell", "gateway", "oidc"])?;
        o.clear();
        o.insert("issuer".into(), oidc.issuer.clone().into());
        o.insert("audience".into(), oidc.audience.clone().into());
        o.insert("roles_claim".into(), oidc.roles_claim.clone().into());
        o.insert("admin_role".into(), oidc.admin_role.clone().into());
        o.insert("user_role".into(), oidc.user_role.clone().into());
        o.insert("scopes_claim".into(), oidc.scopes_claim.clone().into());
        o.insert("jwks_ttl_secs".into(), Value::Integer(oidc.jwks_ttl_secs as i64));
    }
    {
        let j = table(&mut t, &["openshell", "gateway", "gateway_jwt"])?;
        let jwt = l.jwt_dir();
        j.insert("signing_key_path".into(), path(&jwt.join(JWT_SIGNING)));
        j.insert("public_key_path".into(), path(&jwt.join(JWT_PUBLIC)));
        j.insert("kid_path".into(), path(&jwt.join(JWT_KID)));
    }
    {
        // Docker Desktop's VM reaches the Mac only through its bridge, by the name it gives the Mac. The
        // supervisor and sandbox runtime are the images pinned and checked by digest.
        let d = table(&mut t, &["openshell", "drivers", "docker"])?;
        d.insert("socket_path".into(), path(docker_socket));
        d.insert("supervisor_network_mode".into(), "bridge".into());
        d.insert("grpc_endpoint".into(), format!("https://{GATEWAY_DNS}:{GATEWAY_PORT}").into());
        d.insert("supervisor_image".into(), pins.supervisor.image.clone().into());
        d.insert("sandbox_runtime_image".into(), pins.sandbox.image.clone().into());
    }
    let endpoint = format!("unix://{}", l.interceptor_socket().display());
    let interceptors = table(&mut t, &["openshell", "gateway"])?
        .get_mut("interceptors")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| failed("the gateway template has no interceptors"))?;
    for i in interceptors.iter_mut() {
        i.as_table_mut()
            .ok_or_else(|| failed("the gateway template has an interceptor that is not a table"))?
            .insert("grpc_endpoint".into(), endpoint.clone().into());
    }
    let found = findings(&t);
    if !found.is_empty() {
        return Err(refused(format!("the gateway configuration was not written: {}", found.join("; "))));
    }
    let body = toml::to_string(&t).map_err(|e| failed(format!("writing the gateway configuration: {e}")))?;
    Ok(format!("{HEADER}{body}"))
}

fn get<'a>(t: &'a Table, path: &[&str]) -> Option<&'a Value> {
    let (last, rest) = path.split_last()?;
    let mut cur = t;
    for k in rest {
        cur = cur.get(*k)?.as_table()?;
    }
    cur.get(*last)
}

fn truthy(t: &Table, path: &[&str]) -> bool {
    get(t, path).and_then(Value::as_bool).unwrap_or(false)
}

fn loopback_v4(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str)
        .and_then(|s| s.parse::<SocketAddr>().ok())
        .is_some_and(|a| a.is_ipv4() && a.ip().is_loopback())
}

/// Every reason this configuration must not run, by name. Empty when it may.
pub fn findings(t: &Table) -> Vec<String> {
    let mut out = Vec::new();
    let mut bad = |s: &str| out.push(s.to_string());
    let gw = ["openshell", "gateway"];
    if get(t, &[gw[0], gw[1], "tls", "client_ca_path"]).is_some() {
        bad("[openshell.gateway.tls] client_ca_path is set: a gateway that trusts client certificates can hand credentials out");
    }
    if truthy(t, &[gw[0], gw[1], "mtls_auth", "enabled"]) || truthy(t, &[gw[0], gw[1], "mtls_auth", "operator_enabled"])
    {
        bad("[openshell.gateway.mtls_auth] is on: an operator certificate can export desk credentials");
    }
    if truthy(t, &[gw[0], gw[1], "auth", "allow_unauthenticated_users"]) {
        bad("[openshell.gateway.auth] allow_unauthenticated_users is on");
    }
    match get(t, &[gw[0], gw[1], "oidc", "issuer"]).and_then(Value::as_str) {
        Some(i) if i.starts_with("https://") => {}
        _ => bad("[openshell.gateway.oidc] issuer is missing or not https"),
    }
    if get(t, &[gw[0], gw[1], "oidc", "dangerously_allow_insecure_http"]).is_some() {
        bad("[openshell.gateway.oidc] dangerously_allow_insecure_http is set");
    }
    if get(t, &[gw[0], gw[1], "oidc", "audience"]).and_then(Value::as_str).unwrap_or("").is_empty() {
        bad("[openshell.gateway.oidc] audience is missing");
    }
    if !loopback_v4(get(t, &[gw[0], gw[1], "bind_address"])) {
        bad("[openshell.gateway] bind_address is not a 127.0.0.1 address: it would listen beyond this Mac");
    }
    if !loopback_v4(get(t, &[gw[0], gw[1], "health_bind_address"])) {
        bad("[openshell.gateway] health_bind_address is not a 127.0.0.1 address");
    }
    if get(t, &[gw[0], gw[1], "policy_validation_failure_mode"]).and_then(Value::as_str) != Some("fail_closed") {
        bad("[openshell.gateway] policy_validation_failure_mode is not fail_closed");
    }
    if truthy(t, &["openshell", "drivers", "docker", "enable_bind_mounts"]) {
        bad("[openshell.drivers.docker] enable_bind_mounts is on: a desk could mount this Mac's files");
    }
    if truthy(t, &["openshell", "drivers", "docker", "allow_driver_config"]) {
        bad("[openshell.drivers.docker] allow_driver_config is on: a desk's creator could attach mounts");
    }
    let interceptors = get(t, &[gw[0], gw[1], "interceptors"]).and_then(Value::as_array);
    let governance = interceptors.and_then(|a| {
        a.iter().filter_map(Value::as_table).find(|i| i.get("name").and_then(Value::as_str) == Some("ekka-governance"))
    });
    match governance {
        None => bad("the ekka-governance interceptor is missing: desk changes would not be governed"),
        Some(g) => {
            if g.get("failure_policy").and_then(Value::as_str) != Some("fail_closed") {
                bad("the ekka-governance interceptor does not fail closed: with EKKA down a desk change would go through");
            }
            if g.get("binding_policy").and_then(Value::as_str) != Some("allowlist") {
                bad("the ekka-governance interceptor's binding_policy is not allowlist");
            }
        }
    }
    for i in interceptors.into_iter().flatten().filter_map(Value::as_table) {
        let ep = i.get("grpc_endpoint").and_then(Value::as_str).unwrap_or("");
        if !ep.starts_with("unix:///") {
            bad("an interceptor is reached over something other than a local socket");
        }
    }
    out
}

/// The findings of a gateway configuration file as written.
pub fn findings_of_text(text: &str) -> Vec<String> {
    match text.parse::<Table>() {
        Ok(t) => findings(&t),
        Err(e) => vec![format!("the gateway configuration is not TOML: {e}")],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Profile;
    use std::path::PathBuf;

    fn render_sample() -> (Layout, Profile, String) {
        let l = Layout::system(501, PathBuf::from("/Users/dev"));
        let p = Profile::parse(include_str!("../../deploy/macos/identity-profile.sample.json")).unwrap();
        let text = render(&l, &p.gateway, &l.docker_socket(), &Pins::embedded().unwrap()).unwrap();
        (l, p, text)
    }

    fn bindings(t: &Table) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        for i in get(t, &["openshell", "gateway", "interceptors"]).unwrap().as_array().unwrap() {
            let name = i["name"].as_str().unwrap().to_string();
            for b in i["bindings"].as_array().unwrap() {
                for ph in b["phases"].as_array().unwrap() {
                    out.push((name.clone(), b["rpc"].as_str().unwrap().into(), ph.as_str().unwrap().into()));
                }
            }
        }
        out
    }

    #[test]
    fn every_governed_binding_of_the_template_is_kept() {
        let (_, _, text) = render_sample();
        let got: Table = text.parse().unwrap();
        let template: Table = kit::GATEWAY_TEMPLATE.parse().unwrap();
        assert_eq!(bindings(&got), bindings(&template));
        assert_eq!(bindings(&got).len(), 31);
    }

    #[test]
    fn the_gateway_listens_on_numeric_loopback_only() {
        let (_, _, text) = render_sample();
        let t: Table = text.parse().unwrap();
        assert_eq!(get(&t, &["openshell", "gateway", "bind_address"]).unwrap().as_str(), Some("127.0.0.1:8080"));
        assert_eq!(get(&t, &["openshell", "gateway", "health_bind_address"]).unwrap().as_str(), Some("127.0.0.1:8081"));
        assert!(!text.contains("0.0.0.0") && !text.contains("localhost"), "{text}");
        // What desk supervisors in Docker's VM are told to dial: the Mac's name there, over the VM's bridge.
        let d = get(&t, &["openshell", "drivers", "docker"]).unwrap().as_table().unwrap();
        assert_eq!(d["grpc_endpoint"].as_str(), Some("https://host.docker.internal:8080"));
        assert_eq!(d["supervisor_network_mode"].as_str(), Some("bridge"));
        let pins = Pins::embedded().unwrap();
        assert_eq!(d["supervisor_image"].as_str(), Some(pins.supervisor.image.as_str()));
        assert_eq!(d["sandbox_runtime_image"].as_str(), Some(pins.sandbox.image.as_str()));
        assert!(findings(&t).is_empty(), "{:?}", findings(&t));
    }

    #[test]
    fn the_oidc_settings_are_the_profiles_exactly() {
        let (_, p, text) = render_sample();
        let t: Table = text.parse().unwrap();
        let o = get(&t, &["openshell", "gateway", "oidc"]).unwrap().as_table().unwrap();
        assert_eq!(o["issuer"].as_str(), Some(p.gateway.issuer.as_str()));
        assert_eq!(o["audience"].as_str(), Some(p.gateway.audience.as_str()));
        assert_eq!(o["roles_claim"].as_str(), Some("ekka_roles.development"));
        assert_eq!(o["scopes_claim"].as_str(), Some("scope"));
        assert_eq!(o["jwks_ttl_secs"].as_integer(), Some(300));
        assert_eq!(o.len(), 7, "nothing else, never dangerously_allow_insecure_http");
        assert!(!text.contains("realms/ekka-desks") && !text.contains("@@"), "no template placeholder survives");
    }

    #[test]
    fn tls_token_keys_and_the_interceptor_are_this_installations() {
        let (l, _, text) = render_sample();
        let t: Table = text.parse().unwrap();
        let tls = get(&t, &["openshell", "gateway", "tls"]).unwrap().as_table().unwrap();
        assert_eq!(tls["key_path"].as_str(), Some("/private/var/db/ekka-dev/501/tls/gateway.key"));
        assert!(tls.get("client_ca_path").is_none());
        assert_eq!(
            get(&t, &["openshell", "gateway", "guest_tls_ca"]).unwrap().as_str(),
            Some("/private/var/db/ekka-dev/501/tls/ca.crt"),
            "desk supervisors get the public CA only"
        );
        let want = format!("unix://{}", l.interceptor_socket().display());
        for i in get(&t, &["openshell", "gateway", "interceptors"]).unwrap().as_array().unwrap() {
            assert_eq!(i["grpc_endpoint"].as_str(), Some(want.as_str()));
            assert_eq!(i["audience"].as_str(), Some(crate::platform::macos::INTERCEPTOR_AUDIENCE));
        }
        assert_eq!(
            get(&t, &["openshell", "drivers", "docker", "socket_path"]).unwrap().as_str(),
            Some("/Users/dev/.docker/run/docker.sock")
        );
    }

    #[test]
    fn a_planted_fail_open_or_insecure_configuration_is_named() {
        let (_, _, text) = render_sample();
        let plant = |from: &str, to: &str| findings_of_text(&text.replacen(from, to, 1));
        let fail_open = plant("failure_policy = \"fail_closed\"", "failure_policy = \"fail_open\"");
        assert!(fail_open.iter().any(|f| f.contains("does not fail closed")), "{fail_open:?}");
        let wide = plant("127.0.0.1:8080", "0.0.0.0:8080");
        assert!(wide.iter().any(|f| f.contains("listen beyond this Mac")), "{wide:?}");
        let mut t: Table = text.parse().unwrap();
        table(&mut t, &["openshell", "gateway", "oidc"])
            .unwrap()
            .insert("dangerously_allow_insecure_http".into(), true.into());
        table(&mut t, &["openshell", "gateway", "oidc"])
            .unwrap()
            .insert("issuer".into(), "http://x.example.com".into());
        table(&mut t, &["openshell", "gateway", "mtls_auth"]).unwrap().insert("operator_enabled".into(), true.into());
        let f = findings(&t);
        assert!(f.iter().any(|x| x.contains("not https")) && f.iter().any(|x| x.contains("insecure_http")), "{f:?}");
        assert!(f.iter().any(|x| x.contains("operator certificate")), "{f:?}");
    }
}

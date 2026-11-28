//! Tests only: a JSON-schema checker for the vendored contracts, the Rust twin of `tools/schema_check.py`, so the
//! files this tool writes are checked against the vendored schemas themselves: every rule is READ from the schema,
//! never restated in a test.
//!
//! It applies each rule as JSON Schema (draft 07) does: `type`, `const`, `enum`, `required`, `properties`,
//! `additionalProperties`, `maxProperties`, `propertyNames`, `items`, `minItems`, `maxItems`, `uniqueItems`,
//! `pattern`, `minLength`, `maxLength`, `minimum`, `maximum`, `$ref` into `$defs`, `oneOf`, `not`, and
//! `if`/`then`/`else`. A keyword it does not know stops the check (a panic naming it), so a schema that gains a rule
//! can never pass here by being skipped.

use serde_json::Value;

const ANNOTATIONS: [&str; 7] = ["$schema", "$id", "$comment", "title", "description", "default", "examples"];
const RULES: [&str; 24] = [
    "$defs",
    "$ref",
    "type",
    "const",
    "enum",
    "required",
    "properties",
    "additionalProperties",
    "maxProperties",
    "propertyNames",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "pattern",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "oneOf",
    "not",
    "if",
    "then",
    "else",
];

/// Every way `value` breaks `schema`, each with where; empty when it holds.
pub fn errors(value: &Value, schema: &Value) -> Vec<String> {
    check(value, schema, schema, "")
}

fn matches(pattern: &str, s: &str) -> bool {
    regex_lite::Regex::new(pattern).unwrap_or_else(|e| panic!("the schema's pattern {pattern:?}: {e}")).is_match(s)
}

fn is_type(v: &Value, t: &str) -> bool {
    match t {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        "number" => v.is_number(),
        "integer" => v.is_i64() || v.is_u64() || v.as_f64().is_some_and(|f| f.fract() == 0.0),
        other => panic!("the schema names a type this checker does not know: {other}"),
    }
}

fn check(v: &Value, s: &Value, root: &Value, path: &str) -> Vec<String> {
    let Some(rules) = s.as_object() else {
        return match s.as_bool() {
            Some(true) => vec![],
            Some(false) => vec![format!("{path}: nothing is allowed here")],
            None => panic!("a schema at {path} is neither an object nor a boolean"),
        };
    };
    for k in rules.keys() {
        assert!(
            ANNOTATIONS.contains(&k.as_str()) || RULES.contains(&k.as_str()),
            "the schema keyword {k:?} at {path} is not checked by this checker; teach it before trusting a pass"
        );
    }
    let mut errs = Vec::new();
    if let Some(r) = rules.get("$ref").and_then(Value::as_str) {
        let name = r.strip_prefix("#/$defs/").unwrap_or_else(|| panic!("only #/$defs/ references are known: {r}"));
        errs.extend(check(v, &root["$defs"][name], root, path));
    }
    if let Some(t) = rules.get("type") {
        let ok = match t {
            Value::String(t) => is_type(v, t),
            Value::Array(ts) => ts.iter().any(|t| is_type(v, t.as_str().unwrap_or(""))),
            _ => panic!("a type at {path} is not a name"),
        };
        if !ok {
            errs.push(format!("{path}: not {t}"));
        }
    }
    if let Some(c) = rules.get("const") {
        if v != c {
            errs.push(format!("{path}: not {c}"));
        }
    }
    if let Some(e) = rules.get("enum").and_then(Value::as_array) {
        if !e.contains(v) {
            errs.push(format!("{path}: not one of {e:?}"));
        }
    }
    if let Some(o) = v.as_object() {
        for k in rules.get("required").and_then(Value::as_array).into_iter().flatten() {
            if !o.contains_key(k.as_str().unwrap_or("")) {
                errs.push(format!("{path}/{}: required", k.as_str().unwrap_or("?")));
            }
        }
        if rules.get("maxProperties").and_then(Value::as_u64).is_some_and(|m| o.len() as u64 > m) {
            errs.push(format!("{path}: too many properties"));
        }
        let props = rules.get("properties").and_then(Value::as_object);
        for (k, item) in o {
            let here = format!("{path}/{k}");
            if let Some(names) = rules.get("propertyNames") {
                errs.extend(check(&Value::String(k.clone()), names, root, &here));
            }
            match (props.and_then(|p| p.get(k)), rules.get("additionalProperties")) {
                (Some(sub), _) => errs.extend(check(item, sub, root, &here)),
                (None, Some(extra)) => errs.extend(check(item, extra, root, &here)),
                (None, None) => {}
            }
        }
    }
    if let Some(a) = v.as_array() {
        let n = a.len() as u64;
        if rules.get("minItems").and_then(Value::as_u64).is_some_and(|m| n < m)
            || rules.get("maxItems").and_then(Value::as_u64).is_some_and(|m| n > m)
        {
            errs.push(format!("{path}: {n} items"));
        }
        if rules.get("uniqueItems") == Some(&Value::Bool(true)) && a.iter().enumerate().any(|(i, x)| a[..i].contains(x))
        {
            errs.push(format!("{path}: items repeat"));
        }
        if let Some(items) = rules.get("items") {
            for (i, item) in a.iter().enumerate() {
                errs.extend(check(item, items, root, &format!("{path}/{i}")));
            }
        }
    }
    if let Some(text) = v.as_str() {
        let n = text.chars().count() as u64;
        if rules.get("minLength").and_then(Value::as_u64).is_some_and(|m| n < m)
            || rules.get("maxLength").and_then(Value::as_u64).is_some_and(|m| n > m)
        {
            errs.push(format!("{path}: {n} characters"));
        }
        if let Some(p) = rules.get("pattern").and_then(Value::as_str) {
            if !matches(p, text) {
                errs.push(format!("{path}: does not match {p}"));
            }
        }
    }
    if let Some(x) = v.as_f64() {
        if rules.get("minimum").and_then(Value::as_f64).is_some_and(|m| x < m)
            || rules.get("maximum").and_then(Value::as_f64).is_some_and(|m| x > m)
        {
            errs.push(format!("{path}: out of range"));
        }
    }
    if let Some(forms) = rules.get("oneOf").and_then(Value::as_array) {
        let n = forms.iter().filter(|f| check(v, f, root, path).is_empty()).count();
        if n != 1 {
            errs.push(format!("{path}: matches {n} oneOf forms, not exactly one"));
        }
    }
    if let Some(not) = rules.get("not") {
        if check(v, not, root, path).is_empty() {
            errs.push(format!("{path}: matches what it must not"));
        }
    }
    if let Some(cond) = rules.get("if") {
        let branch = if check(v, cond, root, path).is_empty() { rules.get("then") } else { rules.get("else") };
        if let Some(b) = branch {
            errs.extend(check(v, b, root, path));
        }
    }
    errs
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SCHEMA: &str = include_str!("../../vendor/ekka-contracts/backend/adapter-config.v1.schema.json");
    const SAMPLE: &str = include_str!("../../vendor/ekka-contracts/backend/samples/adapter-config.json");

    /// A checker that accepts anything would pass every file it is shown.
    #[test]
    fn the_checker_is_real_on_the_vendored_schema_and_sample() {
        let schema: Value = serde_json::from_str(SCHEMA).unwrap();
        let sample: Value = serde_json::from_str(SAMPLE).unwrap();
        assert_eq!(errors(&sample, &schema), Vec::<String>::new());
        let mut extra = sample.clone();
        extra["client_secret"] = "x".into();
        assert!(!errors(&extra, &schema).is_empty(), "an unknown field");
        let mut gate = sample.clone();
        gate["api_gate_instance"] = "enclaveXApi".into();
        assert!(!errors(&gate, &schema).is_empty(), "a pattern");
        let mut long = sample.clone();
        long["backend_gateway"]["url"] = format!("https://{}.example.com", "a".repeat(520)).into();
        assert!(!errors(&long, &schema).is_empty(), "maxLength");
        let mut desk_pass = sample.clone();
        desk_pass["backend_gateway"]["signin"] = json!({"mode": "ekka_desk_pass.v1",
            "installation_id": "5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d",
            "gateway_id": "urn:ekka:desk-gateway:development:0b6f4a52-1c3d-4e5f-8a9b-0c1d2e3f4a5b",
            "key_path": "/private/var/db/ekka-dev/501/backend/adapter-key.pem"});
        let e = errors(&desk_pass, &schema);
        assert!(
            e.iter().any(|e| e.contains("/backend_gateway/issuer")),
            "if/then: the sample's issuer is not Govern's: {e:?}"
        );
        desk_pass["backend_gateway"]["issuer"] =
            format!("https://govern.example.com/oidc/orgs/{}", sample["organization_id"].as_str().unwrap()).into();
        assert_eq!(errors(&desk_pass, &schema), Vec::<String>::new());
        let mut both = desk_pass.clone();
        both["backend_gateway"]["signin"]["client_id"] = "x".into();
        assert!(!errors(&both, &schema).is_empty(), "oneOf: a form with a field it does not have");
        let mut key = desk_pass.clone();
        key["backend_gateway"]["signin"]["key_path"] = "relative/adapter-key.pem".into();
        assert!(!errors(&key, &schema).is_empty(), "$ref into $defs");
    }

    #[test]
    #[should_panic(expected = "is not checked by this checker")]
    fn a_keyword_it_does_not_know_stops_the_check() {
        errors(&json!(1), &json!({"multipleOf": 2}));
    }
}

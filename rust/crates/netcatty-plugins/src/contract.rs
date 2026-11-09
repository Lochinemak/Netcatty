//! Canonical plugin contract (JSON Schema 2020-12) and the JSON boundary
//! (ports of `contractValidator.cjs` and `jsonBoundary.cjs`).
//!
//! The schema is the committed `packages/plugin-contract/schema` file, so the
//! Rust host validates exactly the same wire messages as the Electron host.

use crate::constants::{PLUGIN_RPC_MAX_JSON_BYTES, PLUGIN_STREAM_MAX_FRAME_JSON_BYTES};
use crate::error::{codes, PluginError, PluginResult};
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

/// The committed contract schema.
pub const SCHEMA_JSON: &str =
    include_str!("../../../../packages/plugin-contract/schema/plugin-contract.schema.json");

pub const PLUGIN_JSON_MAX_DEPTH: usize = 128;
pub const PLUGIN_JSON_MAX_NODES: usize = 100_000;

pub fn schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| serde_json::from_str(SCHEMA_JSON).expect("plugin contract schema is valid JSON"))
}

/// A `$defs` constant (`{ "const": ... }`) of the contract.
pub fn def_const(name: &str) -> Option<&'static Value> {
    schema().get("$defs")?.get(name)?.get("const")
}

/// String value of a `$defs` constant (feature identifiers).
pub fn def_const_str(name: &str) -> &'static str {
    def_const(name).and_then(Value::as_str).unwrap_or("")
}

type Validator = Arc<jsonschema::Validator>;

fn validators() -> &'static Mutex<HashMap<String, Validator>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Validator>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Compile (once) a validator for `#/$defs/<definition>`.
pub fn definition_validator(definition: &str) -> PluginResult<Validator> {
    if let Some(found) = validators().lock().get(definition) {
        return Ok(found.clone());
    }
    let mut document = schema().clone();
    if document["$defs"].get(definition).is_none() {
        return Err(PluginError::host(format!(
            "Unknown plugin contract definition: {definition}"
        )));
    }
    document["$ref"] = Value::String(format!("#/$defs/{definition}"));
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .build(&document)
        .map_err(|err| PluginError::host(format!("plugin contract schema failed to compile: {err}")))?;
    let validator = Arc::new(validator);
    validators()
        .lock()
        .insert(definition.to_string(), validator.clone());
    Ok(validator)
}

/// First (up to eight) schema violations formatted like Ajv's
/// `instancePath message` pairs.
pub fn validation_errors(definition: &str, value: &Value) -> PluginResult<Vec<String>> {
    let validator = definition_validator(definition)?;
    Ok(validator
        .iter_errors(value)
        .take(8)
        .map(|err| {
            let path = err.instance_path.to_string();
            format!("{} {}", if path.is_empty() { "/" } else { &path }, err)
        })
        .collect())
}

pub fn is_valid(definition: &str, value: &Value) -> bool {
    definition_validator(definition)
        .map(|v| v.is_valid(value))
        .unwrap_or(false)
}

/// Throw-style assertion (`assertContractValue`).
pub fn assert_contract(definition: &str, value: &Value, label: &str) -> PluginResult<()> {
    let errors = validation_errors(definition, value)?;
    if errors.is_empty() {
        Ok(())
    } else {
        Err(PluginError::rpc(
            codes::INVALID_PARAMS,
            format!("{label} violates the plugin contract: {}", errors.join("; ")),
        ))
    }
}

/// Byte length of `value` serialized as compact JSON, counted like
/// `jsonStringByteLength` / `assertPluginJsonValue` (UTF-8 + escapes).
fn json_string_bytes(value: &str) -> usize {
    let mut bytes = 2;
    for ch in value.chars() {
        let code = ch as u32;
        bytes += match code {
            0x22 | 0x5c | 0x08 | 0x09 | 0x0a | 0x0c | 0x0d => 2,
            c if c < 0x20 => 6,
            c if c < 0x80 => 1,
            c if c < 0x800 => 2,
            c if c < 0x10000 => 3,
            _ => 4,
        };
    }
    bytes
}

/// `assertPluginJsonValue`: depth, node and byte budgets.
pub fn assert_json_value(value: &Value, max_bytes: usize) -> PluginResult<()> {
    let mut stack: Vec<(&Value, usize)> = vec![(value, 0)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;
    let too_big = || {
        PluginError::rpc(
            codes::INVALID_PARAMS,
            format!("Plugin JSON exceeds {max_bytes} bytes"),
        )
    };
    while let Some((item, depth)) = stack.pop() {
        nodes += 1;
        if nodes > PLUGIN_JSON_MAX_NODES {
            return Err(PluginError::rpc(
                codes::INVALID_PARAMS,
                format!("Plugin JSON exceeds {PLUGIN_JSON_MAX_NODES} values"),
            ));
        }
        if depth > PLUGIN_JSON_MAX_DEPTH {
            return Err(PluginError::rpc(
                codes::INVALID_PARAMS,
                format!("Plugin JSON exceeds {PLUGIN_JSON_MAX_DEPTH} levels"),
            ));
        }
        bytes += match item {
            Value::Null => 4,
            Value::Bool(true) => 4,
            Value::Bool(false) => 5,
            Value::Number(n) => n.to_string().len(),
            Value::String(s) => json_string_bytes(s),
            Value::Array(items) => {
                for child in items.iter().rev() {
                    stack.push((child, depth + 1));
                }
                (items.len() + 1).max(2)
            }
            Value::Object(map) => {
                let mut extra = (map.len() + 1).max(2);
                for (key, child) in map {
                    extra += json_string_bytes(key) + 1;
                    stack.push((child, depth + 1));
                }
                extra
            }
        };
        if bytes > max_bytes {
            return Err(too_big());
        }
    }
    Ok(())
}

/// Contract check of one RPC envelope (`assertRpcMessage`).
pub fn assert_rpc_message(value: &Value) -> PluginResult<()> {
    assert_json_value(value, PLUGIN_RPC_MAX_JSON_BYTES)?;
    assert_contract("RpcMessage", value, "RPC message")
}

pub fn assert_initialize_result(value: &Value) -> PluginResult<()> {
    assert_json_value(value, PLUGIN_RPC_MAX_JSON_BYTES)?;
    assert_contract("RuntimeInitializeResult", value, "Initialize result")
}

pub fn assert_stream_frame(value: &Value) -> PluginResult<()> {
    assert_json_value(value, PLUGIN_STREAM_MAX_FRAME_JSON_BYTES)?;
    assert_contract("StreamFrame", value, "Stream frame")
}

pub fn assert_provider_request(value: &Value) -> PluginResult<()> {
    assert_json_value(value, PLUGIN_RPC_MAX_JSON_BYTES)?;
    assert_contract("ProviderRequest", value, "Provider request")
}

pub fn assert_provider_result(value: &Value) -> PluginResult<()> {
    assert_json_value(value, PLUGIN_RPC_MAX_JSON_BYTES)?;
    assert_contract("ProviderResult", value, "Provider result")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn schema_compiles_and_validates_rpc_messages() {
        assert!(is_valid(
            "RpcMessage",
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "storage.get", "params": { "key": "a" } })
        ));
        assert!(!is_valid("RpcMessage", &json!({ "jsonrpc": "1.0", "id": 1 })));
        assert!(validation_errors("PluginId", &json!("com.netcatty.hello")).unwrap().is_empty());
        assert!(!validation_errors("PluginId", &json!("Bad Id")).unwrap().is_empty());
        assert!(!def_const_str("HostInteractionFeature").is_empty());
    }

    #[test]
    fn json_boundary_limits() {
        assert!(assert_json_value(&json!({ "a": [1, 2, "x"] }), 1024).is_ok());
        assert!(assert_json_value(&json!("x".repeat(100)), 50).is_err());
        let mut deep = json!(null);
        for _ in 0..200 {
            deep = json!([deep]);
        }
        assert!(assert_json_value(&deep, usize::MAX).is_err());
    }
}

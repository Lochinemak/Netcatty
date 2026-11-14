//! MCP-surface refinements layered over the verbatim catalog export.
//!
//! `data/catalog.json` types every tool input as a string or a number,
//! because that is what the Electron Zod schemas emitted: booleans travel as
//! `"true"`, arrays and objects as JSON text. That is awkward for a model and
//! invisible to a client, so the MCP surface advertises the real shape here
//! and [`normalize_arguments`] folds a typed call back into the string form
//! the backend has always received. The catalog itself stays untouched, so
//! regenerating it cannot lose any of this — the tests below fail instead
//! when an overlay entry no longer matches a catalog field.
//!
//! The same module derives the MCP tool annotations (`readOnlyHint`,
//! `destructiveHint`, …) from the capability policy, which lets clients
//! auto-approve reads and warn on destructive calls.

use crate::catalog::{CapabilityPolicy, InputField};
use serde_json::{json, Map, Value};

/// The real shape of a catalog field that is declared as a string.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FieldShape {
    Boolean,
    /// JSON array; the payload is the JSON type of its items.
    Array(&'static str),
    Object,
    Enum(&'static [&'static str]),
}

/// `capability` is an id prefix; `""` applies the entry to every capability
/// that has the field. The first matching entry wins.
struct Overlay {
    capability: &'static str,
    field: &'static str,
    shape: FieldShape,
}

const fn on(capability: &'static str, field: &'static str, shape: FieldShape) -> Overlay {
    Overlay { capability, field, shape }
}

const fn any(field: &'static str, shape: FieldShape) -> Overlay {
    Overlay { capability: "", field, shape }
}

const OVERLAYS: &[Overlay] = &[
    // Flags the catalog documents as "true or false" / "Set to true".
    any("newTab", FieldShape::Boolean),
    any("dryRun", FieldShape::Boolean),
    any("skipDuplicates", FieldShape::Boolean),
    any("savePassword", FieldShape::Boolean),
    any("moshEnabled", FieldShape::Boolean),
    any("etEnabled", FieldShape::Boolean),
    any("deleteHosts", FieldShape::Boolean),
    any("wait", FieldShape::Boolean),
    any("targetsAllHosts", FieldShape::Boolean),
    any("noAutoRun", FieldShape::Boolean),
    any("autoStart", FieldShape::Boolean),
    any("autoReconnect", FieldShape::Boolean),
    // "JSON array of …".
    any("hosts", FieldShape::Array("object")),
    any("documents", FieldShape::Array("object")),
    any("targets", FieldShape::Array("string")),
    any("targetGroups", FieldShape::Array("string")),
    any("scriptIds", FieldShape::Array("string")),
    any("linkedHostIds", FieldShape::Array("string")),
    any("jumpHostIds", FieldShape::Array("string")),
    any("tags", FieldShape::Array("string")),
    // "JSON object of …".
    any("variables", FieldShape::Object),
    any("defaults", FieldShape::Object),
    any("serialConfig", FieldShape::Object),
    any("environmentVariables", FieldShape::Object),
    // Closed value sets spelled out in the field description.
    on("portforward.rules.", "type", FieldShape::Enum(&["local", "remote", "dynamic"])),
    on("vault.snippets.", "kind", FieldShape::Enum(&["snippet", "script"])),
    on("vault.snippets.", "language", FieldShape::Enum(&["javascript", "python"])),
    any("trigger", FieldShape::Enum(&["manual", "onConnect", "onOutput"])),
    any("multiLineRunMode", FieldShape::Enum(&["paste", "lineDelay"])),
    any("startupCommandRunMode", FieldShape::Enum(&["paste", "lineDelay"])),
    on("vault.host.import", "format", FieldShape::Enum(&["auto", "csv", "putty", "mobaxterm", "securecrt", "finalshell", "ssh_config"])),
    on("vault.host.update", "protocol", FieldShape::Enum(&["ssh", "telnet", "local", "serial"])),
    on("vault.host.update", "os", FieldShape::Enum(&["auto", "linux", "windows", "macos", "freebsd", "unknown"])),
    on("harness.terminal.read_context", "range", FieldShape::Enum(&["viewport", "tail", "head", "lines"])),
    on("sftp.find", "type", FieldShape::Enum(&["file", "directory", "symlink"])),
];

/// Description of every `sessionId` input on the MCP surface: the host
/// resolves a session name as well as an id.
pub const SESSION_TARGET_DESCRIPTION: &str =
    "Target session: a sessionId from get_environment, or the session's exact label or hostname (also user@hostname). A name that matches several sessions is rejected with the candidates listed.";

/// The refined shape of `field` on `capability_id`, when it has one.
pub fn field_shape(capability_id: &str, field: &str, def: &InputField) -> Option<FieldShape> {
    if def.field_type != "string" {
        return None;
    }
    OVERLAYS
        .iter()
        .find(|o| o.field == field && capability_id.starts_with(o.capability))
        .map(|o| o.shape)
}

/// JSON Schema of one input field as advertised over MCP.
pub fn field_schema(capability_id: &str, field: &str, def: &InputField) -> Value {
    let mut prop = match field_shape(capability_id, field, def) {
        Some(FieldShape::Boolean) => json!({ "type": "boolean" }),
        Some(FieldShape::Array(items)) => json!({ "type": "array", "items": { "type": items } }),
        Some(FieldShape::Object) => json!({ "type": "object" }),
        Some(FieldShape::Enum(values)) => json!({ "type": "string", "enum": values }),
        None if def.field_type == "number" => json!({ "type": "integer", "minimum": 0 }),
        None => json!({ "type": "string" }),
    };
    let description = if field == "sessionId" { SESSION_TARGET_DESCRIPTION } else { def.description.as_str() };
    if !description.is_empty() {
        prop["description"] = Value::String(description.to_string());
    }
    prop
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Type-check one argument. A string is always accepted for a refined field:
/// that is the legacy wire form, and the backend still validates its content.
pub fn validate_field(capability_id: &str, field: &str, def: &InputField, value: &Value) -> Result<(), String> {
    if def.field_type == "number" {
        return match value.as_f64() {
            Some(n) if n >= 0.0 && n.fract() == 0.0 => Ok(()),
            _ => Err(format!("{field}: Expected a non-negative integer")),
        };
    }
    if value.is_string() {
        return Ok(());
    }
    let expected = match field_shape(capability_id, field, def) {
        Some(FieldShape::Boolean) if value.is_boolean() => return Ok(()),
        // The backend takes either form for these (`tags`, `environmentVariables`).
        Some(FieldShape::Array(_) | FieldShape::Object) if value.is_array() || value.is_object() => return Ok(()),
        Some(FieldShape::Boolean) => "boolean",
        Some(FieldShape::Array(_)) => "array",
        Some(FieldShape::Object) => "object",
        Some(FieldShape::Enum(_)) | None => "string",
    };
    Err(format!("{field}: Expected {expected}, received {}", type_name(value)))
}

/// Fold typed arguments back into the string form the backend receives:
/// booleans become `"true"` / `"false"`, arrays and objects JSON text.
/// Arguments that are already strings, and fields without an overlay, pass
/// through unchanged.
pub fn normalize_arguments(capability_id: &str, fields: &[(String, InputField)], args: &Map<String, Value>) -> Map<String, Value> {
    let mut out = args.clone();
    for (name, def) in fields {
        if field_shape(capability_id, name, def).is_none() {
            continue;
        }
        let Some(value) = out.get_mut(name) else {
            continue;
        };
        match value {
            Value::Bool(b) => *value = Value::String(b.to_string()),
            Value::Array(_) | Value::Object(_) => *value = Value::String(value.to_string()),
            _ => {}
        }
    }
    out
}

/// Human-readable title of a tool (`terminal_execute` → `Terminal execute`).
pub fn tool_title(mcp_tool: &str) -> String {
    let spaced = mcp_tool.replace('_', " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Write capabilities that only add state: nothing existing is changed or
/// removed, so they are not "destructive" in the MCP sense.
fn is_additive(capability_id: &str) -> bool {
    capability_id.ends_with(".create")
        || capability_id.ends_with(".import")
        || capability_id.ends_with(".duplicate")
        || matches!(
            capability_id,
            "sftp.mkdir" | "vault.host.open" | "portforward.start" | "session.reconnect" | "session.recover" | "vault.scripts.run.pause" | "vault.scripts.run.resume"
        )
}

/// Write capabilities where repeating the call with the same arguments
/// leaves the same state.
fn is_idempotent(capability_id: &str) -> bool {
    capability_id.ends_with(".set")
        || matches!(
            capability_id,
            "sftp.write" | "sftp.chmod" | "portforward.start" | "portforward.stop" | "terminal.stop" | "session.close" | "session.reconnect" | "session.recover"
        )
}

/// Capabilities that reach a remote host (or run code there) rather than
/// only reading or changing Netcatty's own vault.
fn is_open_world(capability_id: &str, domain: &str) -> bool {
    matches!(domain, "terminal" | "sftp")
        || matches!(
            capability_id,
            "vault.host.open" | "vault.snippets.run" | "vault.scripts.run" | "portforward.start" | "session.reconnect" | "session.recover" | "harness.terminal.read_context"
        )
}

/// MCP `annotations` of a tool, derived from its capability policy.
pub fn tool_annotations(capability_id: &str, domain: &str, mcp_tool: &str, policy: &CapabilityPolicy) -> Value {
    let mut out = json!({
        "title": tool_title(mcp_tool),
        "readOnlyHint": !policy.write,
        "openWorldHint": is_open_world(capability_id, domain),
    });
    if policy.write {
        out["destructiveHint"] = json!(!is_additive(capability_id));
        out["idempotentHint"] = json!(is_idempotent(capability_id));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{all_capabilities, tool_input_fields, CATALOG};

    fn def(capability: &str, field: &str) -> InputField {
        tool_input_fields(capability).unwrap().iter().find(|(n, _)| n == field).unwrap().1.clone()
    }

    /// A catalog regeneration that renames or retypes a field must not
    /// silently drop its overlay.
    #[test]
    fn every_overlay_matches_a_string_field_in_the_catalog() {
        for overlay in OVERLAYS {
            let hit = CATALOG.tool_input_fields.iter().any(|(id, fields)| {
                id.starts_with(overlay.capability) && fields.iter().any(|(n, f)| n == overlay.field && f.field_type == "string")
            });
            assert!(hit, "overlay {}{} matches no catalog field", overlay.capability, overlay.field);
        }
    }

    /// The reverse guard: a field the catalog documents as a flag or as JSON
    /// has to be covered, or the model is back to guessing string encodings.
    #[test]
    fn fields_documented_as_flags_or_json_are_refined() {
        for (id, fields) in &CATALOG.tool_input_fields {
            for (name, f) in fields {
                let d = f.description.as_str();
                let documented = d.starts_with("true or false") || d.starts_with("Set to true") || d.starts_with("Set true") || d.contains("JSON array") || d.contains("JSON object");
                if f.field_type == "string" && documented {
                    assert!(field_shape(id, name, f).is_some(), "{id}.{name} is documented as typed but has no overlay: {d}");
                }
            }
        }
    }

    #[test]
    fn schemas_carry_the_real_types() {
        let s = field_schema("vault.host.open", "newTab", &def("vault.host.open", "newTab"));
        assert_eq!(s["type"], "boolean");
        let s = field_schema("vault.hosts.create", "hosts", &def("vault.hosts.create", "hosts"));
        assert_eq!(s["type"], "array");
        assert_eq!(s["items"]["type"], "object");
        let s = field_schema("vault.snippets.run", "variables", &def("vault.snippets.run", "variables"));
        assert_eq!(s["type"], "object");
        let s = field_schema("portforward.rules.create", "type", &def("portforward.rules.create", "type"));
        assert_eq!(s["enum"], json!(["local", "remote", "dynamic"]));
        // Fields without an overlay keep the catalog schema.
        let s = field_schema("sftp.chmod", "mode", &def("sftp.chmod", "mode"));
        assert_eq!(s, json!({ "type": "string", "description": "Octal permission mode (e.g. 755)." }));
        let s = field_schema("terminal.execute", "sessionId", &def("terminal.execute", "sessionId"));
        assert_eq!(s["description"], SESSION_TARGET_DESCRIPTION);
        let s = field_schema("terminal.poll", "offset", &def("terminal.poll", "offset"));
        assert_eq!(s["type"], "integer");
    }

    #[test]
    fn validation_accepts_typed_and_legacy_string_forms() {
        let new_tab = def("vault.host.open", "newTab");
        assert!(validate_field("vault.host.open", "newTab", &new_tab, &json!(true)).is_ok());
        assert!(validate_field("vault.host.open", "newTab", &new_tab, &json!("true")).is_ok());
        assert_eq!(validate_field("vault.host.open", "newTab", &new_tab, &json!(1)).unwrap_err(), "newTab: Expected boolean, received number");
        let hosts = def("vault.hosts.create", "hosts");
        assert!(validate_field("vault.hosts.create", "hosts", &hosts, &json!([{ "hostname": "a" }])).is_ok());
        assert!(validate_field("vault.hosts.create", "hosts", &hosts, &json!("[]")).is_ok());
        assert!(validate_field("vault.hosts.create", "hosts", &hosts, &json!(true)).is_err());
        let command = def("terminal.execute", "command");
        assert_eq!(validate_field("terminal.execute", "command", &command, &json!(1)).unwrap_err(), "command: Expected string, received number");
        let offset = def("terminal.poll", "offset");
        assert!(validate_field("terminal.poll", "offset", &offset, &json!(3)).is_ok());
        assert!(validate_field("terminal.poll", "offset", &offset, &json!(-1)).is_err());
    }

    #[test]
    fn normalization_restores_the_backend_string_contract() {
        let fields = tool_input_fields("vault.snippets.run").unwrap();
        let args = json!({ "snippetId": "s", "sessionId": "x", "variables": { "a": 1 }, "wait": true });
        let out = normalize_arguments("vault.snippets.run", fields, args.as_object().unwrap());
        assert_eq!(Value::Object(out), json!({ "snippetId": "s", "sessionId": "x", "variables": "{\"a\":1}", "wait": "true" }));
        // Legacy callers are untouched.
        let args = json!({ "snippetId": "s", "sessionId": "x", "wait": "true" });
        let out = normalize_arguments("vault.snippets.run", fields, args.as_object().unwrap());
        assert_eq!(Value::Object(out), args);
        let fields = tool_input_fields("vault.host.update").unwrap();
        let args = json!({ "hostId": "h", "tags": ["a", "b"], "port": 22, "moshEnabled": false });
        let out = normalize_arguments("vault.host.update", fields, args.as_object().unwrap());
        assert_eq!(Value::Object(out), json!({ "hostId": "h", "tags": "[\"a\",\"b\"]", "port": 22, "moshEnabled": "false" }));
    }

    #[test]
    fn annotations_follow_the_policy() {
        let ann = |id: &str| {
            let cap = all_capabilities().iter().find(|c| c.id == id).unwrap();
            tool_annotations(&cap.id, &cap.domain, "x_y", &cap.policy)
        };
        let read = ann("sftp.read");
        assert_eq!(read["readOnlyHint"], true);
        assert_eq!(read["openWorldHint"], true);
        assert!(read.get("destructiveHint").is_none());
        let exec = ann("terminal.execute");
        assert_eq!((exec["readOnlyHint"].clone(), exec["destructiveHint"].clone()), (json!(false), json!(true)));
        let create = ann("vault.hosts.create");
        assert_eq!((create["destructiveHint"].clone(), create["openWorldHint"].clone()), (json!(false), json!(false)));
        assert_eq!(ann("vault.host.delete")["destructiveHint"], true);
        assert_eq!(ann("vault.host.notes.set")["idempotentHint"], true);
        assert_eq!(ann("vault.host.list")["readOnlyHint"], true);
        assert_eq!(tool_title("terminal_execute"), "Terminal execute");
        // No write capability may be advertised as read-only.
        for cap in all_capabilities() {
            let a = tool_annotations(&cap.id, &cap.domain, "t", &cap.policy);
            assert_eq!(a["readOnlyHint"], !cap.policy.write, "{}", cap.id);
        }
    }
}

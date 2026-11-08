//! Tool surfaces generated from the catalog (Electron
//! `codegen/toolSurfaces.cjs`, `adapters/mcpAdapter.cjs`,
//! `adapters/cliAdapter.cjs`).

use crate::catalog::*;
use crate::registry::{capability_by_cli_command, capability_by_rpc_method, list_capabilities, ListFilter};
use serde::Serialize;
use serde_json::{json, Map, Value};

/// One MCP tool definition.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolDef {
    pub capability_id: String,
    pub domain: String,
    pub mcp_tool: String,
    /// Builtin RPC method when the capability has one, else the public one.
    pub rpc_method: String,
    pub public_rpc_method: Option<String>,
    pub description: String,
    pub policy: CapabilityPolicy,
    pub input_fields: InputFields,
}

impl McpToolDef {
    pub fn has_inputs(&self) -> bool {
        !self.input_fields.is_empty()
    }

    /// JSON Schema of the tool input (what the MCP SDK emits for the
    /// generated Zod object: strings, non-negative integers, `required`).
    pub fn input_schema(&self) -> Value {
        if self.input_fields.is_empty() {
            return json!({ "type": "object", "properties": {} });
        }
        let mut properties = Map::new();
        let mut required = Vec::new();
        for (name, field) in &self.input_fields {
            let mut prop = if field.field_type == "number" {
                json!({ "type": "integer", "minimum": 0 })
            } else {
                json!({ "type": "string" })
            };
            if !field.description.is_empty() {
                prop["description"] = Value::String(field.description.clone());
            }
            properties.insert(name.clone(), prop);
            if !field.optional {
                required.push(Value::String(name.clone()));
            }
        }
        let mut schema = json!({
            "type": "object",
            "properties": properties,
            "additionalProperties": false,
            "$schema": "http://json-schema.org/draft-07/schema#",
        });
        if !required.is_empty() {
            schema["required"] = Value::Array(required);
        }
        schema
    }
}

pub fn mcp_tool_name(cap: &Capability) -> Option<String> {
    cap.surface(SURFACE_PUBLIC)
        .and_then(|b| b.mcp_tool.clone())
        .or_else(|| cap.surface(SURFACE_BUILTIN).and_then(|b| b.mcp_tool.clone()))
}

/// Description with the long-form model hint appended.
pub fn build_tool_description(cap: &Capability) -> String {
    match CATALOG.model_description_hints.get(&cap.id) {
        Some(hint) => format!("{} {hint}", cap.description),
        None => cap.description.clone(),
    }
}

/// Every implemented catalog tool exposed over MCP (`listMcpTools`).
pub fn list_mcp_tools() -> Vec<McpToolDef> {
    let mut out = Vec::new();
    for cap in all_capabilities().iter().filter(|c| c.is_implemented()) {
        let binding = cap.surface(SURFACE_PUBLIC).or_else(|| cap.surface(SURFACE_BUILTIN));
        let Some(binding) = binding else {
            continue;
        };
        let Some(mcp_tool) = mcp_tool_name(cap) else {
            continue;
        };
        let rpc_method = cap
            .surface(SURFACE_BUILTIN)
            .and_then(|b| b.rpc_method.clone())
            .or_else(|| binding.rpc_method.clone());
        let Some(rpc_method) = rpc_method else {
            continue;
        };
        out.push(McpToolDef {
            capability_id: cap.id.clone(),
            domain: cap.domain.clone(),
            mcp_tool,
            rpc_method,
            public_rpc_method: cap.surface(SURFACE_PUBLIC).and_then(|b| b.rpc_method.clone()),
            description: build_tool_description(cap),
            policy: cap.policy.clone(),
            input_fields: tool_input_fields(&cap.id).cloned().unwrap_or_default(),
        });
    }
    out
}

/// Catalog description of an MCP tool (`getCatalogToolDescription`).
pub fn catalog_tool_description(tool: &str) -> Option<String> {
    list_mcp_tools().into_iter().find(|t| t.mcp_tool == tool).map(|t| t.description)
}

/// MCP tool name used in approval cards (`getMcpToolNameForRpcMethod`).
pub fn mcp_tool_name_for_rpc_method(rpc_method: &str, surface: &str) -> Option<String> {
    let cap = capability_by_rpc_method(rpc_method, surface)?;
    cap.surface(surface)
        .and_then(|b| b.mcp_tool.clone())
        .or_else(|| mcp_tool_name(cap))
}

// ── CLI adapter ───────────────────────────────────────────────────────

/// `TOOL_INPUT_FIELDS` key → (CLI flag, opts key).
pub fn cli_field_binding(field: &str) -> Option<(&'static str, &'static str)> {
    Some(match field {
        "hostId" => ("--host-id", "hostId"),
        "workspaceId" => ("--workspace-id", "workspaceId"),
        "newTab" => ("--new-tab", "newTab"),
        "filename" => ("--filename", "filename"),
        "snippetId" => ("--snippet-id", "snippetId"),
        "scriptId" => ("--script-id", "scriptId"),
        "runId" => ("--run-id", "runId"),
        "ruleId" => ("--rule-id", "ruleId"),
        "notes" => ("--notes", "notes"),
        "noteId" => ("--note-id", "noteId"),
        "title" => ("--title", "title"),
        "group" => ("--group", "group"),
        "linkedHostIds" => ("--linked-host-ids", "linkedHostIds"),
        "tags" => ("--tags", "tags"),
        "maxChars" => ("--max-chars", "maxChars"),
        "query" => ("--query", "query"),
        "expectedUpdatedAt" => ("--expected-updated-at", "expectedUpdatedAt"),
        "fileName" => ("--file-name", "fileName"),
        "documents" => ("--documents", "documents"),
        "sessionId" => ("--session", "sessionId"),
        "variables" => ("--variables", "variables"),
        "wait" => ("--wait", "wait"),
        "scriptIds" => ("--script-ids", "scriptIds"),
        "label" => ("--label", "label"),
        "kind" => ("--kind", "kind"),
        "trigger" => ("--trigger", "trigger"),
        "triggerPattern" => ("--trigger-pattern", "triggerPattern"),
        "targets" => ("--targets", "targets"),
        "targetGroups" => ("--target-groups", "targetGroups"),
        "targetsAllHosts" => ("--targets-all-hosts", "targetsAllHosts"),
        "description" => ("--description", "description"),
        "language" => ("--language", "language"),
        "package" => ("--package", "package"),
        "shortkey" => ("--shortkey", "shortkey"),
        "noAutoRun" => ("--no-auto-run", "noAutoRun"),
        "multiLineRunMode" => ("--multi-line-run-mode", "multiLineRunMode"),
        "path" | "remotePath" => ("--remote-path", "remotePath"),
        "localPath" => ("--local-path", "localPath"),
        "oldPath" => ("--old-remote-path", "oldRemotePath"),
        "newPath" => ("--new-remote-path", "newRemotePath"),
        "content" => ("--content", "content"),
        "mode" => ("--mode", "mode"),
        "command" => ("--", "command"),
        "jobId" => ("--job", "jobId"),
        "offset" => ("--offset", "offset"),
        _ => return None,
    })
}

fn resolve_cli_rpc_method(cap: &Capability) -> Option<String> {
    [SURFACE_BUILTIN, SURFACE_GLOBAL, SURFACE_PUBLIC]
        .iter()
        .find_map(|s| cap.surface(s).and_then(|b| b.rpc_method.clone()))
}

pub fn cli_rpc_method(parts: &[String]) -> Option<String> {
    capability_by_cli_command(parts).and_then(resolve_cli_rpc_method)
}

/// One entry of `capabilities --json`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliCapability {
    pub id: String,
    pub domain: String,
    pub status: String,
    pub description: String,
    pub command: Vec<String>,
    pub rpc_method: Option<String>,
    pub policy: CapabilityPolicy,
}

/// `status: None` lists every status.
pub fn list_cli_capabilities(status: Option<&str>) -> Vec<CliCapability> {
    list_capabilities(&ListFilter { status, surface: Some(SURFACE_CLI), ..Default::default() })
        .into_iter()
        .filter_map(|cap| {
            let command = cap.surface(SURFACE_CLI)?.command.clone()?;
            Some(CliCapability {
                id: cap.id.clone(),
                domain: cap.domain.clone(),
                status: cap.status.clone(),
                description: cap.description.clone(),
                command,
                rpc_method: resolve_cli_rpc_method(cap),
                policy: cap.policy.clone(),
            })
        })
        .collect()
}

pub fn format_cli_help_lines() -> Vec<String> {
    list_cli_capabilities(Some(STATUS_IMPLEMENTED))
        .into_iter()
        .map(|e| {
            let suffix = if e.status == STATUS_PLANNED { " (planned)" } else { "" };
            format!("  netcatty-tool-cli {}{suffix}", e.command.join(" "))
        })
        .collect()
}

/// `(code, message)` CLI error.
pub type CliError = (String, String);

/// Map parsed CLI options (keyed by opts key) to RPC params.
pub fn build_catalog_cli_params(capability_id: &str, opts: &Map<String, Value>) -> Result<Map<String, Value>, CliError> {
    let Some(fields) = tool_input_fields(capability_id) else {
        return Ok(Map::new());
    };
    let mut params = Map::new();
    for (name, def) in fields {
        let Some((flag, opt_key)) = cli_field_binding(name) else {
            continue;
        };
        let mut value = opts.get(opt_key).cloned().unwrap_or(Value::Null);
        if name == "command" {
            if let Value::Array(items) = &value {
                value = if items.len() == 1 { items[0].clone() } else { Value::Null };
            }
        }
        if name == "variables" {
            if let Some(text) = value.as_str().filter(|s| !s.trim().is_empty()) {
                value = serde_json::from_str(text).map_err(|_| {
                    ("INVALID_ARGUMENT".to_string(), format!("--variables must be valid JSON for {capability_id}."))
                })?;
            }
        }
        if matches!(name.as_str(), "offset" | "maxChars" | "expectedUpdatedAt") && !value.is_null() {
            let n = match &value {
                Value::Number(n) => n.as_f64(),
                Value::String(s) => s.trim().parse::<f64>().ok(),
                _ => None,
            };
            value = n.and_then(serde_json::Number::from_f64).map(Value::Number).unwrap_or(Value::Null);
            if let Value::Number(n) = &value {
                if let Some(i) = n.as_f64().filter(|f| f.fract() == 0.0) {
                    value = json!(i as i64);
                }
            }
        }
        let empty = value.as_str() == Some("");
        if value.is_null() || (empty && !def.allow_empty) {
            if !def.optional {
                return Err((
                    "INVALID_ARGUMENT".into(),
                    format!("Missing required {flag} for {capability_id}."),
                ));
            }
            continue;
        }
        params.insert(name.clone(), value);
    }
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn mcp_tools_match_electron() {
        let tools = list_mcp_tools();
        assert_eq!(tools.len(), 71);
        let names: HashSet<_> = tools.iter().map(|t| t.mcp_tool.as_str()).collect();
        for n in ["host_open", "vault_hosts_update", "vault_hosts_delete", "session_close", "session_reconnect", "terminal_read_context"] {
            assert!(names.contains(n), "{n}");
        }
        let exec = tools.iter().find(|t| t.mcp_tool == "terminal_execute").unwrap();
        assert_eq!(exec.rpc_method, "netcatty/exec");
        assert!(exec.description.contains("instead of the local shell"));
        let schema = exec.input_schema();
        assert_eq!(schema["required"], json!(["sessionId", "command"]));
        let poll = tools.iter().find(|t| t.mcp_tool == "terminal_poll").unwrap();
        assert_eq!(poll.input_schema()["properties"]["offset"]["type"], "integer");
        let env = tools.iter().find(|t| t.mcp_tool == "get_environment").unwrap();
        assert!(!env.has_inputs());
        let host_list = tools.iter().find(|t| t.mcp_tool == "vault_hosts_list").unwrap();
        assert_eq!(host_list.rpc_method, "public/vault/hosts/list");
        assert!(catalog_tool_description("host_open").unwrap().contains("session_close"));
        assert_eq!(mcp_tool_name_for_rpc_method("vault/host/notes/set", SURFACE_GLOBAL).as_deref(), Some("host_notes_set"));
    }

    #[test]
    fn cli_adapter() {
        assert_eq!(cli_rpc_method(&["exec".into()]).as_deref(), Some("netcatty/exec"));
        assert_eq!(
            cli_rpc_method(&["vault".into(), "host".into(), "get".into()]).as_deref(),
            Some("vault/host/get")
        );
        let caps = list_cli_capabilities(Some(STATUS_IMPLEMENTED));
        assert!(caps.iter().any(|c| c.id == "terminal.execute"));
        assert!(caps.iter().any(|c| c.id == "portforward.rules.list"));
        let opts = json!({ "hostId": "host-1", "newTab": "true", "workspaceId": "current" });
        assert_eq!(
            Value::Object(build_catalog_cli_params("vault.host.open", opts.as_object().unwrap()).unwrap()),
            json!({ "hostId": "host-1", "workspaceId": "current", "newTab": "true" })
        );
        let opts = json!({ "snippetId": "s", "sessionId": "x", "variables": "{\"a\":1}" });
        let p = build_catalog_cli_params("vault.snippets.run", opts.as_object().unwrap()).unwrap();
        assert_eq!(p["variables"], json!({ "a": 1 }));
        let err = build_catalog_cli_params("vault.host.get", &Map::new()).unwrap_err();
        assert_eq!(err.1, "Missing required --host-id for vault.host.get.");
        let opts = json!({ "title": "t", "content": "" });
        let p = build_catalog_cli_params("vault.note.create", opts.as_object().unwrap()).unwrap();
        assert_eq!(p["content"], "");
        let opts = json!({ "noteId": "n", "group": "", "tags": "" });
        let p = build_catalog_cli_params("vault.note.update", opts.as_object().unwrap()).unwrap();
        assert_eq!(p.get("group"), Some(&json!("")));
        assert!(p.get("tags").is_none());
        let opts = json!({ "noteId": "n", "offset": "10", "expectedUpdatedAt": 5 });
        let p = build_catalog_cli_params("vault.note.get", opts.as_object().unwrap()).unwrap();
        assert_eq!(p["offset"], json!(10));
        assert_eq!(p["expectedUpdatedAt"], json!(5));
        assert!(format_cli_help_lines().iter().any(|l| l == "  netcatty-tool-cli exec"));
    }
}

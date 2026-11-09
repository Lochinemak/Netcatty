//! MCP server protocol core shared by the stdio helper (`--mcp-server`)
//! and the External MCP streamable-HTTP server. Ports
//! `electron/mcp/progressiveMcpTools.cjs`, `netcattyMcpInstructions.cjs`,
//! `normalizeMcpCallArguments.cjs` and the tool handlers of
//! `electron/capabilities/codegen/mcpToolRegistry.cjs`; the JSON-RPC subset
//! is what `@modelcontextprotocol/sdk`'s `McpServer` answers.

use netcatty_capabilities::surfaces::{list_mcp_tools, McpToolDef};
use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

pub const SERVER_NAME: &str = "netcatty-remote-hosts";
pub const SERVER_VERSION: &str = "1.0.0";
pub const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 4] = ["2025-06-18", "2025-03-26", "2024-11-05", "2024-10-07"];

pub const NETCATTY_MCP_SERVER_INSTRUCTIONS: &str = "Use Netcatty tools for terminals, hosts, SFTP, vault, snippets/scripts, and port forwards. For terminal work, call get_environment first; select by label or hostname and pass sessionId to terminal_execute/terminal_start. Never use the local shell for Netcatty session commands. If none matches, use vault_hosts_list and host_open. 15 core tools start loaded. For attachments, advanced SFTP, vault/notes, snippets, scripts, or port forwards, call load_netcatty_tools with a toolset; use all for every tool.";

pub const MCP_TOOL_LOADER_NAME: &str = "load_netcatty_tools";
const LOADER_DESCRIPTION: &str = "Load more Netcatty tools by category. Choose sessions, attachments, sftp_advanced, vault_hosts, vault_notes, snippets, scripts, portforward, or all. Newly loaded tools appear immediately without restarting the MCP server.";
const OBSERVER_MESSAGE: &str = "Operation denied: permission mode is \"observer\" (read-only). Change to \"confirm\" or \"auto\" in Settings → AI → Safety to allow this action.";

pub const CORE_MCP_TOOL_NAMES: [&str; 14] = [
    "get_environment", "session_close", "terminal_execute", "terminal_start", "terminal_poll", "terminal_stop", "sftp_list",
    "sftp_read_file", "sftp_write_file", "sftp_download", "sftp_upload", "vault_hosts_list", "host_open", "terminal_read_context",
];

pub fn deferred_toolsets() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("sessions", vec!["session_reconnect", "session_recover"]),
        ("attachments", vec!["list_attachments", "read_attachment"]),
        ("sftp_advanced", vec!["sftp_stat", "sftp_home", "sftp_mkdir", "sftp_delete", "sftp_rename", "sftp_chmod"]),
        ("vault_hosts", vec![
            "host_get", "vault_hosts_create", "vault_hosts_update", "vault_hosts_delete", "vault_hosts_import", "host_notes_get", "host_notes_set",
            "vault_identities_list", "vault_proxy_profiles_list", "vault_groups_list", "vault_groups_create", "vault_groups_update", "vault_groups_delete",
        ]),
        ("vault_notes", vec!["vault_notes_list", "vault_notes_get", "vault_notes_create", "vault_notes_update", "vault_notes_delete", "vault_notes_import"]),
        ("snippets", vec!["snippets_list", "snippets_get", "snippets_run", "snippets_create", "snippets_update", "snippets_delete"]),
        ("scripts", vec![
            "scripts_list", "scripts_get", "scripts_create", "scripts_update", "scripts_delete", "scripts_run", "scripts_reference", "scripts_runs_list",
            "scripts_run_stop", "scripts_run_pause", "scripts_run_resume", "scripts_targets_set", "host_connect_scripts_list", "host_connect_scripts_set",
        ]),
        ("portforward", vec![
            "portforward_rules_list", "portforward_tunnels_list", "portforward_rules_create", "portforward_rules_update", "portforward_rules_duplicate",
            "portforward_rules_delete", "portforward_start", "portforward_stop",
        ]),
    ]
}

pub fn loadable_toolset_names() -> Vec<&'static str> {
    let mut v: Vec<&str> = deferred_toolsets().into_iter().map(|(n, _)| n).collect();
    v.push("all");
    v
}

/// Validate the progressive mapping (every catalog tool exactly once).
pub fn build_progressive_catalog() -> Result<(BTreeMap<String, McpToolDef>, Vec<String>), String> {
    let tools = list_mcp_tools();
    let by_name: BTreeMap<String, McpToolDef> = tools.iter().map(|t| (t.mcp_tool.clone(), t.clone())).collect();
    let mut assigned: Vec<String> = CORE_MCP_TOOL_NAMES.iter().map(|s| s.to_string()).collect();
    for (_, names) in deferred_toolsets() {
        assigned.extend(names.iter().map(|s| s.to_string()));
    }
    let set: HashSet<&String> = assigned.iter().collect();
    let duplicates = assigned.len() != set.len();
    let unknown: Vec<&String> = assigned.iter().filter(|n| !by_name.contains_key(*n)).collect();
    let missing: Vec<&String> = tools.iter().map(|t| &t.mcp_tool).filter(|n| !set.contains(n)).collect();
    if duplicates || !unknown.is_empty() || !missing.is_empty() {
        return Err(format!("Invalid progressive MCP tool mapping: duplicates={duplicates} unknown={unknown:?} missing={missing:?}"));
    }
    let deferred = assigned[CORE_MCP_TOOL_NAMES.len()..].to_vec();
    Ok((by_name, deferred))
}

/// Calls the Netcatty RPC host (TCP bridge or in-process dispatch).
#[async_trait::async_trait]
pub trait RpcCaller: Send + Sync {
    async fn call(&self, method: &str, params: Value) -> Result<Value, String>;
}

/// `true` when write tools must be denied (observer mode).
pub type ObserverCheck = Arc<dyn Fn() -> bool + Send + Sync>;

fn text_result(text: String, is_error: bool) -> Value {
    let mut v = json!({ "content": [{ "type": "text", "text": text }] });
    if is_error {
        v["isError"] = json!(true);
    }
    v
}

pub fn format_rpc_error(result: &Value) -> String {
    if let Some(e) = result.get("error").filter(|e| !e.is_null()) {
        let s = e.as_str().map(str::to_string).unwrap_or_else(|| e.to_string());
        return format!("Error: {s}");
    }
    if let Some(c) = result.get("code").filter(|c| !c.is_null()) {
        let s = c.as_str().map(str::to_string).unwrap_or_else(|| c.to_string());
        return format!("Error: Operation failed ({s})");
    }
    "Error: Operation failed".into()
}

fn non_empty_str(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

fn has_terminal_execute_evidence(r: &Value) -> bool {
    non_empty_str(r, "stdout").is_some() || non_empty_str(r, "stderr").is_some() || r.get("exitCode").is_some_and(|c| !c.is_null())
}

pub fn format_terminal_execute_result(r: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(s) = non_empty_str(r, "stdout") {
        parts.push(s);
    }
    if let Some(s) = non_empty_str(r, "stderr") {
        parts.push(format!("[stderr] {s}"));
    }
    if let Some(c) = r.get("exitCode").filter(|c| !c.is_null()) {
        parts.push(format!("[exit code: {c}]"));
    }
    if let Some(e) = non_empty_str(r, "error") {
        parts.push(format!("[error] {e}"));
    }
    parts.join("\n")
}

/// `formatTerminalExecuteMcpResponse` (#2718 / #2724 semantics).
pub fn format_terminal_execute_response(r: &Value) -> Value {
    if !r.is_object() {
        return text_result(format_rpc_error(r), true);
    }
    let failed = r.get("ok").and_then(Value::as_bool) == Some(false);
    if failed && !has_terminal_execute_evidence(r) {
        return text_result(format_rpc_error(r), true);
    }
    let mut text = format_terminal_execute_result(r);
    if text.is_empty() {
        text = "Command completed (no output)".into();
    }
    text_result(text, failed && non_empty_str(r, "error").is_some())
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

/// Run one catalog tool (`createToolHandler`).
pub async fn call_catalog_tool(tool: &McpToolDef, args: &Map<String, Value>, rpc: &dyn RpcCaller, scope: &Map<String, Value>, observer: &ObserverCheck) -> Result<Value, String> {
    let name = tool.mcp_tool.as_str();
    let with = |extra: Value| -> Value {
        let mut p = scope.clone();
        if let Value::Object(m) = extra {
            for (k, v) in m {
                if !v.is_null() {
                    p.insert(k, v);
                }
            }
        }
        Value::Object(p)
    };
    let failed = |r: &Value| r.get("ok").and_then(Value::as_bool) == Some(false);
    match name {
        "terminal_execute" | "terminal_start" => {
            if observer() {
                return Ok(text_result(format!("Error: {OBSERVER_MESSAGE}"), true));
            }
            let r = rpc.call(&tool.rpc_method, with(json!({ "sessionId": args.get("sessionId"), "command": args.get("command") }))).await?;
            if name == "terminal_start" {
                if r.get("ok").and_then(Value::as_bool) != Some(true) {
                    return Ok(text_result(format_rpc_error(&r), true));
                }
                let summary = json!({
                    "jobId": r.get("jobId"), "sessionId": r.get("sessionId"), "status": r.get("status"), "startedAt": r.get("startedAt"),
                    "outputMode": r.get("outputMode"), "recommendedPollIntervalMs": r.get("recommendedPollIntervalMs"),
                });
                return Ok(text_result(pretty(&summary), false));
            }
            Ok(format_terminal_execute_response(&r))
        }
        "terminal_poll" | "terminal_stop" => {
            let params = if name == "terminal_poll" {
                with(json!({ "jobId": args.get("jobId"), "offset": args.get("offset").cloned().filter(|v| !v.is_null()).unwrap_or(json!(0)) }))
            } else {
                with(json!({ "jobId": args.get("jobId") }))
            };
            let r = rpc.call(&tool.rpc_method, params).await?;
            if r.get("ok").and_then(Value::as_bool) != Some(true) {
                return Ok(text_result(format_rpc_error(&r), true));
            }
            Ok(text_result(pretty(&r), false))
        }
        "session_close" => {
            let r = rpc.call(&tool.rpc_method, with(json!({ "sessionId": args.get("sessionId") }))).await?;
            if r.get("ok").and_then(Value::as_bool) != Some(true) {
                return Ok(text_result(format_rpc_error(&r), true));
            }
            Ok(text_result(pretty(&r), false))
        }
        "get_environment" => Ok(text_result(pretty(&rpc.call(&tool.rpc_method, Value::Object(scope.clone())).await?), false)),
        "list_attachments" => {
            let r = rpc.call(&tool.rpc_method, Value::Object(scope.clone())).await?;
            if r.get("ok").and_then(Value::as_bool) != Some(true) {
                return Ok(text_result(format_rpc_error(&r), true));
            }
            Ok(text_result(pretty(r.get("attachments").unwrap_or(&json!([]))), false))
        }
        "read_attachment" => {
            let r = rpc.call(&tool.rpc_method, with(json!({ "filePath": args.get("filePath"), "filename": args.get("filename") }))).await?;
            if r.get("ok").and_then(Value::as_bool) != Some(true) {
                return Ok(text_result(format_rpc_error(&r), true));
            }
            let mut payload = json!({ "filename": r.get("filename"), "mediaType": r.get("mediaType"), "filePath": r.get("filePath"), "sizeBytes": r.get("sizeBytes") });
            match r.get("text").filter(|t| !t.is_null()) {
                Some(t) => payload["text"] = t.clone(),
                None => payload["base64Data"] = r.get("base64Data").cloned().unwrap_or(Value::Null),
            }
            Ok(text_result(pretty(&payload), false))
        }
        _ => {
            if tool.policy.write && observer() {
                return Ok(text_result(format!("Error: {OBSERVER_MESSAGE}"), true));
            }
            let r = rpc.call(&tool.rpc_method, with(Value::Object(args.clone()))).await?;
            if r.is_object() && failed(&r) {
                return Ok(text_result(format_rpc_error(&r), true));
            }
            Ok(text_result(pretty(&r), false))
        }
    }
}

/// Validate tool arguments against the catalog schema.
pub fn validate_arguments(tool: &McpToolDef, args: &Map<String, Value>) -> Result<(), String> {
    for (name, field) in &tool.input_fields {
        match args.get(name) {
            None | Some(Value::Null) => {
                if !field.optional {
                    return Err(format!("{name}: Required"));
                }
            }
            Some(v) => {
                if field.field_type == "number" {
                    if !v.as_f64().is_some_and(|n| n >= 0.0 && n.fract() == 0.0) {
                        return Err(format!("{name}: Expected a non-negative integer"));
                    }
                } else if !v.is_string() {
                    return Err(format!("{name}: Expected string, received {}", type_name(v)));
                }
            }
        }
    }
    Ok(())
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

/// One MCP server session (one stdio process or one HTTP session).
pub struct McpSession {
    rpc: Arc<dyn RpcCaller>,
    scope: Map<String, Value>,
    observer: ObserverCheck,
    by_name: BTreeMap<String, McpToolDef>,
    deferred: Vec<String>,
    /// `None` = progressive disabled; tools visible are this allow-list.
    loaded: Mutex<Vec<String>>,
    progressive: bool,
}

/// Outcome of handling a message: optional response + notifications to send.
pub struct Handled {
    pub response: Option<Value>,
    pub notifications: Vec<Value>,
}

impl McpSession {
    /// `scope`: params merged into every RPC (`{ chatSessionId }` or
    /// `{ scopedSessionIds, chatSessionId }`). `delegated_tools`: fixed tool
    /// set without the progressive loader.
    pub fn new(rpc: Arc<dyn RpcCaller>, scope: Map<String, Value>, observer: ObserverCheck, delegated_tools: Option<Vec<String>>) -> Self {
        let (by_name, deferred) = build_progressive_catalog().expect("progressive MCP catalog");
        let (loaded, progressive) = match delegated_tools {
            Some(list) => (list.into_iter().filter(|n| by_name.contains_key(n)).collect(), false),
            None => (CORE_MCP_TOOL_NAMES.iter().map(|s| s.to_string()).collect(), true),
        };
        Self { rpc, scope, observer, by_name, deferred, loaded: Mutex::new(loaded), progressive }
    }

    pub fn visible_tool_names(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.progressive {
            v.push(MCP_TOOL_LOADER_NAME.to_string());
        }
        v.extend(self.loaded.lock().iter().cloned());
        v
    }

    fn tool_list(&self) -> Value {
        let mut tools = Vec::new();
        if self.progressive {
            tools.push(json!({
                "name": MCP_TOOL_LOADER_NAME,
                "description": LOADER_DESCRIPTION,
                "inputSchema": {
                    "type": "object",
                    "properties": { "toolset": { "type": "string", "enum": loadable_toolset_names(), "description": "Netcatty tool category to load" } },
                    "required": ["toolset"],
                    "additionalProperties": false,
                    "$schema": "http://json-schema.org/draft-07/schema#",
                },
            }));
        }
        for name in self.loaded.lock().iter() {
            if let Some(t) = self.by_name.get(name) {
                tools.push(json!({ "name": t.mcp_tool, "description": t.description, "inputSchema": t.input_schema() }));
            }
        }
        json!({ "tools": tools })
    }

    fn load_toolset(&self, toolset: &str) -> (Value, bool) {
        let requested: Vec<String> = if toolset == "all" {
            self.deferred.clone()
        } else {
            deferred_toolsets().into_iter().find(|(n, _)| *n == toolset).map(|(_, v)| v.iter().map(|s| s.to_string()).collect()).unwrap_or_default()
        };
        let mut loaded = self.loaded.lock();
        let newly: Vec<String> = requested.iter().filter(|n| !loaded.contains(n)).cloned().collect();
        let already: Vec<String> = requested.iter().filter(|n| loaded.contains(n)).cloned().collect();
        loaded.extend(newly.iter().cloned());
        let count = loaded.len();
        let payload = json!({
            "toolset": toolset,
            "newlyLoaded": newly,
            "alreadyLoaded": already,
            "availableToolsets": loadable_toolset_names(),
            "loadedCatalogToolCount": count,
            "visibleToolCount": count + 1,
            "remainingCatalogToolCount": self.by_name.len() - count,
        });
        (text_result(pretty(&payload), false), !newly.is_empty())
    }

    async fn call_tool(&self, name: &str, args: Map<String, Value>) -> Result<(Value, bool), (i64, String)> {
        if self.progressive && name == MCP_TOOL_LOADER_NAME {
            let toolset = args.get("toolset").and_then(Value::as_str).unwrap_or("");
            if !loadable_toolset_names().contains(&toolset) {
                return Ok((text_result(format!("MCP error -32602: Input validation error: Invalid arguments for tool {name}: toolset: Invalid enum value"), true), false));
            }
            return Ok(self.load_toolset(toolset));
        }
        if !self.loaded.lock().iter().any(|n| n == name) {
            return Err((-32602, format!("MCP error -32602: Tool {name} not found")));
        }
        let tool = self.by_name.get(name).ok_or((-32602, format!("MCP error -32602: Tool {name} not found")))?;
        if let Err(e) = validate_arguments(tool, &args) {
            return Ok((text_result(format!("MCP error -32602: Input validation error: Invalid arguments for tool {name}: {e}"), true), false));
        }
        match call_catalog_tool(tool, &args, &*self.rpc, &self.scope, &self.observer).await {
            Ok(v) => Ok((v, false)),
            Err(e) => Ok((text_result(e, true), false)),
        }
    }

    /// Handle one JSON-RPC message (request or notification).
    pub async fn handle(&self, msg: Value) -> Handled {
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("").to_string();
        let mut params = msg.get("params").cloned().unwrap_or(json!({}));
        if method == "tools/call" && params.is_object() && params.get("arguments").is_none_or(Value::is_null) {
            params["arguments"] = json!({});
        }
        let ok = |result: Value| Handled { response: id.clone().map(|id| json!({ "jsonrpc": "2.0", "id": id, "result": result })), notifications: Vec::new() };
        let err = |code: i64, message: String| Handled {
            response: id.clone().map(|id| json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })),
            notifications: Vec::new(),
        };
        if id.is_none() || method.is_empty() {
            return Handled { response: None, notifications: Vec::new() };
        }
        match method.as_str() {
            "initialize" => {
                let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
                let version = if SUPPORTED_PROTOCOL_VERSIONS.contains(&requested) { requested } else { LATEST_PROTOCOL_VERSION };
                ok(json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": { "listChanged": true }, "resources": { "listChanged": true } },
                    "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
                    "instructions": NETCATTY_MCP_SERVER_INSTRUCTIONS,
                }))
            }
            "ping" => ok(json!({})),
            "tools/list" => ok(self.tool_list()),
            "resources/list" => ok(json!({ "resources": [{
                "uri": "netcatty://context",
                "name": "environment",
                "description": "Current Netcatty workspace context: connected hosts, session IDs, and environment description.",
            }] })),
            "resources/templates/list" => ok(json!({ "resourceTemplates": [] })),
            "prompts/list" => err(-32601, "Method not found".into()),
            "resources/read" => {
                if params.get("uri").and_then(Value::as_str) != Some("netcatty://context") {
                    return err(-32602, format!("MCP error -32602: Resource {} not found", params.get("uri").and_then(Value::as_str).unwrap_or("")));
                }
                match self.rpc.call("netcatty/getContext", Value::Object(self.scope.clone())).await {
                    Ok(ctx) => ok(json!({ "contents": [{ "uri": "netcatty://context", "mimeType": "application/json", "text": pretty(&ctx) }] })),
                    Err(e) => err(-32603, e),
                }
            }
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                let args = params.get("arguments").and_then(Value::as_object).cloned().unwrap_or_default();
                match self.call_tool(&name, args).await {
                    Ok((result, changed)) => {
                        let mut h = ok(result);
                        if changed {
                            h.notifications.push(json!({ "jsonrpc": "2.0", "method": "notifications/tools/list_changed" }));
                        }
                        h
                    }
                    Err((code, message)) => err(code, message),
                }
            }
            "logging/setLevel" => ok(json!({})),
            _ => err(-32601, "Method not found".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo(Mutex<Vec<(String, Value)>>, Value);
    #[async_trait::async_trait]
    impl RpcCaller for Echo {
        async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
            self.0.lock().push((method.into(), params));
            Ok(self.1.clone())
        }
    }

    fn session(reply: Value) -> (McpSession, Arc<Echo>) {
        let rpc = Arc::new(Echo(Default::default(), reply));
        let scope = json!({ "chatSessionId": "chat" }).as_object().unwrap().clone();
        (McpSession::new(rpc.clone(), scope, Arc::new(|| false), None), rpc)
    }

    async fn call(s: &McpSession, name: &str, args: Value) -> Handled {
        s.handle(json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": name, "arguments": args } })).await
    }

    #[test]
    fn progressive_catalog_assigns_every_tool_once() {
        let (by_name, deferred) = build_progressive_catalog().unwrap();
        assert_eq!(by_name.len(), 71);
        assert_eq!(deferred.len(), 71 - 14);
    }

    #[tokio::test]
    async fn initial_surface_is_fifteen_tools_and_loading_is_idempotent() {
        let (s, _) = session(json!({ "ok": true }));
        let init = s.handle(json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": { "protocolVersion": "2025-03-26" } })).await;
        let r = init.response.unwrap();
        assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(r["result"]["instructions"], NETCATTY_MCP_SERVER_INSTRUCTIONS);
        let list = s.handle(json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })).await.response.unwrap();
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 15);
        let h = call(&s, MCP_TOOL_LOADER_NAME, json!({ "toolset": "snippets" })).await;
        assert_eq!(h.notifications.len(), 1);
        let text = h.response.unwrap()["result"]["content"][0]["text"].as_str().unwrap().to_string();
        assert!(text.contains("\"newlyLoaded\""));
        let h = call(&s, MCP_TOOL_LOADER_NAME, json!({ "toolset": "snippets" })).await;
        assert!(h.notifications.is_empty());
        call(&s, MCP_TOOL_LOADER_NAME, json!({ "toolset": "all" })).await;
        let list = s.handle(json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })).await.response.unwrap();
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 72);
        let bad = call(&s, MCP_TOOL_LOADER_NAME, json!({ "toolset": "nope" })).await.response.unwrap();
        assert_eq!(bad["result"]["isError"], true);
    }

    #[tokio::test]
    async fn get_environment_with_omitted_arguments_and_unknown_tool() {
        let (s, rpc) = session(json!({ "hosts": [] }));
        let h = s.handle(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "get_environment" } })).await;
        assert!(h.response.unwrap()["result"]["content"][0]["text"].as_str().unwrap().contains("hosts"));
        assert_eq!(rpc.0.lock()[0], ("netcatty/getContext".to_string(), json!({ "chatSessionId": "chat" })));
        let h = call(&s, "snippets_list", json!({})).await.response.unwrap();
        assert_eq!(h["error"]["code"], -32602);
    }

    #[tokio::test]
    async fn terminal_execute_formatting() {
        let (s, _) = session(json!({ "ok": false, "stdout": "out", "exitCode": 2 }));
        let r = call(&s, "terminal_execute", json!({ "sessionId": "s", "command": "x" })).await.response.unwrap();
        assert_eq!(r["result"]["content"][0]["text"], "out\n[exit code: 2]");
        assert!(r["result"].get("isError").is_none());
        let (s, _) = session(json!({ "ok": true, "stdout": "", "stderr": "", "exitCode": null }));
        let r = call(&s, "terminal_execute", json!({ "sessionId": "s", "command": "x" })).await.response.unwrap();
        assert_eq!(r["result"]["content"][0]["text"], "Command completed (no output)");
        let (s, _) = session(json!({ "ok": false, "error": "Session not found" }));
        let r = call(&s, "terminal_execute", json!({ "sessionId": "s", "command": "x" })).await.response.unwrap();
        assert_eq!(r["result"]["content"][0]["text"], "Error: Session not found");
        assert_eq!(r["result"]["isError"], true);
        let (s, _) = session(json!({ "ok": false, "stdout": "part", "exitCode": -1, "error": "Command timed out (60s)" }));
        let r = call(&s, "terminal_execute", json!({ "sessionId": "s", "command": "x" })).await.response.unwrap();
        assert_eq!(r["result"]["content"][0]["text"], "part\n[exit code: -1]\n[error] Command timed out (60s)");
        assert_eq!(r["result"]["isError"], true);
        let r = call(&s, "terminal_execute", json!({ "sessionId": 1 })).await.response.unwrap();
        assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("Input validation error"));
    }

    #[tokio::test]
    async fn observer_mode_blocks_writes_but_session_close_stays_available() {
        let rpc = Arc::new(Echo(Default::default(), json!({ "ok": true })));
        let s = McpSession::new(rpc.clone(), Map::new(), Arc::new(|| true), None);
        let r = call(&s, "terminal_execute", json!({ "sessionId": "s", "command": "x" })).await.response.unwrap();
        assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("observer"));
        let r = call(&s, "session_close", json!({ "sessionId": "s" })).await.response.unwrap();
        assert!(r["result"].get("isError").is_none());
        assert_eq!(rpc.0.lock().len(), 1);
    }
}

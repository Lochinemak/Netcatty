//! Grok Build ACP runtime: `grok [global flags] agent [flags] stdio` JSON-RPC
//! (Electron: `sdk/grokAcpDriver.cjs`).
//!
//! `initialize` → `authenticate` (when methods are advertised) →
//! `session/resume` | `session/load` | `session/new` → `session/prompt`, with
//! `session/update` notifications translated to renderer events. Updates are
//! ignored until the prompt is in flight so `session/load` history replay never
//! lands in the current bubble.

use super::grok::{
    apply_grok_reasoning_fallback, emit_grok_usage, extract_grok_acp_prompt_usage, format_grok_error_for_user,
    normalize_grok_plan_update, parse_grok_model_selection, resolve_grok_catalog_current_model_id,
    resolve_grok_tool_integration_flags, resolve_grok_turn_prompt, GrokState, GROK_MCP_MODE_DISALLOWED_LOCAL_TOOLS,
    MAX_GROK_LINE_BYTES,
};
use super::jsonrpc::{Framing, Incoming, RpcClient};
use super::{absolute_cwd, ListContext, TurnContext, TurnResult};
use crate::catalog::ModelCatalog;
use crate::emit::Emitter;
use crate::mcp::McpServerConfig;
use crate::process::{build_command, terminate_child, Stdin, StderrTail, DEFAULT_ABORT_GRACE};
use serde_json::{json, Value};
use std::time::Duration;

pub const ACP_PROTOCOL_VERSION: u64 = 1;
const MODEL_LIST_TIMEOUT: Duration = Duration::from_secs(4);
const FALLBACK_EFFORTS: &[&str] = &["low", "medium", "high", "xhigh"];

/// argv: global flags precede `agent`; agent flags follow it.
pub fn build_spawn_args(model: Option<&str>, permission_mode: &str, tool_mode: &str) -> Vec<String> {
    let mut args = vec!["--no-auto-update".to_string()];
    args.extend(resolve_grok_tool_integration_flags(tool_mode));
    args.push("agent".into());
    if !permission_mode.eq_ignore_ascii_case("observer") {
        args.push("--always-approve".into());
    }
    let (model, effort) = parse_grok_model_selection(model);
    if let Some(m) = model {
        args.extend(["-m".into(), m]);
    }
    if let Some(e) = effort {
        args.extend(["--reasoning-effort".into(), e]);
    }
    args.push("stdio".into());
    args
}

/// ACP `mcpServers` (env as `[{name, value}]`).
pub fn to_acp_mcp_servers(servers: &[McpServerConfig]) -> Value {
    Value::Array(
        servers
            .iter()
            .filter(|c| !c.name.is_empty() && !c.command.is_empty())
            .map(|c| json!({ "name": c.name, "type": "stdio", "command": c.command, "args": c.args, "env": c.env }))
            .collect(),
    )
}

pub fn build_session_new_params(cwd: &str, servers: &[McpServerConfig], permission_mode: &str, tool_mode: &str, system_context: Option<&str>) -> Value {
    let mut meta = serde_json::Map::new();
    if permission_mode.eq_ignore_ascii_case("observer") {
        meta.insert("autoMode".into(), json!(true));
    } else {
        meta.insert("yoloMode".into(), json!(true));
    }
    let mut rules = String::new();
    if !tool_mode.eq_ignore_ascii_case("skills") {
        rules = format!(
            "Netcatty MCP mode is active. Do not use local shell, search_replace, or write tools for side effects. Operate on remote terminal sessions only through the injected netcatty-remote-hosts MCP server. Disallowed local built-ins (policy): {}.",
            GROK_MCP_MODE_DISALLOWED_LOCAL_TOOLS.join(", ")
        );
    }
    if let Some(ctx) = system_context.map(str::trim).filter(|c| !c.is_empty()) {
        rules = if rules.is_empty() { ctx.to_string() } else { format!("{rules} {ctx}") };
        rules = rules.chars().take(16_000).collect();
    }
    if !rules.is_empty() {
        meta.insert("rules".into(), json!(rules));
    }
    json!({ "cwd": cwd, "mcpServers": to_acp_mcp_servers(servers), "_meta": meta })
}

pub fn initialize_params() -> Value {
    json!({
        "protocolVersion": ACP_PROTOCOL_VERSION,
        "clientCapabilities": { "fs": { "readTextFile": false, "writeTextFile": false }, "terminal": false },
        "clientInfo": { "name": "netcatty", "version": "0.0.0" },
    })
}

/// `parseGrokAcpModelCatalog` from the initialize result's `modelState`.
pub fn parse_model_catalog(init: &Value) -> ModelCatalog {
    let state = [init.pointer("/_meta/modelState"), init.get("modelState"), init.pointer("/agentCapabilities/_meta/modelState")]
        .into_iter()
        .flatten()
        .find(|v| v.is_object());
    let Some(state) = state else { return ModelCatalog::default() };
    let mut models = Vec::new();
    for entry in state["availableModels"].as_array().cloned().unwrap_or_default() {
        let id = entry["modelId"].as_str().or(entry["id"].as_str()).unwrap_or("").trim().to_string();
        if id.is_empty() {
            continue;
        }
        let mut preset = json!({ "id": id, "name": entry["name"].as_str().unwrap_or(&id) });
        if let Some(d) = entry["description"].as_str().filter(|d| !d.is_empty()) {
            preset["description"] = json!(d);
        }
        let meta = if entry["_meta"].is_object() { &entry["_meta"] } else { &entry["meta"] };
        let supports = meta["supportsReasoningEffort"] == true || meta["supports_reasoning_effort"] == true;
        let unsupported = !supports && (meta["supportsReasoningEffort"] == false || meta["supports_reasoning_effort"] == false);
        if supports {
            let options = meta["reasoningEfforts"].as_array().or(meta["reasoning_efforts"].as_array()).cloned().unwrap_or_default();
            let mut levels: Vec<String> = Vec::new();
            for o in &options {
                let v = o["value"].as_str().or(o["id"].as_str()).unwrap_or("").trim().to_lowercase();
                if super::grok::GROK_REASONING_EFFORTS.contains(&v.as_str()) && !levels.contains(&v) {
                    levels.push(v);
                }
            }
            if levels.is_empty() {
                let fb = apply_grok_reasoning_fallback(preset.clone());
                levels = fb["thinkingLevels"].as_array().map(|l| l.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_else(|| FALLBACK_EFFORTS.iter().map(|s| s.to_string()).collect());
            }
            let advertised = meta["reasoningEffort"].as_str().or(meta["reasoning_effort"].as_str()).unwrap_or("").to_lowercase();
            let option_default = options.iter().find(|o| o["default"] == true).and_then(|o| o["value"].as_str().or(o["id"].as_str())).unwrap_or("").to_lowercase();
            let default = if levels.contains(&advertised) {
                advertised
            } else if levels.contains(&option_default) {
                option_default
            } else if levels.iter().any(|l| l == "high") {
                "high".into()
            } else {
                levels[0].clone()
            };
            preset["thinkingLevels"] = json!(levels);
            preset["defaultThinkingLevel"] = json!(default);
        } else if !unsupported {
            preset = apply_grok_reasoning_fallback(preset);
        }
        models.push(preset);
    }
    let advertised = state["currentModelId"].as_str().or(state["current_model_id"].as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let current = resolve_grok_catalog_current_model_id(&models, advertised.as_deref());
    ModelCatalog { current_model_id: current, models }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentCapabilities {
    pub load_session: bool,
    pub resume: bool,
    pub has_capability_info: bool,
}

pub fn parse_agent_capabilities(init: &Value) -> AgentCapabilities {
    let caps = &init["agentCapabilities"];
    let session = &caps["sessionCapabilities"];
    AgentCapabilities {
        load_session: caps["loadSession"] == true,
        resume: !session["resume"].is_null() && session["resume"] != false,
        has_capability_info: caps.get("loadSession").is_some() || session.get("resume").is_some(),
    }
}

/// resume → load → new (unknown capabilities still try resume and load).
pub fn plan_session_establish(resume: Option<&str>, caps: AgentCapabilities) -> Vec<&'static str> {
    if resume.is_none() {
        return vec!["new"];
    }
    let mut methods = Vec::new();
    if caps.resume || !caps.has_capability_info {
        methods.push("resume");
    }
    if caps.load_session || !caps.has_capability_info {
        methods.push("load");
    }
    methods.push("new");
    methods
}

/// `selectGrokAcpAuthMethodId` → `(methodId, required)`.
pub fn select_auth_method(init: &Value, env: &crate::EnvMap) -> (Option<&'static str>, bool) {
    let methods: Vec<&str> = init["authMethods"].as_array().map(|m| m.iter().filter_map(|x| x["id"].as_str()).collect()).unwrap_or_default();
    if init["authMethods"].as_array().map(|m| m.is_empty()).unwrap_or(true) {
        return (None, false);
    }
    let has_key = env.get("XAI_API_KEY").map(|k| !k.trim().is_empty()).unwrap_or(false);
    if has_key && methods.contains(&"xai.api_key") {
        return (Some("xai.api_key"), true);
    }
    if methods.contains(&"cached_token") {
        return (Some("cached_token"), true);
    }
    if methods.contains(&"xai.api_key") {
        return (Some("xai.api_key"), true);
    }
    (None, true)
}

/// ACP permission reply using a real offered `optionId`.
pub fn build_permission_response(params: &Value, allow: bool) -> Value {
    let options = params["options"].as_array().cloned().unwrap_or_default();
    let key = |o: &Value| {
        let id = o["optionId"].as_str().or(o["id"].as_str()).unwrap_or("").trim().to_string();
        let kind = o["kind"].as_str().or(o["name"].as_str()).unwrap_or("").trim().to_string();
        (id.clone(), format!("{id} {kind}").to_lowercase())
    };
    if allow {
        let always = regex::Regex::new(r"allow[_-]?always|always[_-]?allow|allow_for_session|allow-session").unwrap();
        let once = regex::Regex::new(r"allow[_-]?once|once|allow_this|allow-this").unwrap();
        let plain = regex::Regex::new(r"\ballow\b").unwrap();
        let mut best: Option<(u8, String)> = None;
        for o in options.iter().filter(|o| o.is_object()) {
            let (id, blob) = key(o);
            if id.is_empty() {
                continue;
            }
            let score = if always.is_match(&blob) { 3 } else if once.is_match(&blob) { 2 } else if plain.is_match(&blob) { 1 } else { 0 };
            if score > best.as_ref().map(|b| b.0).unwrap_or(0) {
                best = Some((score, id));
            }
        }
        let id = best.map(|b| b.1).unwrap_or_else(|| "allow_once".into());
        return json!({ "outcome": { "outcome": "selected", "optionId": id } });
    }
    let deny = regex::Regex::new(r"reject|cancel|deny|refuse|disallow").unwrap();
    for o in options.iter().filter(|o| o.is_object()) {
        let (id, blob) = key(o);
        if !id.is_empty() && deny.is_match(&blob) {
            return json!({ "outcome": { "outcome": "selected", "optionId": id } });
        }
    }
    json!({ "outcome": { "outcome": "cancelled" } })
}

/// Map one `session/update` payload. Returns `true` on a terminal error.
pub fn translate_update(update: &Value, emitter: &Emitter, st: &mut GrokState) -> bool {
    let kind = update["sessionUpdate"].as_str().or(update["type"].as_str()).or(update["kind"].as_str()).unwrap_or("");
    let text_of = |u: &Value| -> String {
        u.pointer("/content/text").and_then(|t| t.as_str()).or(u["text"].as_str()).or(u["data"].as_str()).or(u["content"].as_str()).unwrap_or("").to_string()
    };
    match kind {
        "agent_message_chunk" | "message_chunk" | "text" => {
            st.close_reasoning(emitter);
            let text = text_of(update);
            if !text.is_empty() {
                emitter.text(&text);
                st.streamed_assistant_text = true;
            }
        }
        "agent_thought_chunk" | "thought_chunk" | "thought" => {
            let text = update.pointer("/content/text").and_then(|t| t.as_str()).or(update["text"].as_str()).or(update["data"].as_str()).unwrap_or("");
            if !text.is_empty() {
                emitter.reasoning(text);
                st.reasoning_open = true;
            }
        }
        "tool_call" => st.tool_event(update, emitter, false, true),
        "tool_call_update" => st.tool_event(update, emitter, true, true),
        "plan" => {
            if let Some((items, status)) = normalize_grok_plan_update(&update["entries"]) {
                emitter.plan_update("grok-plan", items, status);
            }
        }
        "error" => {
            st.close_reasoning(emitter);
            st.failed = true;
            emitter.emit_error(format_grok_error_for_user(update["message"].as_str().or(update["error"].as_str()).unwrap_or("Grok ACP turn failed")));
            return true;
        }
        _ => {}
    }
    false
}

fn spawn_agent(bin: &str, args: &[String], ctx_env: &crate::EnvMap, cwd: Option<&std::path::Path>) -> std::io::Result<(tokio::process::Child, std::sync::Arc<RpcClient>, tokio::sync::mpsc::UnboundedReceiver<Incoming>, StderrTail)> {
    let spec = crate::cli::prepare_command_for_spawn(bin, args, true);
    let mut child = build_command(&spec, ctx_env, cwd, Stdin::Piped).spawn()?;
    let stdin = child.stdin.take().ok_or_else(|| std::io::Error::other("no stdin"))?;
    let stdout = child.stdout.take().ok_or_else(|| std::io::Error::other("no stdout"))?;
    let stderr = StderrTail::spawn(child.stderr.take(), 64 * 1024);
    let (client, rx) = RpcClient::start(stdin, stdout, Framing::Ndjson, MAX_GROK_LINE_BYTES);
    Ok((child, client, rx, stderr))
}

/// Run an ACP turn.
pub async fn run_turn(ctx: &TurnContext) -> TurnResult {
    let emitter = ctx.emitter.clone();
    let Some(bin) = ctx.bin_path.clone().filter(|b| !b.trim().is_empty()) else {
        emitter.emit_error("Grok Build CLI not found. Install the Grok CLI (`grok`) and ensure it is on PATH, or set the path in Settings → AI.");
        return TurnResult { session_id: ctx.resume_session_id.clone() };
    };
    let cwd = absolute_cwd(&ctx.cwd);
    let cwd_text = cwd.to_string_lossy().into_owned();
    let args = build_spawn_args(ctx.model.as_deref(), &ctx.permission_mode, &ctx.tool_integration_mode);
    let (mut child, rpc, mut incoming, stderr) = match spawn_agent(&bin, &args, &ctx.env, Some(&cwd)) {
        Ok(v) => v,
        Err(e) => {
            emitter.emit_error(format_grok_error_for_user(&e.to_string()));
            return TurnResult { session_id: ctx.resume_session_id.clone() };
        }
    };
    let state = std::sync::Arc::new(parking_lot::Mutex::new(GrokState { session_id: ctx.resume_session_id.clone(), ..Default::default() }));
    let accept = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let auto_allow = !ctx.permission_mode.eq_ignore_ascii_case("observer");
    // Dispatch notifications / server requests in the background.
    let pump = {
        let state = state.clone();
        let accept = accept.clone();
        let emitter = emitter.clone();
        let rpc = rpc.clone();
        tokio::spawn(async move {
            while let Some(message) = incoming.recv().await {
                match message {
                    Incoming::Notification(m) => {
                        let method = m["method"].as_str().unwrap_or("");
                        if method != "session/update" && method != "x.ai/session/update" {
                            continue;
                        }
                        let params = &m["params"];
                        let mut st = state.lock();
                        if !accept.load(std::sync::atomic::Ordering::SeqCst) {
                            if st.session_id.is_none() {
                                st.session_id = params["sessionId"].as_str().map(str::to_string);
                            }
                            continue;
                        }
                        let update = if params["update"].is_object() { params["update"].clone() } else { params.clone() };
                        translate_update(&update, &emitter, &mut st);
                        if st.session_id.is_none() {
                            if let Some(id) = params["sessionId"].as_str() {
                                st.session_id = Some(id.to_string());
                                emitter.session_id(id);
                            }
                        }
                    }
                    Incoming::Request(m) => {
                        let method = m["method"].as_str().unwrap_or("");
                        if method == "session/request_permission" || method == "request_permission" {
                            rpc.respond(&m["id"], build_permission_response(&m["params"], auto_allow));
                        } else {
                            rpc.respond_error(&m["id"], -32601, "Method not found");
                        }
                    }
                    Incoming::Response(_) => {}
                }
            }
        })
    };
    let work = async {
        let init = rpc.request("initialize", initialize_params(), Duration::from_secs(30)).await.map_err(|e| e.message)?;
        let (method, required) = select_auth_method(&init, &ctx.env);
        match method {
            Some(m) => {
                rpc.request("authenticate", json!({ "methodId": m, "_meta": { "headless": true } }), Duration::from_secs(60)).await.map_err(|e| e.message)?;
            }
            None if required => return Err("Run `grok login` first, or set XAI_API_KEY.".to_string()),
            None => {}
        }
        let caps = parse_agent_capabilities(&init);
        let mut established: Option<(String, &str)> = None;
        let mut last_error = String::from("Grok ACP session establish failed");
        for method in plan_session_establish(ctx.resume_session_id.as_deref(), caps) {
            let result = if method == "new" {
                rpc.request("session/new", build_session_new_params(&cwd_text, &ctx.injected_mcp_servers, &ctx.permission_mode, &ctx.tool_integration_mode, ctx.system_prompt.as_deref()), Duration::from_secs(30)).await
                    .and_then(|r| r["sessionId"].as_str().or(r["session_id"].as_str()).map(str::to_string).ok_or(super::jsonrpc::RpcError { code: None, message: "Grok ACP session/new did not return a sessionId".into() }))
            } else {
                let rpc_method = if method == "resume" { "session/resume" } else { "session/load" };
                let resume = ctx.resume_session_id.clone().unwrap_or_default();
                rpc.request(rpc_method, json!({ "sessionId": resume, "cwd": cwd_text, "mcpServers": to_acp_mcp_servers(&ctx.injected_mcp_servers) }), Duration::from_secs(30)).await
                    .map(|r| r["sessionId"].as_str().or(r["session_id"].as_str()).map(str::to_string).unwrap_or(resume))
            };
            match result {
                Ok(id) => {
                    established = Some((id, method));
                    break;
                }
                Err(e) => last_error = e.message,
            }
        }
        let (session_id, method) = established.ok_or(last_error)?;
        state.lock().session_id = Some(session_id.clone());
        emitter.session_id(&session_id);
        let prompt = resolve_grok_turn_prompt(&ctx.prompt, ctx.history_seed.as_deref(), ctx.resume_session_id.as_deref(), method);
        accept.store(true, std::sync::atomic::Ordering::SeqCst);
        let result = rpc.request("session/prompt", json!({ "sessionId": session_id, "prompt": [{ "type": "text", "text": prompt }] }), Duration::from_secs(30 * 60)).await.map_err(|e| e.message)?;
        let mut st = state.lock();
        st.turn_completed = true;
        emit_grok_usage(&emitter, extract_grok_acp_prompt_usage(&result).as_ref());
        Ok::<(), String>(())
    };
    let outcome = tokio::select! {
        _ = ctx.cancel.cancelled() => None,
        r = work => Some(r),
    };
    if outcome.is_none() {
        let sid = state.lock().session_id.clone();
        if let Some(sid) = sid {
            rpc.notify("session/cancel", json!({ "sessionId": sid }));
        }
    }
    rpc.close_stdin();
    terminate_child(&mut child, DEFAULT_ABORT_GRACE).await;
    pump.abort();
    let mut st = state.lock();
    st.close_reasoning(&emitter);
    match outcome {
        None => {}
        Some(Err(message)) if !st.failed => {
            st.failed = true;
            let err = stderr.text().trim().to_string();
            let text = if !err.is_empty() && !message.contains(&err) { format!("{message} ({err})") } else { message };
            emitter.emit_error(format_grok_error_for_user(&text));
        }
        Some(_) if st.failed => {}
        Some(_) if st.turn_completed => emitter.emit_done(),
        Some(_) => emitter.emit_error(format_grok_error_for_user("Grok ACP ended before the turn completed")),
    }
    TurnResult { session_id: st.session_id.clone() }
}

/// Live catalog from ACP `initialize` (authentication not required).
pub async fn list_models(ctx: &ListContext) -> ModelCatalog {
    let Some(bin) = ctx.bin_path.clone().filter(|b| !b.trim().is_empty()) else { return ModelCatalog::default() };
    let args: Vec<String> = ["--no-auto-update", "agent", "stdio"].iter().map(|s| s.to_string()).collect();
    let Ok((mut child, rpc, _rx, _stderr)) = spawn_agent(&bin, &args, &ctx.env, None) else { return ModelCatalog::default() };
    let timeout = MODEL_LIST_TIMEOUT.min(ctx.remaining());
    let result = tokio::select! {
        _ = ctx.cancel.cancelled() => None,
        r = rpc.request("initialize", initialize_params(), timeout) => r.ok(),
    };
    rpc.close_stdin();
    terminate_child(&mut child, DEFAULT_ABORT_GRACE).await;
    result.map(|r| parse_model_catalog(&r)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::RecordingSink;
    use std::sync::Arc;

    #[test]
    fn spawn_args_order() {
        assert_eq!(build_spawn_args(Some("grok-4.7/high"), "confirm", "mcp").join(" "), "--no-auto-update --disallowed-tools run_terminal_command,run_terminal_cmd,search_replace,write,Agent agent --always-approve -m grok-4.7 --reasoning-effort high stdio");
        assert_eq!(build_spawn_args(None, "observer", "skills").join(" "), "--no-auto-update agent stdio");
    }

    #[test]
    fn session_params_and_establish_plan() {
        let p = build_session_new_params("/w", &[McpServerConfig::stdio("n", "/c", vec![], vec![crate::mcp::EnvPair { name: "A".into(), value: "1".into() }])], "observer", "mcp", Some("ctx"));
        assert_eq!(p["_meta"]["autoMode"], true);
        assert!(p["_meta"]["rules"].as_str().unwrap().ends_with(" ctx"));
        assert_eq!(p["mcpServers"][0]["env"], json!([{ "name": "A", "value": "1" }]));
        let unknown = parse_agent_capabilities(&json!({}));
        assert_eq!(plan_session_establish(Some("s"), unknown), vec!["resume", "load", "new"]);
        let load_only = parse_agent_capabilities(&json!({ "agentCapabilities": { "loadSession": true } }));
        assert_eq!(plan_session_establish(Some("s"), load_only), vec!["load", "new"]);
        assert_eq!(plan_session_establish(None, unknown), vec!["new"]);
    }

    #[test]
    fn auth_and_permissions() {
        let init = json!({ "authMethods": [{ "id": "cached_token" }, { "id": "xai.api_key" }] });
        let with_key: crate::EnvMap = [("XAI_API_KEY".to_string(), "k".to_string())].into_iter().collect();
        assert_eq!(select_auth_method(&init, &with_key), (Some("xai.api_key"), true));
        assert_eq!(select_auth_method(&init, &crate::EnvMap::new()), (Some("cached_token"), true));
        assert_eq!(select_auth_method(&json!({ "authMethods": [] }), &crate::EnvMap::new()), (None, false));
        assert_eq!(select_auth_method(&json!({ "authMethods": [{ "id": "oauth" }] }), &crate::EnvMap::new()), (None, true));
        let params = json!({ "options": [{ "optionId": "o1", "kind": "allow_once" }, { "optionId": "o2", "kind": "allow_always" }, { "optionId": "o3", "kind": "reject_once" }] });
        assert_eq!(build_permission_response(&params, true)["outcome"]["optionId"], "o2");
        assert_eq!(build_permission_response(&params, false)["outcome"]["optionId"], "o3");
        assert_eq!(build_permission_response(&json!({}), false)["outcome"]["outcome"], "cancelled");
        assert_eq!(build_permission_response(&json!({}), true)["outcome"]["optionId"], "allow_once");
    }

    #[test]
    fn catalog_parsing() {
        let c = parse_model_catalog(&json!({ "_meta": { "modelState": { "currentModelId": "grok-4.6", "availableModels": [
            { "modelId": "grok-4.6", "name": "Grok 4.6", "_meta": { "supportsReasoningEffort": true, "reasoningEfforts": [{ "value": "low" }, { "value": "HIGH", "default": true }] } },
            { "modelId": "grok-fast", "_meta": { "supportsReasoningEffort": false } },
            { "modelId": "grok-4.7" }
        ] } } }));
        assert_eq!(c.models[0]["thinkingLevels"], json!(["low", "high"]));
        assert_eq!(c.models[0]["defaultThinkingLevel"], "high");
        assert!(c.models[1].get("thinkingLevels").is_none());
        assert_eq!(c.models[2]["defaultThinkingLevel"], "high");
        assert_eq!(c.current_model_id.as_deref(), Some("grok-4.6/high"));
        assert!(parse_model_catalog(&json!({})).models.is_empty());
    }

    #[test]
    fn update_translation() {
        let sink = Arc::new(RecordingSink::default());
        let e = Emitter::new(sink.clone(), "r");
        let mut st = GrokState::default();
        translate_update(&json!({ "sessionUpdate": "agent_thought_chunk", "content": { "text": "t" } }), &e, &mut st);
        translate_update(&json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "Hi" } }), &e, &mut st);
        translate_update(&json!({ "sessionUpdate": "tool_call", "toolCallId": "c1", "title": "Run", "rawInput": { "cmd": "ls" } }), &e, &mut st);
        translate_update(&json!({ "sessionUpdate": "tool_call_update", "toolCallId": "c1", "status": "completed", "rawOutput": "ok" }), &e, &mut st);
        let types: Vec<String> = sink.stream_events().iter().map(|v| v["type"].as_str().unwrap().to_string()).collect();
        assert_eq!(types, vec!["reasoning-delta", "reasoning-end", "text-delta", "tool-call", "tool-result"]);
        assert_eq!(sink.stream_events()[3]["toolName"], "Run");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn acp_turn_against_fake_agent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("grok");
        std::fs::write(&bin, r#"#!/usr/bin/env python3
import sys, json
def send(o):
    sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    m = json.loads(line)
    meth = m.get("method")
    if meth == "initialize":
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"authMethods": [], "agentCapabilities": {"loadSession": True}}})
    elif meth == "session/load":
        send({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "old", "update": {"sessionUpdate": "agent_message_chunk", "content": {"text": "REPLAY"}}}})
        send({"jsonrpc": "2.0", "id": m["id"], "result": {}})
    elif meth == "session/prompt":
        pid = m["id"]
        send({"jsonrpc": "2.0", "id": 77, "method": "session/request_permission", "params": {"options": [{"optionId": "yes", "kind": "allow_once"}]}})
    elif m.get("id") == 77:
        send({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "old", "update": {"sessionUpdate": "agent_message_chunk", "content": {"text": "picked " + m["result"]["outcome"]["optionId"]}}}})
        send({"jsonrpc": "2.0", "id": pid, "result": {"stopReason": "end_turn", "_meta": {"inputTokens": 5, "outputTokens": 6}}})
"#).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sink = Arc::new(RecordingSink::default());
        let env: crate::EnvMap = std::env::vars().collect();
        let mut ctx = crate::drivers::test_turn_context(Emitter::new(sink.clone(), "r"), Some(bin.to_string_lossy().into_owned()), env);
        ctx.resume_session_id = Some("old".into());
        let result = tokio::time::timeout(Duration::from_secs(10), run_turn(&ctx)).await.unwrap();
        assert_eq!(result.session_id.as_deref(), Some("old"));
        let text: String = sink.stream_events().iter().filter(|e| e["type"] == "text-delta").map(|e| e["textDelta"].as_str().unwrap().to_string()).collect();
        assert_eq!(text, "picked yes");
        assert!(sink.stream_events().iter().any(|e| e["type"] == "usage" && e["totalTokens"] == 11));
        assert_eq!(sink.done_count(), 1);
    }
}

//! CodeBuddy Code driver (Electron: `sdk/codebuddyDriver.cjs`,
//! `sdk/codebuddySessionManager.cjs` over `@tencent-ai/agent-sdk`).
//!
//! The SDK's process transport runs the CLI with
//! `--input-format=stream-json --output-format=stream-json --verbose ...` and
//! a control channel (`initialize`, `hook_callback`, `can_use_tool`,
//! `elicitation_create`, `mcp_status`, `get_available_models`). This driver
//! implements the per-turn `query()` path; the SDK's warm V2 session is an
//! optimisation (it keeps the CLI alive between turns) and is not ported.

use super::copilot::is_likely_netcatty_cli_shell_command;
use super::stream_json::{ControlHandler, StreamEvent, StreamJsonProcess};
use super::{split_model_effort, ApprovalProvider, ElicitationRegistry, ListContext, TurnContext, TurnResult};
use crate::emit::{Emitter, Usage};
use crate::mcp::McpServerConfig;
use crate::EnvMap;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub const UI_DISALLOWED_TOOLS: &[&str] = &["AskUserQuestion"];
pub const CODEBUDDY_REASONING_LEVELS: &[&str] = &["minimal", "low", "medium", "high", "xhigh", "max"];
const IMAGE_MEDIA_TYPES: &[&str] = &["image/jpeg", "image/png", "image/gif", "image/webp"];
const HOOK_EVENTS: &[&str] = &["PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionEnd", "Notification", "PostCompact"];

/// `parseCodebuddyThinking`.
pub fn parse_thinking(value: Option<&str>) -> Option<Value> {
    let v = value?.trim().to_lowercase();
    match v.as_str() {
        "" => None,
        "adaptive" => Some(json!({ "type": "adaptive" })),
        "enabled" => Some(json!({ "type": "enabled", "budgetTokens": 16000 })),
        "disabled" => Some(json!({ "type": "disabled" })),
        s if s.starts_with("enabled:") => {
            let budget = s[8..].parse::<u64>().ok().filter(|b| *b > 0).unwrap_or(16000);
            Some(json!({ "type": "enabled", "budgetTokens": budget }))
        }
        _ => None,
    }
}

pub fn to_sdk_mcp_servers(servers: &[McpServerConfig]) -> Value {
    let mut map = serde_json::Map::new();
    for c in servers.iter().filter(|c| !c.name.is_empty()) {
        map.insert(c.name.clone(), json!({ "type": "stdio", "command": c.command, "args": c.args, "env": c.env_object() }));
    }
    Value::Object(map)
}

pub struct ArgsInput<'a> {
    pub model: Option<&'a str>,
    pub fallback_model: Option<&'a str>,
    pub max_turns: Option<u64>,
    pub tool_mode: &'a str,
    pub resume: Option<&'a str>,
    pub persist_session: Option<bool>,
    pub servers: &'a [McpServerConfig],
    pub append_system_prompt: Option<&'a str>,
    pub thinking: Option<&'a Value>,
    pub effort: Option<&'a str>,
}

/// `ProcessTransport.buildArgs` for the options `buildCodebuddyQueryOptions` produces.
pub fn build_args(i: &ArgsInput<'_>) -> Vec<String> {
    let mut args: Vec<String> = vec!["--input-format=stream-json".into(), "--output-format=stream-json".into(), "--verbose".into()];
    if let Some(m) = i.model {
        args.extend(["--model".into(), m.into()]);
    }
    if let Some(f) = i.fallback_model.filter(|f| Some(*f) != i.model) {
        args.extend(["--fallback-model".into(), f.into()]);
    }
    if let Some(t) = i.max_turns {
        args.extend(["--max-turns".into(), t.to_string()]);
    }
    args.extend(["--permission-mode".into(), "bypassPermissions".into()]);
    args.push("--disallowedTools".into());
    args.extend(UI_DISALLOWED_TOOLS.iter().map(|s| s.to_string()));
    let tools: Vec<&str> = if i.tool_mode == "skills" { vec!["Bash"] } else { vec![] };
    args.extend(["--tools".into(), tools.join(",")]);
    if let Some(r) = i.resume.filter(|r| !r.is_empty()) {
        args.extend(["--resume".into(), r.into()]);
    }
    if i.persist_session == Some(false) {
        args.push("--no-session-persistence".into());
    }
    let mcp = to_sdk_mcp_servers(i.servers);
    if mcp.as_object().map(|m| !m.is_empty()).unwrap_or(false) {
        args.extend(["--mcp-config".into(), json!({ "mcpServers": mcp }).to_string()]);
    }
    args.extend(["--setting-sources".into(), "none".into()]);
    args.push("--include-partial-messages".into());
    if let Some(s) = i.append_system_prompt.filter(|s| !s.is_empty()) {
        args.extend(["--append-system-prompt".into(), s.into()]);
    }
    let thinking_type = i.thinking.and_then(|t| t["type"].as_str());
    match thinking_type {
        Some("adaptive") | Some("enabled") => args.extend(["--settings".into(), json!({ "alwaysThinkingEnabled": true }).to_string()]),
        Some("disabled") => args.extend(["--settings".into(), json!({ "alwaysThinkingEnabled": false }).to_string()]),
        _ => {}
    }
    if let Some(e) = i.effort.filter(|_| thinking_type != Some("disabled")) {
        args.extend(["--effort".into(), e.into()]);
    }
    args.push("--dangerously-skip-permissions".into());
    args
}

/// Env the SDK transport sets.
pub fn process_env(env: &EnvMap, thinking: Option<&Value>) -> EnvMap {
    let mut env = env.clone();
    env.entry("CODEBUDDY_CODE_DISABLE_BACKGROUND_TASKS".into()).or_insert_with(|| "1".into());
    env.entry("CODEBUDDY_CODE_ENTRYPOINT".into()).or_insert_with(|| "sdk-ts".into());
    env.insert("DISABLE_AUTOUPDATER".into(), "1".into());
    env.entry("CODEBUDDY_DISABLE_AUTO_MEMORY".into()).or_insert_with(|| "1".into());
    if let Some(t) = thinking.filter(|t| t["type"] == "enabled") {
        if let Some(b) = t["budgetTokens"].as_u64().filter(|b| *b > 0) {
            env.insert("MAX_THINKING_TOKENS".into(), b.to_string());
        }
    }
    let ua = "User-Agent: CodeBuddy Agent SDK/0.3.258 (Netcatty) CodeBuddy Code/unknown".to_string();
    let headers = env.get("CODEBUDDY_CUSTOM_HEADERS").filter(|h| !h.is_empty()).map(|h| format!("{ua}\n{h}")).unwrap_or(ua);
    env.insert("CODEBUDDY_CUSTOM_HEADERS".into(), headers);
    env
}

/// `resolveRuntime`: `.exe` runs directly; JS entries (incl. `bin/codebuddy`,
/// mapped to `dist/codebuddy-headless.js`) run through `node`; other native
/// binaries run directly.
pub fn launch_spec(bin: &str, args: Vec<String>) -> crate::cli::SpawnSpec {
    let lower = bin.to_ascii_lowercase();
    if lower.ends_with(".exe") {
        return crate::cli::SpawnSpec { command: bin.into(), args, shell: false };
    }
    let mut js = bin.to_string();
    if bin.ends_with("/bin/codebuddy") || bin.ends_with("\\bin\\codebuddy") {
        let headless = Path::new(bin).parent().and_then(|p| p.parent()).map(|root| root.join("dist").join("codebuddy-headless.js"));
        if let Some(h) = headless.filter(|h| h.exists()) {
            js = h.to_string_lossy().into_owned();
        }
    }
    let is_js = js.ends_with(".js") || js.ends_with(".mjs") || js.ends_with(".cjs") || std::fs::read(&js).map(|b| b.starts_with(b"#!") && String::from_utf8_lossy(&b[..b.len().min(128)]).contains("node")).unwrap_or(false);
    if is_js {
        let mut full = vec![js];
        full.extend(args);
        return crate::cli::SpawnSpec { command: "node".into(), args: full, shell: false };
    }
    crate::cli::SpawnSpec { command: bin.into(), args, shell: false }
}

pub fn build_prompt_content(prompt: &str, attachments: &[crate::session::StagedAttachment]) -> Value {
    let images: Vec<_> = attachments.iter().filter(|a| !a.base64_data.is_empty() && IMAGE_MEDIA_TYPES.contains(&a.media_type.to_ascii_lowercase().as_str())).collect();
    if images.is_empty() {
        return json!(prompt);
    }
    let mut content = vec![json!({ "type": "text", "text": prompt })];
    for a in images {
        content.push(json!({ "type": "image", "source": { "type": "base64", "media_type": a.media_type.to_ascii_lowercase(), "data": a.base64_data } }));
    }
    Value::Array(content)
}

fn hooks_config() -> Value {
    let mut map = serde_json::Map::new();
    for e in HOOK_EVENTS {
        map.insert(e.to_string(), json!([{ "hookCallbackIds": [format!("hook_{e}_0_0")] }]));
    }
    Value::Object(map)
}

/// `isAllowedCodebuddySkillsBash`.
pub fn is_allowed_skills_bash(command: &str, prefix: &str) -> bool {
    let text = command.trim();
    let prefix = prefix.trim();
    if text.is_empty() || prefix.is_empty() || (text != prefix && !text.starts_with(&format!("{prefix} "))) {
        return false;
    }
    is_likely_netcatty_cli_shell_command(text)
}

/// Answers the CLI's control requests for one turn.
pub struct CodebuddyControl {
    pub emitter: Emitter,
    pub permission_mode: String,
    pub chat_session_id: String,
    pub tool_mode: String,
    pub skills_prefix: Option<String>,
    pub approvals: Arc<dyn ApprovalProvider>,
    pub elicitations: Arc<ElicitationRegistry>,
}

impl CodebuddyControl {
    pub fn scoped_elicitation_id(&self, raw: &str) -> String {
        if self.chat_session_id.is_empty() {
            raw.to_string()
        } else {
            format!("codebuddy:{}:{}", crate::session::encode_uri_component(&self.chat_session_id), crate::session::encode_uri_component(raw))
        }
    }

    fn hook(&self, request: &Value) -> Value {
        let id = request["callback_id"].as_str().unwrap_or("");
        let input = &request["input"];
        let event = id.strip_prefix("hook_").and_then(|r| r.split('_').next()).unwrap_or("");
        let payload = match event {
            "PreToolUse" | "PostToolUse" => json!({ "toolName": input["tool_name"], "toolInput": input["tool_input"], "toolUseId": input["tool_use_id"] }),
            "PostToolUseFailure" => json!({ "toolName": input["tool_name"], "toolInput": input["tool_input"], "toolUseId": input["tool_use_id"], "error": input["error"] }),
            "SessionEnd" => json!({ "reason": input["reason"] }),
            "Notification" => json!({ "message": input["message"], "title": input["title"], "notificationType": input["notification_type"] }),
            "PostCompact" => json!({ "trigger": input["trigger"], "compactSummary": input["compact_summary"] }),
            _ => return json!({ "continue": true }),
        };
        let mut event_obj = json!({ "type": "hook", "hookEvent": event });
        for (k, v) in payload.as_object().unwrap() {
            if !v.is_null() {
                event_obj[k] = v.clone();
            }
        }
        self.emitter.emit_event(event_obj);
        if event == "PreToolUse" && self.tool_mode == "skills" && input["tool_name"] == "Bash" {
            let background = input.pointer("/tool_input/run_in_background") == Some(&json!(true));
            let allowed = is_allowed_skills_bash(input.pointer("/tool_input/command").and_then(|c| c.as_str()).unwrap_or(""), self.skills_prefix.as_deref().unwrap_or(""));
            if background || !allowed {
                return json!({ "continue": true, "decision": "block", "reason": "Only Netcatty CLI commands are allowed in Skills mode. Use the netcatty-tool-cli command prefix provided by the host. Do not pass --chat-session or override NETCATTY_CLI_CHAT_SESSION_ID; the host already bound this process." });
            }
        }
        json!({ "continue": true })
    }

    async fn permission(&self, request: &Value) -> Value {
        let tool = request["tool_name"].as_str().unwrap_or("");
        let tool_use_id = request["tool_use_id"].clone();
        let deny = |reason: String| json!({ "allowed": false, "reason": reason, "tool_use_id": tool_use_id });
        match self.permission_mode.as_str() {
            "auto" => json!({ "allowed": true, "tool_use_id": tool_use_id }),
            "observer" => deny(format!("Observer mode: tool \"{tool}\" execution denied.")),
            _ => {
                let input = if request["input"].is_object() { request["input"].clone() } else { json!({}) };
                if self.approvals.request_approval(tool, input, &self.chat_session_id).await {
                    json!({ "allowed": true, "tool_use_id": tool_use_id })
                } else {
                    deny(format!("User denied execution of tool \"{tool}\"."))
                }
            }
        }
    }

    async fn elicitation(&self, request: &Value) -> Value {
        let mut params = request.clone();
        if let Some(o) = params.as_object_mut() {
            o.remove("subtype");
        }
        let raw = params.pointer("/_meta/codebuddy.ai/elicitationId").and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| format!("elicitation_{}", uuid::Uuid::new_v4()));
        let id = self.scoped_elicitation_id(&raw);
        let rx = self.elicitations.register(&id, &self.chat_session_id);
        self.emitter.emit_event(json!({ "type": "elicitation-create", "elicitationId": id, "request": params }));
        rx.await.unwrap_or_else(|_| json!({ "action": "cancel" }))
    }

    /// `elicitation` control notification (the agent closed the card).
    pub fn complete_elicitation(&self, notification: &Value) {
        let raw = notification["elicitationId"].as_str().unwrap_or("");
        let id = self.scoped_elicitation_id(raw);
        if !raw.is_empty() {
            self.elicitations.resolve(&id, json!({ "action": "cancel" }));
        }
        let mut n = notification.clone();
        n["elicitationId"] = json!(id);
        self.emitter.emit_event(json!({ "type": "elicitation-complete", "notification": n }));
    }
}

#[async_trait::async_trait]
impl ControlHandler for CodebuddyControl {
    async fn handle(&self, request: Value) -> Result<Value, String> {
        match request["subtype"].as_str().unwrap_or("") {
            "hook_callback" => Ok(self.hook(&request)),
            "can_use_tool" => Ok(self.permission(&request).await),
            "elicitation_create" => Ok(self.elicitation(&request).await),
            other => Err(format!("Unsupported control request subtype: {other}")),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ContentState {
    pub has_content: bool,
    pub has_text: bool,
    pub streamed_text: bool,
    pub streamed_reasoning: bool,
}

pub fn inspect_content(message: &Value) -> ContentState {
    let delta = if message["type"] == "stream_event" { &message["event"]["delta"] } else { &Value::Null };
    let blocks = message.pointer("/message/content").and_then(|c| c.as_array()).cloned().unwrap_or_default();
    let streamed_text = delta["type"] == "text_delta" && delta["text"].as_str().map(|t| !t.is_empty()).unwrap_or(false);
    let streamed_reasoning = delta["type"] == "thinking_delta" && delta["thinking"].as_str().map(|t| !t.is_empty()).unwrap_or(false);
    let assistant = message["type"] == "assistant";
    let a_text = assistant && blocks.iter().any(|b| b["type"] == "text" && b["text"].as_str().map(|t| !t.is_empty()).unwrap_or(false));
    let a_reason = assistant && blocks.iter().any(|b| b["type"] == "thinking" && b["thinking"].as_str().map(|t| !t.is_empty()).unwrap_or(false));
    let a_tool = assistant && blocks.iter().any(|b| b["type"] == "tool_use");
    let t_result = message["type"] == "user" && blocks.iter().any(|b| b["type"] == "tool_result");
    ContentState { has_content: streamed_text || streamed_reasoning || a_text || a_reason || a_tool || t_result, has_text: streamed_text || a_text, streamed_text, streamed_reasoning }
}

pub fn result_fallback_text(message: &Value) -> String {
    if message["type"] != "result" || message["is_error"] == true {
        return String::new();
    }
    if let Some(r) = message["result"].as_str().filter(|r| !r.is_empty()) {
        return r.to_string();
    }
    match &message["structured_output"] {
        Value::Null => String::new(),
        v => serde_json::to_string_pretty(v).unwrap_or_default(),
    }
}

/// `translateCodebuddyMessage`; returns `Some(true)` on a terminal error.
pub fn translate_message(message: &Value, emitter: &Emitter, skip_text: bool, skip_reasoning: bool) -> Option<bool> {
    match message["type"].as_str().unwrap_or("") {
        "system" => {
            if let Some(id) = message["session_id"].as_str() {
                emitter.session_id(id);
            }
            if let Some(m) = message["message"].as_str() {
                emitter.status(m);
            }
            None
        }
        "stream_event" => {
            let d = &message["event"]["delta"];
            if message["event"]["type"] == "content_block_delta" {
                match d["type"].as_str() {
                    Some("text_delta") => emitter.text(d["text"].as_str().unwrap_or("")),
                    Some("thinking_delta") => emitter.reasoning(d["thinking"].as_str().unwrap_or("")),
                    _ => {}
                }
            }
            None
        }
        "error" => {
            emitter.emit_error(message["error"].as_str().map(str::to_string).unwrap_or_else(|| if message["error"].is_null() { "CodeBuddy execution failed.".into() } else { message["error"].to_string() }));
            Some(true)
        }
        "assistant" => {
            if let Some(err) = message.get("error").filter(|e| !e.is_null()) {
                emitter.emit_error(err.as_str().map(str::to_string).unwrap_or_else(|| err.to_string()));
                return Some(true);
            }
            for b in message.pointer("/message/content").and_then(|c| c.as_array()).cloned().unwrap_or_default() {
                match b["type"].as_str() {
                    Some("tool_use") => emitter.tool_call(b["name"].as_str().unwrap_or(""), if b["input"].is_object() { b["input"].clone() } else { json!({}) }, b["id"].as_str().unwrap_or("")),
                    Some("text") if !skip_text => emitter.text(b["text"].as_str().unwrap_or("")),
                    Some("thinking") if !skip_reasoning => emitter.reasoning(b["thinking"].as_str().unwrap_or("")),
                    _ => {}
                }
            }
            None
        }
        "user" => {
            for b in message.pointer("/message/content").and_then(|c| c.as_array()).cloned().unwrap_or_default().iter().filter(|b| b["type"] == "tool_result") {
                let out = match &b["content"] {
                    Value::String(s) => s.clone(),
                    o => o.to_string(),
                };
                emitter.tool_result(b["tool_use_id"].as_str().unwrap_or(""), &out, None);
            }
            None
        }
        "status" => {
            if let Some(m) = message["message"].as_str() {
                emitter.status(m);
            }
            None
        }
        "result" => {
            let u = &message["usage"];
            if u.is_object() {
                let uncached = u["input_tokens"].as_u64().unwrap_or(0);
                let cached = u["cache_read_input_tokens"].as_u64().unwrap_or(0);
                let creation = u["cache_creation_input_tokens"].as_u64().unwrap_or(0);
                let input = uncached + cached + creation;
                let output = u["output_tokens"].as_u64().unwrap_or(0);
                emitter.usage(Usage { input_tokens: input, cached_input_tokens: cached, output_tokens: output, reasoning_tokens: 0, total_tokens: input + output });
            }
            let errors: Vec<String> = message["errors"].as_array().map(|e| e.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
            let mut parts = Vec::new();
            if let Some(n) = message["num_turns"].as_u64().filter(|n| *n > 0) {
                parts.push(format!("{n} turns"));
            }
            if let Some(c) = message["total_cost_usd"].as_f64().filter(|c| *c > 0.0) {
                parts.push(format!("${c:.4}"));
            }
            let is_error = message["is_error"] == true;
            if is_error && !errors.is_empty() {
                parts.push(format!("errors: {}", errors.join("; ")));
            }
            if !parts.is_empty() {
                emitter.status(&format!("CodeBuddy: {}", parts.join(", ")));
            }
            if is_error {
                let detail = if !errors.is_empty() {
                    errors.join("; ")
                } else if message["subtype"] == "error_max_turns" {
                    "CodeBuddy stopped after reaching the maximum turn limit.".into()
                } else if message["subtype"] == "error_max_budget_usd" {
                    "CodeBuddy stopped after reaching the configured budget limit.".into()
                } else {
                    "CodeBuddy execution failed.".into()
                };
                emitter.emit_error(detail);
                return Some(true);
            }
            Some(false)
        }
        _ => None,
    }
}

const NOT_FOUND: &str = "CodeBuddy CLI not found or not runnable. Install codebuddy and ensure it's on PATH, or set CODEBUDDY_CODE_PATH.";
const EMPTY: &str = "CodeBuddy returned an empty response. Run `codebuddy` in a terminal to log in, or set CODEBUDDY_API_KEY / CODEBUDDY_AUTH_TOKEN.";

pub async fn run_turn(ctx: &TurnContext) -> TurnResult {
    let emitter = &ctx.emitter;
    if ctx.aborted() {
        emitter.emit_done();
        return TurnResult::default();
    }
    let Some(bin) = ctx.bin_path.clone().filter(|b| !b.is_empty()) else {
        emitter.emit_error(NOT_FOUND);
        return TurnResult::default();
    };
    let (model, model_effort) = split_model_effort(ctx.model.as_deref(), CODEBUDDY_REASONING_LEVELS, true);
    let effort = model_effort.or(ctx.advanced.effort.clone()).filter(|e| CODEBUDDY_REASONING_LEVELS.contains(&e.as_str()));
    let thinking = parse_thinking(ctx.env.get("NETCATTY_CODEBUDDY_THINKING").map(String::as_str));
    let args = build_args(&ArgsInput {
        model: model.as_deref(),
        fallback_model: ctx.advanced.fallback_model.as_deref().map(str::trim).filter(|f| !f.is_empty()),
        max_turns: ctx.advanced.max_turns.filter(|t| *t > 0),
        tool_mode: &ctx.tool_integration_mode,
        resume: ctx.resume_session_id.as_deref(),
        persist_session: ctx.advanced.persist_session,
        servers: &ctx.injected_mcp_servers,
        append_system_prompt: ctx.system_prompt.as_deref(),
        thinking: thinking.as_ref(),
        effort: effort.as_deref(),
    });
    let env = process_env(&ctx.env, thinking.as_ref());
    let control = Arc::new(CodebuddyControl {
        emitter: emitter.clone(),
        permission_mode: ctx.permission_mode.clone(),
        chat_session_id: ctx.chat_session_id.clone(),
        tool_mode: ctx.tool_integration_mode.clone(),
        skills_prefix: ctx.skills_cli_prefix.clone(),
        approvals: ctx.approvals.clone(),
        elicitations: ctx.elicitations.clone(),
    });
    let (mut process, mut events) = match StreamJsonProcess::spawn(&launch_spec(&bin, args), &env, Some(&ctx.cwd), control.clone()) {
        Ok(p) => p,
        Err(e) => {
            emitter.emit_error(if e.kind() == std::io::ErrorKind::NotFound { NOT_FOUND.to_string() } else { e.to_string() });
            return TurnResult::default();
        }
    };
    let mut init = json!({
        "subtype": "initialize",
        "hooks": hooks_config(),
        "capabilities": { "askUserQuestion": true, "elicitation": { "form": true } },
        "hasPrompt": !ctx.prompt.is_empty(),
    });
    if let Some(s) = ctx.system_prompt.as_deref().filter(|s| !s.is_empty()) {
        init["appendSystemPrompt"] = json!(s);
    }
    let init_result = tokio::select! {
        _ = ctx.cancel.cancelled() => { process.terminate().await; emitter.emit_done(); return TurnResult::default(); }
        r = process.request_timeout(init, Duration::from_secs(60)) => r,
    };
    if let Err(e) = init_result {
        process.terminate().await;
        let stderr = process.stderr.text().trim().to_string();
        emitter.emit_error(if stderr.is_empty() { e } else { stderr });
        return TurnResult::default();
    }
    process.send_user_message(build_prompt_content(&ctx.prompt, &ctx.attachments));
    let mut session_id: Option<String> = None;
    let (mut content, mut text, mut streamed_text, mut streamed_reasoning, mut terminal) = (false, false, false, false, false);
    let mut fallback = String::new();
    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => {
                let _ = process.request_timeout(json!({ "subtype": "interrupt" }), Duration::from_secs(2)).await;
                process.terminate().await;
                emitter.emit_done();
                return TurnResult { session_id };
            }
            ev = events.recv() => {
                let Some(StreamEvent::Message(message)) = ev else { break };
                if message["type"] == "control_notification" {
                    if message["channel"] == "elicitation" {
                        control.complete_elicitation(&message["data"]);
                    }
                    continue;
                }
                if let Some(id) = message["session_id"].as_str().filter(|s| !s.is_empty()) {
                    session_id = Some(id.into());
                }
                let c = inspect_content(&message);
                content |= c.has_content;
                text |= c.has_text;
                if fallback.is_empty() {
                    fallback = result_fallback_text(&message);
                }
                if translate_message(&message, emitter, streamed_text, streamed_reasoning) == Some(true) {
                    terminal = true;
                }
                streamed_text |= c.streamed_text;
                streamed_reasoning |= c.streamed_reasoning;
                if message["type"] == "result" {
                    process.end_input();
                }
            }
        }
    }
    let code = process.wait_exit(Duration::from_secs(10)).await;
    if terminal {
        return TurnResult { session_id };
    }
    if !text && !fallback.is_empty() {
        emitter.text(&fallback);
        content = true;
    }
    if !content {
        let stderr = process.stderr.text().trim().to_string();
        emitter.emit_error(if code.map(|c| c != 0).unwrap_or(false) && !stderr.is_empty() { stderr } else { EMPTY.to_string() });
        return TurnResult { session_id };
    }
    emitter.emit_done();
    TurnResult { session_id }
}

/// `mapCodebuddyModels` (accepts `id|modelId|value`, reasoning metadata).
pub fn map_models(models: &Value) -> Vec<Value> {
    models
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|m| {
            let id = m["id"].as_str().or(m["modelId"].as_str()).or(m["value"].as_str())?;
            let declared: Vec<&str> = m.pointer("/reasoning/supportedEfforts").and_then(|e| e.as_array()).map(|e| e.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
            let ordered: Vec<&str> = CODEBUDDY_REASONING_LEVELS.iter().copied().filter(|l| declared.contains(l)).collect();
            let levels = if ordered.is_empty() { CODEBUDDY_REASONING_LEVELS.to_vec() } else { ordered };
            let declared_default = m.pointer("/reasoning/defaultEffort").and_then(|d| d.as_str()).filter(|d| levels.contains(d));
            let default = declared_default.unwrap_or(if levels.contains(&"medium") { "medium" } else { levels[0] });
            let mut preset = json!({ "id": id, "name": m["name"].as_str().or(m["displayName"].as_str()).unwrap_or(id), "thinkingLevels": levels, "defaultThinkingLevel": default, "encodeDefaultThinking": false });
            if !m["description"].is_null() {
                preset["description"] = m["description"].clone();
            }
            Some(preset)
        })
        .collect()
}

async fn idle_query(bin: &str, env: &EnvMap, cwd: &Path, request: Value, timeout: Duration) -> Result<Value, String> {
    let args: Vec<String> = vec!["--input-format=stream-json".into(), "--output-format=stream-json".into(), "--verbose".into(), "--setting-sources".into(), "none".into()];
    let (mut p, _rx) = StreamJsonProcess::spawn(&launch_spec(bin, args), &process_env(env, None), Some(cwd), Arc::new(super::stream_json::RejectAll)).map_err(|e| e.to_string())?;
    let r = p.request_timeout(request, timeout).await;
    p.terminate().await;
    r
}

pub async fn list_models(ctx: &ListContext) -> Vec<Value> {
    let Some(bin) = ctx.bin_path.clone().filter(|b| !b.is_empty()) else { return Vec::new() };
    let work = async {
        if let Ok(r) = idle_query(&bin, &ctx.env, &ctx.cwd, json!({ "subtype": "get_available_models" }), ctx.remaining()).await {
            for key in ["rawModels", "availableModels"] {
                let m = map_models(&r[key]);
                if !m.is_empty() {
                    return m;
                }
            }
        }
        idle_query(&bin, &ctx.env, &ctx.cwd, json!({ "subtype": "initialize" }), ctx.remaining()).await.map(|r| map_models(&r["models"])).unwrap_or_default()
    };
    tokio::select! {
        _ = ctx.cancel.cancelled() => Vec::new(),
        r = work => r,
    }
}

pub async fn mcp_status(bin: Option<&str>, env: &EnvMap) -> Value {
    let Some(bin) = bin else { return json!([]) };
    idle_query(bin, env, &std::env::temp_dir(), json!({ "subtype": "mcp_status" }), Duration::from_secs(30)).await.ok().map(|r| r.get("mcp_servers").cloned().filter(|v| !v.is_null()).unwrap_or(json!([]))).unwrap_or(json!([]))
}

pub async fn account_info(bin: Option<&str>, env: &EnvMap) -> Value {
    let Some(bin) = bin else { return Value::Null };
    match idle_query(bin, env, &std::env::temp_dir(), json!({ "subtype": "initialize" }), Duration::from_secs(30)).await {
        Ok(r) => r.get("account").cloned().filter(|v| !v.is_null()).unwrap_or(json!({})),
        Err(_) => Value::Null,
    }
}

/// Plugin / marketplace management on `~/.codebuddy/settings.json` (the SDK's `plugin.ts`).
pub mod plugins {
    use serde_json::{json, Map, Value};
    use std::path::{Path, PathBuf};

    pub fn codebuddy_dir() -> PathBuf {
        dirs::home_dir().unwrap_or_default().join(".codebuddy")
    }

    fn read(path: &Path) -> Map<String, Value> {
        std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).and_then(|v| v.as_object().cloned()).unwrap_or_default()
    }

    fn write(path: &Path, value: &Map<String, Value>) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, serde_json::to_string_pretty(value).unwrap_or_default()).map_err(|e| e.to_string())
    }

    fn result(success: bool, message: String) -> Value {
        json!({ "success": success, "message": message })
    }

    pub fn install_marketplace(dir: &Path, name: &str, repo: &str, auto_update: bool) -> Result<Value, String> {
        if name.is_empty() || repo.is_empty() {
            return Ok(result(false, "Marketplace name and repo are required".into()));
        }
        if !repo.contains('/') {
            return Ok(result(false, "Repo must be in format \"owner/repo\"".into()));
        }
        let path = dir.join("settings.json");
        let mut settings = read(&path);
        let markets = settings.entry("extraKnownMarketplaces").or_insert_with(|| json!({}));
        if markets.get(name).is_some() {
            return Ok(result(false, format!("Marketplace \"{name}\" already exists")));
        }
        markets[name] = json!({ "source": { "source": "github", "repo": repo }, "autoUpdate": auto_update });
        write(&path, &settings)?;
        Ok(result(true, format!("Marketplace \"{name}\" installed successfully")))
    }

    pub fn remove_marketplace(dir: &Path, name: &str, remove_plugins: bool) -> Result<Value, String> {
        if name.is_empty() {
            return Ok(result(false, "Marketplace name is required".into()));
        }
        let path = dir.join("settings.json");
        let known_path = dir.join("plugins").join("known_marketplaces.json");
        let mut settings = read(&path);
        let mut known = read(&known_path);
        let in_settings = settings.get("extraKnownMarketplaces").and_then(|m| m.get(name)).is_some();
        if !in_settings && !known.contains_key(name) {
            return Ok(result(false, format!("Marketplace \"{name}\" not found")));
        }
        if let Some(Value::Object(m)) = settings.get_mut("extraKnownMarketplaces") {
            m.remove(name);
            if m.is_empty() {
                settings.remove("extraKnownMarketplaces");
            }
        }
        if remove_plugins {
            if let Some(Value::Object(p)) = settings.get_mut("enabledPlugins") {
                p.retain(|k, _| !k.ends_with(&format!("@{name}")));
                if p.is_empty() {
                    settings.remove("enabledPlugins");
                }
            }
        }
        write(&path, &settings)?;
        if known.remove(name).is_some() {
            write(&known_path, &known)?;
        }
        Ok(result(true, format!("Marketplace \"{name}\" removed successfully")))
    }

    pub fn set_plugin(dir: &Path, name: &str, marketplace: &str, enabled: bool) -> Result<Value, String> {
        if name.is_empty() || marketplace.is_empty() {
            return Ok(result(false, "Plugin name and marketplace are required".into()));
        }
        let id = format!("{name}@{marketplace}");
        let path = dir.join("settings.json");
        let mut settings = read(&path);
        settings.entry("enabledPlugins").or_insert_with(|| json!({}))[&id] = json!(enabled);
        write(&path, &settings)?;
        Ok(result(true, if enabled { format!("Plugin \"{id}\" installed and enabled successfully") } else { format!("Plugin \"{id}\" disabled successfully") }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::RecordingSink;

    #[test]
    fn thinking_and_args() {
        assert_eq!(parse_thinking(Some("enabled:2000")), Some(json!({ "type": "enabled", "budgetTokens": 2000 })));
        assert_eq!(parse_thinking(Some("enabled:x")), Some(json!({ "type": "enabled", "budgetTokens": 16000 })));
        assert_eq!(parse_thinking(Some("nope")), None);
        let thinking = json!({ "type": "disabled" });
        let args = build_args(&ArgsInput { model: Some("glm"), fallback_model: Some("glm"), max_turns: Some(3), tool_mode: "mcp", resume: Some("r"), persist_session: Some(false), servers: &[], append_system_prompt: Some("ctx"), thinking: Some(&thinking), effort: Some("high") });
        let joined = args.join(" ");
        assert!(joined.starts_with("--input-format=stream-json --output-format=stream-json --verbose --model glm --max-turns 3 --permission-mode bypassPermissions --disallowedTools AskUserQuestion --tools  --resume r --no-session-persistence --setting-sources none --include-partial-messages --append-system-prompt ctx --settings {\"alwaysThinkingEnabled\":false}"));
        assert!(!args.contains(&"--effort".to_string()));
        assert!(!args.contains(&"--fallback-model".to_string()));
        assert_eq!(args.last().unwrap(), "--dangerously-skip-permissions");
        let env = process_env(&EnvMap::new(), Some(&json!({ "type": "enabled", "budgetTokens": 9 })));
        assert_eq!(env["MAX_THINKING_TOKENS"], "9");
        assert_eq!(env["DISABLE_AUTOUPDATER"], "1");
    }

    #[tokio::test]
    async fn control_handler_modes_and_hooks() {
        let sink = Arc::new(RecordingSink::default());
        let mk = |mode: &str, tool: &str| CodebuddyControl { emitter: Emitter::new(sink.clone(), "r"), permission_mode: mode.into(), chat_session_id: "chat 1".into(), tool_mode: tool.into(), skills_prefix: Some("netcatty-tool-cli".into()), approvals: Arc::new(crate::drivers::NoopApprovalProvider), elicitations: Arc::new(ElicitationRegistry::default()) };
        let req = json!({ "subtype": "can_use_tool", "tool_name": "Bash", "tool_use_id": "t" });
        assert_eq!(mk("auto", "mcp").handle(req.clone()).await.unwrap()["allowed"], true);
        assert_eq!(mk("observer", "mcp").handle(req.clone()).await.unwrap()["reason"], "Observer mode: tool \"Bash\" execution denied.");
        assert_eq!(mk("confirm", "mcp").handle(req).await.unwrap()["allowed"], false);
        let skills = mk("auto", "skills");
        let blocked = skills.handle(json!({ "subtype": "hook_callback", "callback_id": "hook_PreToolUse_0_0", "input": { "tool_name": "Bash", "tool_input": { "command": "rm -rf /" } } })).await.unwrap();
        assert_eq!(blocked["decision"], "block");
        let ok = skills.handle(json!({ "subtype": "hook_callback", "callback_id": "hook_PreToolUse_0_0", "input": { "tool_name": "Bash", "tool_input": { "command": "netcatty-tool-cli env --json" } } })).await.unwrap();
        assert!(ok.get("decision").is_none());
        assert_eq!(sink.stream_events()[0]["hookEvent"], "PreToolUse");
        // Elicitation round trip through the registry.
        let control = Arc::new(mk("confirm", "mcp"));
        let c2 = control.clone();
        let pending = tokio::spawn(async move { c2.handle(json!({ "subtype": "elicitation_create", "message": "Pick", "_meta": { "codebuddy.ai": { "elicitationId": "e1" } } })).await });
        let id = control.scoped_elicitation_id("e1");
        assert_eq!(id, "codebuddy:chat%201:e1");
        for _ in 0..100 {
            if control.elicitations.contains(&id) { break }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(control.elicitations.resolve(&id, json!({ "action": "accept", "content": { "x": 1 } })));
        assert_eq!(pending.await.unwrap().unwrap()["action"], "accept");
        assert!(sink.stream_events().iter().any(|e| e["type"] == "elicitation-create" && e["elicitationId"] == id));
    }

    #[test]
    fn message_translation_and_models() {
        let sink = Arc::new(RecordingSink::default());
        let e = Emitter::new(sink.clone(), "r");
        translate_message(&json!({ "type": "assistant", "message": { "content": [{ "type": "text", "text": "x" }, { "type": "tool_use", "id": "t", "name": "mcp" }] } }), &e, true, false);
        assert_eq!(translate_message(&json!({ "type": "result", "usage": { "input_tokens": 1, "cache_read_input_tokens": 2, "output_tokens": 3 }, "num_turns": 2 }), &e, false, false), Some(false));
        let ev = sink.stream_events();
        assert_eq!(ev[0]["type"], "tool-call");
        assert_eq!(ev[1]["inputTokens"], 3);
        assert_eq!(ev[2]["message"], "CodeBuddy: 2 turns");
        assert_eq!(translate_message(&json!({ "type": "result", "is_error": true, "subtype": "error_max_turns" }), &e, false, false), Some(true));
        assert_eq!(sink.errors()[0], "CodeBuddy stopped after reaching the maximum turn limit.");
        let m = map_models(&json!([{ "id": "glm-5.1", "name": "GLM-5.1", "reasoning": { "supportedEfforts": ["high", "low"], "defaultEffort": "high" } }, { "value": "x" }]));
        assert_eq!(m[0]["thinkingLevels"], json!(["low", "high"]));
        assert_eq!(m[0]["defaultThinkingLevel"], "high");
        assert_eq!(m[1]["defaultThinkingLevel"], "medium");
        assert_eq!(result_fallback_text(&json!({ "type": "result", "structured_output": { "a": 1 } })), "{\n  \"a\": 1\n}");
    }

    #[test]
    fn plugin_settings() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(plugins::install_marketplace(dir.path(), "m", "bad", true).unwrap()["success"], false);
        assert_eq!(plugins::install_marketplace(dir.path(), "m", "o/r", true).unwrap()["success"], true);
        assert_eq!(plugins::install_marketplace(dir.path(), "m", "o/r", true).unwrap()["message"], "Marketplace \"m\" already exists");
        assert_eq!(plugins::set_plugin(dir.path(), "p", "m", true).unwrap()["success"], true);
        assert_eq!(plugins::set_plugin(dir.path(), "q", "m", false).unwrap()["message"], "Plugin \"q@m\" disabled successfully");
        let removed = plugins::remove_marketplace(dir.path(), "m", true).unwrap();
        assert_eq!(removed["success"], true);
        let settings: Value = serde_json::from_str(&std::fs::read_to_string(dir.path().join("settings.json")).unwrap()).unwrap();
        assert!(settings.get("enabledPlugins").is_none() && settings.get("extraKnownMarketplaces").is_none());
        assert_eq!(plugins::remove_marketplace(dir.path(), "m", true).unwrap()["success"], false);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn turn_against_fake_cli() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("codebuddy");
        std::fs::write(&bin, r#"#!/usr/bin/env python3
import sys, json
def send(o):
    sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    m = json.loads(line)
    if m.get("type") == "control_request" and m["request"]["subtype"] == "initialize":
        assert "hook_PreToolUse_0_0" in json.dumps(m["request"]["hooks"])
        send({"type": "control_response", "response": {"subtype": "success", "request_id": m["request_id"], "response": {}}})
    elif m.get("type") == "user":
        send({"type": "control_request", "request_id": "cli-1", "request": {"subtype": "can_use_tool", "tool_name": "Bash", "tool_use_id": "t1"}})
    elif m.get("type") == "control_response":
        allowed = m["response"]["response"]["allowed"]
        send({"type": "system", "session_id": "cb-1"})
        send({"type": "stream_event", "event": {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "allowed=%s" % allowed}}})
        send({"type": "result", "subtype": "success", "session_id": "cb-1", "result": "ignored"})
        break
"#).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sink = Arc::new(RecordingSink::default());
        let env: EnvMap = std::env::vars().collect();
        let mut ctx = crate::drivers::test_turn_context(Emitter::new(sink.clone(), "r"), Some(bin.to_string_lossy().into_owned()), env);
        ctx.permission_mode = "auto".into();
        let r = tokio::time::timeout(Duration::from_secs(15), run_turn(&ctx)).await.unwrap();
        assert_eq!(r.session_id.as_deref(), Some("cb-1"));
        let text: String = sink.stream_events().iter().filter(|x| x["type"] == "text-delta").map(|x| x["textDelta"].as_str().unwrap().to_string()).collect();
        assert_eq!(text, "allowed=True");
        assert_eq!(sink.done_count(), 1);
    }
}

//! Claude Code driver (Electron: `sdk/claudeDriver.cjs`, `sdk/claudeConfig.cjs`).
//!
//! Electron drives the CLI through `@anthropic-ai/claude-agent-sdk`; here the
//! user's `claude` binary is spawned directly with the flags the SDK derives
//! from the same options:
//!
//! ```text
//! claude --output-format stream-json --verbose --input-format stream-json
//!        [--effort E] [--model M] [--resume S] --disallowedTools EnterPlanMode,ExitPlanMode,AskUserQuestion
//!        --tools "" | Bash,Skill  [--mcp-config {"mcpServers":{...}}]
//!        --permission-mode bypassPermissions --allow-dangerously-skip-permissions
//!        --include-partial-messages [--settings <path|json>]
//! ```
//!
//! Built-in local tools are disabled (MCP mode) or restricted to Bash + Skill
//! (skills mode) so remote work goes through Netcatty's MCP / CLI gate.

use super::stream_json::{spec_for_cli, RejectAll, StreamEvent, StreamJsonProcess};
use super::{ListContext, TurnContext, TurnResult};
use crate::emit::Emitter;
use crate::mcp::McpServerConfig;
use crate::session::StagedAttachment;
use crate::EnvMap;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

pub const UI_DISALLOWED_TOOLS: &[&str] = &["EnterPlanMode", "ExitPlanMode", "AskUserQuestion"];
pub const SKILLS_MODE_TOOLS: &[&str] = &["Bash", "Skill"];
pub const CLAUDE_REASONING_LEVELS: &[&str] = &["low", "medium", "high", "xhigh", "max"];
const CLAUDE_AGENT_SDK_VERSION: &str = "0.3.161";
const IMAGE_MEDIA_TYPES: &[&str] = &["image/jpeg", "image/png", "image/gif", "image/webp"];

pub fn claude_builtin_tools(mode: &str) -> Vec<&'static str> {
    if mode == "skills" {
        SKILLS_MODE_TOOLS.to_vec()
    } else {
        Vec::new()
    }
}

/// Neutral injected servers → `{ name: { type, command, args, env } }`.
pub fn to_sdk_mcp_servers(servers: &[McpServerConfig]) -> Value {
    let mut map = serde_json::Map::new();
    for cfg in servers.iter().filter(|c| !c.name.is_empty()) {
        map.insert(cfg.name.clone(), json!({ "type": "stdio", "command": cfg.command, "args": cfg.args, "env": cfg.env_object() }));
    }
    Value::Object(map)
}

/// `parseClaudeSettings`: inline JSON object or a settings.json path.
pub fn parse_claude_settings(settings: Option<&str>) -> Option<Value> {
    let s = settings?.trim();
    if s.is_empty() {
        return None;
    }
    if s.starts_with('{') {
        if let Ok(value) = serde_json::from_str::<Value>(s) {
            return Some(value);
        }
    }
    Some(Value::String(s.to_string()))
}

pub fn split_claude_model_selection(model: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(model) = model.filter(|m| !m.is_empty()) else { return (None, None) };
    match model.rfind('/') {
        Some(slash) if slash > 0 && CLAUDE_REASONING_LEVELS.contains(&&model[slash + 1..]) => {
            (Some(model[..slash].to_string()), Some(model[slash + 1..].to_string()))
        }
        _ => (Some(model.to_string()), None),
    }
}

/// `mergeClaudeEffortSettings`: an inline settings object also carries `effort`.
pub fn merge_claude_effort_settings(settings: Option<Value>, effort: Option<&str>) -> Option<Value> {
    let Some(effort) = effort else { return settings };
    match settings {
        None => Some(json!({ "effort": effort })),
        Some(Value::Object(mut map)) => {
            map.insert("effort".into(), json!(effort));
            Some(Value::Object(map))
        }
        other => other,
    }
}

pub struct ClaudeArgsInput<'a> {
    pub model: Option<&'a str>,
    pub resume: Option<&'a str>,
    pub tool_integration_mode: &'a str,
    pub injected_mcp_servers: &'a [McpServerConfig],
    pub settings: Option<&'a str>,
}

/// CLI argv in the SDK's order.
pub fn build_claude_args(input: &ClaudeArgsInput<'_>) -> Vec<String> {
    let (model, effort) = split_claude_model_selection(input.model);
    let mut args: Vec<String> = ["--output-format", "stream-json", "--verbose", "--input-format", "stream-json"].iter().map(|s| s.to_string()).collect();
    if let Some(effort) = &effort {
        args.extend(["--effort".into(), effort.clone()]);
    }
    if let Some(model) = &model {
        args.extend(["--model".into(), model.clone()]);
    }
    if let Some(resume) = input.resume.filter(|r| !r.is_empty()) {
        args.extend(["--resume".into(), resume.to_string()]);
    }
    args.extend(["--disallowedTools".into(), UI_DISALLOWED_TOOLS.join(",")]);
    args.extend(["--tools".into(), claude_builtin_tools(input.tool_integration_mode).join(",")]);
    let mcp = to_sdk_mcp_servers(input.injected_mcp_servers);
    if mcp.as_object().map(|m| !m.is_empty()).unwrap_or(false) {
        args.extend(["--mcp-config".into(), json!({ "mcpServers": mcp }).to_string()]);
    }
    args.extend(["--permission-mode".into(), "bypassPermissions".into(), "--allow-dangerously-skip-permissions".into()]);
    args.push("--include-partial-messages".into());
    if let Some(settings) = merge_claude_effort_settings(parse_claude_settings(input.settings), effort.as_deref()) {
        let text = match settings {
            Value::String(s) => s,
            other => other.to_string(),
        };
        args.extend(["--settings".into(), text]);
    }
    args
}

/// Env the SDK hands to the CLI.
pub fn claude_process_env(env: &EnvMap) -> EnvMap {
    let mut env = env.clone();
    env.entry("CLAUDE_CODE_ENTRYPOINT".into()).or_insert_with(|| "sdk-ts".into());
    env.entry("CLAUDE_AGENT_SDK_VERSION".into()).or_insert_with(|| CLAUDE_AGENT_SDK_VERSION.into());
    env.remove("NODE_OPTIONS");
    env.remove("DEBUG");
    env
}

/// Prompt content: plain text, plus base64 image blocks for image attachments.
pub fn build_claude_prompt_content(prompt: &str, attachments: &[StagedAttachment]) -> Value {
    let images: Vec<&StagedAttachment> = attachments
        .iter()
        .filter(|a| IMAGE_MEDIA_TYPES.contains(&a.media_type.to_ascii_lowercase().as_str()) && !a.base64_data.is_empty())
        .collect();
    if images.is_empty() {
        return json!([{ "type": "text", "text": prompt }]);
    }
    let mut content = vec![json!({ "type": "text", "text": prompt })];
    for image in images {
        content.push(json!({ "type": "image", "source": { "type": "base64", "media_type": image.media_type.to_ascii_lowercase(), "data": image.base64_data } }));
    }
    Value::Array(content)
}

/// `translateClaudeMessage`. Streamed text arrives through `stream_event`, so
/// consolidated assistant text blocks are skipped; tool_use blocks are kept.
pub fn translate_claude_message(message: &Value, emitter: &Emitter) {
    match message.get("type").and_then(|t| t.as_str()) {
        Some("system") => {
            if message["subtype"] == "init" {
                if let Some(id) = message["session_id"].as_str() {
                    emitter.session_id(id);
                }
            }
        }
        Some("stream_event") => {
            let ev = &message["event"];
            if ev["type"] == "content_block_delta" {
                let delta = &ev["delta"];
                match delta["type"].as_str() {
                    Some("text_delta") => emitter.text(delta["text"].as_str().unwrap_or("")),
                    Some("thinking_delta") => emitter.reasoning(delta["thinking"].as_str().unwrap_or("")),
                    _ => {}
                }
            }
        }
        Some("assistant") => {
            if let Some(blocks) = message["message"]["content"].as_array() {
                for block in blocks.iter().filter(|b| b["type"] == "tool_use") {
                    let input = if block["input"].is_object() { block["input"].clone() } else { json!({}) };
                    emitter.tool_call(block["name"].as_str().unwrap_or(""), input, block["id"].as_str().unwrap_or(""));
                }
            }
        }
        Some("user") => {
            if let Some(blocks) = message["message"]["content"].as_array() {
                for block in blocks.iter().filter(|b| b["type"] == "tool_result") {
                    let out = match &block["content"] {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    emitter.tool_result(block["tool_use_id"].as_str().unwrap_or(""), &out, None);
                }
            }
        }
        _ => {}
    }
}

fn has_content(message: &Value) -> bool {
    message["type"] == "stream_event"
        || (message["type"] == "assistant" && message["message"]["content"].as_array().map(|c| !c.is_empty()).unwrap_or(false))
}

/// `ensureClaudeConfig`: repair `~/.claude.json` once per process (missing,
/// empty, BOM-prefixed or corrupt configs make the CLI print plain text to stdout).
pub fn ensure_claude_config() {
    static CHECKED: std::sync::Once = std::sync::Once::new();
    CHECKED.call_once(|| {
        if let Some(home) = dirs::home_dir() {
            repair_claude_config(&home);
        }
    });
}

pub fn repair_claude_config(home: &std::path::Path) {
    let config = home.join(".claude.json");
    let _ = std::fs::remove_file(home.join(".claude.json.backup"));
    if let Ok(entries) = std::fs::read_dir(home) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(".claude.json.corrupted.") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    let Ok(raw) = std::fs::read_to_string(&config) else {
        if !config.exists() {
            let _ = std::fs::write(&config, "{}");
        }
        return;
    };
    let content = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    if content.trim().is_empty() || serde_json::from_str::<Value>(content).is_err() {
        let _ = std::fs::write(&config, "{}");
    } else if content.len() != raw.len() {
        let _ = std::fs::write(&config, content);
    }
}

fn is_spawn_enoent(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
}

/// Run a Claude turn.
pub async fn run_turn(ctx: &TurnContext) -> TurnResult {
    ensure_claude_config();
    let emitter = &ctx.emitter;
    let Some(bin) = ctx.bin_path.clone().filter(|b| !b.is_empty()) else {
        emitter.emit_error("Claude Code binary not found or not runnable (auto-discovery). Install with `npm i -g @anthropic-ai/claude-code` and ensure it's on PATH.");
        return TurnResult::default();
    };
    let args = build_claude_args(&ClaudeArgsInput {
        model: ctx.model.as_deref(),
        resume: ctx.resume_session_id.as_deref(),
        tool_integration_mode: &ctx.tool_integration_mode,
        injected_mcp_servers: &ctx.injected_mcp_servers,
        settings: ctx.claude_settings.as_deref(),
    });
    let env = claude_process_env(&ctx.env);
    let spec = spec_for_cli(&bin, args);
    let (mut process, mut events) = match StreamJsonProcess::spawn(&spec, &env, Some(&ctx.cwd), Arc::new(RejectAll)) {
        Ok(p) => p,
        Err(error) => {
            if is_spawn_enoent(&error) {
                emitter.emit_error(format!("Claude Code binary not found or not runnable ({bin}). Install with `npm i -g @anthropic-ai/claude-code` and ensure it's on PATH."));
            } else {
                emitter.emit_error(error.to_string());
            }
            return TurnResult::default();
        }
    };
    // SDK order: initialize control request, then the user message.
    let _init = process.request(json!({ "subtype": "initialize", "hooks": null }));
    process.send_user_message(build_claude_prompt_content(&ctx.prompt, &ctx.attachments));

    let mut session_id: Option<String> = None;
    let mut content = false;
    let mut error_result: Option<String> = None;
    let mut got_result = false;
    let mut overflow = false;
    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => {
                process.terminate().await;
                return TurnResult { session_id };
            }
            event = events.recv() => {
                match event {
                    None => break,
                    Some(StreamEvent::Overflow) => { overflow = true; break; }
                    Some(StreamEvent::Message(message)) => {
                        if let Some(id) = message["session_id"].as_str().filter(|s| !s.is_empty()) {
                            if session_id.as_deref() != Some(id) {
                                session_id = Some(id.to_string());
                            }
                        }
                        if has_content(&message) {
                            content = true;
                        }
                        translate_claude_message(&message, emitter);
                        if message["type"] == "result" {
                            got_result = true;
                            if message["is_error"] == true {
                                let text = message["result"].as_str().map(str::to_string).unwrap_or_else(|| {
                                    message["errors"].as_array().map(|e| e.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join("; ")).unwrap_or_default()
                                });
                                error_result = Some(if text.is_empty() { "Claude turn failed".into() } else { text });
                            }
                            process.end_input();
                        }
                    }
                }
            }
        }
    }
    if ctx.aborted() {
        process.terminate().await;
        return TurnResult { session_id };
    }
    let code = process.wait_exit(Duration::from_secs(10)).await;
    if overflow {
        emitter.emit_error("Claude Code emitted a message larger than the transport limit.");
        return TurnResult { session_id };
    }
    if let Some(error) = error_result {
        emitter.emit_error(error);
        return TurnResult { session_id };
    }
    if !got_result && code.map(|c| c != 0).unwrap_or(true) {
        let stderr = process.stderr.text().trim().to_string();
        let message = if stderr.is_empty() {
            format!("Claude Code process exited with code {}", code.map(|c| c.to_string()).unwrap_or_else(|| "unknown".into()))
        } else {
            stderr
        };
        emitter.emit_error(message);
        return TurnResult { session_id };
    }
    if !content {
        emitter.emit_error("Claude returned an empty response. Run `claude` in a terminal to log in, or set ANTHROPIC_API_KEY / CLAUDE_CODE_OAUTH_TOKEN.");
        return TurnResult { session_id };
    }
    emitter.emit_done();
    TurnResult { session_id }
}

/// `mapClaudeModels`: `{value|id, displayName|name, ...}` → picker presets,
/// disambiguating duplicate display names.
pub fn map_claude_models(models: &Value) -> Vec<Value> {
    let Some(items) = models.as_array() else { return Vec::new() };
    let mut presets: Vec<Value> = Vec::new();
    for m in items {
        let Some(id) = m.get("value").or_else(|| m.get("id")).or_else(|| m.get("modelId")).and_then(|v| v.as_str()).filter(|s| !s.is_empty()) else { continue };
        let advertised = m.get("supportedEffortLevels").or_else(|| m.pointer("/thinking/effort_options"));
        let levels: Vec<String> = if m.get("supportsEffort") == Some(&Value::Bool(false)) {
            Vec::new()
        } else if let Some(Value::Array(levels)) = advertised {
            levels.iter().filter_map(|l| l.as_str()).filter(|l| CLAUDE_REASONING_LEVELS.contains(l)).map(str::to_string).collect()
        } else {
            ["low", "medium", "high", "max"].iter().map(|s| s.to_string()).collect()
        };
        let name = m.get("displayName").or_else(|| m.get("name")).and_then(|v| v.as_str()).unwrap_or(id);
        let mut preset = json!({ "id": id, "name": name, "thinkingLevels": levels });
        if let Some(description) = m.get("description").filter(|d| !d.is_null()) {
            preset["description"] = description.clone();
        }
        if !levels.is_empty() {
            preset["defaultThinkingLevel"] = json!(if levels.iter().any(|l| l == "medium") { "medium".to_string() } else { levels[0].clone() });
        }
        presets.push(preset);
    }
    let mut counts = std::collections::HashMap::new();
    for p in &presets {
        *counts.entry(p["name"].as_str().unwrap_or("").to_string()).or_insert(0) += 1;
    }
    let mut used: std::collections::HashSet<String> = presets.iter().map(|p| p["name"].as_str().unwrap_or("").to_string()).collect();
    for preset in presets.iter_mut() {
        let name = preset["name"].as_str().unwrap_or("").to_string();
        if counts.get(&name).copied().unwrap_or(0) <= 1 {
            continue;
        }
        let id = preset["id"].as_str().unwrap_or("").to_string();
        let mut suffix = 1;
        let mut candidate = format!("[{id}] {name}");
        while used.contains(&candidate) {
            suffix += 1;
            candidate = format!("[{id} #{suffix}] {name}");
        }
        used.insert(candidate.clone());
        preset["name"] = json!(candidate);
    }
    presets
}

/// Live catalog: spawn an idle session, ask `initialize` for `models`, tear down.
pub async fn list_models(ctx: &ListContext) -> Vec<Value> {
    ensure_claude_config();
    let Some(bin) = ctx.bin_path.clone().filter(|b| !b.is_empty()) else { return Vec::new() };
    let args: Vec<String> = ["--output-format", "stream-json", "--verbose", "--input-format", "stream-json"].iter().map(|s| s.to_string()).collect();
    let env = claude_process_env(&ctx.env);
    let Ok((mut process, _events)) = StreamJsonProcess::spawn(&spec_for_cli(&bin, args), &env, Some(&ctx.cwd), Arc::new(RejectAll)) else {
        return Vec::new();
    };
    let result = tokio::select! {
        _ = ctx.cancel.cancelled() => Err("aborted".to_string()),
        r = process.request_timeout(json!({ "subtype": "initialize", "hooks": null }), ctx.remaining()) => r,
    };
    process.terminate().await;
    match result {
        Ok(response) => map_claude_models(&response["models"]),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::RecordingSink;

    #[test]
    fn args_mcp_mode() {
        let servers = vec![McpServerConfig::stdio("netcatty-remote-hosts", "/app/netcatty", vec!["--mcp-server".into()], vec![crate::mcp::EnvPair { name: "T".into(), value: "1".into() }])];
        let args = build_claude_args(&ClaudeArgsInput { model: Some("opus/high"), resume: Some("sess-1"), tool_integration_mode: "mcp", injected_mcp_servers: &servers, settings: None });
        let joined = args.join(" ");
        assert!(joined.starts_with("--output-format stream-json --verbose --input-format stream-json --effort high --model opus --resume sess-1"));
        let tools = args.iter().position(|a| a == "--tools").unwrap();
        assert_eq!(args[tools + 1], "");
        assert!(joined.contains("--disallowedTools EnterPlanMode,ExitPlanMode,AskUserQuestion"));
        let mcp = args.iter().position(|a| a == "--mcp-config").unwrap();
        let cfg: Value = serde_json::from_str(&args[mcp + 1]).unwrap();
        assert_eq!(cfg["mcpServers"]["netcatty-remote-hosts"]["env"]["T"], "1");
        assert!(joined.contains("--permission-mode bypassPermissions --allow-dangerously-skip-permissions --include-partial-messages"));
        let settings = args.iter().position(|a| a == "--settings").unwrap();
        assert_eq!(serde_json::from_str::<Value>(&args[settings + 1]).unwrap(), json!({ "effort": "high" }));
    }

    #[test]
    fn args_skills_mode_and_settings() {
        let args = build_claude_args(&ClaudeArgsInput { model: Some("org/custom"), resume: None, tool_integration_mode: "skills", injected_mcp_servers: &[], settings: Some("/x/settings.json") });
        let tools = args.iter().position(|a| a == "--tools").unwrap();
        assert_eq!(args[tools + 1], "Bash,Skill");
        assert!(!args.contains(&"--mcp-config".to_string()));
        assert!(!args.contains(&"--effort".to_string()));
        assert!(args.contains(&"org/custom".to_string()));
        assert_eq!(args.last().unwrap(), "/x/settings.json");
        assert_eq!(parse_claude_settings(Some("{\"a\":1}")), Some(json!({ "a": 1 })));
        assert_eq!(parse_claude_settings(Some("{bad")), Some(json!("{bad")));
        assert_eq!(parse_claude_settings(Some("  ")), None);
        assert_eq!(merge_claude_effort_settings(Some(json!("/p")), Some("low")), Some(json!("/p")));
        assert_eq!(merge_claude_effort_settings(Some(json!({ "x": 1 })), Some("low")), Some(json!({ "x": 1, "effort": "low" })));
    }

    #[test]
    fn env_is_sdk_like() {
        let env: EnvMap = [("NODE_OPTIONS".to_string(), "x".to_string()), ("DEBUG".to_string(), "1".to_string())].into_iter().collect();
        let out = claude_process_env(&env);
        assert_eq!(out["CLAUDE_CODE_ENTRYPOINT"], "sdk-ts");
        assert!(!out.contains_key("NODE_OPTIONS") && !out.contains_key("DEBUG"));
    }

    #[test]
    fn translation() {
        let sink = Arc::new(RecordingSink::default());
        let e = Emitter::new(sink.clone(), "r");
        translate_claude_message(&json!({ "type": "system", "subtype": "init", "session_id": "s1" }), &e);
        translate_claude_message(&json!({ "type": "stream_event", "event": { "type": "content_block_delta", "delta": { "type": "text_delta", "text": "hi" } } }), &e);
        translate_claude_message(&json!({ "type": "stream_event", "event": { "type": "content_block_delta", "delta": { "type": "thinking_delta", "thinking": "hm" } } }), &e);
        translate_claude_message(&json!({ "type": "assistant", "message": { "content": [{ "type": "text", "text": "dup" }, { "type": "tool_use", "id": "t1", "name": "mcp__x__exec", "input": { "c": 1 } }] } }), &e);
        translate_claude_message(&json!({ "type": "user", "message": { "content": [{ "type": "tool_result", "tool_use_id": "t1", "content": [{ "type": "text", "text": "ok" }] }] } }), &e);
        let ev = sink.stream_events();
        assert_eq!(ev[0]["type"], "session-id");
        assert_eq!(ev[1]["textDelta"], "hi");
        assert_eq!(ev[2]["delta"], "hm");
        assert_eq!(ev[3], json!({ "type": "tool-call", "toolName": "mcp__x__exec", "args": { "c": 1 }, "toolCallId": "t1" }));
        assert_eq!(ev[4]["output"], "[{\"text\":\"ok\",\"type\":\"text\"}]");
        assert_eq!(ev.len(), 5);
    }

    #[test]
    fn prompt_content_with_images() {
        let att = vec![
            StagedAttachment { filename: "a.png".into(), media_type: "IMAGE/PNG".into(), file_path: "/t/a.png".into(), base64_data: "AAA".into() },
            StagedAttachment { filename: "b.txt".into(), media_type: "text/plain".into(), file_path: "/t/b".into(), base64_data: "BBB".into() },
        ];
        let content = build_claude_prompt_content("p", &att);
        assert_eq!(content.as_array().unwrap().len(), 2);
        assert_eq!(content[1]["source"]["media_type"], "image/png");
        assert_eq!(build_claude_prompt_content("p", &[]), json!([{ "type": "text", "text": "p" }]));
    }

    #[test]
    fn model_mapping() {
        let models = map_claude_models(&json!([
            { "value": "default", "displayName": "Default", "supportedEffortLevels": ["low", "high", "bogus"] },
            { "id": "sonnet", "name": "Same" },
            { "id": "haiku", "name": "Same", "supportsEffort": false },
            { "displayName": "no id" }
        ]));
        assert_eq!(models.len(), 3);
        assert_eq!(models[0]["thinkingLevels"], json!(["low", "high"]));
        assert_eq!(models[0]["defaultThinkingLevel"], "low");
        assert_eq!(models[1]["defaultThinkingLevel"], "medium");
        assert_eq!(models[1]["name"], "[sonnet] Same");
        assert_eq!(models[2]["name"], "[haiku] Same");
        assert_eq!(models[2]["thinkingLevels"], json!([]));
    }

    #[test]
    fn config_repair() {
        let home = tempfile::tempdir().unwrap();
        repair_claude_config(home.path());
        assert_eq!(std::fs::read_to_string(home.path().join(".claude.json")).unwrap(), "{}");
        std::fs::write(home.path().join(".claude.json"), "\u{feff}{\"a\":1}").unwrap();
        std::fs::write(home.path().join(".claude.json.corrupted.123"), "x").unwrap();
        repair_claude_config(home.path());
        assert_eq!(std::fs::read_to_string(home.path().join(".claude.json")).unwrap(), "{\"a\":1}");
        assert!(!home.path().join(".claude.json.corrupted.123").exists());
        std::fs::write(home.path().join(".claude.json"), "{broken").unwrap();
        repair_claude_config(home.path());
        assert_eq!(std::fs::read_to_string(home.path().join(".claude.json")).unwrap(), "{}");
    }
}

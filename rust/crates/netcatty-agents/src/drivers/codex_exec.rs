//! Codex `sdk` runtime (Electron: `sdk/codexDriver.cjs` over `@openai/codex-sdk`).
//!
//! The codex-sdk spawns `codex exec --experimental-json [--config k=v]...
//! [--model M] [--sandbox S] [--cd DIR] [--skip-git-repo-check]
//! [--config model_reasoning_effort="E"] [--config approval_policy="P"]
//! [resume THREAD] [--image PATH]...`, writes the prompt to stdin, closes it
//! and reads JSONL `ThreadEvent`s from stdout. This driver does the same.

use super::{split_model_effort, TurnContext, TurnResult};
use crate::emit::{Emitter, Usage};
use crate::mcp::McpServerConfig;
use crate::process::{spawn_lines, Stdin};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use tokio::io::AsyncWriteExt;

pub const CODEX_REASONING_EFFORTS: &[&str] = &["minimal", "low", "medium", "high", "xhigh", "max", "ultra"];
const MAX_LINE_BYTES: usize = 64 * 1024 * 1024;

pub fn parse_codex_model_selection(model: Option<&str>) -> (Option<String>, Option<String>) {
    split_model_effort(model, CODEX_REASONING_EFFORTS, false)
}

/// `toCodexMcpConfig`.
pub fn to_codex_mcp_config(servers: &[McpServerConfig], default_tools_approval_mode: Option<&str>) -> Value {
    let mut map = serde_json::Map::new();
    for cfg in servers.iter().filter(|c| !c.name.is_empty()) {
        let mut entry = json!({ "command": cfg.command, "args": cfg.args, "env": cfg.env_object() });
        if let Some(mode) = default_tools_approval_mode {
            entry["default_tools_approval_mode"] = json!(mode);
        }
        map.insert(cfg.name.clone(), entry);
    }
    Value::Object(map)
}

/// `toTomlValue`.
pub fn to_toml_value(value: &Value) -> String {
    match value {
        Value::String(s) => serde_json::to_string(s).unwrap_or_default(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Array(items) => format!("[{}]", items.iter().map(to_toml_value).collect::<Vec<_>>().join(", ")),
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter().map(|(k, v)| format!("{} = {}", toml_key(k), to_toml_value(v))).collect::<Vec<_>>().join(", ")
        ),
        Value::Null => "\"\"".into(),
    }
}

fn toml_key(key: &str) -> String {
    if !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        key.to_string()
    } else {
        serde_json::to_string(key).unwrap_or_default()
    }
}

/// `serializeConfigOverrides`: flatten nested objects into `a.b=toml` pairs.
pub fn serialize_config_overrides(config: &Value) -> Vec<String> {
    fn flatten(value: &Value, prefix: &str, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                if map.is_empty() {
                    if !prefix.is_empty() {
                        out.push(format!("{prefix}={{}}"));
                    }
                    return;
                }
                for (k, v) in map {
                    if v.is_null() {
                        continue;
                    }
                    let path = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                    if v.is_object() {
                        flatten(v, &path, out);
                    } else {
                        out.push(format!("{path}={}", to_toml_value(v)));
                    }
                }
            }
            other if !prefix.is_empty() => out.push(format!("{prefix}={}", to_toml_value(other))),
            _ => {}
        }
    }
    let mut out = Vec::new();
    flatten(config, "", &mut out);
    out
}

pub struct CodexExecArgs<'a> {
    pub injected_mcp_servers: &'a [McpServerConfig],
    pub base_url: Option<&'a str>,
    pub model: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub resume_thread_id: Option<&'a str>,
    pub images: Vec<String>,
}

/// argv for one turn (`buildCodexConstructorOptions` + `buildCodexThreadOptions`).
pub fn build_codex_exec_args(input: &CodexExecArgs<'_>) -> Vec<String> {
    let mut args = vec!["exec".to_string(), "--experimental-json".to_string()];
    let config = json!({ "mcp_servers": to_codex_mcp_config(input.injected_mcp_servers, None), "model_reasoning_summary": "concise" });
    for override_ in serialize_config_overrides(&config) {
        args.extend(["--config".into(), override_]);
    }
    if let Some(base) = input.base_url {
        args.extend(["--config".into(), format!("openai_base_url={}", to_toml_value(&json!(base)))]);
    }
    let (model, effort) = parse_codex_model_selection(input.model);
    if let Some(model) = model {
        args.extend(["--model".into(), model]);
    }
    // Non-interactive exec cancels every MCP call unless approvals are bypassed.
    args.extend(["--sandbox".into(), "danger-full-access".into()]);
    if let Some(cwd) = input.cwd {
        args.extend(["--cd".into(), cwd.to_string()]);
    }
    args.push("--skip-git-repo-check".into());
    if let Some(effort) = effort {
        args.extend(["--config".into(), format!("model_reasoning_effort=\"{effort}\"")]);
    }
    args.extend(["--config".into(), "approval_policy=\"never\"".into()]);
    if let Some(thread) = input.resume_thread_id.filter(|t| !t.is_empty()) {
        args.extend(["resume".into(), thread.to_string()]);
    }
    for image in &input.images {
        args.extend(["--image".into(), image.clone()]);
    }
    args
}

/// Translation state threaded across events.
#[derive(Default)]
pub struct CodexState {
    pub reasoning_open: bool,
    pub fatal_error: bool,
    reasoning_text: HashMap<String, String>,
    tool_calls: HashSet<String>,
    tool_results: HashSet<String>,
    stream_warning_count: u64,
}

/// Mid-turn reconnect errors are recoverable (`isCodexRetryableStreamError`).
pub fn is_codex_retryable_stream_error(event: &Value) -> bool {
    if event.get("willRetry") == Some(&json!(false)) || event.get("will_retry") == Some(&json!(false)) {
        return false;
    }
    if event.get("willRetry") == Some(&json!(true)) || event.get("will_retry") == Some(&json!(true)) {
        return true;
    }
    let message = event["message"].as_str().unwrap_or("").to_ascii_lowercase();
    let re = regex::Regex::new(r"\b(?:reconnecting|retrying)\b").unwrap();
    !message.is_empty() && re.is_match(&message)
}

fn extract_mcp_result_text(item: &Value) -> String {
    if let Some(message) = item.pointer("/error/message").and_then(|m| m.as_str()) {
        return message.to_string();
    }
    if let Some(content) = item.pointer("/result/content").and_then(|c| c.as_array()) {
        return content
            .iter()
            .map(|b| b.get("text").and_then(|t| t.as_str()).map(str::to_string).unwrap_or_else(|| if b.is_null() { String::new() } else { b.to_string() }))
            .collect();
    }
    match item.get("result") {
        Some(r) if !r.is_null() => r.to_string(),
        _ => String::new(),
    }
}

/// `translateCodexEvent`.
pub fn translate_codex_event(event: &Value, emitter: &Emitter, st: &mut CodexState) {
    let close_reasoning = |st: &mut CodexState| {
        if st.reasoning_open {
            emitter.reasoning_end();
            st.reasoning_open = false;
        }
    };
    let kind = event["type"].as_str().unwrap_or("");
    match kind {
        "turn.failed" => {
            close_reasoning(st);
            st.fatal_error = true;
            emitter.emit_error(event.pointer("/error/message").and_then(|m| m.as_str()).unwrap_or("Codex turn failed"));
            return;
        }
        "error" => {
            let message = event["message"].as_str().unwrap_or("Codex stream failed");
            if is_codex_retryable_stream_error(event) {
                st.stream_warning_count += 1;
                emitter.warning(&format!("codex-stream-error:{}", st.stream_warning_count), message);
                return;
            }
            close_reasoning(st);
            st.fatal_error = true;
            emitter.emit_error(message);
            return;
        }
        "turn.completed" => {
            let usage = &event["usage"];
            let fields = ["input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens"];
            if !fields.iter().any(|f| usage[*f].is_number()) {
                return;
            }
            let input = usage["input_tokens"].as_u64().unwrap_or(0);
            let output = usage["output_tokens"].as_u64().unwrap_or(0);
            emitter.usage(Usage {
                input_tokens: input,
                cached_input_tokens: usage["cached_input_tokens"].as_u64().unwrap_or(0),
                output_tokens: output,
                reasoning_tokens: usage["reasoning_output_tokens"].as_u64().unwrap_or(0),
                total_tokens: input + output,
            });
            return;
        }
        "item.started" | "item.updated" | "item.completed" => {}
        _ => return,
    }
    let item = &event["item"];
    if !item.is_object() {
        return;
    }
    let completed = kind == "item.completed";
    let id = item["id"].as_str().unwrap_or("").to_string();
    if item["type"] == "reasoning" {
        let Some(text) = item["text"].as_str().filter(|t| !t.is_empty()) else { return };
        let key = if id.is_empty() { "__default_reasoning".to_string() } else { id.clone() };
        let previous = st.reasoning_text.get(&key).cloned().unwrap_or_default();
        let delta = text.strip_prefix(previous.as_str()).unwrap_or(text).to_string();
        st.reasoning_text.insert(key, text.to_string());
        if !delta.is_empty() {
            emitter.reasoning(&delta);
            st.reasoning_open = true;
        }
        return;
    }
    close_reasoning(st);
    let tool_call = |st: &mut CodexState, name: &str, args: Value| {
        if !id.is_empty() && st.tool_calls.insert(id.clone()) {
            emitter.tool_call(name, args, &id);
        }
    };
    match item["type"].as_str().unwrap_or("") {
        "agent_message" => {
            if completed {
                emitter.text(item["text"].as_str().unwrap_or(""));
            }
        }
        "command_execution" => {
            tool_call(st, "shell", json!({ "command": item["command"].as_str().unwrap_or("") }));
            if let (true, Some(out)) = (completed, item["aggregated_output"].as_str().filter(|o| !o.is_empty())) {
                if !id.is_empty() && st.tool_results.insert(id.clone()) {
                    emitter.tool_result(&id, out, Some("shell"));
                }
            }
        }
        "mcp_tool_call" => {
            let name = item["tool"].as_str().unwrap_or("mcp_tool").to_string();
            let args = if item["arguments"].is_object() { item["arguments"].clone() } else { json!({}) };
            tool_call(st, &name, args);
            if completed && !id.is_empty() && st.tool_results.insert(id.clone()) {
                emitter.tool_result(&id, &extract_mcp_result_text(item), Some(&name));
            }
        }
        "file_change" => {
            if completed {
                let status = if item["status"] == "failed" { "failed" } else { "completed" };
                emitter.file_change(&id, item["changes"].clone(), status);
            }
        }
        "web_search" => emitter.web_search(&id, item["query"].as_str().unwrap_or(""), if completed { "completed" } else { "running" }),
        "todo_list" => emitter.plan_update(&id, item["items"].clone(), if completed { "completed" } else { "running" }),
        "error" => {
            if completed {
                emitter.warning(&id, item["message"].as_str().unwrap_or("Codex reported a recoverable error"));
            }
        }
        _ => {}
    }
}

/// Run a Codex turn on the exec transport.
pub async fn run_turn(ctx: &TurnContext, api_key: Option<&str>, base_url: Option<&str>) -> TurnResult {
    let emitter = &ctx.emitter;
    let Some(bin) = ctx.bin_path.clone().filter(|b| !b.is_empty()) else {
        emitter.emit_error("Codex binary not found. Install with `npm i -g @openai/codex` (or `brew install --cask codex`).");
        return TurnResult::default();
    };
    let images: Vec<String> = ctx.attachments.iter().filter(|a| a.media_type.to_ascii_lowercase().starts_with("image/") && !a.file_path.is_empty()).map(|a| a.file_path.clone()).collect();
    let cwd = ctx.cwd.to_string_lossy().into_owned();
    let args = build_codex_exec_args(&CodexExecArgs {
        injected_mcp_servers: &ctx.injected_mcp_servers,
        base_url,
        model: ctx.model.as_deref(),
        cwd: Some(&cwd),
        resume_thread_id: ctx.resume_session_id.as_deref(),
        images,
    });
    let mut env = ctx.env.clone();
    env.entry("CODEX_INTERNAL_ORIGINATOR_OVERRIDE".into()).or_insert_with(|| "codex_sdk_ts".into());
    if let Some(key) = api_key.filter(|k| !k.is_empty()) {
        env.insert("CODEX_API_KEY".into(), key.to_string());
    }
    let spec = crate::cli::SpawnSpec { command: bin.clone(), args, shell: false };
    let mut spawned = match spawn_lines(&spec, &env, None, Stdin::Piped, MAX_LINE_BYTES, 64 * 1024) {
        Ok(s) => s,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            emitter.emit_error("Codex binary not found. Install with `npm i -g @openai/codex` (or `brew install --cask codex`).");
            return TurnResult::default();
        }
        Err(error) => {
            emitter.emit_error(error.to_string());
            return TurnResult::default();
        }
    };
    if let Some(mut stdin) = spawned.child.stdin.take() {
        let _ = stdin.write_all(ctx.prompt.as_bytes()).await;
        let _ = stdin.shutdown().await;
    }
    let mut thread_id: Option<String> = None;
    let mut state = CodexState::default();
    let mut has_content = false;
    loop {
        let line = tokio::select! {
            _ = ctx.cancel.cancelled() => {
                crate::process::terminate_child(&mut spawned.child, crate::process::DEFAULT_ABORT_GRACE).await;
                return TurnResult { session_id: thread_id.or(ctx.resume_session_id.clone()) };
            }
            line = spawned.stdout.next_line() => line,
        };
        let line = match line {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => {
                emitter.emit_error(format!("Codex {error}"));
                crate::process::terminate_child(&mut spawned.child, crate::process::DEFAULT_ABORT_GRACE).await;
                return TurnResult { session_id: thread_id };
            }
        };
        let Ok(event) = serde_json::from_str::<Value>(&line) else {
            emitter.emit_error(format!("Failed to parse item: {line}"));
            crate::process::terminate_child(&mut spawned.child, crate::process::DEFAULT_ABORT_GRACE).await;
            return TurnResult { session_id: thread_id };
        };
        if thread_id.is_none() && event["type"] == "thread.started" {
            if let Some(id) = event["thread_id"].as_str() {
                thread_id = Some(id.to_string());
                emitter.session_id(id);
            }
        }
        if event["type"] == "item.completed" {
            has_content = true;
        }
        translate_codex_event(&event, emitter, &mut state);
        if state.fatal_error {
            break;
        }
    }
    if state.reasoning_open {
        emitter.reasoning_end();
    }
    if thread_id.is_none() {
        if let Some(id) = ctx.resume_session_id.clone() {
            emitter.session_id(&id);
            thread_id = Some(id);
        }
    }
    if state.fatal_error {
        crate::process::terminate_child(&mut spawned.child, crate::process::DEFAULT_ABORT_GRACE).await;
        return TurnResult { session_id: thread_id };
    }
    let status = spawned.child.wait().await.ok();
    if ctx.aborted() {
        return TurnResult { session_id: thread_id };
    }
    let code = status.and_then(|s| s.code());
    if code != Some(0) {
        let detail = code.map(|c| format!("code {c}")).unwrap_or_else(|| "signal".into());
        emitter.emit_error(format!("Codex Exec exited with {detail}: {}", spawned.stderr.text()));
        return TurnResult { session_id: thread_id };
    }
    if !has_content {
        emitter.emit_error("Codex returned an empty response. Reconnect Codex in Settings -> AI (codex login), or configure a provider in ~/.codex/config.toml.");
        return TurnResult { session_id: thread_id };
    }
    emitter.emit_done();
    TurnResult { session_id: thread_id }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::RecordingSink;
    use std::sync::Arc;

    #[test]
    fn config_overrides_match_sdk() {
        let servers = vec![McpServerConfig::stdio("netcatty", "/app/nc", vec!["--mcp-server".into()], vec![crate::mcp::EnvPair { name: "TOKEN".into(), value: "x\"y".into() }])];
        let overrides = serialize_config_overrides(&json!({ "mcp_servers": to_codex_mcp_config(&servers, None), "model_reasoning_summary": "concise" }));
        assert!(overrides.contains(&"mcp_servers.netcatty.command=\"/app/nc\"".to_string()));
        assert!(overrides.contains(&"mcp_servers.netcatty.args=[\"--mcp-server\"]".to_string()));
        assert!(overrides.contains(&"mcp_servers.netcatty.env.TOKEN=\"x\\\"y\"".to_string()));
        assert!(overrides.contains(&"model_reasoning_summary=\"concise\"".to_string()));
        assert_eq!(serialize_config_overrides(&json!({ "mcp_servers": {} })), vec!["mcp_servers={}".to_string()]);
    }

    #[test]
    fn exec_args() {
        let args = build_codex_exec_args(&CodexExecArgs { injected_mcp_servers: &[], base_url: Some("https://x"), model: Some("gpt-5.5/high"), cwd: Some("/w"), resume_thread_id: Some("th"), images: vec!["/i.png".into()] });
        let joined = args.join(" ");
        assert!(joined.starts_with("exec --experimental-json --config mcp_servers={} --config model_reasoning_summary=\"concise\" --config openai_base_url=\"https://x\" --model gpt-5.5 --sandbox danger-full-access --cd /w --skip-git-repo-check --config model_reasoning_effort=\"high\" --config approval_policy=\"never\" resume th --image /i.png"));
        let (m, e) = parse_codex_model_selection(Some("openrouter/x"));
        assert_eq!((m.as_deref(), e), (Some("openrouter/x"), None));
    }

    #[test]
    fn translation_dedupes_and_streams_reasoning_suffix() {
        let sink = Arc::new(RecordingSink::default());
        let e = Emitter::new(sink.clone(), "r");
        let mut st = CodexState::default();
        for ev in [
            json!({ "type": "item.updated", "item": { "id": "r1", "type": "reasoning", "text": "Think" } }),
            json!({ "type": "item.completed", "item": { "id": "r1", "type": "reasoning", "text": "Thinking" } }),
            json!({ "type": "item.started", "item": { "id": "c1", "type": "command_execution", "command": "ls" } }),
            json!({ "type": "item.completed", "item": { "id": "c1", "type": "command_execution", "command": "ls", "aggregated_output": "a\n" } }),
            json!({ "type": "item.completed", "item": { "id": "m1", "type": "mcp_tool_call", "tool": "exec", "arguments": { "x": 1 }, "result": { "content": [{ "type": "text", "text": "ok" }] } } }),
            json!({ "type": "error", "message": "Reconnecting... 1/5" }),
            json!({ "type": "item.completed", "item": { "id": "a1", "type": "agent_message", "text": "done" } }),
            json!({ "type": "turn.completed", "usage": { "input_tokens": 3, "output_tokens": 4 } }),
        ] {
            translate_codex_event(&ev, &e, &mut st);
        }
        let ev = sink.stream_events();
        let types: Vec<&str> = ev.iter().map(|v| v["type"].as_str().unwrap()).collect();
        assert_eq!(types, vec!["reasoning-delta", "reasoning-delta", "reasoning-end", "tool-call", "tool-result", "tool-call", "tool-result", "warning", "text-delta", "usage"]);
        assert_eq!(ev[1]["delta"], "ing");
        assert_eq!(ev[6]["output"], "ok");
        assert_eq!(ev[7]["itemId"], "codex-stream-error:1");
        assert_eq!(ev[9]["totalTokens"], 7);
        assert!(!st.fatal_error);
        translate_codex_event(&json!({ "type": "error", "message": "stream dropped", "willRetry": false }), &e, &mut st);
        assert!(st.fatal_error);
        assert_eq!(sink.errors(), vec!["stream dropped".to_string()]);
    }
}

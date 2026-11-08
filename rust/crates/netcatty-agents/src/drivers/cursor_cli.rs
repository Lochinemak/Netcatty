//! Cursor Agent CLI driver (CLI login / subscription quota; Electron:
//! `sdk/cursorCliDriver.cjs`, `aiBridge/cursorCliSpawn.cjs`).
//!
//! `cursor-agent --print --trust --approve-mcps --output-format stream-json
//! --stream-partial-output --model M [--workspace DIR] [--resume S]
//! (--mode ask | --force) PROMPT`, with Netcatty MCP merged into
//! `<workspace>/.cursor/mcp.json` for the turn.
//!
//! The Cursor SDK (API-key mode) is a Node package and is not available here.

use super::grok::{merge_workspace_file, ConfigMergeGuard, MergeState};
use super::{result_to_text, ListContext, TurnContext, TurnResult};
use crate::catalog::ModelCatalog;
use crate::emit::Emitter;
use crate::mcp::McpServerConfig;
use crate::process::{spawn_lines, terminate_child, Stdin, DEFAULT_ABORT_GRACE};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const DEFAULT_CURSOR_CLI_MODEL: &str = "auto";
const CURSOR_REASONING_EFFORTS: &[&str] = &["low", "medium", "high", "xhigh"];
const MAX_LINE_BYTES: usize = 10 * 1024 * 1024;

/// `encodeCursorCliModel`: `<id>/<effort>` → `<id>?effort=<effort>`; query ids kept.
pub fn encode_cursor_cli_model(model: Option<&str>) -> String {
    let raw = model.unwrap_or("").trim();
    if raw.is_empty() {
        return String::new();
    }
    if let Some(q) = raw.find('?') {
        let params: Vec<(String, String)> = url::form_urlencoded::parse(raw[q + 1..].as_bytes()).filter(|(k, v)| !k.is_empty() && !v.is_empty()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
        let id = &raw[..q];
        if params.is_empty() {
            return id.to_string();
        }
        let qs = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(params).finish();
        return format!("{id}?{qs}");
    }
    if let Some(slash) = raw.rfind('/') {
        let effort = raw[slash + 1..].to_ascii_lowercase();
        if slash > 0 && CURSOR_REASONING_EFFORTS.contains(&effort.as_str()) {
            return format!("{}?effort={effort}", &raw[..slash]);
        }
    }
    raw.to_string()
}

pub fn resolve_exec_mode(permission_mode: &str) -> &'static str {
    if permission_mode.eq_ignore_ascii_case("observer") { "ask" } else { "agent" }
}

pub fn build_args(model: Option<&str>, resume: Option<&str>, permission_mode: &str, cwd: Option<&str>, prompt: &str) -> Vec<String> {
    let encoded = encode_cursor_cli_model(model);
    let mut args: Vec<String> = ["--print", "--trust", "--approve-mcps", "--output-format", "stream-json", "--stream-partial-output", "--model"].iter().map(|s| s.to_string()).collect();
    args.push(if encoded.is_empty() { DEFAULT_CURSOR_CLI_MODEL.into() } else { encoded });
    if let Some(c) = cwd {
        args.extend(["--workspace".into(), c.into()]);
    }
    if let Some(r) = resume.filter(|r| !r.is_empty()) {
        args.extend(["--resume".into(), r.into()]);
    }
    if resolve_exec_mode(permission_mode) == "ask" {
        args.extend(["--mode".into(), "ask".into()]);
    } else {
        args.push("--force".into());
    }
    args.push(prompt.into());
    args
}

/// Writable per-chat workspace (`cursor-cli-mcp/<chat>` under the temp dir).
pub fn workspace_cwd(temp_dir: &Path, chat_session_id: &str) -> std::io::Result<PathBuf> {
    let safe: String = chat_session_id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' }).take(80).collect();
    let dir = temp_dir.join("cursor-cli-mcp").join(if safe.is_empty() { "default".into() } else { safe });
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn registry() -> &'static Mutex<HashMap<PathBuf, MergeState>> {
    static REG: OnceLock<Mutex<HashMap<PathBuf, MergeState>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Merge injected servers into `<cwd>/.cursor/mcp.json`; restored on drop.
pub fn merge_workspace_mcp_json(cwd: &Path, servers: &[McpServerConfig]) -> std::io::Result<ConfigMergeGuard> {
    let path = cwd.join(".cursor").join("mcp.json");
    merge_workspace_file(&path, registry(), |base| {
        let mut doc = base.and_then(|b| serde_json::from_str::<Value>(&b).ok()).filter(|d| d.is_object()).unwrap_or_else(|| json!({}));
        if !doc["mcpServers"].is_object() {
            doc["mcpServers"] = json!({});
        }
        for c in servers.iter().filter(|c| !c.name.is_empty() && !c.command.is_empty()) {
            let mut entry = json!({ "type": "stdio", "command": c.command, "args": c.args });
            if !c.env.is_empty() {
                entry["env"] = c.env_object();
            }
            doc["mcpServers"][&c.name] = entry;
        }
        format!("{}\n", serde_json::to_string_pretty(&doc).unwrap_or_default())
    })
}

pub fn format_error_for_user(message: &str) -> String {
    let text = message.trim();
    let login = regex::Regex::new(r"(?i)not authenticated|not logged in|please run .*login|unauthenticated|unauthorized").unwrap();
    let cmd = regex::Regex::new(r"(?i)(?:^|\b)(?:agent|cursor-agent)\s+login\b").unwrap();
    if login.is_match(text) || cmd.is_match(text) {
        return "Cursor CLI is not logged in. Run `cursor-agent login` in a terminal, then retry.".into();
    }
    let key = regex::Regex::new(r"(?i)\bapi[_\s-]?key\b").unwrap();
    let bad = regex::Regex::new(r"(?i)invalid|missing|required|auth").unwrap();
    if key.is_match(text) && bad.is_match(text) {
        return "Cursor CLI authentication failed. Run `cursor-agent login` or switch Cursor to API Key mode in Settings → AI.".into();
    }
    if text.is_empty() { "Cursor CLI turn failed".into() } else { text.to_string() }
}

fn extract_tool_call(event: &Value) -> (Option<String>, String, Value, Value) {
    let call_id = event["call_id"].as_str().or(event["toolCallId"].as_str()).map(str::to_string);
    let tc = if event["tool_call"].is_object() { &event["tool_call"] } else { &event["toolCall"] };
    if let Some(map) = tc.as_object() {
        for (k, v) in map {
            if let (Some(name), true) = (k.strip_suffix("ToolCall"), v.is_object()) {
                let args = if v["args"].is_object() { v["args"].clone() } else { json!({}) };
                return (call_id.or(v["toolCallId"].as_str().map(str::to_string)), name.to_string(), args, v["result"].clone());
            }
        }
        return (call_id, event["name"].as_str().unwrap_or("tool").into(), tc["args"].clone(), tc["result"].clone());
    }
    (call_id, event["name"].as_str().unwrap_or("tool").into(), event["args"].clone(), event["result"].clone())
}

fn cursor_result_text(v: &Value) -> String {
    if let Some(s) = v.pointer("/success/content").and_then(|c| c.as_str()) {
        return s.to_string();
    }
    result_to_text(v)
}

#[derive(Default)]
pub struct CursorState {
    pub session_id: Option<String>,
    pub reasoning_open: bool,
    pub streamed_text: bool,
    pub failed: bool,
    calls: HashSet<String>,
    results: HashSet<String>,
}

/// `translateCursorCliEvent`; returns `true` on a terminal error.
pub fn translate_event(event: &Value, emitter: &Emitter, st: &mut CursorState) -> bool {
    let close = |st: &mut CursorState| {
        if st.reasoning_open {
            emitter.reasoning_end();
            st.reasoning_open = false;
        }
    };
    match event["type"].as_str().unwrap_or("") {
        "system" => {
            if let Some(id) = event["session_id"].as_str() {
                st.session_id = Some(id.into());
                emitter.session_id(id);
            }
        }
        "thinking" => {
            if event["subtype"] == "completed" {
                close(st);
            } else if let Some(t) = event["text"].as_str().filter(|t| !t.is_empty()) {
                emitter.reasoning(t);
                st.reasoning_open = true;
            }
        }
        "assistant" => {
            close(st);
            if !event["model_call_id"].is_null() {
                return false;
            }
            let partial = !event["timestamp_ms"].is_null();
            let text: String = event.pointer("/message/content").and_then(|c| c.as_array()).map(|blocks| blocks.iter().filter(|b| b["type"] == "text").filter_map(|b| b["text"].as_str()).collect()).unwrap_or_default();
            if text.is_empty() || (!partial && st.streamed_text) {
                return false;
            }
            emitter.text(&text);
            st.streamed_text = true;
        }
        "tool_call" => {
            close(st);
            let (id, name, args, result) = extract_tool_call(event);
            let Some(id) = id else { return false };
            let args = if args.is_object() { args } else { json!({}) };
            let subtype = event["subtype"].as_str().unwrap_or("");
            if matches!(subtype, "" | "started" | "running" | "completed" | "error") && st.calls.insert(id.clone()) {
                emitter.tool_call(&name, args, &id);
            }
            if matches!(subtype, "completed" | "error") && st.results.insert(id.clone()) {
                let r = if result.is_null() { event["error"].clone() } else { result };
                emitter.tool_result(&id, &cursor_result_text(&r), Some(&name));
            }
        }
        "result" => {
            close(st);
            if let Some(id) = event["session_id"].as_str() {
                st.session_id = Some(id.into());
                emitter.session_id(id);
            }
            if event["is_error"] == true || event["subtype"] == "error" {
                st.failed = true;
                let msg = event["result"].as_str().or(event["error"].as_str()).or(event["message"].as_str()).unwrap_or("Cursor CLI turn failed");
                emitter.emit_error(format_error_for_user(msg));
                return true;
            }
        }
        "error" => {
            close(st);
            st.failed = true;
            emitter.emit_error(format_error_for_user(event["message"].as_str().or(event["error"].as_str()).unwrap_or("Cursor CLI turn failed")));
            return true;
        }
        _ => {}
    }
    false
}

fn spec(bin: &str, args: &[String]) -> crate::cli::SpawnSpec {
    crate::cli::resolve_cursor_cli_spawn_spec(bin, args)
}

pub async fn run_turn(ctx: &TurnContext) -> TurnResult {
    let emitter = &ctx.emitter;
    let Some(bin) = ctx.cursor_cli_bin_path.clone().or(ctx.bin_path.clone()).filter(|b| !b.trim().is_empty()) else {
        emitter.emit_error("Cursor Agent CLI not found. Install the Cursor CLI (`cursor-agent`) and ensure it is on PATH.");
        return TurnResult { session_id: ctx.resume_session_id.clone() };
    };
    let cwd = match workspace_cwd(&ctx.temp_dir, &ctx.chat_session_id) {
        Ok(c) => c,
        Err(e) => {
            emitter.emit_error(format!("Failed to prepare Netcatty MCP for Cursor CLI (cannot create workspace: {e}). Terminal tools will be unavailable."));
            return TurnResult { session_id: ctx.resume_session_id.clone() };
        }
    };
    let env = crate::auth::strip_cursor_api_key_from_env(&ctx.env);
    let cwd_text = cwd.to_string_lossy().into_owned();
    let args = build_args(ctx.model.as_deref(), ctx.resume_session_id.as_deref(), &ctx.permission_mode, Some(&cwd_text), &ctx.prompt);
    let mut guard = None;
    if !ctx.injected_mcp_servers.is_empty() {
        match merge_workspace_mcp_json(&cwd, &ctx.injected_mcp_servers) {
            Ok(g) => guard = Some(g),
            Err(e) => {
                emitter.emit_error(format!("Failed to prepare Netcatty MCP for Cursor CLI (cannot write workspace MCP config: {e}). Terminal tools will be unavailable."));
                return TurnResult { session_id: ctx.resume_session_id.clone() };
            }
        }
    }
    let mut st = CursorState { session_id: ctx.resume_session_id.clone(), ..Default::default() };
    let mut spawned = match spawn_lines(&spec(&bin, &args), &env, Some(&cwd), Stdin::Null, MAX_LINE_BYTES, 64 * 1024) {
        Ok(s) => s,
        Err(e) => {
            emitter.emit_error(format_error_for_user(&e.to_string()));
            return TurnResult { session_id: st.session_id };
        }
    };
    loop {
        let line = tokio::select! {
            _ = ctx.cancel.cancelled() => {
                terminate_child(&mut spawned.child, DEFAULT_ABORT_GRACE).await;
                drop(guard);
                return TurnResult { session_id: st.session_id };
            }
            line = spawned.stdout.next_line() => line,
        };
        match line {
            Ok(Some(l)) => {
                if let Ok(ev) = serde_json::from_str::<Value>(&l) {
                    translate_event(&ev, emitter, &mut st);
                }
            }
            Ok(None) => break,
            Err(e) => {
                if !st.failed {
                    st.failed = true;
                    emitter.emit_error(format_error_for_user(&format!("Cursor CLI {e}")));
                }
                terminate_child(&mut spawned.child, std::time::Duration::ZERO).await;
                break;
            }
        }
    }
    let code = spawned.child.wait().await.ok().and_then(|s| s.code());
    drop(guard);
    if st.reasoning_open {
        emitter.reasoning_end();
    }
    if !st.failed && !ctx.aborted() && code.map(|c| c != 0).unwrap_or(false) && !st.streamed_text {
        let stderr = spawned.stderr.text().trim().to_string();
        st.failed = true;
        emitter.emit_error(format_error_for_user(&if stderr.is_empty() { format!("Cursor CLI exited with code {}", code.unwrap()) } else { stderr }));
    }
    if !st.failed && !ctx.aborted() {
        emitter.emit_done();
    }
    TurnResult { session_id: st.session_id }
}

/// `cursor-agent models` text output.
pub fn parse_models_output(stdout: &str) -> ModelCatalog {
    let line_re = regex::Regex::new(r"(?i)^([a-z0-9][a-z0-9._-]*)\s+-\s+(.+)$").unwrap();
    let current_re = regex::Regex::new(r"(?i)\s*\(\s*current(?:\s*,\s*default)?\s*\)\s*").unwrap();
    let mut models = Vec::new();
    let mut seen = HashSet::new();
    let mut current = None;
    for line in stdout.lines() {
        let t = line.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("available models") {
            continue;
        }
        let Some(c) = line_re.captures(t) else { continue };
        let id = c[1].to_string();
        if !seen.insert(id.clone()) {
            continue;
        }
        let raw = c[2].trim();
        if current_re.is_match(raw) {
            current = Some(id.clone());
        }
        let name = current_re.replace_all(raw, " ").split_whitespace().collect::<Vec<_>>().join(" ");
        models.push(json!({ "id": id, "name": if name.is_empty() { id.clone() } else { name } }));
    }
    if current.is_none() && models.iter().any(|m| m["id"] == "auto") {
        current = Some("auto".into());
    }
    ModelCatalog { current_model_id: current, models }
}

pub async fn list_models(ctx: &ListContext) -> ModelCatalog {
    let Some(bin) = ctx.cursor_cli_bin_path.clone().or(ctx.bin_path.clone()).filter(|b| !b.trim().is_empty()) else { return ModelCatalog::default() };
    let env = crate::auth::strip_cursor_api_key_from_env(&ctx.env);
    let s = spec(&bin, &["models".into()]);
    let mut cmd = crate::cli::command_for_spec(&s);
    cmd.env_clear().envs(env.iter()).stdin(std::process::Stdio::null()).kill_on_drop(true);
    tokio::select! {
        _ = ctx.cancel.cancelled() => ModelCatalog::default(),
        r = tokio::time::timeout(ctx.remaining(), cmd.output()) => match r {
            Ok(Ok(out)) => parse_models_output(&crate::cli::strip_ansi(&String::from_utf8_lossy(&out.stdout))),
            _ => ModelCatalog::default(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::RecordingSink;
    use std::sync::Arc;

    #[test]
    fn model_encoding_and_args() {
        assert_eq!(encode_cursor_cli_model(Some("gpt-5/high")), "gpt-5?effort=high");
        assert_eq!(encode_cursor_cli_model(Some("gpt-5?effort=low&x=")), "gpt-5?effort=low");
        assert_eq!(encode_cursor_cli_model(Some("vendor/model")), "vendor/model");
        assert_eq!(encode_cursor_cli_model(None), "");
        let args = build_args(None, Some("s"), "observer", Some("/w"), "hi");
        assert_eq!(args.join(" "), "--print --trust --approve-mcps --output-format stream-json --stream-partial-output --model auto --workspace /w --resume s --mode ask hi");
        assert!(build_args(Some("m"), None, "confirm", None, "p").contains(&"--force".to_string()));
    }

    #[test]
    fn translation_dedupes_final_flush() {
        let sink = Arc::new(RecordingSink::default());
        let e = Emitter::new(sink.clone(), "r");
        let mut st = CursorState::default();
        for ev in [
            json!({ "type": "system", "session_id": "c-1" }),
            json!({ "type": "thinking", "text": "hm" }),
            json!({ "type": "thinking", "subtype": "completed" }),
            json!({ "type": "assistant", "timestamp_ms": 1, "message": { "content": [{ "type": "text", "text": "Hi" }] } }),
            json!({ "type": "assistant", "timestamp_ms": 2, "model_call_id": "m", "message": { "content": [{ "type": "text", "text": "Hi" }] } }),
            json!({ "type": "tool_call", "subtype": "completed", "call_id": "t1", "tool_call": { "shellToolCall": { "args": { "command": "ls" }, "result": { "success": { "content": "a" } } } } }),
            json!({ "type": "assistant", "message": { "content": [{ "type": "text", "text": "Hi" }] } }),
        ] {
            translate_event(&ev, &e, &mut st);
        }
        let ev = sink.stream_events();
        let types: Vec<&str> = ev.iter().map(|v| v["type"].as_str().unwrap()).collect();
        assert_eq!(types, vec!["session-id", "reasoning-delta", "reasoning-end", "text-delta", "tool-call", "tool-result"]);
        assert_eq!(ev[4]["toolName"], "shell");
        assert_eq!(ev[5]["output"], "a");
        assert!(translate_event(&json!({ "type": "result", "is_error": true, "result": "Please run cursor-agent login" }), &e, &mut st));
        assert_eq!(sink.errors()[0], "Cursor CLI is not logged in. Run `cursor-agent login` in a terminal, then retry.");
    }

    #[test]
    fn mcp_json_merge() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".cursor/mcp.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{\"mcpServers\":{\"mine\":{\"command\":\"x\"}}}").unwrap();
        let g = merge_workspace_mcp_json(dir.path(), &[McpServerConfig::stdio("netcatty-remote-hosts", "/c", vec![], vec![])]).unwrap();
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["mcpServers"]["mine"]["command"], "x");
        assert_eq!(doc["mcpServers"]["netcatty-remote-hosts"]["type"], "stdio");
        assert!(doc["mcpServers"]["netcatty-remote-hosts"].get("env").is_none());
        drop(g);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"mcpServers\":{\"mine\":{\"command\":\"x\"}}}");
        assert_eq!(workspace_cwd(dir.path(), "a/b c").unwrap(), dir.path().join("cursor-cli-mcp/a_b_c"));
    }

    #[test]
    fn models_output() {
        let c = parse_models_output("Available models\n\nauto - Auto  (current, default)\ngpt-5 - GPT-5\ngpt-5 - dup\n");
        assert_eq!(c.current_model_id.as_deref(), Some("auto"));
        assert_eq!(c.models, vec![json!({ "id": "auto", "name": "Auto" }), json!({ "id": "gpt-5", "name": "GPT-5" })]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn turn_against_fake_cli() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("cursor-agent");
        std::fs::write(&bin, "#!/bin/sh\n[ -n \"$CURSOR_API_KEY\" ] && exit 9\nprintf '{\"type\":\"system\",\"session_id\":\"cs\"}\\n{\"type\":\"assistant\",\"timestamp_ms\":1,\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}\\n{\"type\":\"result\",\"subtype\":\"success\"}\\n'\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sink = Arc::new(RecordingSink::default());
        let env: crate::EnvMap = [("PATH".to_string(), "/usr/bin:/bin".to_string()), ("CURSOR_API_KEY".to_string(), "k".to_string())].into_iter().collect();
        let mut ctx = crate::drivers::test_turn_context(Emitter::new(sink.clone(), "r"), None, env);
        ctx.cursor_cli_bin_path = Some(bin.to_string_lossy().into_owned());
        ctx.temp_dir = dir.path().to_path_buf();
        let r = run_turn(&ctx).await;
        assert_eq!(r.session_id.as_deref(), Some("cs"));
        assert_eq!(sink.done_count(), 1);
    }
}

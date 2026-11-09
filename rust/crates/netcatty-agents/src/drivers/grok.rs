//! Grok Build headless `streaming-json` runtime and shared Grok helpers
//! (Electron: `sdk/grokDriver.cjs`). Netcatty MCP is merged into the project's
//! `.grok/config.toml` for the turn and restored afterwards.

use super::{result_to_text, split_model_effort, ListContext, TurnContext, TurnResult};
use crate::catalog::ModelCatalog;
use crate::emit::{Emitter, Usage};
use crate::mcp::McpServerConfig;
use crate::process::{spawn_lines, terminate_child, Stdin, DEFAULT_ABORT_GRACE};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const NETCATTY_MCP_NAME: &str = "netcatty-remote-hosts";
pub const MAX_GROK_LINE_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_GROK_STDERR_CHARS: usize = 64 * 1024;
pub const GROK_REASONING_EFFORTS: &[&str] = &["none", "minimal", "low", "medium", "high", "xhigh", "max"];
pub const GROK_MCP_MODE_DISALLOWED_LOCAL_TOOLS: &[&str] = &["run_terminal_command", "run_terminal_cmd", "search_replace", "write", "Agent"];

pub fn parse_grok_model_selection(model: Option<&str>) -> (Option<String>, Option<String>) {
    split_model_effort(model, GROK_REASONING_EFFORTS, true)
}

pub fn resolve_grok_tool_integration_flags(mode: &str) -> Vec<String> {
    if mode.eq_ignore_ascii_case("skills") {
        Vec::new()
    } else {
        vec!["--disallowed-tools".into(), GROK_MCP_MODE_DISALLOWED_LOCAL_TOOLS.join(",")]
    }
}

pub fn resolve_grok_permission_flags(permission_mode: &str) -> Vec<String> {
    if permission_mode.eq_ignore_ascii_case("observer") {
        vec!["--permission-mode".into(), "plan".into()]
    } else {
        vec!["--always-approve".into()]
    }
}

pub fn build_grok_cli_args(prompt: &str, model: Option<&str>, cwd: Option<&str>, resume: Option<&str>, permission_mode: &str, tool_mode: &str) -> Vec<String> {
    let mut args: Vec<String> = vec!["--no-auto-update".into(), "-p".into(), prompt.into(), "--output-format".into(), "streaming-json".into()];
    let (model, effort) = parse_grok_model_selection(model);
    if let Some(m) = model {
        args.extend(["-m".into(), m]);
    }
    if let Some(e) = effort {
        args.extend(["--reasoning-effort".into(), e]);
    }
    if let Some(c) = cwd {
        args.extend(["--cwd".into(), c.into()]);
    }
    if let Some(r) = resume.filter(|r| !r.is_empty()) {
        args.extend(["-r".into(), r.into()]);
    }
    args.extend(resolve_grok_permission_flags(permission_mode));
    args.extend(resolve_grok_tool_integration_flags(tool_mode));
    args
}

/// `normalizeGrokPlanUpdate` → `({ text, completed }[], status)`.
pub fn normalize_grok_plan_update(entries: &Value) -> Option<(Value, &'static str)> {
    let mut items = Vec::new();
    for entry in entries.as_array().cloned().unwrap_or_default() {
        let (text, status) = match &entry {
            Value::String(s) => (s.clone(), String::new()),
            Value::Object(o) => (
                ["content", "text", "title", "step"].iter().find_map(|k| o.get(*k).and_then(|v| v.as_str())).unwrap_or("").to_string(),
                ["status", "state"].iter().find_map(|k| o.get(*k).and_then(|v| v.as_str())).unwrap_or("").to_lowercase(),
            ),
            Value::Null => continue,
            other => (other.to_string(), String::new()),
        };
        let text = text.trim().to_string();
        if text.is_empty() {
            continue;
        }
        let completed = matches!(status.as_str(), "completed" | "complete" | "done" | "finished" | "success") || entry.get("completed") == Some(&json!(true));
        items.push(json!({ "text": text, "completed": completed }));
    }
    if items.is_empty() {
        return None;
    }
    let status = if items.iter().all(|i| i["completed"] == true) { "completed" } else { "running" };
    Some((Value::Array(items), status))
}

pub fn is_grok_auth_failure_message(message: &str) -> bool {
    static A: OnceLock<regex::Regex> = OnceLock::new();
    static B: OnceLock<regex::Regex> = OnceLock::new();
    static C: OnceLock<regex::Regex> = OnceLock::new();
    let a = A.get_or_init(|| regex::Regex::new(r"(?i)not authenticated|not logged in|please run .*login|unauthenticated|unauthorized|sign in|auth(?:entication)? (?:failed|required|missing)").unwrap());
    if a.is_match(message) {
        return true;
    }
    let b = B.get_or_init(|| regex::Regex::new(r"(?i)\bxai[_\s-]?api[_\s-]?key\b").unwrap());
    let c = C.get_or_init(|| regex::Regex::new(r"(?i)invalid|missing|required|auth").unwrap());
    b.is_match(message) && c.is_match(message)
}

pub fn format_grok_error_for_user(message: &str) -> String {
    let text = message.trim();
    if is_grok_auth_failure_message(text) {
        return "Grok Build is not logged in. Run `grok login` or set XAI_API_KEY, then retry.".into();
    }
    if text.is_empty() { "Grok Build turn failed".into() } else { text.to_string() }
}

/// Seed history only when a resume fell back to `session/new`.
pub fn resolve_grok_turn_prompt(turn_prompt: &str, history_seed: Option<&str>, resume: Option<&str>, establish_method: &str) -> String {
    let seed = history_seed.unwrap_or("").trim();
    if resume.is_none() || seed.is_empty() || !establish_method.eq_ignore_ascii_case("new") {
        return turn_prompt.to_string();
    }
    if turn_prompt.is_empty() { seed.to_string() } else { format!("{seed}\n\n{turn_prompt}") }
}

/// Usage from an ACP `session/prompt` result (`_meta` camelCase).
pub fn extract_grok_acp_prompt_usage(result: &Value) -> Option<Value> {
    if !result.is_object() {
        return None;
    }
    if result["usage"].is_object() {
        return Some(result["usage"].clone());
    }
    let meta = if result["_meta"].is_object() { &result["_meta"] } else { &result["meta"] };
    if meta["usage"].is_object() {
        return Some(meta["usage"].clone());
    }
    let keys = ["inputTokens", "outputTokens", "totalTokens", "input_tokens", "output_tokens"];
    (meta.is_object() && keys.iter().any(|k| !meta[*k].is_null())).then(|| meta.clone())
}

fn num(usage: &Value, keys: &[&str]) -> u64 {
    keys.iter().find_map(|k| usage.get(*k).and_then(|v| v.as_f64())).unwrap_or(0.0) as u64
}

pub fn emit_grok_usage(emitter: &Emitter, usage: Option<&Value>) -> bool {
    let Some(u) = usage.filter(|u| u.is_object()) else { return false };
    let input = num(u, &["input_tokens", "inputTokens", "prompt_tokens", "promptTokens"]);
    let output = num(u, &["output_tokens", "outputTokens", "completion_tokens", "completionTokens"]);
    let cached = num(u, &["cache_read_input_tokens", "cached_input_tokens", "cachedInputTokens", "cachedReadTokens", "cached_read_tokens"]);
    let reasoning = num(u, &["reasoning_tokens", "reasoningTokens", "reasoning_output_tokens", "reasoningOutputTokens"]);
    let mut total = num(u, &["total_tokens", "totalTokens"]);
    if total == 0 && (input > 0 || output > 0) {
        total = input + output;
    }
    if input == 0 && output == 0 && total == 0 && cached == 0 && reasoning == 0 {
        return false;
    }
    emitter.usage(Usage { input_tokens: input, cached_input_tokens: cached, output_tokens: output, reasoning_tokens: reasoning, total_tokens: total });
    true
}

/// Translation state shared by the headless and ACP runtimes.
#[derive(Default)]
pub struct GrokState {
    pub session_id: Option<String>,
    pub reasoning_open: bool,
    pub streamed_assistant_text: bool,
    pub failed: bool,
    pub turn_completed: bool,
    pub tool_calls: HashSet<String>,
    pub tool_results: HashSet<String>,
    pub tool_names: HashMap<String, String>,
}

impl GrokState {
    pub fn close_reasoning(&mut self, emitter: &Emitter) {
        if self.reasoning_open {
            emitter.reasoning_end();
            self.reasoning_open = false;
        }
    }

    /// `tool_call` / `tool_call_update` handling shared by both runtimes.
    pub fn tool_event(&mut self, update: &Value, emitter: &Emitter, is_update: bool, acp: bool) {
        self.close_reasoning(emitter);
        let Some(id) = ["toolCallId", "tool_call_id", "id"].iter().find_map(|k| update[*k].as_str()).map(str::to_string) else { return };
        let fallback = || {
            let keys: &[&str] = if acp && !is_update { &["toolName", "tool_name", "title", "kind"] } else { &["toolName", "tool_name", "title"] };
            keys.iter().find_map(|k| update[*k].as_str()).unwrap_or("tool").to_string()
        };
        if !is_update {
            let name = fallback();
            let args = if update["rawInput"].is_object() { update["rawInput"].clone() } else if update["input"].is_object() { update["input"].clone() } else { json!({}) };
            self.tool_names.insert(id.clone(), name.clone());
            if self.tool_calls.insert(id.clone()) {
                emitter.tool_call(&name, args, &id);
            }
            return;
        }
        let status = update["status"].as_str().unwrap_or("").to_lowercase();
        let name = self.tool_names.get(&id).cloned().unwrap_or_else(fallback);
        if self.tool_calls.insert(id.clone()) {
            self.tool_names.insert(id.clone(), name.clone());
            let args = if !acp && update["rawInput"].is_object() { update["rawInput"].clone() } else { json!({}) };
            emitter.tool_call(&name, args, &id);
        }
        let terminal = matches!(status.as_str(), "completed" | "failed" | "error" | "cancelled") || !update["rawOutput"].is_null();
        if terminal && self.tool_results.insert(id.clone()) {
            let output = if !update["rawOutput"].is_null() {
                result_to_text(&update["rawOutput"])
            } else if !update["content"].is_null() {
                result_to_text(&update["content"])
            } else {
                result_to_text(&update["error"])
            };
            emitter.tool_result(&id, &output, Some(&name));
        }
    }
}

/// `translateGrokStreamEvent`; returns `true` on a terminal error.
pub fn translate_grok_stream_event(event: &Value, emitter: &Emitter, st: &mut GrokState) -> bool {
    match event["type"].as_str().unwrap_or("") {
        "thought" => {
            let data = result_to_text(&event["data"]);
            if !data.is_empty() {
                emitter.reasoning(&data);
                st.reasoning_open = true;
            }
        }
        "text" => {
            st.close_reasoning(emitter);
            let data = result_to_text(&event["data"]);
            if !data.is_empty() {
                emitter.text(&data);
                st.streamed_assistant_text = true;
            }
        }
        "tool_call" => st.tool_event(event, emitter, false, false),
        "tool_call_update" => st.tool_event(event, emitter, true, false),
        "plan" => {
            if let Some((items, status)) = normalize_grok_plan_update(&event["entries"]) {
                emitter.plan_update(event["itemId"].as_str().unwrap_or("grok-plan"), items, status);
            }
        }
        "usage" => {
            let usage = if event["usage"].is_object() { &event["usage"] } else { event };
            emit_grok_usage(emitter, Some(usage));
        }
        "end" => {
            st.close_reasoning(emitter);
            st.turn_completed = true;
            if let Some(id) = event["sessionId"].as_str().or(event["session_id"].as_str()) {
                st.session_id = Some(id.to_string());
                emitter.session_id(id);
            }
            if event["usage"].is_object() {
                emit_grok_usage(emitter, Some(&event["usage"]));
            }
        }
        "error" => {
            st.close_reasoning(emitter);
            st.failed = true;
            let message = event["message"].as_str().or(event["error"].as_str()).unwrap_or("Grok Build turn failed");
            emitter.emit_error(format_grok_error_for_user(message));
            return true;
        }
        _ => {}
    }
    false
}

// ── `.grok/config.toml` MCP merge ──

fn escape_toml(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn sanitize_server_name(name: &str) -> String {
    let s: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect();
    if s.is_empty() { NETCATTY_MCP_NAME.into() } else { s }
}

pub fn build_grok_mcp_server_toml_section(cfg: &McpServerConfig) -> String {
    if cfg.name.is_empty() || cfg.command.is_empty() {
        return String::new();
    }
    let env = cfg.env_map();
    let env_table = if env.is_empty() {
        "{}".to_string()
    } else {
        format!("{{ {} }}", env.iter().map(|(k, v)| format!("{k} = \"{}\"", escape_toml(v))).collect::<Vec<_>>().join(", "))
    };
    let args = if cfg.args.is_empty() { "[]".to_string() } else { format!("[{}]", cfg.args.iter().map(|a| format!("\"{}\"", escape_toml(a))).collect::<Vec<_>>().join(", ")) };
    [format!("[mcp_servers.{}]", sanitize_server_name(&cfg.name)), format!("command = \"{}\"", escape_toml(&cfg.command)), format!("args = {args}"), format!("env = {env_table}"), "enabled = true".into(), String::new()].join("\n")
}

pub fn strip_grok_mcp_server_section(toml: &str, name: &str) -> String {
    let name = sanitize_server_name(name);
    let exact = format!("[mcp_servers.{name}]");
    let nested = format!("[mcp_servers.{name}.");
    let mut out: Vec<&str> = Vec::new();
    let mut skipping = false;
    for line in toml.lines() {
        let t = line.trim();
        if t.starts_with('[') && t.ends_with(']') {
            if t == exact || t.starts_with(&nested) {
                skipping = true;
                continue;
            }
            skipping = false;
        }
        if !skipping {
            out.push(line);
        }
    }
    while out.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
        out.pop();
    }
    out.join("\n")
}

pub struct MergeState {
    refs: usize,
    previous: Option<String>,
}

fn merge_registry() -> &'static Mutex<HashMap<PathBuf, MergeState>> {
    static REG: OnceLock<Mutex<HashMap<PathBuf, MergeState>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Restores a merged workspace config file when dropped / restored.
pub struct ConfigMergeGuard {
    path: PathBuf,
    registry: &'static Mutex<HashMap<PathBuf, MergeState>>,
    restored: bool,
}

impl ConfigMergeGuard {
    pub fn restore(&mut self) {
        if std::mem::replace(&mut self.restored, true) {
            return;
        }
        let mut reg = self.registry.lock();
        let Some(state) = reg.get_mut(&self.path) else { return };
        state.refs = state.refs.saturating_sub(1);
        if state.refs > 0 {
            return;
        }
        let state = reg.remove(&self.path).unwrap();
        match state.previous {
            Some(raw) => {
                let _ = std::fs::write(&self.path, raw);
            }
            None => {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

impl Drop for ConfigMergeGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Shared refcounted merge for workspace config files (Grok TOML, Cursor JSON):
/// the first merger snapshots the original, the last restorer writes it back.
pub fn merge_workspace_file(
    path: &Path,
    registry: &'static Mutex<HashMap<PathBuf, MergeState>>,
    transform: impl FnOnce(Option<String>) -> String,
) -> std::io::Result<ConfigMergeGuard> {
    let mut reg = registry.lock();
    let state = reg.entry(path.to_path_buf()).or_insert_with(|| MergeState { refs: 0, previous: std::fs::read_to_string(path).ok() });
    state.refs += 1;
    let base = std::fs::read_to_string(path).ok().or_else(|| state.previous.clone());
    let next = transform(base);
    let write = (|| {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, next)
    })();
    if let Err(e) = write {
        state.refs -= 1;
        if state.refs == 0 {
            reg.remove(path);
        }
        return Err(e);
    }
    Ok(ConfigMergeGuard { path: path.to_path_buf(), registry, restored: false })
}

pub fn merge_workspace_grok_mcp_toml(cwd: &Path, servers: &[McpServerConfig]) -> std::io::Result<ConfigMergeGuard> {
    let path = cwd.join(".grok").join("config.toml");
    merge_workspace_file(&path, merge_registry(), |base| {
        let mut text = base.unwrap_or_default();
        let mut sections = Vec::new();
        for cfg in servers.iter().filter(|c| !c.name.is_empty() && !c.command.is_empty()) {
            text = strip_grok_mcp_server_section(&text, &cfg.name);
            sections.push(build_grok_mcp_server_toml_section(cfg).trim_end().to_string());
        }
        if sections.is_empty() {
            return text;
        }
        let body = text.trim_end();
        if body.is_empty() { format!("{}\n", sections.join("\n\n")) } else { format!("{body}\n\n{}\n", sections.join("\n\n")) }
    })
}

/// Run a headless Grok turn.
pub async fn run_turn(ctx: &TurnContext) -> TurnResult {
    let emitter = &ctx.emitter;
    let Some(bin) = ctx.bin_path.clone().filter(|b| !b.trim().is_empty()) else {
        emitter.emit_error("Grok Build CLI not found. Install the Grok CLI (`grok`) and ensure it is on PATH, or set the path in Settings → AI.");
        return TurnResult { session_id: ctx.resume_session_id.clone() };
    };
    let cwd = ctx.cwd.to_string_lossy().into_owned();
    let args = build_grok_cli_args(&ctx.prompt, ctx.model.as_deref(), Some(&cwd), ctx.resume_session_id.as_deref(), &ctx.permission_mode, &ctx.tool_integration_mode);
    let mut guard = None;
    if !ctx.injected_mcp_servers.is_empty() {
        match merge_workspace_grok_mcp_toml(&ctx.cwd, &ctx.injected_mcp_servers) {
            Ok(g) => guard = Some(g),
            Err(e) => {
                emitter.emit_error(format!("Failed to prepare Netcatty MCP for Grok Build (cannot write project .grok/config.toml: {e}). Terminal tools will be unavailable."));
                return TurnResult { session_id: ctx.resume_session_id.clone() };
            }
        }
    }
    let mut st = GrokState { session_id: ctx.resume_session_id.clone(), ..Default::default() };
    let spec = crate::cli::prepare_command_for_spawn(&bin, &args, true);
    let mut spawned = match spawn_lines(&spec, &ctx.env, Some(&ctx.cwd), Stdin::Null, MAX_GROK_LINE_BYTES, MAX_GROK_STDERR_CHARS) {
        Ok(s) => s,
        Err(e) => {
            emitter.emit_error(format_grok_error_for_user(&e.to_string()));
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
            Ok(Some(line)) => {
                if let Ok(event) = serde_json::from_str::<Value>(&line) {
                    translate_grok_stream_event(&event, emitter, &mut st);
                }
            }
            Ok(None) => break,
            Err(e) => {
                if !st.failed {
                    st.failed = true;
                    emitter.emit_error(format_grok_error_for_user(&format!("Grok Build {e}")));
                }
                terminate_child(&mut spawned.child, std::time::Duration::from_millis(0)).await;
                break;
            }
        }
    }
    let status = spawned.child.wait().await.ok();
    if let Some(mut g) = guard {
        g.restore();
    }
    st.close_reasoning(emitter);
    if ctx.aborted() || st.failed {
        return TurnResult { session_id: st.session_id };
    }
    if st.turn_completed {
        emitter.emit_done();
    } else {
        let stderr = spawned.stderr.text().trim().to_string();
        let detail = match status.and_then(|s| s.code()) {
            Some(code) if code != 0 => format!("exited with code {code}"),
            Some(_) => "exited before the turn completed".into(),
            None => "terminated by signal".into(),
        };
        let message = if stderr.is_empty() { format!("Grok Build {detail}") } else { stderr };
        emitter.emit_error(format_grok_error_for_user(&message));
    }
    TurnResult { session_id: st.session_id }
}

struct Fallback {
    name: &'static str,
    levels: &'static [&'static str],
    default: &'static str,
}

fn reasoning_fallback(id: &str) -> Option<Fallback> {
    let four = &["xhigh", "high", "medium", "low"][..];
    Some(match id {
        "grok-4.7" => Fallback { name: "Grok 4.7", levels: four, default: "high" },
        "grok-4.7-build-fast" => Fallback { name: "Grok 4.7 Build Fast", levels: four, default: "high" },
        "grok-4.5" => Fallback { name: "Grok 4.5", levels: &["high", "medium", "low"], default: "high" },
        "grok-4.6" => Fallback { name: "Grok 4.6", levels: four, default: "high" },
        _ => return None,
    })
}

pub fn apply_grok_reasoning_fallback(model: Value) -> Value {
    let id = model["id"].as_str().unwrap_or("").trim().to_string();
    let has_levels = model["thinkingLevels"].as_array().map(|l| !l.is_empty()).unwrap_or(false);
    let Some(fb) = reasoning_fallback(&id) else { return model };
    if has_levels {
        return model;
    }
    let mut out = model;
    if out["name"].as_str().map(|s| s.is_empty()).unwrap_or(true) {
        out["name"] = json!(fb.name);
    }
    out["thinkingLevels"] = json!(fb.levels);
    out["defaultThinkingLevel"] = json!(fb.default);
    out
}

/// `parseGrokModelsOutput` for `grok models`.
pub fn parse_grok_models_output(stdout: &str) -> ModelCatalog {
    let default_re = regex::Regex::new(r"(?i)^Default model:\s*(\S+)").unwrap();
    let bullet_re = regex::Regex::new(r"^[*•‣-]+\s*([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*(.*)$").unwrap();
    let default_tag = regex::Regex::new(r"(?i)\s*\(\s*default\s*\)\s*").unwrap();
    let mut models: Vec<Value> = Vec::new();
    let mut seen = HashSet::new();
    let mut current = None;
    let mut header_default = None;
    for line in stdout.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(c) = default_re.captures(t) {
            header_default = Some(c[1].to_string());
            continue;
        }
        let Some(c) = bullet_re.captures(t) else { continue };
        let id = c[1].to_string();
        if !seen.insert(id.clone()) {
            continue;
        }
        let rest = c[2].to_string();
        if default_tag.is_match(&rest) {
            current = Some(id.clone());
        }
        let name = default_tag.replace_all(&rest, " ").split_whitespace().collect::<Vec<_>>().join(" ");
        models.push(json!({ "id": id, "name": if name.is_empty() { id.clone() } else { name } }));
    }
    if current.is_none() {
        if let Some(d) = header_default {
            if !seen.contains(&d) {
                models.insert(0, json!({ "id": d, "name": d }));
            }
            current = Some(d);
        }
    }
    ModelCatalog { current_model_id: current, models: models.into_iter().map(apply_grok_reasoning_fallback).collect() }
}

/// Union ACP + CLI catalogs (ACP wins for shared ids; CLI fills missing fields
/// except reasoning metadata).
pub fn merge_grok_catalog_models(acp: &[Value], cli: &[Value]) -> Vec<Value> {
    let mut order: Vec<String> = Vec::new();
    let mut by_id: HashMap<String, Value> = HashMap::new();
    for m in acp.iter().filter(|m| m["id"].is_string()) {
        let id = m["id"].as_str().unwrap().to_string();
        if !by_id.contains_key(&id) {
            order.push(id.clone());
        }
        by_id.insert(id, m.clone());
    }
    for m in cli.iter().filter(|m| m["id"].is_string()) {
        let id = m["id"].as_str().unwrap().to_string();
        match by_id.get_mut(&id) {
            None => {
                order.push(id.clone());
                by_id.insert(id, m.clone());
            }
            Some(existing) => {
                if let (Some(target), Some(src)) = (existing.as_object_mut(), m.as_object()) {
                    for (k, v) in src {
                        if k == "thinkingLevels" || k == "defaultThinkingLevel" {
                            continue;
                        }
                        target.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
            }
        }
    }
    order.into_iter().filter_map(|id| by_id.remove(&id)).collect()
}

pub fn resolve_grok_catalog_current_model_id(models: &[Value], current: Option<&str>) -> Option<String> {
    let advertised = current?.trim();
    if advertised.is_empty() {
        return None;
    }
    let (model, effort) = parse_grok_model_selection(Some(advertised));
    let Some(preset) = models.iter().find(|m| m["id"].as_str() == model.as_deref()) else { return Some(advertised.to_string()) };
    let levels: Vec<&str> = preset["thinkingLevels"].as_array().map(|l| l.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
    if levels.is_empty() {
        return Some(advertised.to_string());
    }
    let id = preset["id"].as_str().unwrap_or("");
    let chosen = effort.filter(|e| levels.contains(&e.as_str())).or_else(|| preset["defaultThinkingLevel"].as_str().map(str::to_string)).or_else(|| levels.first().map(|s| s.to_string()));
    Some(match chosen {
        Some(e) => format!("{id}/{e}"),
        None => id.to_string(),
    })
}

/// `grok models`.
pub async fn list_cli_models(ctx: &ListContext) -> ModelCatalog {
    let Some(bin) = ctx.bin_path.clone().filter(|b| !b.trim().is_empty()) else { return ModelCatalog::default() };
    let args: Vec<String> = vec!["--no-auto-update".into(), "models".into()];
    let run = crate::cli::run_command(&bin, &args, &ctx.env, None, Some(ctx.remaining()));
    tokio::select! {
        _ = ctx.cancel.cancelled() => ModelCatalog::default(),
        r = run => r.map(|r| parse_grok_models_output(&r.stdout)).unwrap_or_default(),
    }
}

/// Union of the ACP initialize catalog and `grok models`, settled before the
/// outer deadline so one stalled probe cannot discard the other.
pub async fn list_models(ctx: &ListContext) -> ModelCatalog {
    let deadline = ctx.deadline.checked_sub(std::time::Duration::from_secs(1)).unwrap_or(ctx.deadline);
    let sub = ListContext { bin_path: ctx.bin_path.clone(), env: ctx.env.clone(), cwd: ctx.cwd.clone(), cancel: ctx.cancel.child_token(), deadline, cursor_auth_mode: String::new(), cursor_cli_bin_path: None };
    let (acp, cli) = tokio::join!(super::grok_acp::list_models(&sub), list_cli_models(&sub));
    let current = acp.current_model_id.clone().or(cli.current_model_id.clone());
    let merged = merge_grok_catalog_models(&acp.models, &cli.models);
    let models = if merged.is_empty() {
        current.as_ref().map(|c| vec![apply_grok_reasoning_fallback(json!({ "id": c, "name": c }))]).unwrap_or_default()
    } else {
        merged
    };
    ModelCatalog { current_model_id: resolve_grok_catalog_current_model_id(&models, current.as_deref()), models }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::RecordingSink;
    use std::sync::Arc;

    #[test]
    fn cli_args() {
        let args = build_grok_cli_args("hi", Some("grok-4.6/HIGH"), Some("/w"), Some("s1"), "observer", "mcp");
        assert_eq!(args.join(" "), "--no-auto-update -p hi --output-format streaming-json -m grok-4.6 --reasoning-effort high --cwd /w -r s1 --permission-mode plan --disallowed-tools run_terminal_command,run_terminal_cmd,search_replace,write,Agent");
        let args = build_grok_cli_args("hi", None, None, None, "auto", "skills");
        assert_eq!(args.last().unwrap(), "--always-approve");
    }

    #[test]
    fn stream_translation() {
        let sink = Arc::new(RecordingSink::default());
        let e = Emitter::new(sink.clone(), "r");
        let mut st = GrokState::default();
        for ev in [
            json!({ "type": "thought", "data": "hmm" }),
            json!({ "type": "text", "data": "Hi" }),
            json!({ "type": "tool_call_update", "toolCallId": "t1", "title": "run", "status": "completed", "rawOutput": { "content": "ok" } }),
            json!({ "type": "plan", "entries": [{ "content": "a", "status": "done" }, "b"] }),
            json!({ "type": "end", "sessionId": "s9", "usage": { "input_tokens": 2, "output_tokens": 3 } }),
        ] {
            assert!(!translate_grok_stream_event(&ev, &e, &mut st));
        }
        let ev = sink.stream_events();
        let types: Vec<&str> = ev.iter().map(|v| v["type"].as_str().unwrap()).collect();
        assert_eq!(types, vec!["reasoning-delta", "reasoning-end", "text-delta", "tool-call", "tool-result", "plan-update", "session-id", "usage"]);
        assert_eq!(ev[4]["output"], "ok");
        assert_eq!(ev[5]["status"], "running");
        assert_eq!(ev[7]["totalTokens"], 5);
        assert!(st.turn_completed);
        assert!(translate_grok_stream_event(&json!({ "type": "error", "message": "Not logged in" }), &e, &mut st));
        assert_eq!(sink.errors()[0], "Grok Build is not logged in. Run `grok login` or set XAI_API_KEY, then retry.");
    }

    #[test]
    fn prompt_seed_and_usage() {
        assert_eq!(resolve_grok_turn_prompt("p", Some("seed"), Some("s"), "new"), "seed\n\np");
        assert_eq!(resolve_grok_turn_prompt("p", Some("seed"), Some("s"), "load"), "p");
        assert_eq!(resolve_grok_turn_prompt("p", Some("seed"), None, "new"), "p");
        assert!(extract_grok_acp_prompt_usage(&json!({ "_meta": { "inputTokens": 1 } })).is_some());
        assert!(extract_grok_acp_prompt_usage(&json!({ "stopReason": "end" })).is_none());
    }

    #[test]
    fn toml_merge_and_restore() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".grok/config.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "model = \"x\"\n[mcp_servers.netcatty-remote-hosts]\ncommand = \"old\"\n[mcp_servers.netcatty-remote-hosts.env]\nA = \"1\"\n[other]\nk = 1\n").unwrap();
        let servers = vec![McpServerConfig::stdio("netcatty-remote-hosts", "/app/nc", vec!["--mcp-server".into()], vec![crate::mcp::EnvPair { name: "T".into(), value: "a\"b".into() }])];
        let mut g1 = merge_workspace_grok_mcp_toml(dir.path(), &servers).unwrap();
        let g2 = merge_workspace_grok_mcp_toml(dir.path(), &servers).unwrap();
        let merged = std::fs::read_to_string(&path).unwrap();
        assert!(!merged.contains("command = \"old\""));
        assert!(merged.contains("[other]"));
        assert_eq!(merged.matches("[mcp_servers.netcatty-remote-hosts]").count(), 1);
        assert!(merged.contains("env = { T = \"a\\\"b\" }"));
        g1.restore();
        assert!(std::fs::read_to_string(&path).unwrap().contains("/app/nc"));
        drop(g2);
        assert!(std::fs::read_to_string(&path).unwrap().contains("command = \"old\""));
        let fresh = tempfile::tempdir().unwrap();
        drop(merge_workspace_grok_mcp_toml(fresh.path(), &servers).unwrap());
        assert!(!fresh.path().join(".grok/config.toml").exists());
    }

    #[test]
    fn model_catalog_helpers() {
        let cli = parse_grok_models_output("Default model: grok-4.6\nAvailable:\n  * grok-4.7 (default)\n  - grok-4.6\n  - custom-x  Custom X\n");
        assert_eq!(cli.current_model_id.as_deref(), Some("grok-4.7"));
        assert_eq!(cli.models.len(), 3);
        assert_eq!(cli.models[0]["thinkingLevels"], json!(["xhigh", "high", "medium", "low"]));
        assert_eq!(cli.models[2]["name"], "Custom X");
        let acp = vec![json!({ "id": "grok-4.6", "name": "ACP 4.6", "thinkingLevels": ["high"] })];
        let merged = merge_grok_catalog_models(&acp, &cli.models);
        assert_eq!(merged.iter().map(|m| m["id"].as_str().unwrap()).collect::<Vec<_>>(), vec!["grok-4.6", "grok-4.7", "custom-x"]);
        assert_eq!(merged[0]["thinkingLevels"], json!(["high"]));
        assert_eq!(resolve_grok_catalog_current_model_id(&merged, Some("grok-4.6/low")).as_deref(), Some("grok-4.6/high"));
        assert_eq!(resolve_grok_catalog_current_model_id(&merged, Some("custom-x")).as_deref(), Some("custom-x"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn headless_turn_against_fake_cli() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("grok");
        std::fs::write(&bin, "#!/bin/sh\necho '{\"type\":\"text\",\"data\":\"pong\"}'\necho '{\"type\":\"end\",\"sessionId\":\"g-1\"}'\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sink = Arc::new(RecordingSink::default());
        let env: crate::EnvMap = [("PATH".to_string(), "/usr/bin:/bin".to_string())].into_iter().collect();
        let mut ctx = crate::drivers::test_turn_context(Emitter::new(sink.clone(), "r"), Some(bin.to_string_lossy().into_owned()), env);
        ctx.cwd = dir.path().to_path_buf();
        let result = run_turn(&ctx).await;
        assert_eq!(result.session_id.as_deref(), Some("g-1"));
        assert_eq!(sink.done_count(), 1);
        std::fs::write(&bin, "#!/bin/sh\necho 'boom' 1>&2\nexit 3\n").unwrap();
        let sink = Arc::new(RecordingSink::default());
        ctx.emitter = Emitter::new(sink.clone(), "r2");
        run_turn(&ctx).await;
        assert_eq!(sink.errors(), vec!["boom".to_string()]);
    }
}

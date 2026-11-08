//! OpenCode driver (Electron: `sdk/opencodeDriver.cjs`, `sdk/opencodeV2.cjs`,
//! `sdk/netcattySkillsOpenCodePermissions.cjs`).
//!
//! OpenCode 1.x: `opencode serve --hostname=127.0.0.1 --port=P` with the
//! config in `OPENCODE_CONFIG_CONTENT`, then the `@opencode-ai/sdk` HTTP API
//! (`GET /global/event` SSE, `POST /session`, `POST /session/{id}/prompt_async`,
//! `POST /session/{id}/abort`, `GET /config/providers`).
//! OpenCode 2.x (detected from `opencode --version`): basic-auth `/api/*` API.

use super::{ListContext, TurnContext, TurnResult};
use crate::catalog::ModelCatalog;
use crate::emit::Emitter;
use crate::mcp::McpServerConfig;
use crate::process::{build_command, Stdin};
use crate::EnvMap;
use futures::StreamExt;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Child;
use tokio::sync::mpsc;

/// Generous startup deadline (Windows cold starts exceed 8s, #3579).
pub const OPENCODE_SERVER_START_TIMEOUT: Duration = if cfg!(windows) { Duration::from_secs(60) } else { Duration::from_secs(30) };
pub const DEFAULT_OPENCODE_PORT: u16 = 4096;
const IMAGE_MEDIA_TYPES: &[&str] = &["image/jpeg", "image/png", "image/gif", "image/webp"];

// ── Permission rules ──

const OPENCODE_NATIVE_SKILL_DIR_SUFFIXES: &[&str] = &[".opencode/skill", ".opencode/skills", ".config/opencode/skill", ".config/opencode/skills", ".claude/skills", ".agents/skills", ".cache/opencode/skills"];
const MIMO_NATIVE_SKILL_DIR_SUFFIXES: &[&str] = &[".mimocode/skill", ".mimocode/skills", ".config/mimocode/skill", ".config/mimocode/skills", ".cache/mimocode/skills", ".local/share/mimocode/builtin_skills", ".local/share/mimocode/compose"];

/// Native skill options (`nativeSkillOptions`).
#[derive(Debug, Clone, Default)]
pub struct NativeSkillOptions {
    pub mimo: bool,
    pub env: EnvMap,
    pub cwd: Option<PathBuf>,
    pub skill_paths: Vec<String>,
}

fn normalize_path(p: &str) -> String {
    if cfg!(windows) { p.replace('\\', "/") } else { p.to_string() }
}

fn append_pattern(base: &str, suffix: &str) -> String {
    let suffix = suffix.trim_start_matches('/');
    if base.ends_with('/') { format!("{base}{suffix}") } else { format!("{base}/{suffix}") }
}

fn directory_base(dir: &str) -> Option<String> {
    if dir.is_empty() {
        return None;
    }
    let resolved = std::path::absolute(dir).ok()?;
    let base = if resolved.is_file() { resolved.parent()?.to_path_buf() } else { resolved };
    Some(normalize_path(&base.to_string_lossy()))
}

fn directory_permission_patterns(dir: &str) -> Vec<String> {
    directory_base(dir).map(|b| vec![b.clone(), append_pattern(&b, "*"), append_pattern(&b, "**")]).unwrap_or_default()
}

fn file_parent_permission_patterns(file: &str) -> Vec<String> {
    if file.is_empty() {
        return Vec::new();
    }
    std::path::absolute(file).ok().and_then(|p| p.parent().map(|p| p.to_string_lossy().into_owned())).map(|p| directory_permission_patterns(&p)).unwrap_or_default()
}

fn native_skill_suffixes(options: &NativeSkillOptions) -> Vec<&'static str> {
    if !options.mimo {
        return OPENCODE_NATIVE_SKILL_DIR_SUFFIXES.to_vec();
    }
    let enabled = |k: &str| options.env.get(k).map(|v| v.eq_ignore_ascii_case("true") || v == "1").unwrap_or(false);
    let mut s = MIMO_NATIVE_SKILL_DIR_SUFFIXES.to_vec();
    if !enabled("MIMOCODE_DISABLE_AGENTS_SKILLS") {
        s.push(".agents/skills");
    }
    if enabled("MIMOCODE_ENABLE_CLAUDE_CODE_SKILLS") {
        s.push(".claude/skills");
    }
    if enabled("MIMOCODE_ENABLE_CODEX_SKILLS") {
        s.push(".codex/skills");
    }
    if enabled("MIMOCODE_ENABLE_OPENCODE_SKILLS") {
        s.extend(OPENCODE_NATIVE_SKILL_DIR_SUFFIXES.iter().filter(|x| x.contains("opencode") && !x.contains(".cache/")));
    }
    s
}

fn resolve_mimo_skill_path(item: &str, cwd: &Path, env: &EnvMap) -> Option<PathBuf> {
    if item.trim().is_empty() {
        return None;
    }
    let home = [env.get("HOME"), env.get("USERPROFILE")].into_iter().flatten().find(|h| Path::new(h).is_absolute());
    let expanded = match (item.strip_prefix("~/"), home) {
        (Some(rest), Some(h)) => PathBuf::from(h).join(rest),
        (Some(_), None) => return None,
        _ => PathBuf::from(item),
    };
    Some(if expanded.is_absolute() { expanded } else { cwd.join(expanded) })
}

/// `filterMimoTrustedSkillPaths`: keep global roots and paths inside the project.
pub fn filter_mimo_trusted_skill_paths(paths: &[String], cwd: &Path, env: &EnvMap, global: &[String]) -> Vec<String> {
    let global_roots: HashSet<PathBuf> = global.iter().filter_map(|g| resolve_mimo_skill_path(g, cwd, env)).collect();
    let real_cwd = std::fs::canonicalize(cwd).ok();
    paths
        .iter()
        .filter_map(|item| {
            let resolved = resolve_mimo_skill_path(item, cwd, env)?;
            let canonical = std::fs::canonicalize(&resolved).ok()?;
            if global_roots.contains(&resolved) {
                return Some(canonical.to_string_lossy().into_owned());
            }
            let real = real_cwd.as_ref()?;
            canonical.starts_with(real).then(|| canonical.to_string_lossy().into_owned())
        })
        .collect()
}

fn mimo_native_skill_directories(options: &NativeSkillOptions) -> Vec<String> {
    if !options.mimo {
        return Vec::new();
    }
    let abs = |k: &str| options.env.get(k).filter(|v| Path::new(v).is_absolute()).map(PathBuf::from);
    let cwd = options.cwd.clone().unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let suffixes = native_skill_suffixes(options);
    let project_suffixes: Vec<&str> = suffixes.iter().copied().filter(|s| !s.starts_with(".config/") && !s.starts_with(".cache/") && !s.starts_with(".local/")).collect();
    let mut bases: Vec<PathBuf> = Vec::new();
    for base in [Some(cwd.clone()), std::fs::canonicalize(&cwd).ok()].into_iter().flatten() {
        let mut current = std::path::absolute(&base).unwrap_or(base);
        loop {
            if !bases.contains(&current) {
                bases.push(current.clone());
            }
            match current.parent() {
                Some(p) => current = p.to_path_buf(),
                None => break,
            }
        }
    }
    let mut dirs: Vec<PathBuf> = bases.iter().flat_map(|b| project_suffixes.iter().map(move |s| b.join(s))).collect();
    let home = abs("HOME").or_else(|| abs("USERPROFILE"));
    for h in [home.clone(), home.as_ref().and_then(|h| std::fs::canonicalize(h).ok())].into_iter().flatten() {
        dirs.extend(suffixes.iter().map(|s| h.join(s)));
    }
    if let Some(m) = abs("MIMOCODE_HOME") {
        dirs.extend(["config/skill", "config/skills", "data/builtin_skills", "data/compose", "cache/skills"].iter().map(|s| m.join(s)));
    }
    if let Some(c) = abs("MIMOCODE_CONFIG_DIR") {
        dirs.extend([c.join("skill"), c.join("skills")]);
    }
    if let Some(x) = abs("XDG_CONFIG_HOME") {
        dirs.extend([x.join("mimocode/skill"), x.join("mimocode/skills")]);
    }
    if let Some(x) = abs("XDG_DATA_HOME") {
        dirs.extend([x.join("mimocode/builtin_skills"), x.join("mimocode/compose")]);
    }
    if let Some(x) = abs("XDG_CACHE_HOME") {
        dirs.push(x.join("mimocode/skills"));
    }
    if cfg!(target_os = "macos") {
        if let Some(h) = abs("HOME") {
            let d = h.join("Library/Application Support/mimocode");
            dirs.extend([d.join("builtin_skills"), d.join("compose")]);
        }
    }
    if cfg!(windows) {
        if let Some(l) = abs("LOCALAPPDATA") {
            dirs.extend([l.join("mimocode/builtin_skills"), l.join("mimocode/compose")]);
        }
    }
    dirs.extend(options.skill_paths.iter().filter_map(|p| resolve_mimo_skill_path(p, &cwd, &options.env)));
    dirs.into_iter().map(|d| d.to_string_lossy().into_owned()).collect()
}

fn mimo_relative_dir(dir: &str, options: &NativeSkillOptions) -> Option<String> {
    directory_base(dir)?;
    let cwd = options.cwd.clone().unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let rel = pathdiff(Path::new(dir), &cwd);
    Some(normalize_path(if rel.is_empty() { "." } else { &rel }))
}

fn pathdiff(target: &Path, base: &Path) -> String {
    let target = std::path::absolute(target).unwrap_or_else(|_| target.to_path_buf());
    let base = std::path::absolute(base).unwrap_or_else(|_| base.to_path_buf());
    let t: Vec<_> = target.components().collect();
    let b: Vec<_> = base.components().collect();
    let common = t.iter().zip(b.iter()).take_while(|(x, y)| x == y).count();
    let mut parts: Vec<String> = std::iter::repeat_n("..".to_string(), b.len() - common).collect();
    parts.extend(t[common..].iter().map(|c| c.as_os_str().to_string_lossy().into_owned()));
    parts.join(std::path::MAIN_SEPARATOR_STR)
}

/// `buildOpenCodeNativeSkillsPermissionRules`.
pub fn native_skills_permission_rules(options: &NativeSkillOptions) -> (Map<String, Value>, Map<String, Value>) {
    let mut external = Map::new();
    let mut read = Map::new();
    external.insert("*".into(), json!("deny"));
    let suffix_patterns: Vec<String> = if options.mimo { Vec::new() } else { native_skill_suffixes(options).iter().flat_map(|s| vec![format!("*{s}"), format!("*{s}/*"), format!("*{s}/**")]).collect() };
    let dirs = mimo_native_skill_directories(options);
    for p in suffix_patterns.iter().cloned().chain(dirs.iter().flat_map(|d| directory_permission_patterns(d))) {
        external.insert(p.clone(), json!("allow"));
        read.insert(p, json!("allow"));
    }
    for d in &dirs {
        if let Some(rel) = mimo_relative_dir(d, options) {
            for p in [rel.clone(), format!("{rel}/*"), format!("{rel}/**")] {
                read.insert(p, json!("allow"));
            }
        }
    }
    let mut deny: Vec<String> = if options.mimo { Vec::new() } else { native_skill_suffixes(options).iter().flat_map(|s| vec![format!("*{s}/**.env"), format!("*{s}/**.env.*")]).collect() };
    for d in &dirs {
        if let (Some(base), Some(rel)) = (directory_base(d), mimo_relative_dir(d, options)) {
            deny.extend([format!("{base}/**.env"), format!("{base}/**.env.*"), format!("{rel}/**.env"), format!("{rel}/**.env.*")]);
        }
    }
    for p in deny {
        read.insert(p, json!("deny"));
    }
    (read, external)
}

/// `buildNetcattySkillsOpenCodePathAllowlist`.
pub fn skills_path_allowlist(file_paths: &[String], state_dir: Option<&str>, temp_dir: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in file_paths.iter().flat_map(|f| file_parent_permission_patterns(f)).chain(state_dir.into_iter().flat_map(directory_permission_patterns)).chain(temp_dir.into_iter().flat_map(directory_permission_patterns)) {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

pub fn to_opencode_mcp_config(servers: &[McpServerConfig]) -> Value {
    let mut map = Map::new();
    for c in servers.iter().filter(|c| !c.name.is_empty()) {
        let mut command = vec![c.command.clone()];
        command.extend(c.args.iter().cloned());
        map.insert(c.name.clone(), json!({ "type": "local", "command": command, "environment": c.env_object(), "enabled": true }));
    }
    Value::Object(map)
}

/// `buildOpenCodeConfig`.
pub fn build_opencode_config(model: Option<&str>, servers: &[McpServerConfig], tool_mode: &str, allowlist: &[String], native: &NativeSkillOptions) -> Value {
    let allow_bash = tool_mode == "skills";
    let (mut read, mut external) = native_skills_permission_rules(native);
    let mut permission = json!({
        "edit": "deny",
        "bash": if allow_bash { "allow" } else { "deny" },
        "webfetch": "deny",
        "question": "deny",
        "skill": "allow",
    });
    if allow_bash && !allowlist.is_empty() {
        for p in allowlist {
            external.insert(p.clone(), json!("allow"));
            read.insert(p.clone(), json!("allow"));
        }
        permission["bash"] = json!("allow");
        permission["list"] = json!("deny");
        permission["glob"] = json!("deny");
        permission["grep"] = json!("deny");
    }
    permission["read"] = Value::Object(read);
    permission["external_directory"] = Value::Object(external);
    let mut config = json!({ "share": "disabled", "autoupdate": false, "permission": permission, "mcp": to_opencode_mcp_config(servers) });
    if let Some(m) = model.filter(|m| !m.is_empty()) {
        config["model"] = json!(m);
    }
    config
}

pub fn parse_opencode_model(model: Option<&str>) -> Option<Value> {
    let raw = model?.trim();
    let slash = raw.find('/')?;
    if slash == 0 || slash == raw.len() - 1 {
        return None;
    }
    Some(json!({ "providerID": &raw[..slash], "modelID": &raw[slash + 1..] }))
}

pub fn file_url(path: &str) -> String {
    url::Url::from_file_path(path).map(|u| u.to_string()).unwrap_or_else(|_| format!("file://{path}"))
}

pub fn build_prompt_parts(prompt: &str, attachments: &[crate::session::StagedAttachment]) -> Vec<Value> {
    let mut parts = vec![json!({ "type": "text", "text": prompt })];
    for a in attachments.iter().filter(|a| !a.file_path.is_empty() && IMAGE_MEDIA_TYPES.contains(&a.media_type.to_ascii_lowercase().as_str())) {
        parts.push(json!({ "type": "file", "mime": a.media_type.to_ascii_lowercase(), "filename": a.filename, "url": file_url(&a.file_path) }));
    }
    parts
}

fn error_message(error: &Value) -> String {
    match error {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        e => e.pointer("/data/message").and_then(|v| v.as_str()).or(e["message"].as_str()).or(e["name"].as_str()).unwrap_or("").to_string(),
    }
}

pub fn event_payload(event: &Value) -> Option<&Value> {
    if event["payload"].is_object() {
        Some(&event["payload"])
    } else if event["type"].is_string() && !event["properties"].is_null() {
        Some(event)
    } else {
        None
    }
}

pub fn event_session_id(event: &Value) -> Option<String> {
    let p = &event_payload(event)?["properties"];
    ["/sessionID", "/sessionId", "/part/sessionID", "/part/sessionId", "/info/sessionID", "/info/sessionId", "/info/id"].iter().find_map(|k| p.pointer(k).and_then(|v| v.as_str())).map(str::to_string)
}

/// Per-turn translation state.
#[derive(Default)]
pub struct OpenCodeState {
    pub reasoning_open: bool,
    /// Product name in generated status / error text (`OpenCode` or `MiMo Code`).
    pub brand: &'static str,
    part_types: HashMap<String, String>,
    message_roles: HashMap<String, String>,
    part_offsets: HashMap<String, usize>,
    tool_calls: HashSet<String>,
    tool_results: HashSet<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EventOutcome {
    pub idle: bool,
    pub error: bool,
    pub content: bool,
}

fn message_id(v: &Value) -> Option<&str> {
    v["messageID"].as_str().or(v["messageId"].as_str()).or(v.pointer("/part/messageID").and_then(|x| x.as_str())).or(v.pointer("/part/messageId").and_then(|x| x.as_str()))
}

fn part_id(part: &Value) -> Option<String> {
    part["id"].as_str().or(part["partID"].as_str()).or(part["partId"].as_str()).map(str::to_string)
}

impl OpenCodeState {
    pub fn branded(brand: &'static str) -> Self {
        Self { brand, ..Default::default() }
    }

    fn brand(&self) -> &'static str {
        if self.brand.is_empty() { "OpenCode" } else { self.brand }
    }

    fn assistant(&self, source: &Value) -> bool {
        match message_id(source).and_then(|m| self.message_roles.get(m)) {
            Some(role) => role == "assistant",
            None => true,
        }
    }

    fn emit_chunk(&mut self, emitter: &Emitter, part_id: Option<String>, reasoning: bool, text: &str, is_delta: bool) -> bool {
        if text.is_empty() {
            return false;
        }
        let mut chunk = text.to_string();
        if let Some(id) = part_id {
            let emitted = *self.part_offsets.get(&id).unwrap_or(&0);
            let len = text.chars().count();
            if is_delta {
                self.part_offsets.insert(id, emitted + len);
            } else {
                chunk = text.chars().skip(emitted).collect();
                self.part_offsets.insert(id, emitted.max(len));
            }
        }
        if chunk.is_empty() {
            return false;
        }
        if reasoning {
            emitter.reasoning(&chunk);
            self.reasoning_open = true;
        } else {
            emitter.text(&chunk);
        }
        true
    }

    fn close_reasoning(&mut self, emitter: &Emitter) {
        if self.reasoning_open {
            emitter.reasoning_end();
            self.reasoning_open = false;
        }
    }
}

/// `translateOpenCodeEvent` (v1 SSE events).
pub fn translate_event(event: &Value, emitter: &Emitter, st: &mut OpenCodeState) -> EventOutcome {
    let none = EventOutcome::default();
    let Some(payload) = event_payload(event) else { return none };
    let props = &payload["properties"];
    match payload["type"].as_str().unwrap_or("") {
        "message.updated" => {
            if let (Some(id), Some(role)) = (props.pointer("/info/id").and_then(|v| v.as_str()), props.pointer("/info/role").and_then(|v| v.as_str())) {
                st.message_roles.insert(id.into(), role.into());
            }
            none
        }
        "message.removed" => {
            if let Some(id) = props["messageID"].as_str().or(props["messageId"].as_str()) {
                st.message_roles.remove(id);
            }
            none
        }
        "message.part.updated" => {
            let part = &props["part"];
            if !part.is_object() || !st.assistant(part) {
                return none;
            }
            if let (Some(id), Some(t)) = (part_id(part), part["type"].as_str()) {
                st.part_types.insert(id, t.into());
            }
            match part["type"].as_str().unwrap_or("") {
                kind @ ("text" | "reasoning") => {
                    let delta = props["delta"].as_str();
                    let text = delta.or(part["text"].as_str()).unwrap_or("");
                    let content = st.emit_chunk(emitter, part_id(part), kind == "reasoning", text, delta.is_some());
                    EventOutcome { content, ..none }
                }
                "tool" => {
                    st.close_reasoning(emitter);
                    let call_id = part["callID"].as_str().or(part["id"].as_str()).unwrap_or("").to_string();
                    let name = part["tool"].as_str().unwrap_or("tool").to_string();
                    let input = if part.pointer("/state/input").map(|v| v.is_object()).unwrap_or(false) { part["state"]["input"].clone() } else { json!({}) };
                    let status = part.pointer("/state/status").and_then(|v| v.as_str()).unwrap_or("");
                    if matches!(status, "running" | "pending" | "completed" | "error") && st.tool_calls.insert(call_id.clone()) {
                        emitter.tool_call(&name, input, &call_id);
                    }
                    if status == "completed" && st.tool_results.insert(call_id.clone()) {
                        emitter.tool_result(&call_id, part.pointer("/state/output").and_then(|v| v.as_str()).unwrap_or(""), Some(&name));
                    }
                    if status == "error" && st.tool_results.insert(call_id.clone()) {
                        let state = &part["state"];
                        let raw = if state["error"].as_str().map(|s| !s.is_empty()).unwrap_or(!state["error"].is_null()) { &state["error"] } else { &state["output"] };
                        let text = match raw {
                            Value::String(s) if !s.is_empty() => s.clone(),
                            Value::Null | Value::String(_) => format!("{} tool failed", st.brand()),
                            other => Some(error_message(other)).filter(|s| !s.is_empty()).unwrap_or_else(|| format!("{} tool failed", st.brand())),
                        };
                        emitter.tool_result(&call_id, &text, Some(&name));
                    }
                    EventOutcome { content: true, ..none }
                }
                _ => none,
            }
        }
        "message.part.delta" => {
            if !st.assistant(props) {
                return none;
            }
            let delta = props["delta"].as_str().unwrap_or("");
            let pid = props["partID"].as_str().or(props["partId"].as_str()).map(str::to_string);
            let known = pid.as_ref().and_then(|p| st.part_types.get(p)).cloned();
            let field = props["field"].as_str().unwrap_or("").to_lowercase();
            let kind = match known.as_deref() {
                Some("reasoning") => Some(true),
                Some("text") => Some(false),
                _ if field.contains("reason") || field.contains("thinking") => Some(true),
                _ if field == "text" || field == "content" || field.ends_with(".text") || field.ends_with(".content") => Some(false),
                _ => None,
            };
            match kind {
                Some(reasoning) if !delta.is_empty() => EventOutcome { content: st.emit_chunk(emitter, pid, reasoning, delta, true), ..none },
                _ => none,
            }
        }
        "session.error" => {
            let msg = error_message(&props["error"]);
            emitter.emit_error(if msg.is_empty() { format!("{} session failed", st.brand()) } else { msg });
            EventOutcome { error: true, ..none }
        }
        "session.idle" => {
            st.close_reasoning(emitter);
            emitter.status(&format!("{} session idle", st.brand()));
            EventOutcome { idle: true, ..none }
        }
        "session.status" => {
            if let Some(t) = props.pointer("/status/type").and_then(|v| v.as_str()) {
                emitter.status(&format!("{} session {t}", st.brand()));
            }
            none
        }
        _ => none,
    }
}

pub fn map_opencode_models(response: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    for p in response["providers"].as_array().cloned().unwrap_or_default() {
        let Some(pid) = p["id"].as_str().or(p["providerID"].as_str()) else { continue };
        let Some(models) = p["models"].as_object() else { continue };
        let pname = p["name"].as_str().unwrap_or(pid);
        for (mid, info) in models {
            out.push(json!({ "id": format!("{pid}/{mid}"), "name": format!("{pname} {}", info["name"].as_str().unwrap_or(mid)) }));
        }
    }
    out
}

/// Every default id the catalog advertises (`getOpenCodeDefaultModelIds`).
pub fn default_model_ids(response: &Value) -> Vec<String> {
    let v = &response["default"];
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Object(o) => {
            if let (Some(p), Some(m)) = (o.get("providerID").and_then(|x| x.as_str()), o.get("modelID").and_then(|x| x.as_str())) {
                return vec![format!("{p}/{m}")];
            }
            if let (Some(p), Some(m)) = (o.get("provider").and_then(|x| x.as_str()), o.get("model").and_then(|x| x.as_str())) {
                return vec![if m.contains('/') { m.to_string() } else { format!("{p}/{m}") }];
            }
            if let Some(m) = o.get("model").and_then(|x| x.as_str()) {
                return vec![m.to_string()];
            }
            o.iter()
                .filter_map(|(pid, m)| match m {
                    Value::String(s) if !s.is_empty() => Some(if s.contains('/') { s.clone() } else { format!("{pid}/{s}") }),
                    Value::Object(n) => n.get("modelID").and_then(|x| x.as_str()).map(|mid| format!("{}/{mid}", n.get("providerID").and_then(|x| x.as_str()).unwrap_or(pid))),
                    _ => None,
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

/// `getOpenCodeDefaultModelId`: first qualified default.
pub fn default_model_id(response: &Value) -> Option<String> {
    default_model_ids(response).into_iter().find(|id| id.contains('/'))
}

// ── HTTP client with SSE ──

#[derive(Clone)]
pub struct HttpClient {
    pub base: String,
    pub auth: Option<String>,
    client: reqwest::Client,
}

impl HttpClient {
    pub fn new(base: &str, auth: Option<String>) -> Self {
        let client = reqwest::Client::builder().no_proxy().build().unwrap_or_default();
        Self { base: base.trim_end_matches('/').to_string(), auth, client }
    }

    fn url(&self, path: &str, query: &[(&str, &str)]) -> String {
        let mut url = url::Url::parse(&format!("{}{}", self.base, path)).unwrap_or_else(|_| url::Url::parse("http://127.0.0.1/").unwrap());
        for (k, v) in query {
            url.query_pairs_mut().append_pair(k, v);
        }
        url.to_string()
    }

    fn req(&self, method: reqwest::Method, path: &str, query: &[(&str, &str)]) -> reqwest::RequestBuilder {
        let mut r = self.client.request(method, self.url(path, query));
        if let Some(a) = &self.auth {
            r = r.header("Authorization", a);
        }
        r.header("Accept", "application/json")
    }

    /// JSON request; `Err((status, message))` on transport / HTTP failures.
    pub async fn json(&self, method: reqwest::Method, path: &str, query: &[(&str, &str)], body: Option<&Value>) -> Result<Value, (u16, String)> {
        let mut r = self.req(method, path, query);
        if let Some(b) = body {
            r = r.json(b);
        }
        let resp = r.send().await.map_err(|e| (0, e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| (status, e.to_string()))?;
        if !(200..300).contains(&status) {
            let detail = serde_json::from_str::<Value>(&text).ok().and_then(|v| v["message"].as_str().or(v.pointer("/data/message").and_then(|m| m.as_str())).map(str::to_string)).unwrap_or_default();
            return Err((status, detail));
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|e| (status, e.to_string()))
    }

    /// Open an SSE stream; `data:` payloads arrive as parsed JSON.
    pub async fn sse(&self, path: &str) -> Result<mpsc::UnboundedReceiver<Value>, (u16, String)> {
        let resp = self.req(reqwest::Method::GET, path, &[]).header("Accept", "text/event-stream").send().await.map_err(|e| (0, e.to_string()))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err((status, String::new()));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let mut stream = resp.bytes_stream();
        tokio::spawn(async move {
            let mut buffer = String::new();
            while let Some(chunk) = stream.next().await {
                let Ok(chunk) = chunk else { break };
                buffer.push_str(&String::from_utf8_lossy(&chunk));
                buffer = buffer.replace("\r\n", "\n").replace('\r', "\n");
                while let Some(idx) = buffer.find("\n\n") {
                    let block: String = buffer.drain(..idx + 2).collect();
                    let data: Vec<&str> = block.lines().filter_map(|l| l.strip_prefix("data:")).map(|l| l.strip_prefix(' ').unwrap_or(l)).collect();
                    let data = data.join("\n");
                    if data.is_empty() || data == "[DONE]" {
                        continue;
                    }
                    if let Ok(v) = serde_json::from_str::<Value>(&data) {
                        if tx.send(v).is_err() {
                            return;
                        }
                    }
                }
                if buffer.len() > 1024 * 1024 {
                    buffer.clear();
                }
            }
        });
        Ok(rx)
    }
}

// ── `serve` process ──

pub struct ServeProcess {
    pub child: Child,
    pub url: String,
    pub password: Option<String>,
}

impl ServeProcess {
    pub async fn stop(&mut self) {
        crate::process::terminate_child(&mut self.child, Duration::from_secs(2)).await;
    }
}

/// Spawn `<bin> serve ...` and wait for the readiness banner (`listen_re`
/// captures the URL; an optional `server password:` line follows).
pub async fn spawn_serve(bin: &str, args: &[String], env: &EnvMap, cwd: Option<&Path>, timeout: Duration, listen_re: &regex::Regex, wait_password: bool) -> Result<ServeProcess, String> {
    let spec = crate::cli::prepare_command_for_spawn(bin, args, false);
    let mut child = build_command(&spec, env, cwd, Stdin::Null).spawn().map_err(|e| e.to_string())?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    for reader in [stdout.map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>), stderr.map(|s| Box::new(s) as _)].into_iter().flatten() {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(crate::cli::strip_ansi(&line)).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);
    let pass_re = regex::Regex::new(r"(?i)^server password:?\s+(\S+)").unwrap();
    let mut tail = String::new();
    let wait = async {
        let mut url: Option<String> = None;
        let mut password = None;
        loop {
            let next = if url.is_some() { tokio::time::timeout(Duration::from_millis(400), rx.recv()).await.unwrap_or(None) } else { rx.recv().await };
            let Some(line) = next else { break };
            tail = format!("{tail}{line}\n").chars().rev().take(64 * 1024).collect::<String>().chars().rev().collect();
            let t = line.trim();
            if let Some(c) = listen_re.captures(t) {
                url = Some(c[1].trim_end_matches([')', ',', '.', ';']).to_string());
                if !wait_password {
                    break;
                }
            }
            if let Some(c) = pass_re.captures(t) {
                password = Some(c[1].to_string());
            }
            if url.is_some() && password.is_some() {
                break;
            }
        }
        (url, password)
    };
    match tokio::time::timeout(timeout, wait).await {
        Ok((Some(url), password)) => Ok(ServeProcess { child, url, password }),
        Ok((None, _)) => {
            let _ = crate::process::terminate_child(&mut child, Duration::from_millis(200)).await;
            let detail = if tail.trim().is_empty() { String::new() } else { format!("\nServer output: {}", tail.trim()) };
            Err(format!("Server exited before it was ready{detail}"))
        }
        Err(_) => {
            crate::process::terminate_child(&mut child, Duration::from_millis(200)).await;
            Err(format!("Timeout waiting for server to start after {}ms", timeout.as_millis()))
        }
    }
}

fn not_found_message(e: &str) -> bool {
    e.contains("No such file") || e.contains("not found") || e.contains("ENOENT") || e.contains("os error 2")
}

const OPENCODE_NOT_FOUND: &str = "OpenCode CLI not found or not runnable. Install OpenCode and ensure `opencode` is on PATH, or set a custom path in Settings.";

fn resolve_bin(ctx_bin: Option<&str>, env: &EnvMap) -> Option<String> {
    ctx_bin.filter(|b| Path::new(b).is_file()).map(str::to_string).or_else(|| env.get("OPENCODE_BIN").filter(|b| Path::new(b).is_file()).cloned())
}

/// `parseOpenCodeVersionOutput` → major version.
pub fn parse_opencode_version(text: &str) -> Option<(u64, u64, u64)> {
    let re = regex::Regex::new(r"(?i)(?:^|[^\d.])v?(\d+)\.(\d+)(?:\.(\d+))?(?:[-+][0-9A-Za-z.-]+)?").unwrap();
    for raw in crate::cli::strip_ansi(text).lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("at ") || line.contains("://") || regex::Regex::new(r"\b(?:Error|TypeError|ReferenceError|SyntaxError|ERR_[A-Z_]+)\b").unwrap().is_match(line) {
            continue;
        }
        if regex::Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b").unwrap().is_match(line) {
            continue;
        }
        let Some(c) = re.captures(line) else { continue };
        let prefix = &line[..c.get(0).unwrap().start()];
        if regex::Regex::new(r"(?i)(?:^|\b)(?:node\.js|bun)\s*$").unwrap().is_match(prefix.trim_end()) {
            continue;
        }
        let major: u64 = c[1].parse().ok()?;
        if major > 100 {
            continue;
        }
        return Some((major, c[2].parse().unwrap_or(0), c.get(3).and_then(|m| m.as_str().parse().ok()).unwrap_or(0)));
    }
    None
}

async fn is_v2(bin: &str, env: &EnvMap) -> bool {
    let env = crate::env::build_sdk_agent_env(env, None, None);
    match crate::cli::run_command(bin, &["--version".into()], &env, None, Some(Duration::from_secs(8))).await {
        Ok(r) => parse_opencode_version(&format!("{}\n{}", r.stdout, r.stderr)).map(|v| v.0 >= 2).unwrap_or(false),
        Err(_) => false,
    }
}

fn serve_args(port: u16) -> Vec<String> {
    vec!["serve".into(), "--hostname=127.0.0.1".into(), format!("--port={port}")]
}

/// Run an OpenCode turn (v1 or v2 depending on the CLI version).
pub async fn run_turn(ctx: &TurnContext) -> TurnResult {
    let bin = resolve_bin(ctx.bin_path.as_deref(), &ctx.env).or_else(|| ctx.bin_path.clone()).unwrap_or_else(|| "opencode".into());
    if is_v2(&bin, &ctx.env).await {
        return v2::run_turn(ctx, &bin).await;
    }
    run_v1_turn(ctx, &bin).await
}

async fn run_v1_turn(ctx: &TurnContext, bin: &str) -> TurnResult {
    let emitter = &ctx.emitter;
    let native = NativeSkillOptions::default();
    let config = build_opencode_config(ctx.model.as_deref(), &ctx.injected_mcp_servers, &ctx.tool_integration_mode, &ctx.skills_path_allowlist, &native);
    let mut session_id = ctx.resume_session_id.clone();
    let port = match crate::process::available_port("127.0.0.1", DEFAULT_OPENCODE_PORT).await {
        Ok(p) => p,
        Err(e) => {
            emitter.emit_error(e.to_string());
            return TurnResult { session_id };
        }
    };
    let mut env = ctx.env.clone();
    env.insert("OPENCODE_CONFIG_CONTENT".into(), config.to_string());
    env.insert("OPENCODE_BIN".into(), bin.to_string());
    let re = regex::Regex::new(r"^opencode server listening.*?on\s+(https?://\S+)").unwrap();
    let args = serve_args(port);
    let serve = tokio::select! {
        _ = ctx.cancel.cancelled() => return TurnResult { session_id },
        s = spawn_serve(bin, &args, &env, None, OPENCODE_SERVER_START_TIMEOUT, &re, false) => s,
    };
    let mut serve = match serve {
        Ok(s) => s,
        Err(e) => {
            emitter.emit_error(if not_found_message(&e) { OPENCODE_NOT_FOUND.to_string() } else { e });
            return TurnResult { session_id };
        }
    };
    let client = HttpClient::new(&serve.url, None);
    let result = drive_v1_session(ctx, &client, &mut session_id, "Netcatty OpenCode", None, "OpenCode").await;
    if ctx.aborted() {
        if let Some(id) = &session_id {
            let dir = ctx.cwd.to_string_lossy().into_owned();
            let _ = client.json(reqwest::Method::POST, &format!("/session/{id}/abort"), &[("directory", &dir)], None).await;
        }
    }
    serve.stop().await;
    match result {
        _ if ctx.aborted() => {}
        Ok(SessionOutcome { failed: true, .. }) => {}
        Ok(SessionOutcome { has_content: false, .. }) => emitter.emit_error("OpenCode returned an empty response. Run `opencode` in a terminal to configure authentication and models."),
        Ok(_) => emitter.emit_done(),
        Err(e) => emitter.emit_error(if not_found_message(&e) { OPENCODE_NOT_FOUND.to_string() } else { e }),
    }
    TurnResult { session_id }
}

#[derive(Debug, Default)]
pub struct SessionOutcome {
    pub has_content: bool,
    pub failed: bool,
    pub completed: bool,
}

/// Handles `permission.*` events (MiMo); returns `true` when consumed.
#[async_trait::async_trait]
pub trait PermissionHook: Send + Sync {
    async fn handle(&self, payload: &Value) -> Result<bool, String>;
}

/// v1 session protocol shared by OpenCode and MiMo: subscribe to
/// `/global/event`, create the session, `prompt_async`, translate until idle.
pub async fn drive_v1_session(ctx: &TurnContext, client: &HttpClient, session_id: &mut Option<String>, title: &str, permissions: Option<&dyn PermissionHook>, brand: &'static str) -> Result<SessionOutcome, String> {
    let emitter = &ctx.emitter;
    let dir = ctx.cwd.to_string_lossy().into_owned();
    let query = [("directory", dir.as_str())];
    let mut events = client.sse("/global/event").await.map_err(|(_, e)| if e.is_empty() { format!("{brand} did not provide an event stream") } else { e })?;
    if session_id.is_none() {
        let created = client.json(reqwest::Method::POST, "/session", &query, Some(&json!({ "title": title }))).await.map_err(|(_, e)| e)?;
        *session_id = created["id"].as_str().or(created.pointer("/data/id").and_then(|v| v.as_str())).map(str::to_string);
    }
    let sid = session_id.clone().ok_or(format!("{brand} did not create a session"))?;
    emitter.session_id(&sid);
    let mut body = json!({ "parts": build_prompt_parts(&ctx.prompt, &ctx.attachments) });
    if let Some(sys) = ctx.system_prompt.as_deref().filter(|s| !s.is_empty()) {
        body["system"] = json!(sys);
    }
    if let Some(m) = parse_opencode_model(ctx.model.as_deref()) {
        body["model"] = m;
    }
    let mut outcome = SessionOutcome::default();
    let mut st = OpenCodeState::branded(brand);
    let mut turn_started = permissions.is_none();
    let mut warnings = 0;
    let prompt_path = format!("/session/{sid}/prompt_async");
    let prompt = client.json(reqwest::Method::POST, &prompt_path, &query, Some(&body));
    tokio::pin!(prompt);
    let mut prompt_done = false;
    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => return Ok(outcome),
            r = &mut prompt, if !prompt_done => {
                prompt_done = true;
                if let Err((_, e)) = r {
                    return Err(if e.is_empty() { "OpenCode turn failed".into() } else { e });
                }
            }
            ev = events.recv() => {
                let Some(event) = ev else { break };
                let esid = event_session_id(&event);
                if esid.as_deref().map(|s| s != sid).unwrap_or(false) {
                    continue;
                }
                let Some(payload) = event_payload(&event).cloned() else { continue };
                let kind = payload["type"].as_str().unwrap_or("").to_string();
                if esid.is_none() && kind == "session.error" {
                    warnings += 1;
                    let msg = error_message(&payload["properties"]["error"]);
                    let fallback = format!("{brand} reported a background error");
                    emitter.warning(&format!("opencode-background-error:{warnings}"), if msg.is_empty() { &fallback } else { &msg });
                    continue;
                }
                if let Some(hook) = permissions {
                    if kind == "permission.updated" || kind == "permission.asked" {
                        hook.handle(&payload).await?;
                        continue;
                    }
                    if kind == "session.idle" && !turn_started {
                        continue;
                    }
                    if kind == "session.status" && payload.pointer("/properties/status/type").and_then(|v| v.as_str()) == Some("busy") {
                        turn_started = true;
                    }
                }
                let r = translate_event(&event, emitter, &mut st);
                if r.content {
                    outcome.has_content = true;
                    turn_started = true;
                }
                if r.error {
                    outcome.failed = true;
                    break;
                }
                if r.idle {
                    outcome.completed = true;
                    break;
                }
            }
        }
    }
    Ok(outcome)
}

/// Live catalog (v1 `GET /config/providers`, v2 `/api/model`).
pub async fn list_models(ctx: &ListContext) -> Result<ModelCatalog, String> {
    let bin = resolve_bin(ctx.bin_path.as_deref(), &ctx.env).or_else(|| ctx.bin_path.clone()).unwrap_or_else(|| "opencode".into());
    if is_v2(&bin, &ctx.env).await {
        return v2::list_models(ctx, &bin).await;
    }
    let port = crate::process::available_port("127.0.0.1", DEFAULT_OPENCODE_PORT).await.map_err(|e| e.to_string())?;
    let mut env = ctx.env.clone();
    env.insert("OPENCODE_CONFIG_CONTENT".into(), json!({ "autoupdate": false }).to_string());
    let re = regex::Regex::new(r"^opencode server listening.*?on\s+(https?://\S+)").unwrap();
    let args = serve_args(port);
    let mut serve = tokio::select! {
        _ = ctx.cancel.cancelled() => return Ok(ModelCatalog::default()),
        s = spawn_serve(&bin, &args, &env, None, OPENCODE_SERVER_START_TIMEOUT.min(ctx.remaining()), &re, false) => s?,
    };
    let client = HttpClient::new(&serve.url, None);
    let response = tokio::select! {
        _ = ctx.cancel.cancelled() => Ok(Value::Null),
        r = client.json(reqwest::Method::GET, "/config/providers", &[], None) => r,
    };
    serve.stop().await;
    let data = response.map_err(|(_, e)| if e.is_empty() { "OpenCode providers unavailable".to_string() } else { e })?;
    Ok(ModelCatalog { current_model_id: default_model_id(&data), models: map_opencode_models(&data) })
}

/// OpenCode 2.x protocol.
pub mod v2 {
    use super::*;

    pub fn flatten_permission_rules(permission: &Value) -> Vec<Value> {
        let mut rules = Vec::new();
        for (action, value) in permission.as_object().cloned().unwrap_or_default() {
            match &value {
                Value::String(e) if matches!(e.as_str(), "allow" | "deny" | "ask") => rules.push(json!({ "action": action, "resource": "*", "effect": e })),
                Value::Object(map) => {
                    for (resource, effect) in map {
                        if let Some(e) = effect.as_str().filter(|e| matches!(*e, "allow" | "deny" | "ask")) {
                            rules.push(json!({ "action": action, "resource": resource, "effect": e }));
                        }
                    }
                }
                _ => {}
            }
        }
        rules
    }

    /// `buildOpenCodeV2ConfigContent`.
    pub fn config_content(v1: &Value) -> Value {
        let mut content = json!({ "share": v1["share"].as_str().unwrap_or("disabled") });
        if v1["autoupdate"] == false || v1["update"] == "disable" {
            content["update"] = json!("disable");
        }
        let rules = flatten_permission_rules(&v1["permission"]);
        if !rules.is_empty() {
            content["permissions"] = Value::Array(rules);
        }
        let mut servers = Map::new();
        for (name, cfg) in v1["mcp"].as_object().cloned().unwrap_or_default() {
            if cfg["command"].as_array().map(|c| c.is_empty()).unwrap_or(true) {
                continue;
            }
            servers.insert(name, json!({ "type": "local", "command": cfg["command"], "environment": if cfg["environment"].is_object() { cfg["environment"].clone() } else { json!({}) }, "disabled": cfg["enabled"] == false }));
        }
        if !servers.is_empty() {
            content["mcp"] = json!({ "servers": servers });
        }
        if let Some(m) = v1["model"].as_str().filter(|m| parse_opencode_model(Some(m)).is_some()) {
            content["model"] = json!(m);
        }
        content
    }

    /// Merge with a caller-provided `OPENCODE_CONFIG_CONTENT` (generated keys win).
    pub fn merge_config_content(generated: Value, caller: Option<&str>) -> Value {
        let Some(Value::Object(caller)) = caller.and_then(|c| serde_json::from_str::<Value>(c).ok()) else { return generated };
        let gen = generated.as_object().cloned().unwrap_or_default();
        let mut merged = caller.clone();
        for (k, v) in &gen {
            merged.insert(k.clone(), v.clone());
        }
        for k in ["permission", "autoupdate", "username"] {
            if !gen.contains_key(k) {
                merged.remove(k);
            }
        }
        if let (Some(cm), Some(gm)) = (caller.get("mcp").filter(|v| v.is_object()), gen.get("mcp").filter(|v| v.is_object())) {
            let mut servers = cm["servers"].as_object().cloned().unwrap_or_default();
            for (k, v) in gm["servers"].as_object().cloned().unwrap_or_default() {
                servers.insert(k, v);
            }
            let mut mcp = cm.as_object().cloned().unwrap_or_default();
            for (k, v) in gm.as_object().cloned().unwrap_or_default() {
                mcp.insert(k, v);
            }
            mcp.insert("servers".into(), Value::Object(servers));
            merged.insert("mcp".into(), Value::Object(mcp));
        }
        Value::Object(merged)
    }

    pub fn catalog_model_id(m: &Value) -> Option<String> {
        let pid = m["providerID"].as_str().unwrap_or("");
        let id = m["id"].as_str().unwrap_or("");
        if !pid.is_empty() && !id.is_empty() {
            return Some(if id.starts_with(&format!("{pid}/")) { id.to_string() } else { format!("{pid}/{id}") });
        }
        if id.contains('/') {
            return Some(id.to_string());
        }
        m["modelID"].as_str().filter(|x| !pid.is_empty() && !x.is_empty()).map(|x| format!("{pid}/{x}"))
    }

    fn unwrap_data(v: &Value) -> &Value {
        if v.get("data").is_some() { &v["data"] } else { v }
    }

    pub fn map_catalog(models: &Value, providers: &Value, default: &Value) -> ModelCatalog {
        let names: HashMap<String, String> = unwrap_data(providers).as_array().cloned().unwrap_or_default().iter().filter_map(|p| p["id"].as_str().map(|id| (id.to_string(), p["name"].as_str().unwrap_or(id).to_string()))).collect();
        let mut out = Vec::new();
        for m in unwrap_data(models).as_array().cloned().unwrap_or_default() {
            if m["enabled"] == false {
                continue;
            }
            let Some(id) = catalog_model_id(&m) else { continue };
            let slash = id.find('/');
            let pid = m["providerID"].as_str().map(str::to_string).unwrap_or_else(|| slash.map(|s| id[..s].to_string()).unwrap_or(id.clone()));
            let mname = m["name"].as_str().or(m["modelID"].as_str()).map(str::to_string).unwrap_or_else(|| slash.map(|s| id[s + 1..].to_string()).unwrap_or(id.clone()));
            out.push(json!({ "id": id, "name": format!("{} {mname}", names.get(&pid).cloned().unwrap_or(pid.clone())) }));
        }
        ModelCatalog { current_model_id: catalog_model_id(unwrap_data(default)), models: out }
    }

    fn sanitize(message: &str) -> String {
        let raw = message.trim();
        if raw.is_empty() || raw.contains('\n') || raw.len() > 240 {
            return String::new();
        }
        let secret = regex::Regex::new(r"(?i)server password|authorization\s*[:=]|bearer\s+\S+|basic\s+[a-z0-9+/=]{8,}").unwrap();
        let noise = regex::Regex::new(r"(?i)<html|<!doctype|node:internal|\bat\s+\S+:\d+:\d+\b").unwrap();
        if secret.is_match(raw) || noise.is_match(raw) {
            return String::new();
        }
        raw.to_string()
    }

    fn user_error(status: u16, message: &str) -> String {
        if status == 401 {
            return "ai.opencode.v2.unauthorized".into();
        }
        let s = sanitize(message);
        if s.is_empty() { "ai.opencode.v2.unavailable".into() } else { s }
    }

    /// `translateOpenCodeV2Event`.
    pub fn translate_event(event: &Value, emitter: &Emitter, st: &mut OpenCodeState, session_id: &str, tool_names: &mut HashMap<String, String>) -> EventOutcome {
        let none = EventOutcome::default();
        let kind = event["type"].as_str().unwrap_or("");
        let data = if event["data"].is_object() { &event["data"] } else { &Value::Null };
        if data["sessionID"].as_str().map(|s| s != session_id).unwrap_or(false) {
            return none;
        }
        match kind {
            "session.text.delta" if data["delta"].as_str().map(|d| !d.is_empty()).unwrap_or(false) => {
                emitter.text(data["delta"].as_str().unwrap());
                EventOutcome { content: true, ..none }
            }
            "session.reasoning.delta" if data["delta"].as_str().map(|d| !d.is_empty()).unwrap_or(false) => {
                emitter.reasoning(data["delta"].as_str().unwrap());
                st.reasoning_open = true;
                EventOutcome { content: true, ..none }
            }
            "session.reasoning.ended" => {
                st.close_reasoning(emitter);
                none
            }
            "session.tool.input.started" => {
                if let Some(id) = data["id"].as_str() {
                    tool_names.insert(id.into(), data["name"].as_str().unwrap_or("tool").into());
                }
                none
            }
            "session.tool.called" | "session.tool.success" | "session.tool.failed" => {
                st.close_reasoning(emitter);
                let id = data["id"].as_str().unwrap_or("").to_string();
                let name = tool_names.get(&id).cloned().or(data["name"].as_str().map(str::to_string)).unwrap_or_else(|| "tool".into());
                if st.tool_calls.insert(id.clone()) {
                    emitter.tool_call(&name, if data["input"].is_object() { data["input"].clone() } else { json!({}) }, &id);
                }
                if kind != "session.tool.called" && st.tool_results.insert(id.clone()) {
                    let output = if kind == "session.tool.failed" {
                        Some(sanitize(data.pointer("/error/message").and_then(|m| m.as_str()).unwrap_or(""))).filter(|s| !s.is_empty()).unwrap_or_else(|| "OpenCode tool failed".into())
                    } else {
                        match &data["content"] {
                            Value::String(s) => s.clone(),
                            Value::Array(parts) => parts.iter().filter_map(|p| match p {
                                Value::String(s) => Some(s.clone()),
                                p if p["type"] == "text" => Some(p["text"].as_str().unwrap_or("").to_string()),
                                p if p["type"] == "file" => Some(p["name"].as_str().or(p["uri"].as_str()).unwrap_or("").to_string()),
                                _ => None,
                            }).filter(|s| !s.is_empty()).collect::<Vec<_>>().join("\n"),
                            _ => String::new(),
                        }
                    };
                    emitter.tool_result(&id, &output, Some(&name));
                }
                EventOutcome { content: true, ..none }
            }
            "session.execution.failed" => {
                let s = sanitize(data.pointer("/error/message").and_then(|m| m.as_str()).or(data.pointer("/error/data/message").and_then(|m| m.as_str())).unwrap_or(""));
                emitter.emit_error(if s.is_empty() { "ai.opencode.v2.sessionFailed".to_string() } else { s });
                EventOutcome { error: true, ..none }
            }
            "session.execution.succeeded" | "session.execution.interrupted" => {
                st.close_reasoning(emitter);
                EventOutcome { idle: true, ..none }
            }
            _ => none,
        }
    }

    async fn open_server(bin: &str, config: &Value, env: &EnvMap, cwd: Option<&Path>, timeout: Duration) -> Result<(ServeProcess, HttpClient), String> {
        use base64::Engine;
        let password: String = {
            use rand::RngExt;
            let bytes: [u8; 24] = rand::rng().random();
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        };
        let port = crate::process::available_port("127.0.0.1", DEFAULT_OPENCODE_PORT).await.map_err(|e| e.to_string())?;
        let mut child_env = crate::env::build_sdk_agent_env(env, None, None);
        child_env.insert("OPENCODE_CONFIG_CONTENT".into(), merge_config_content(config_content(config), env.get("OPENCODE_CONFIG_CONTENT").map(String::as_str)).to_string());
        child_env.insert("OPENCODE_SERVER_USERNAME".into(), "opencode".into());
        child_env.insert("OPENCODE_SERVER_PASSWORD".into(), password.clone());
        let re = regex::Regex::new(r"(?i)^(?:opencode\s+)?server listening on\s+(https?://\S+)").unwrap();
        let serve = spawn_serve(bin, &serve_args(port), &child_env, cwd, timeout, &re, true).await.map_err(|e| if e.contains("Timeout") { "ai.opencode.v2.startupTimeout".to_string() } else if not_found_message(&e) { OPENCODE_NOT_FOUND.to_string() } else { "ai.opencode.v2.exited".to_string() })?;
        let pass = serve.password.clone().unwrap_or(password);
        let auth = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("opencode:{pass}")));
        let client = HttpClient::new(&serve.url, Some(auth));
        Ok((serve, client))
    }

    pub async fn run_turn(ctx: &TurnContext, bin: &str) -> TurnResult {
        let emitter = &ctx.emitter;
        let config = build_opencode_config(ctx.model.as_deref(), &ctx.injected_mcp_servers, &ctx.tool_integration_mode, &ctx.skills_path_allowlist, &NativeSkillOptions::default());
        let mut session_id = ctx.resume_session_id.clone();
        let opened = tokio::select! {
            _ = ctx.cancel.cancelled() => return TurnResult { session_id },
            o = open_server(bin, &config, &ctx.env, Some(&ctx.cwd), OPENCODE_SERVER_START_TIMEOUT) => o,
        };
        let (mut serve, client) = match opened {
            Ok(v) => v,
            Err(e) => {
                emitter.emit_error(e);
                return TurnResult { session_id };
            }
        };
        let result = drive(ctx, &client, &config, &mut session_id).await;
        if ctx.aborted() {
            if let Some(id) = &session_id {
                let _ = client.json(reqwest::Method::POST, &format!("/api/session/{}/interrupt", crate::session::encode_uri_component(id)), &[], None).await;
            }
        }
        serve.stop().await;
        match result {
            _ if ctx.aborted() => {}
            Ok(SessionOutcome { failed: true, .. }) => {}
            Ok(SessionOutcome { has_content: false, .. }) => emitter.emit_error("ai.opencode.v2.empty"),
            Ok(_) => emitter.emit_done(),
            Err(e) => emitter.emit_error(e),
        }
        TurnResult { session_id }
    }

    async fn drive(ctx: &TurnContext, client: &HttpClient, config: &Value, session_id: &mut Option<String>) -> Result<SessionOutcome, String> {
        let emitter = &ctx.emitter;
        let enc = crate::session::encode_uri_component;
        let parsed = parse_opencode_model(ctx.model.as_deref());
        let session_model = parsed.as_ref().map(|m| json!({ "id": m["modelID"], "providerID": m["providerID"] }));
        if let (Some(id), Some(model)) = (session_id.clone(), &session_model) {
            if let Err((status, e)) = client.json(reqwest::Method::POST, &format!("/api/session/{}/model", enc(&id)), &[], Some(&json!({ "model": model }))).await {
                if status != 404 {
                    return Err(user_error(status, &e));
                }
                *session_id = None;
            }
        }
        if session_id.is_none() {
            let mut body = json!({ "title": "Netcatty OpenCode", "location": { "directory": ctx.cwd.to_string_lossy() } });
            if let Some(m) = &session_model {
                body["model"] = m.clone();
            }
            let rules = flatten_permission_rules(&config["permission"]);
            if !rules.is_empty() {
                body["permissions"] = Value::Array(rules);
            }
            let created = client.json(reqwest::Method::POST, "/api/session", &[], Some(&body)).await.map_err(|(s, e)| user_error(s, &e))?;
            let created = if created.get("data").is_some() { created["data"].clone() } else { created };
            *session_id = created["id"].as_str().map(str::to_string);
        }
        let sid = session_id.clone().ok_or("ai.opencode.v2.unavailable")?;
        emitter.session_id(&sid);
        if let Some(sys) = ctx.system_prompt.as_deref().filter(|s| !s.is_empty()) {
            let r = client.json(reqwest::Method::PUT, &format!("/api/experimental/session/{}/instructions/entries/netcatty", enc(&sid)), &[], Some(&json!({ "value": sys }))).await;
            match r {
                Ok(_) => {}
                Err((s, _)) if matches!(s, 400 | 404 | 405 | 413) => emitter.warning("opencode-v2-context", "ai.opencode.v2.contextSkipped"),
                Err((s, e)) => return Err(user_error(s, &e)),
            }
        }
        for (name, cfg) in config["mcp"].as_object().cloned().unwrap_or_default() {
            let body = json!({ "config": { "type": "local", "command": cfg["command"], "environment": cfg["environment"], "disabled": cfg["enabled"] == false } });
            let dir = ctx.cwd.to_string_lossy().into_owned();
            if client.json(reqwest::Method::PUT, &format!("/api/experimental/mcp/{}", enc(&name)), &[("location[directory]", &dir)], Some(&body)).await.is_err() {
                emitter.warning(&format!("opencode-v2-mcp:{name}"), "ai.opencode.v2.mcpSkipped");
            }
        }
        let mut events = client.sse("/api/event").await.map_err(|(s, _)| user_error(s, ""))?;
        let parts = build_prompt_parts(&ctx.prompt, &ctx.attachments);
        let files: Vec<Value> = parts.iter().filter(|p| p["type"] == "file").map(|p| json!({ "uri": p["url"], "name": p["filename"] })).collect();
        let mut body = json!({ "text": ctx.prompt });
        if !files.is_empty() {
            body["files"] = Value::Array(files);
        }
        let prompt_path = format!("/api/session/{}/prompt", enc(&sid));
        let prompt = client.json(reqwest::Method::POST, &prompt_path, &[], Some(&body));
        tokio::pin!(prompt);
        let mut prompt_done = false;
        let mut outcome = SessionOutcome::default();
        let mut st = OpenCodeState::default();
        let mut tool_names = HashMap::new();
        loop {
            tokio::select! {
                _ = ctx.cancel.cancelled() => return Ok(outcome),
                r = &mut prompt, if !prompt_done => {
                    prompt_done = true;
                    if let Err((s, e)) = r {
                        return Err(user_error(s, &e));
                    }
                }
                ev = events.recv() => {
                    let Some(event) = ev else { return Err("ai.opencode.v2.sessionFailed".into()) };
                    let r = translate_event(&event, emitter, &mut st, &sid, &mut tool_names);
                    if r.content { outcome.has_content = true; }
                    if r.error { outcome.failed = true; return Ok(outcome); }
                    if r.idle { outcome.completed = true; return Ok(outcome); }
                }
            }
        }
    }

    pub async fn list_models(ctx: &ListContext, bin: &str) -> Result<ModelCatalog, String> {
        let config = json!({ "autoupdate": false, "share": "disabled" });
        let (mut serve, client) = tokio::select! {
            _ = ctx.cancel.cancelled() => return Ok(ModelCatalog::default()),
            o = open_server(bin, &config, &ctx.env, Some(&ctx.cwd), OPENCODE_SERVER_START_TIMEOUT.min(ctx.remaining())) => o?,
        };
        let dir = ctx.cwd.to_string_lossy().into_owned();
        let q = [("location[directory]", dir.as_str())];
        let models = client.json(reqwest::Method::GET, "/api/model", &q, None).await;
        let providers = client.json(reqwest::Method::GET, "/api/provider", &q, None).await.unwrap_or(Value::Null);
        let default = client.json(reqwest::Method::GET, "/api/model/default", &q, None).await.unwrap_or(Value::Null);
        serve.stop().await;
        let models = models.map_err(|(s, e)| user_error(s, &e))?;
        Ok(map_catalog(&models, &providers, &default))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::RecordingSink;
    use std::sync::Arc;

    #[test]
    fn config_permissions_by_mode() {
        let mcp = build_opencode_config(Some("anthropic/claude"), &[McpServerConfig::stdio("n", "/c", vec!["--mcp-server".into()], vec![])], "mcp", &[], &NativeSkillOptions::default());
        assert_eq!(mcp["permission"]["bash"], "deny");
        assert_eq!(mcp["permission"]["question"], "deny");
        assert_eq!(mcp["permission"]["external_directory"]["*"], "deny");
        assert_eq!(mcp["permission"]["external_directory"]["*.opencode/skills/**"], "allow");
        assert_eq!(mcp["permission"]["read"]["*.opencode/skills/**.env"], "deny");
        assert_eq!(mcp["mcp"]["n"]["command"], json!(["/c", "--mcp-server"]));
        assert_eq!(mcp["model"], "anthropic/claude");
        let dir = tempfile::tempdir().unwrap();
        let allow = skills_path_allowlist(&[dir.path().join("cli.js").to_string_lossy().into_owned()], None, None);
        assert_eq!(allow.len(), 3);
        let skills = build_opencode_config(None, &[], "skills", &allow, &NativeSkillOptions::default());
        assert_eq!(skills["permission"]["bash"], "allow");
        assert_eq!(skills["permission"]["grep"], "deny");
        assert_eq!(skills["permission"]["read"][&allow[2]], "allow");
    }

    #[test]
    fn mimo_native_skills_and_trust() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let env: EnvMap = [("HOME".to_string(), home.path().to_string_lossy().into_owned())].into_iter().collect();
        let opts = NativeSkillOptions { mimo: true, env: env.clone(), cwd: Some(project.path().to_path_buf()), skill_paths: vec![] };
        let (read, external) = native_skills_permission_rules(&opts);
        assert!(!external.contains_key("*.opencode/skills"));
        let home_skills = normalize_path(&std::path::absolute(home.path().join(".mimocode/skills")).unwrap().to_string_lossy());
        assert_eq!(external.get(&format!("{home_skills}/**")), Some(&json!("allow")));
        assert_eq!(read.get(&format!("{home_skills}/**.env")), Some(&json!("deny")));
        std::fs::create_dir_all(project.path().join("skills")).unwrap();
        let trusted = filter_mimo_trusted_skill_paths(&["skills".into(), "/etc".into(), "~/x".into()], project.path(), &env, &[]);
        assert_eq!(trusted.len(), 1);
    }

    #[test]
    fn v1_translation() {
        let sink = Arc::new(RecordingSink::default());
        let e = Emitter::new(sink.clone(), "r");
        let mut st = OpenCodeState::default();
        let ev = |t: &str, p: Value| json!({ "directory": "/w", "payload": { "type": t, "properties": p } });
        translate_event(&ev("message.updated", json!({ "info": { "id": "u1", "role": "user" } })), &e, &mut st);
        assert!(!translate_event(&ev("message.part.updated", json!({ "part": { "id": "p0", "messageID": "u1", "type": "text", "text": "user echo" } })), &e, &mut st).content);
        assert!(translate_event(&ev("message.part.updated", json!({ "part": { "id": "p1", "messageID": "a1", "type": "text", "text": "Hel" } })), &e, &mut st).content);
        translate_event(&ev("message.part.updated", json!({ "part": { "id": "p1", "messageID": "a1", "type": "text", "text": "Hello" } })), &e, &mut st);
        translate_event(&ev("message.part.delta", json!({ "partID": "p1", "delta": "!", "field": "x" })), &e, &mut st);
        translate_event(&ev("message.part.updated", json!({ "part": { "callID": "c1", "type": "tool", "tool": "bash", "state": { "status": "error", "error": "", "output": "partial" } } })), &e, &mut st);
        let idle = translate_event(&ev("session.idle", json!({ "sessionID": "s" })), &e, &mut st);
        assert!(idle.idle);
        let text: String = sink.stream_events().iter().filter(|x| x["type"] == "text-delta").map(|x| x["textDelta"].as_str().unwrap().to_string()).collect();
        assert_eq!(text, "Hello!");
        assert!(sink.stream_events().iter().any(|x| x["type"] == "tool-result" && x["output"] == "partial"));
        assert_eq!(event_session_id(&ev("x", json!({ "part": { "sessionID": "s2" } }))).as_deref(), Some("s2"));
        assert!(translate_event(&ev("session.error", json!({ "error": { "data": { "message": "bad key" } } })), &e, &mut st).error);
        assert_eq!(sink.errors(), vec!["bad key".to_string()]);
    }

    #[test]
    fn catalogs_and_versions() {
        let data = json!({ "providers": [{ "id": "anthropic", "name": "Anthropic", "models": { "claude": { "name": "Claude" } } }], "default": { "anthropic": "claude" } });
        assert_eq!(map_opencode_models(&data), vec![json!({ "id": "anthropic/claude", "name": "Anthropic Claude" })]);
        assert_eq!(default_model_id(&data).as_deref(), Some("anthropic/claude"));
        assert_eq!(default_model_ids(&json!({ "default": { "providerID": "p", "modelID": "m" } })), vec!["p/m".to_string()]);
        assert_eq!(parse_opencode_version("opencode 2.1.0"), Some((2, 1, 0)));
        assert_eq!(parse_opencode_version("1.17.9\n"), Some((1, 17, 9)));
        assert_eq!(parse_opencode_version("Bun v1.2.3\nerror"), None);
        assert_eq!(parse_opencode_version("listening on 127.0.0.1:4096"), None);
        let c = v2::map_catalog(&json!({ "data": [{ "id": "coding-default", "providerID": "openai", "modelID": "gpt-5.2", "name": "Coding" }, { "id": "x", "providerID": "openai", "enabled": false }] }), &json!([{ "id": "openai", "name": "OpenAI" }]), &json!({ "id": "coding-default", "providerID": "openai" }));
        assert_eq!(c.models, vec![json!({ "id": "openai/coding-default", "name": "OpenAI Coding" })]);
        assert_eq!(c.current_model_id.as_deref(), Some("openai/coding-default"));
    }

    #[test]
    fn v2_config_content() {
        let v1 = build_opencode_config(Some("a/b"), &[McpServerConfig::stdio("n", "/c", vec![], vec![])], "mcp", &[], &NativeSkillOptions::default());
        let c = v2::config_content(&v1);
        assert_eq!(c["update"], "disable");
        assert_eq!(c["model"], "a/b");
        assert_eq!(c["mcp"]["servers"]["n"]["disabled"], false);
        assert!(c["permissions"].as_array().unwrap().iter().any(|r| r == &json!({ "action": "bash", "resource": "*", "effect": "deny" })));
        let merged = v2::merge_config_content(c, Some("{\"theme\":\"x\",\"permission\":{},\"mcp\":{\"servers\":{\"mine\":{}}}}"));
        assert_eq!(merged["theme"], "x");
        assert!(merged.get("permission").is_none());
        assert!(merged["mcp"]["servers"]["mine"].is_object() && merged["mcp"]["servers"]["n"].is_object());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn v1_turn_against_fake_server() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("opencode");
        std::fs::write(&bin, r#"#!/usr/bin/env python3
import sys, json, threading, queue
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
if "--version" in sys.argv:
    print("1.17.9"); sys.exit(0)
port = int([a for a in sys.argv if a.startswith("--port=")][0].split("=")[1])
cfg = json.loads(__import__("os").environ.get("OPENCODE_CONFIG_CONTENT", "{}"))
events = queue.Queue()
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, o):
        b = json.dumps(o).encode(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path.startswith("/global/event"):
            self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
            while True:
                e = events.get()
                self.wfile.write(("data: " + json.dumps(e) + "\n\n").encode()); self.wfile.flush()
        elif self.path.startswith("/config/providers"):
            self._json({"providers": [{"id": "p", "name": "P", "models": {"m": {"name": "M"}}}], "default": {"p": "m"}})
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = json.loads(self.rfile.read(n) or b"{}")
        if self.path.startswith("/session?") or self.path == "/session":
            self._json({"id": "ses_1"})
        elif "/prompt_async" in self.path:
            self._json({})
            text = body["parts"][0]["text"] + "|" + cfg["permission"]["bash"]
            events.put({"payload": {"type": "message.part.updated", "properties": {"part": {"id": "p1", "sessionID": "ses_1", "messageID": "a", "type": "text", "text": text}}}})
            events.put({"payload": {"type": "session.idle", "properties": {"sessionID": "ses_1"}}})
        else:
            self._json({})
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
print("opencode server listening on http://127.0.0.1:%d" % port, flush=True)
srv.serve_forever()
"#).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sink = Arc::new(RecordingSink::default());
        let env: EnvMap = std::env::vars().collect();
        let ctx = crate::drivers::test_turn_context(Emitter::new(sink.clone(), "r"), Some(bin.to_string_lossy().into_owned()), env.clone());
        let result = tokio::time::timeout(Duration::from_secs(20), run_turn(&ctx)).await.unwrap();
        assert_eq!(result.session_id.as_deref(), Some("ses_1"));
        let text: String = sink.stream_events().iter().filter(|x| x["type"] == "text-delta").map(|x| x["textDelta"].as_str().unwrap().to_string()).collect();
        assert_eq!(text, "hello|deny");
        assert_eq!(sink.done_count(), 1);
        let lctx = ListContext { bin_path: Some(bin.to_string_lossy().into_owned()), env, cwd: std::env::temp_dir(), cancel: tokio_util::sync::CancellationToken::new(), deadline: std::time::Instant::now() + Duration::from_secs(20), cursor_auth_mode: String::new(), cursor_cli_bin_path: None };
        let catalog = list_models(&lctx).await.unwrap();
        assert_eq!(catalog.current_model_id.as_deref(), Some("p/m"));
    }
}

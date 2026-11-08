//! GitHub Copilot CLI driver (Electron: `sdk/copilotDriver.cjs` over
//! `@github/copilot-sdk`). The SDK spawns `copilot --headless --no-auto-update
//! --stdio` and talks vscode-jsonrpc (`Content-Length` framing): `connect`,
//! `session.create|resume`, `session.send`, `session.event` notifications,
//! `session.permissions.handlePendingPermissionRequest`, `session.abort`,
//! `models.list`. This driver speaks the same protocol.

use super::jsonrpc::{Framing, Incoming, RpcClient};
use super::{TurnContext, TurnResult};
use crate::emit::Emitter;
use crate::mcp::McpServerConfig;
use crate::process::{build_command, terminate_child, Stdin, StderrTail, DEFAULT_ABORT_GRACE};
use crate::EnvMap;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
/// `sendAndWait` default timeout.
const SEND_AND_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

pub fn to_copilot_mcp_servers(servers: &[McpServerConfig]) -> Value {
    let mut map = serde_json::Map::new();
    for c in servers.iter().filter(|c| !c.name.is_empty()) {
        map.insert(c.name.clone(), json!({ "type": "stdio", "command": c.command, "args": c.args, "env": c.env_object(), "tools": ["*"] }));
    }
    Value::Object(map)
}

// ── Netcatty CLI shell command guard (shared with CodeBuddy skills mode) ──

const NETCATTY_CLI_TOKEN: &str = r"netcatty-tool-cli(?:\.(?:cjs|cmd))?";

fn metachar_re() -> regex::Regex {
    regex::Regex::new(r"^(?:[;&|`]|&&|\|\||\$\(|\$\{|<<?|>{1,2}|\r?\n)").unwrap()
}

/// Last ` -- ` outside quotes (exec / job-start remote payload separator).
pub fn find_exec_payload_separator_index(command: &str) -> Option<usize> {
    let b = command.as_bytes();
    let (mut single, mut double, mut escape) = (false, false, false);
    let mut last = None;
    let mut i = 0;
    while i < b.len() {
        let ch = b[i];
        if escape {
            escape = false;
        } else if ch == b'\\' && (single || double) {
            escape = true;
        } else if !double && ch == b'\'' {
            single = !single;
        } else if !single && ch == b'"' {
            double = !double;
        } else if !single && !double && command[i..].starts_with(" -- ") {
            last = Some(i);
            i += 3;
        }
        i += 1;
    }
    last
}

/// Unquoted shell chaining / substitution (`$(` and backticks also inside double quotes).
pub fn contains_unsafe_shell_metachar(text: &str) -> bool {
    let re = metachar_re();
    let b = text.as_bytes();
    let (mut single, mut double, mut escape) = (false, false, false);
    for i in 0..b.len() {
        if !text.is_char_boundary(i) {
            continue;
        }
        let ch = b[i];
        if escape {
            escape = false;
            continue;
        }
        if ch == b'\\' && (single || double) {
            escape = true;
            continue;
        }
        if !double && ch == b'\'' {
            single = !single;
            continue;
        }
        if !single && ch == b'"' {
            double = !double;
            continue;
        }
        if single {
            continue;
        }
        if double {
            if text[i..].starts_with("$(") || ch == b'`' {
                return true;
            }
            continue;
        }
        if re.is_match(&text[i..]) {
            return true;
        }
    }
    false
}

fn cli_tokens(local: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (mut single, mut double, mut escape) = (false, false, false);
    let mut token = String::new();
    for ch in local.chars() {
        if escape {
            token.push(ch);
            escape = false;
            continue;
        }
        if ch == '\\' && (single || double) {
            escape = true;
            token.push(ch);
            continue;
        }
        if !double && ch == '\'' {
            single = !single;
            token.push(ch);
            continue;
        }
        if !single && ch == '"' {
            double = !double;
            token.push(ch);
            continue;
        }
        if !single && !double && ch.is_whitespace() {
            if !token.is_empty() {
                out.push(std::mem::take(&mut token));
            }
            continue;
        }
        token.push(ch);
    }
    if !token.is_empty() {
        out.push(token);
    }
    out.into_iter()
        .map(|t| {
            if t.len() >= 2 && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\''))) {
                t[1..t.len() - 1].to_string()
            } else {
                t
            }
        })
        .collect()
}

fn is_removed_chat_session_flag(token: &str) -> bool {
    token == "--chat-session" || token.starts_with("--chat-session=")
}

pub fn is_netcatty_cli_invocation_prefix(local: &str) -> bool {
    let text = local.trim();
    if text.is_empty() {
        return false;
    }
    let path_prefix = r#"(?:\.\./|\./|/|[A-Za-z]:[\\/])[\w. \\-]*[\\/]"#;
    let suffix = format!(r"(?:[\\/]|^){NETCATTY_CLI_TOKEN}");
    let pattern = format!(
        r#"(?i)^(?:"[^"]*{suffix}"|'[^']*{suffix}'|{tok}(?:\s|$)|{path_prefix}{tok}(?:\s|$)|node\s+(?:{tok}(?:\s|$)|{path_prefix}{tok}(?:\s|$)|(?:[\w.-]+(?:[\\/][\w.-]+)*[\\/])?{tok}(?:\s|$)|"[^"]*{suffix}"|'[^']*{suffix}'))"#,
        tok = NETCATTY_CLI_TOKEN
    );
    regex::Regex::new(&pattern).map(|re| re.is_match(text)).unwrap_or(false)
}

/// `isLikelyNetcattyCliShellCommand`.
pub fn is_likely_netcatty_cli_shell_command(full: &str) -> bool {
    let command = full.trim();
    if command.is_empty() {
        return false;
    }
    let split = find_exec_payload_separator_index(command);
    let local = split.map(|i| command[..i].trim()).unwrap_or(command);
    let remote = split.map(|i| command[i + 4..].trim()).unwrap_or("");
    if local.is_empty() || regex::Regex::new(r"(?i)^(?:/[^\s]+/)?(?:ba|z|fi)?sh(?:\.exe)?\s+-c\b").unwrap().is_match(local) {
        return false;
    }
    let tokens = cli_tokens(local);
    if tokens.iter().any(|t| t.starts_with("NETCATTY_CLI_CHAT_SESSION_ID=") || t.starts_with("NETCATTY_TOOL_CLI_DISCOVERY_FILE=")) {
        return false;
    }
    if tokens.iter().any(|t| is_removed_chat_session_flag(t)) {
        return false;
    }
    if !is_netcatty_cli_invocation_prefix(local) {
        return false;
    }
    if !remote.is_empty() {
        if !regex::Regex::new(r"(?i)\b(?:exec|job-start)\b").unwrap().is_match(local) {
            return false;
        }
        return !contains_unsafe_shell_metachar(local) && !contains_unsafe_shell_metachar(command);
    }
    !contains_unsafe_shell_metachar(command)
}

/// Permission policy: MCP mode allows only MCP requests; skills mode only
/// Netcatty CLI shell commands.
pub fn permission_decision(request: &Value, tool_mode: &str) -> Value {
    if tool_mode == "skills" {
        if request["kind"] == "shell" {
            if is_likely_netcatty_cli_shell_command(request["fullCommandText"].as_str().unwrap_or("")) {
                return json!({ "kind": "approve-once" });
            }
            return json!({ "kind": "reject", "feedback": "Only Netcatty CLI shell commands are allowed. Invoke the netcatty-tool-cli launcher or script prefix provided by the host. Do not pass --chat-session or override NETCATTY_CLI_CHAT_SESSION_ID; the host already bound this process." });
        }
        return json!({ "kind": "reject", "feedback": "Only Netcatty CLI shell commands are allowed from this integration." });
    }
    if request["kind"] == "mcp" && request["toolName"].as_str().map(|t| !t.is_empty()).unwrap_or(false) {
        return json!({ "kind": "approve-once" });
    }
    json!({ "kind": "reject", "feedback": "Only Netcatty MCP tools are allowed from this integration." })
}

pub fn build_message_attachments(attachments: &[crate::session::StagedAttachment]) -> Vec<Value> {
    attachments
        .iter()
        .filter_map(|a| {
            let display = if a.filename.is_empty() { Value::Null } else { json!(a.filename) };
            if !a.base64_data.is_empty() && !a.media_type.is_empty() {
                Some(json!({ "type": "blob", "data": a.base64_data, "mimeType": a.media_type, "displayName": display }))
            } else if !a.file_path.is_empty() {
                Some(json!({ "type": "file", "path": a.file_path, "displayName": display }))
            } else {
                None
            }
        })
        .collect()
}

fn result_text(data: &Value) -> String {
    if let Some(m) = data.pointer("/error/message").and_then(|m| m.as_str()) {
        return m.to_string();
    }
    match &data["result"] {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        r => match r["content"].as_array() {
            Some(blocks) => blocks.iter().map(|b| b["text"].as_str().map(str::to_string).unwrap_or_else(|| if b.is_null() { String::new() } else { b.to_string() })).collect(),
            None => r.to_string(),
        },
    }
}

#[derive(Default)]
pub struct CopilotState {
    pub reasoning_open: bool,
    pub streamed_text: bool,
    pub streamed_reasoning: bool,
}

/// `translateCopilotEvent`.
pub fn translate_event(event: &Value, emitter: &Emitter, st: &mut CopilotState) {
    let data = &event["data"];
    let close = |st: &mut CopilotState| {
        if st.reasoning_open {
            emitter.reasoning_end();
            st.reasoning_open = false;
        }
    };
    match event["type"].as_str().unwrap_or("") {
        "assistant.reasoning_delta" => {
            if let Some(d) = data["deltaContent"].as_str().filter(|d| !d.is_empty()) {
                emitter.reasoning(d);
                st.reasoning_open = true;
                st.streamed_reasoning = true;
            }
        }
        "assistant.reasoning" => {
            if let Some(c) = data["content"].as_str().filter(|c| !c.is_empty() && !st.streamed_reasoning) {
                emitter.reasoning(c);
                st.reasoning_open = true;
                close(st);
            }
        }
        "assistant.message_delta" => {
            if let Some(d) = data["deltaContent"].as_str().filter(|d| !d.is_empty()) {
                close(st);
                emitter.text(d);
                st.streamed_text = true;
            }
        }
        "tool.execution_start" => {
            close(st);
            let name = data["toolName"].as_str().or(data["mcpToolName"].as_str()).unwrap_or("tool");
            emitter.tool_call(name, if data["arguments"].is_object() { data["arguments"].clone() } else { json!({}) }, data["toolCallId"].as_str().unwrap_or(""));
        }
        "tool.execution_complete" => emitter.tool_result(data["toolCallId"].as_str().unwrap_or(""), &result_text(data), None),
        _ => {}
    }
}

/// `connectCopilotStdioPath` + the SDK's `.js` → node launch.
fn launch_spec(cli_path: &str, args: Vec<String>) -> crate::cli::SpawnSpec {
    let prefer_native = std::env::var("NETCATTY_COPILOT_PREFER_NATIVE").map(|v| v == "1").unwrap_or(false);
    let mut resolved = crate::cli::resolve_copilot_executable_for_sdk(cli_path, prefer_native).unwrap_or_else(|| cli_path.to_string());
    if cfg!(windows) && regex::Regex::new(r"(?i)(?:^|[\\/])@github[\\/]copilot[\\/]npm-loader\.js$").unwrap().is_match(&resolved) {
        if let Some(native) = crate::cli::resolve_copilot_platform_executable(&resolved) {
            resolved = native;
        }
    }
    if resolved.ends_with(".js") {
        let mut full = vec![resolved];
        full.extend(args);
        return crate::cli::SpawnSpec { command: "node".into(), args: full, shell: false };
    }
    crate::cli::SpawnSpec { command: resolved, args, shell: false }
}

struct CopilotProcess {
    child: tokio::process::Child,
    rpc: Arc<RpcClient>,
    incoming: tokio::sync::mpsc::UnboundedReceiver<Incoming>,
    _stderr: StderrTail,
}

async fn start(cli_path: &str, env: &EnvMap) -> Result<CopilotProcess, String> {
    let spec = launch_spec(cli_path, vec!["--headless".into(), "--no-auto-update".into(), "--stdio".into()]);
    let mut env = env.clone();
    env.remove("NODE_DEBUG");
    let mut child = build_command(&spec, &env, None, Stdin::Piped).spawn().map_err(|e| e.to_string())?;
    let stdin = child.stdin.take().ok_or("Copilot CLI stdin unavailable")?;
    let stdout = child.stdout.take().ok_or("Copilot CLI stdout unavailable")?;
    let stderr = StderrTail::spawn(child.stderr.take(), 32 * 1024);
    let (rpc, incoming) = RpcClient::start(stdin, stdout, Framing::ContentLength, MAX_MESSAGE_BYTES);
    match rpc.request("connect", json!({}), Duration::from_secs(30)).await {
        Ok(_) => {}
        Err(e) if e.code == Some(-32601) || e.message == "Unhandled method connect" => {
            rpc.request("ping", json!({ "message": null }), Duration::from_secs(30)).await.map_err(|e| e.message)?;
        }
        Err(e) => return Err(e.message),
    }
    Ok(CopilotProcess { child, rpc, incoming, _stderr: stderr })
}

async fn stop(p: &mut CopilotProcess, session_id: Option<&str>) {
    if let Some(id) = session_id {
        let _ = p.rpc.request("session.destroy", json!({ "sessionId": id }), Duration::from_secs(3)).await;
    }
    p.rpc.close_stdin();
    terminate_child(&mut p.child, DEFAULT_ABORT_GRACE).await;
}

fn not_found(msg: &str) -> bool {
    msg.contains("No such file") || msg.contains("os error 2") || msg.contains("ENOENT")
}

pub async fn run_turn(ctx: &TurnContext) -> TurnResult {
    let emitter = &ctx.emitter;
    let mut session_id = ctx.resume_session_id.clone();
    let Some(cli) = ctx.bin_path.clone().filter(|b| !b.is_empty()) else {
        emitter.emit_error("Copilot CLI not found. Install with `npm i -g @github/copilot` and run `gh auth login`.");
        return TurnResult { session_id };
    };
    let mut proc_ = match tokio::select! {
        _ = ctx.cancel.cancelled() => return TurnResult { session_id },
        p = start(&cli, &ctx.env) => p,
    } {
        Ok(p) => p,
        Err(e) => {
            emitter.emit_error(if not_found(&e) { "Copilot CLI not found. Install with `npm i -g @github/copilot` and run `gh auth login`.".to_string() } else { e });
            return TurnResult { session_id };
        }
    };
    let mut config = json!({
        "mcpServers": to_copilot_mcp_servers(&ctx.injected_mcp_servers),
        "streaming": true,
        "requestPermission": true,
        "includeSubAgentStreamingEvents": true,
        "envValueMode": "direct",
    });
    if ctx.tool_integration_mode == "skills" {
        config["availableTools"] = json!(["builtin:bash"]);
    }
    if let Some(m) = ctx.model.as_deref().filter(|m| !m.is_empty()) {
        config["model"] = json!(m);
    }
    let mut created = None;
    if let Some(resume) = ctx.resume_session_id.clone() {
        let mut params = config.clone();
        params["sessionId"] = json!(resume);
        created = proc_.rpc.request("session.resume", params, Duration::from_secs(60)).await.ok().map(|r| r["sessionId"].as_str().map(str::to_string).unwrap_or(resume));
    }
    let sid = match created {
        Some(s) => s,
        None => {
            let mut params = config.clone();
            params["sessionId"] = json!(uuid::Uuid::new_v4().to_string());
            match proc_.rpc.request("session.create", params, Duration::from_secs(60)).await {
                Ok(r) => match r["sessionId"].as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        emitter.emit_error("session.create response did not include a sessionId");
                        stop(&mut proc_, None).await;
                        return TurnResult { session_id };
                    }
                },
                Err(e) => {
                    emitter.emit_error(e.message);
                    stop(&mut proc_, None).await;
                    return TurnResult { session_id };
                }
            }
        }
    };
    session_id = Some(sid.clone());
    emitter.session_id(&sid);
    let mut body = json!({ "sessionId": sid, "prompt": ctx.prompt });
    let attachments = build_message_attachments(&ctx.attachments);
    if !attachments.is_empty() {
        body["attachments"] = Value::Array(attachments);
    }
    let mut st = CopilotState::default();
    let mut last_message: Option<String> = None;
    let mut failure: Option<String> = None;
    let rpc = proc_.rpc.clone();
    let send = rpc.request("session.send", body, Duration::from_secs(60));
    tokio::pin!(send);
    let mut sent = false;
    let deadline = tokio::time::sleep(SEND_AND_WAIT_TIMEOUT);
    tokio::pin!(deadline);
    let mut aborted = false;
    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => { aborted = true; break; }
            r = &mut send, if !sent => {
                sent = true;
                if let Err(e) = r { failure = Some(e.message); break; }
            }
            _ = &mut deadline, if sent => {
                failure = Some(format!("Timeout after {}ms waiting for session.idle", SEND_AND_WAIT_TIMEOUT.as_millis()));
                break;
            }
            msg = proc_.incoming.recv() => {
                let Some(msg) = msg else { failure = Some("Copilot CLI connection closed".into()); break };
                let Incoming::Notification(n) = msg else { continue };
                if n["method"] != "session.event" || n["params"]["sessionId"].as_str() != Some(&sid) { continue }
                let event = &n["params"]["event"];
                match event["type"].as_str().unwrap_or("") {
                    "assistant.message" => last_message = event.pointer("/data/content").and_then(|c| c.as_str()).map(str::to_string),
                    "session.idle" => break,
                    "session.error" => { failure = Some(event.pointer("/data/message").and_then(|m| m.as_str()).unwrap_or("Copilot turn failed").to_string()); break; }
                    "permission.requested" => {
                        let data = &event["data"];
                        if data["resolvedByHook"] != true {
                            let result = permission_decision(&data["permissionRequest"], &ctx.tool_integration_mode);
                            let rpc = rpc.clone();
                            let params = json!({ "sessionId": sid, "requestId": data["requestId"], "result": result });
                            tokio::spawn(async move { let _ = rpc.request("session.permissions.handlePendingPermissionRequest", params, Duration::from_secs(30)).await; });
                        }
                    }
                    _ => translate_event(event, emitter, &mut st),
                }
            }
        }
    }
    if st.reasoning_open {
        emitter.reasoning_end();
    }
    if aborted {
        let _ = rpc.request("session.abort", json!({ "sessionId": sid }), Duration::from_secs(3)).await;
        stop(&mut proc_, None).await;
        return TurnResult { session_id };
    }
    stop(&mut proc_, None).await;
    if let Some(e) = failure {
        emitter.emit_error(if not_found(&e) { "Copilot CLI not found. Install with `npm i -g @github/copilot` and run `gh auth login`.".to_string() } else if e.is_empty() { "Copilot turn failed".into() } else { e });
        return TurnResult { session_id };
    }
    if !st.streamed_text {
        match last_message.filter(|m| !m.is_empty()) {
            Some(content) => emitter.text(&content),
            None => {
                emitter.emit_error("Copilot returned an empty response. Run `copilot` once to log in, or `gh auth login`.");
                return TurnResult { session_id };
            }
        }
    }
    emitter.emit_done();
    TurnResult { session_id }
}

pub async fn list_models(ctx: &super::ListContext) -> Vec<Value> {
    let Some(cli) = ctx.bin_path.clone().filter(|b| !b.is_empty()) else { return Vec::new() };
    let work = async {
        let mut p = start(&cli, &ctx.env).await.ok()?;
        let r = p.rpc.request("models.list", json!({}), ctx.remaining()).await.ok();
        stop(&mut p, None).await;
        r
    };
    let result = tokio::select! {
        _ = ctx.cancel.cancelled() => None,
        r = work => r,
    };
    result
        .and_then(|r| r["models"].as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter(|m| m["id"].is_string())
        .map(|m| json!({ "id": m["id"], "name": m["name"].as_str().unwrap_or(m["id"].as_str().unwrap()) }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::RecordingSink;

    #[test]
    fn shell_guard() {
        assert!(is_likely_netcatty_cli_shell_command("netcatty-tool-cli env --json"));
        assert!(is_likely_netcatty_cli_shell_command("\"/app/x/netcatty-tool-cli\" session --session s1 --json"));
        assert!(!is_likely_netcatty_cli_shell_command("node /opt/netcatty/netcatty-tool-cli.cjs exec --session s -- uname -a"));
        assert!(is_likely_netcatty_cli_shell_command("node resources/netcatty-tool-cli.cjs exec --session s -- uname -a"));
        assert!(is_likely_netcatty_cli_shell_command("netcatty-tool-cli exec --session s -- 'ls | wc -l'"));
        assert!(!is_likely_netcatty_cli_shell_command("netcatty-tool-cli exec --session s -- ls | wc -l"));
        assert!(!is_likely_netcatty_cli_shell_command("netcatty-tool-cli env; rm -rf /"));
        assert!(!is_likely_netcatty_cli_shell_command("netcatty-tool-cli env --chat-session x"));
        assert!(!is_likely_netcatty_cli_shell_command("NETCATTY_CLI_CHAT_SESSION_ID=x netcatty-tool-cli env"));
        assert!(!is_likely_netcatty_cli_shell_command("bash -c 'netcatty-tool-cli env'"));
        assert!(!is_likely_netcatty_cli_shell_command("netcatty-tool-cli session -- whoami"));
        assert!(!is_likely_netcatty_cli_shell_command("ls -la"));
        assert!(!is_likely_netcatty_cli_shell_command("netcatty-tool-cli env \"$(id)\""));
        assert_eq!(find_exec_payload_separator_index("a -- b ' -- ' -- c"), Some(13));
    }

    #[test]
    fn permission_policies() {
        assert_eq!(permission_decision(&json!({ "kind": "mcp", "toolName": "exec" }), "mcp")["kind"], "approve-once");
        assert_eq!(permission_decision(&json!({ "kind": "shell", "fullCommandText": "ls" }), "mcp")["kind"], "reject");
        assert_eq!(permission_decision(&json!({ "kind": "shell", "fullCommandText": "netcatty-tool-cli env --json" }), "skills")["kind"], "approve-once");
        assert_eq!(permission_decision(&json!({ "kind": "write" }), "skills")["kind"], "reject");
    }

    #[test]
    fn event_translation() {
        let sink = Arc::new(RecordingSink::default());
        let e = Emitter::new(sink.clone(), "r");
        let mut st = CopilotState::default();
        for ev in [
            json!({ "type": "assistant.reasoning_delta", "data": { "deltaContent": "t" } }),
            json!({ "type": "assistant.reasoning", "data": { "content": "dup" } }),
            json!({ "type": "tool.execution_start", "data": { "mcpToolName": "exec", "arguments": { "a": 1 }, "toolCallId": "c" } }),
            json!({ "type": "tool.execution_complete", "data": { "toolCallId": "c", "result": { "content": [{ "text": "ok" }] } } }),
            json!({ "type": "assistant.message_delta", "data": { "deltaContent": "Hi" } }),
        ] {
            translate_event(&ev, &e, &mut st);
        }
        let types: Vec<String> = sink.stream_events().iter().map(|v| v["type"].as_str().unwrap().to_string()).collect();
        assert_eq!(types, vec!["reasoning-delta", "reasoning-end", "tool-call", "tool-result", "text-delta"]);
        assert!(st.streamed_text);
        let att = build_message_attachments(&[crate::session::StagedAttachment { filename: "a".into(), media_type: "image/png".into(), file_path: "/a".into(), base64_data: "x".into() }]);
        assert_eq!(att[0]["type"], "blob");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn turn_against_fake_cli() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("copilot");
        std::fs::write(&bin, r#"#!/usr/bin/env python3
import sys, json
def read():
    h = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line: return None
        line = line.strip()
        if not line: break
        k, v = line.split(b":", 1); h[k.lower()] = int(v)
    return json.loads(sys.stdin.buffer.read(h[b"content-length"]))
def send(o):
    b = json.dumps(o).encode(); sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(b) + b); sys.stdout.flush()
assert "--headless" in sys.argv and "--stdio" in sys.argv
while True:
    m = read()
    if m is None: break
    meth = m.get("method")
    if meth == "connect": send({"jsonrpc": "2.0", "id": m["id"], "result": {"protocolVersion": 3}})
    elif meth == "session.create":
        sid = m["params"]["sessionId"]
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"sessionId": sid}})
    elif meth == "session.send":
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"messageId": "x"}})
        send({"jsonrpc": "2.0", "method": "session.event", "params": {"sessionId": sid, "event": {"type": "permission.requested", "data": {"requestId": "p1", "permissionRequest": {"kind": "mcp", "toolName": "exec"}}}}})
    elif meth == "session.permissions.handlePendingPermissionRequest":
        send({"jsonrpc": "2.0", "id": m["id"], "result": {}})
        send({"jsonrpc": "2.0", "method": "session.event", "params": {"sessionId": sid, "event": {"type": "assistant.message_delta", "data": {"deltaContent": m["params"]["result"]["kind"]}}}})
        send({"jsonrpc": "2.0", "method": "session.event", "params": {"sessionId": sid, "event": {"type": "session.idle", "data": {}}}})
    elif "id" in m:
        send({"jsonrpc": "2.0", "id": m["id"], "result": {}})
"#).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sink = Arc::new(RecordingSink::default());
        let env: EnvMap = std::env::vars().collect();
        let ctx = crate::drivers::test_turn_context(Emitter::new(sink.clone(), "r"), Some(bin.to_string_lossy().into_owned()), env);
        let result = tokio::time::timeout(Duration::from_secs(15), run_turn(&ctx)).await.unwrap();
        assert!(result.session_id.is_some());
        let text: String = sink.stream_events().iter().filter(|x| x["type"] == "text-delta").map(|x| x["textDelta"].as_str().unwrap().to_string()).collect();
        assert_eq!(text, "approve-once");
        assert_eq!(sink.done_count(), 1);
    }
}

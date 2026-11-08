//! Tool CLI helper mode (Electron `electron/cli/netcatty-tool-cli.cjs`,
//! `netcattyRpcClient.cjs`, `cliChatSession.cjs`): the Netcatty executable
//! started as `netcatty --tool-cli <args>` behaves like `netcatty-tool-cli`,
//! connecting through the tool-CLI discovery file.

use crate::discovery::{TOOL_CLI_CHAT_SESSION_ENV_VAR, TOOL_CLI_DISCOVERY_ENV_VAR};
use netcatty_capabilities::catalog::STATUS_IMPLEMENTED;
use netcatty_capabilities::registry::capability_by_cli_command;
use netcatty_capabilities::surfaces::{build_catalog_cli_params, cli_rpc_method, format_cli_help_lines, list_cli_capabilities};
use netcatty_capabilities::transport::NdjsonRpcClient;
use serde_json::{json, Map, Value};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

const MAX_NOTE_STDIN_BYTES: usize = 4 * 1024 * 1024;
const MAX_NOTE_ATTACHMENT_BYTES: u64 = 1024 * 1024;
const MAX_NOTE_RPC_BYTES: usize = 8 * 1024 * 1024;
const MAX_NOTE_IMPORT_CHARS: usize = 512_000;
const CONNECT_RETRY_DELAYS_MS: [u64; 2] = [300, 900];

static DEFAULT_DISCOVERY: OnceLock<PathBuf> = OnceLock::new();

/// Default discovery path (`<data>/netcatty-tool-cli/discovery.json`), set
/// by the desktop entry point before [`run`].
pub fn set_default_discovery_path(path: PathBuf) {
    let _ = DEFAULT_DISCOVERY.set(path);
}

fn discovery_path() -> PathBuf {
    std::env::var_os(TOOL_CLI_DISCOVERY_ENV_VAR)
        .map(PathBuf::from)
        .or_else(|| DEFAULT_DISCOVERY.get().cloned())
        .unwrap_or_else(|| PathBuf::from("discovery.json"))
}

/// `{ code, message, details? }` CLI error.
#[derive(Debug, Clone)]
pub struct CliError {
    pub code: String,
    pub message: String,
    pub details: Option<Value>,
}

fn err(code: &str, message: impl Into<String>) -> CliError {
    CliError { code: code.into(), message: message.into(), details: None }
}

pub fn help_text() -> String {
    format!(
        "Netcatty Tool CLI\n\nUsage:\n{}\n\nExamples:\n  netcatty-tool-cli status --json\n  netcatty-tool-cli env --json\n  netcatty-tool-cli attachment list --json\n  netcatty-tool-cli attachment read --filename hosts.csv --json\n  netcatty-tool-cli session --session sess_123 --json\n  netcatty-tool-cli exec --session sess_123 --json -- \"pwd\"\n  netcatty-tool-cli vault host get --host-id host_123 --json\n  netcatty-tool-cli vault host open --host-id host_123 --json\n  netcatty-tool-cli snippets run --snippet-id snip_1 --session sess_123 --json\n  netcatty-tool-cli notes import --attachment-index 0 --json\n  netcatty-tool-cli portforward rules list --json\n\nNotes:\n  - Start the Netcatty desktop app before using this CLI.\n  - Host-launched agents receive NETCATTY_CLI_CHAT_SESSION_ID in the environment. There is no --chat-session flag.\n  - `env` and `session` require NETCATTY_CLI_CHAT_SESSION_ID.\n  - `exec` always requires --session <id>, plus NETCATTY_CLI_CHAT_SESSION_ID.\n  - `job-start` always requires --session <id>, plus NETCATTY_CLI_CHAT_SESSION_ID.\n  - `job-poll` and `job-stop` always require --job <id>, plus NETCATTY_CLI_CHAT_SESSION_ID.\n  - Every `sftp <op>` always requires --session <id>, plus NETCATTY_CLI_CHAT_SESSION_ID, and only works on connected SSH-backed sessions.\n  - Vault/portforward/snippet/notes commands use catalog-driven dispatch; see `capabilities --json` for the full list.\n  - notes create, update, delete, and import change Vault notes and require user approval in confirm mode.\n  - Use --attachment-index from attachment list for attached Markdown. Pipe generated note text through --content-stdin (or --documents-stdin for a batch). Never interpolate note text into a shell command.\n  - notes create requires a body via --content-stdin or an explicit --content (including an empty string). notes update --content \"\" clears the body and --group \"\" clears the folder; omitting those flags keeps the current values. notes import accepts --content \"\".\n  - After `--`, pass exactly one shell-ready command string. Preserve quoting inside that one argument.\n  - `cancel` stops in-flight execs, session-backed SFTP transfers, and running jobs for that chat session, then blocks further execs until `resume`.\n",
        format_cli_help_lines().join("\n")
    )
}

/// Parsed options keyed by the catalog `optKey` names.
#[derive(Debug, Default)]
pub struct Opts {
    pub json: bool,
    pub chat_session_id: Option<String>,
    pub scoped_session_ids: Vec<String>,
    pub content_stdin: bool,
    pub documents_stdin: bool,
    pub attachment_index: Option<String>,
    pub encoding: Option<String>,
    pub command: Vec<String>,
    pub values: Map<String, Value>,
}

impl Opts {
    fn s(&self, k: &str) -> Option<String> {
        self.values.get(k).and_then(Value::as_str).map(str::to_string)
    }
}

/// `parseArgs` (args exclude the program name).
pub fn parse_args(args: &[String]) -> Result<(Vec<String>, Opts), CliError> {
    let mut opts = Opts::default();
    let mut pos = Vec::new();
    let flag_map: &[(&str, &str, bool)] = &[
        ("--session", "sessionId", false), ("--job", "jobId", true), ("--offset", "offset", true), ("--remote-path", "remotePath", false),
        ("--local-path", "localPath", false), ("--old-remote-path", "oldRemotePath", false), ("--new-remote-path", "newRemotePath", false),
        ("--content", "content", false), ("--mode", "mode", false), ("--host-id", "hostId", false), ("--filename", "filename", false),
        ("--snippet-id", "snippetId", false), ("--script-id", "scriptId", false), ("--rule-id", "ruleId", false), ("--notes", "notes", false),
        ("--variables", "variables", false), ("--target-groups", "targetGroups", false), ("--multi-line-run-mode", "multiLineRunMode", false),
        ("--note-id", "noteId", false), ("--title", "title", false), ("--group", "group", false), ("--linked-host-ids", "linkedHostIds", false),
        ("--tags", "tags", false), ("--max-chars", "maxChars", true), ("--query", "query", false), ("--expected-updated-at", "expectedUpdatedAt", true),
        ("--file-name", "fileName", false), ("--documents", "documents", false), ("--run-id", "runId", false), ("--label", "label", false),
        ("--kind", "kind", false), ("--trigger", "trigger", false), ("--trigger-pattern", "triggerPattern", false), ("--targets", "targets", false),
        ("--targets-all-hosts", "targetsAllHosts", false), ("--description", "description", false), ("--language", "language", false),
        ("--package", "package", false), ("--shortkey", "shortkey", false), ("--no-auto-run", "noAutoRun", false), ("--wait", "wait", false),
        ("--script-ids", "scriptIds", false),
    ];
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let next = args.get(i + 1).cloned();
        if a == "--" {
            opts.command = args[i + 1..].to_vec();
            break;
        }
        if a == "--json" {
            opts.json = true;
        } else if a == "--chat-session" || a.starts_with("--chat-session=") {
            return Err(err("INVALID_ARGUMENT", format!("--chat-session is not a CLI flag. The host binds the chat session via {TOOL_CLI_CHAT_SESSION_ENV_VAR}.")));
        } else if a == "--scope-session" {
            if let Some(v) = next.filter(|v| !v.is_empty()) {
                opts.scoped_session_ids.push(v);
            }
            i += 1;
        } else if a == "--content-stdin" {
            opts.content_stdin = true;
        } else if a == "--documents-stdin" {
            opts.documents_stdin = true;
        } else if a == "--attachment-index" {
            opts.attachment_index = next;
            i += 1;
        } else if a == "--encoding" {
            opts.encoding = next;
            i += 1;
        } else if a == "--workspace-id" {
            match next.filter(|v| !v.is_empty() && !v.starts_with("--")) {
                Some(v) => opts.values.insert("workspaceId".into(), json!(v)),
                None => return Err(err("INVALID_ARGUMENT", "--workspace-id requires an id or current.")),
            };
            i += 1;
        } else if a == "--new-tab" {
            opts.values.insert("newTab".into(), json!("true"));
        } else if let Some((_, key, numeric)) = flag_map.iter().find(|(f, _, _)| *f == a) {
            let v = match next {
                None => Value::Null,
                Some(v) if *numeric => v.trim().parse::<f64>().ok().and_then(serde_json::Number::from_f64).map(Value::Number).unwrap_or(Value::Null),
                Some(v) => Value::String(v),
            };
            opts.values.insert((*key).into(), v);
            i += 1;
        } else {
            pos.push(a.to_string());
        }
        i += 1;
    }
    if !opts.command.is_empty() {
        opts.values.insert("command".into(), json!(opts.command));
    }
    Ok((pos, opts))
}

fn read_note_stdin(pos: &[String], opts: &mut Opts) -> Result<(), CliError> {
    if !opts.content_stdin && !opts.documents_stdin {
        return Ok(());
    }
    let command = pos.join(" ");
    if opts.content_stdin && opts.documents_stdin {
        return Err(err("INVALID_ARGUMENT", "Choose only one of --content-stdin and --documents-stdin."));
    }
    if opts.content_stdin && !["notes create", "notes update", "notes import"].contains(&command.as_str()) {
        return Err(err("INVALID_ARGUMENT", "--content-stdin is only supported for notes create, update, and import."));
    }
    if opts.documents_stdin && command != "notes import" {
        return Err(err("INVALID_ARGUMENT", "--documents-stdin is only supported for notes import."));
    }
    if opts.values.get("content").is_some_and(|v| !v.is_null()) || opts.values.get("documents").is_some_and(|v| !v.is_null()) {
        return Err(err("INVALID_ARGUMENT", "Do not combine stdin note input with --content or --documents."));
    }
    if opts.attachment_index.is_some() {
        return Err(err("INVALID_ARGUMENT", "Do not combine stdin note input with --attachment-index."));
    }
    if std::io::stdin().is_terminal() {
        return Err(err("INVALID_ARGUMENT", "Pipe note data to standard input when using a stdin flag."));
    }
    let mut buf = Vec::new();
    std::io::stdin().take(MAX_NOTE_STDIN_BYTES as u64 + 1).read_to_end(&mut buf).map_err(|e| err("INVALID_ARGUMENT", e.to_string()))?;
    if buf.len() > MAX_NOTE_STDIN_BYTES {
        return Err(err("INVALID_ARGUMENT", "Piped note data exceeds the 4 MiB CLI limit."));
    }
    let text = String::from_utf8(buf).map_err(|_| err("INVALID_ARGUMENT", "Piped note data must be valid UTF-8."))?;
    let key = if opts.content_stdin { "content" } else { "documents" };
    opts.values.insert(key.into(), json!(text));
    Ok(())
}

// ── connection ──────────────────────────────────────────────────────────

fn load_discovery() -> Result<Value, CliError> {
    let path = discovery_path();
    let raw = std::fs::read_to_string(&path).map_err(|_| err("APP_NOT_RUNNING", format!("Netcatty discovery file is missing at {}. Either Netcatty is not running, or the discovery file was removed while Netcatty is still up; Netcatty recreates it automatically within a few seconds — retry shortly, or toggle the AI permission mode / restart Netcatty to regenerate it immediately. Session data is not affected.", path.display())))?;
    let parsed: Value = serde_json::from_str(&raw).map_err(|_| err("DISCOVERY_INVALID", format!("Netcatty discovery file at {} is invalid JSON.", path.display())))?;
    if parsed["port"].as_u64().is_none() || parsed["token"].as_str().is_none_or(str::is_empty) {
        return Err(err("DISCOVERY_INVALID", format!("Netcatty discovery file at {} is missing required port/token fields.", path.display())));
    }
    Ok(parsed)
}

fn retryable(e: &CliError) -> bool {
    matches!(e.code.as_str(), "CONNECT_FAILED" | "AUTH_FAILED" | "CONNECTION_CLOSED" | "CONNECTION_ERROR")
        || (e.code == "RPC_ERROR" && e.message.contains("Authentication required"))
}

async fn establish(discovery: &Value) -> Result<Arc<NdjsonRpcClient>, CliError> {
    let port = discovery["port"].as_u64().unwrap_or(0) as u16;
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| err("CONNECT_FAILED", format!("Failed to connect to Netcatty TCP bridge: {e}")))?;
    let client = NdjsonRpcClient::new(stream, "builtin");
    let auth = client.call("auth/verify", json!({ "token": discovery["token"] })).await.map_err(|e| err(&e.code, e.message))?;
    if auth["ok"].as_bool() != Some(true) {
        return Err(err("AUTH_FAILED", "Failed to authenticate to Netcatty TCP bridge."));
    }
    if let Ok(status) = client.call("netcatty/getStatus", json!({})).await {
        client.ingest_bridge_status(&status);
    }
    Ok(client)
}

/// `connectClient`: bounded retry across app restarts (discovery identity).
pub async fn connect_client() -> Result<Arc<NdjsonRpcClient>, CliError> {
    let mut last: Option<CliError> = None;
    let mut attempted: Option<(Value, Value, Value)> = None;
    for attempt in 0..=CONNECT_RETRY_DELAYS_MS.len() {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(CONNECT_RETRY_DELAYS_MS[attempt - 1])).await;
        }
        let d = match load_discovery() {
            Ok(d) => d,
            Err(e) => {
                last.get_or_insert(e);
                continue;
            }
        };
        let identity = (d["port"].clone(), d["token"].clone(), d["pid"].clone());
        if attempted.as_ref() == Some(&identity) {
            continue;
        }
        attempted = Some(identity);
        match establish(&d).await {
            Ok(c) => return Ok(c),
            Err(e) => {
                let stop = !retryable(&e);
                last = Some(e);
                if stop {
                    break;
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| err("APP_NOT_RUNNING", "Netcatty is not running.")))
}

// ── formatting ──────────────────────────────────────────────────────────

fn s(v: &Value, k: &str) -> String {
    v.get(k).map(|x| match x {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        o => o.to_string(),
    }).unwrap_or_default()
}

fn or_s(v: &Value, k: &str, d: &str) -> String {
    let x = s(v, k);
    if x.is_empty() { d.into() } else { x }
}

pub fn format_env_text(ctx: &Value) -> String {
    let header = format!("Environment: {}\nHosts: {}", or_s(ctx, "environment", "netcatty-terminal"), ctx["hostCount"].as_u64().unwrap_or(0));
    let hosts = ctx["hosts"].as_array().cloned().unwrap_or_default();
    if hosts.is_empty() {
        return format!("{header}\n\nNo hosts are available in the current scope.\n");
    }
    let rows: Vec<String> = hosts
        .iter()
        .map(|h| {
            let name = [s(h, "label"), s(h, "hostname")].into_iter().find(|x| !x.is_empty()).unwrap_or_else(|| "(unnamed)".into());
            let kind = [s(h, "os"), s(h, "deviceType"), s(h, "shellType")].into_iter().find(|x| !x.is_empty()).unwrap_or_else(|| "unknown".into());
            let conn = if h["connected"] == json!(false) { "disconnected" } else { "connected" };
            format!("{}\t{name}\t{}\t{kind}\t{conn}", s(h, "sessionId"), or_s(h, "protocol", "unknown"))
        })
        .collect();
    format!("{header}\n\n{}\n", rows.join("\n"))
}

pub fn format_exec_text(r: &Value) -> String {
    let mut parts = Vec::new();
    let out = s(r, "stdout");
    if !out.is_empty() {
        parts.push(out.strip_suffix('\n').unwrap_or(&out).to_string());
    }
    let errs = s(r, "stderr");
    if !errs.is_empty() {
        parts.push(format!("[stderr] {}", errs.strip_suffix('\n').unwrap_or(&errs)));
    }
    if !r["exitCode"].is_null() && r.get("exitCode").is_some() {
        parts.push(format!("[exit code: {}]", r["exitCode"]));
    }
    if parts.is_empty() {
        parts.push("[no output]".into());
    }
    format!("{}\n", parts.join("\n"))
}

fn format_job_text(r: &Value) -> String {
    let mut lines = vec![format!("Job: {}", s(r, "jobId")), format!("Session: {}", s(r, "sessionId")), format!("Status: {}", or_s(r, "status", "unknown"))];
    let iso = |k: &str| r[k].as_u64().map(|ms| crate::discovery::chrono_like_iso(std::time::UNIX_EPOCH + Duration::from_millis(ms)));
    if let Some(t) = iso("startedAt") {
        lines.push(format!("Started: {t}"));
    }
    if let Some(t) = iso("updatedAt") {
        lines.push(format!("Updated: {t}"));
    }
    if let Some(c) = r["exitCode"].as_i64() {
        lines.push(format!("Exit Code: {c}"));
    }
    let e = s(r, "error");
    if !e.is_empty() {
        lines.push(format!("Error: {e}"));
    }
    let out = s(r, "output");
    if !out.is_empty() {
        lines.push(String::new());
        lines.push(out.strip_suffix('\n').unwrap_or(&out).to_string());
    }
    format!("{}\n", lines.join("\n"))
}

fn format_session_text(h: &Value) -> String {
    format!(
        "Session: {}\nLabel: {}\nHostname: {}\nProtocol: {}\nOS: {}\nUsername: {}\nShell Type: {}\nDevice Type: {}\nConnected: {}\n",
        s(h, "sessionId"), or_s(h, "label", "(unnamed)"), s(h, "hostname"), or_s(h, "protocol", "unknown"), s(h, "os"), s(h, "username"),
        s(h, "shellType"), s(h, "deviceType"), if h["connected"] == json!(false) { "false" } else { "true" }
    )
}

fn format_status_text(st: &Value) -> String {
    let n = |k: &str| if st[k].is_null() { "unknown".into() } else { st[k].to_string() };
    let z = |k: &str| st[k].as_u64().unwrap_or(0);
    format!(
        "Netcatty Tool Status\nPermission Mode: {}\nCommand Timeout (ms): {}\nMax Iterations: {}\nSessions: {}\nScoped Contexts: {}\nActive Executions: {}\nActive Chat Execution Locks: {}\nPending Approvals: {}\nDiscovery File: {}\n",
        or_s(st, "permissionMode", "unknown"), n("commandTimeoutMs"), n("maxIterations"), z("sessionCount"), z("scopedContextCount"),
        z("activeExecutionCount"), z("activeChatExecutionCount"), z("pendingApprovalCount"), or_s(st, "discoveryFilePath", "(none)")
    )
}

fn format_sftp_list_text(entries: &Value) -> String {
    let list = entries.as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        return "No entries.\n".into();
    }
    let rows: Vec<String> = list
        .iter()
        .map(|e| format!("{}\t{}\t{}\t{}\t{}", or_s(e, "type", "file"), s(e, "name"), s(e, "size"), s(e, "permissions"), s(e, "lastModified")))
        .collect();
    format!("Type\tName\tSize\tPermissions\tModified\n{}\n", rows.join("\n"))
}

pub fn sftp_capability_error(host: &Value) -> Option<String> {
    if host["connected"] == json!(false) {
        return Some(format!("Session \"{}\" is not connected. Reconnect it before using SFTP.", s(host, "sessionId")));
    }
    let protocol = s(host, "protocol").to_lowercase();
    let device = s(host, "deviceType").to_lowercase();
    match protocol.as_str() {
        "ssh" => None,
        "local" => Some("SFTP is not available for local sessions. Use normal local filesystem tools instead.".into()),
        "mosh" => Some("SFTP is not available for Mosh sessions. Open an SSH session for this host or use another transfer path.".into()),
        "telnet" => Some("SFTP is not available for Telnet sessions. Open an SSH session for this host or use another transfer path.".into()),
        _ if protocol == "serial" || device == "network" => Some("SFTP is not available for serial or network-device sessions. Use exec/vendor CLI commands or another transfer path.".into()),
        "" => Some("SFTP is only available for connected SSH-backed sessions.".into()),
        p => Some(format!("SFTP is not available for {p} sessions. Open an SSH session for this host or use another transfer path.")),
    }
}

// ── run ─────────────────────────────────────────────────────────────────

struct Out(String);

fn json_out(v: &Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(v).unwrap_or_default())
}

fn with_ok(r: &Value) -> Value {
    let mut out = json!({ "ok": true });
    if let Some(m) = r.as_object() {
        for (k, v) in m {
            out[k] = v.clone();
        }
    }
    out
}

fn require_chat(opts: &Opts, label: &str) -> Result<String, CliError> {
    opts.chat_session_id.clone().ok_or_else(|| err("INVALID_ARGUMENT", format!("Missing chat session for {label}. Set {TOOL_CLI_CHAT_SESSION_ENV_VAR} in the host-launched environment.")))
}

fn scope_params(opts: &Opts) -> Map<String, Value> {
    let mut p = Map::new();
    if let Some(c) = &opts.chat_session_id {
        p.insert("chatSessionId".into(), json!(c));
    }
    if !opts.scoped_session_ids.is_empty() {
        p.insert("scopedSessionIds".into(), json!(opts.scoped_session_ids));
    }
    p
}

fn ensure_ok(r: Value, code: &str, msg: &str) -> Result<Value, CliError> {
    if r["ok"] == json!(false) {
        let c = r["code"].as_str().unwrap_or(code).to_string();
        let m = r["error"].as_str().unwrap_or(msg).to_string();
        return Err(CliError { code: c, message: m, details: Some(r) });
    }
    Ok(r)
}

async fn call(client: &NdjsonRpcClient, method: &str, params: Map<String, Value>) -> Result<Value, CliError> {
    client.call(method, Value::Object(params)).await.map_err(|e| err(&e.code, e.message))
}

fn single_command(opts: &Opts, name: &str) -> Result<String, CliError> {
    match opts.command.len() {
        0 => Err(err("INVALID_ARGUMENT", "Missing command after --.")),
        1 => Ok(opts.command[0].clone()),
        _ => Err(err("INVALID_ARGUMENT", format!("{name} expects exactly one shell-ready command string after --. Preserve quoting in a single argument instead of passing multiple tokens."))),
    }
}

async fn resolve_host(client: &NdjsonRpcClient, opts: &Opts) -> Result<Value, CliError> {
    let ctx = call(client, "netcatty/getContext", scope_params(opts)).await?;
    let Some(sid) = opts.s("sessionId") else {
        return Err(err("INVALID_ARGUMENT", "Missing required --session <id>. Run env --json to inspect available sessions first."));
    };
    ctx["hosts"]
        .as_array()
        .and_then(|h| h.iter().find(|x| x["sessionId"] == json!(sid)).cloned())
        .ok_or_else(|| err("SESSION_NOT_FOUND", format!("Session \"{sid}\" is not available in the current scope.")))
}

async fn run_inner(args: Vec<String>) -> Result<Out, CliError> {
    let (pos, mut opts) = parse_args(&args)?;
    let command = pos.first().cloned().unwrap_or_default();
    let sub = pos.get(1).cloned().unwrap_or_default();
    if command.is_empty() || matches!(command.as_str(), "help" | "--help" | "-h") {
        return Ok(Out(help_text()));
    }
    if command == "capabilities" {
        let status_idx = args.iter().position(|a| a == "--status");
        let status = match status_idx.and_then(|i| args.get(i + 1)) {
            Some(s) if s == "all" => None,
            Some(s) => Some(s.clone()),
            None if status_idx.is_some() => None,
            None => Some(STATUS_IMPLEMENTED.to_string()),
        };
        let caps = list_cli_capabilities(status.as_deref());
        return Ok(Out(if opts.json {
            json_out(&json!({ "ok": true, "capabilities": caps }))
        } else {
            format!("{}\n", caps.iter().map(|c| c.command.join(" ")).collect::<Vec<_>>().join("\n"))
        }));
    }
    read_note_stdin(&pos, &mut opts)?;
    opts.chat_session_id = std::env::var(TOOL_CLI_CHAT_SESSION_ENV_VAR).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let client = connect_client().await?;
    let client = &*client;
    let pj = |v: &Value| json_out(v);
    match command.as_str() {
        "status" => {
            let r = call(client, "netcatty/getStatus", Map::new()).await?;
            return Ok(Out(if opts.json { pj(&r) } else { format_status_text(&r) }));
        }
        "env" => {
            require_chat(&opts, "env")?;
            let r = call(client, "netcatty/getContext", scope_params(&opts)).await?;
            return Ok(Out(if opts.json { pj(&with_ok(&r)) } else { format_env_text(&r) }));
        }
        "session" => {
            require_chat(&opts, "session")?;
            let host = resolve_host(client, &opts).await?;
            return Ok(Out(if opts.json { pj(&json!({ "ok": true, "host": host })) } else { format_session_text(&host) }));
        }
        "exec" | "job-start" => {
            let chat = require_chat(&opts, &command)?;
            let cmd = single_command(&opts, &command)?;
            let host = resolve_host(client, &opts).await?;
            let method = if command == "exec" { "netcatty/exec" } else { "netcatty/jobStart" };
            let mut p = Map::new();
            p.insert("sessionId".into(), host["sessionId"].clone());
            p.insert("command".into(), json!(cmd));
            p.insert("chatSessionId".into(), json!(chat));
            let r = call(client, method, p).await?;
            if command == "exec" {
                if r["ok"] == json!(false) {
                    let code = r["code"].as_str().unwrap_or("EXEC_FAILED").to_string();
                    let msg = r["error"].as_str().unwrap_or("Command failed").to_string();
                    return Err(CliError { code, message: msg, details: Some(r) });
                }
                return Ok(Out(if opts.json { pj(&with_ok(&r)) } else { format_exec_text(&r) }));
            }
            if r["ok"] != json!(true) {
                return Err(err(r["code"].as_str().unwrap_or("JOB_START_FAILED"), r["error"].as_str().unwrap_or("Failed to start long-running command")));
            }
            return Ok(Out(if opts.json { pj(&r) } else { format_job_text(&r) }));
        }
        "job-poll" | "job-stop" => {
            let chat = require_chat(&opts, &command)?;
            let Some(job) = opts.s("jobId").or_else(|| opts.values.get("jobId").filter(|v| !v.is_null()).map(|v| v.to_string())) else {
                return Err(err("INVALID_ARGUMENT", format!("Missing required --job <id> for {command}.")));
            };
            let mut p = scope_params(&opts);
            p.insert("jobId".into(), json!(job));
            p.insert("chatSessionId".into(), json!(chat));
            let (method, code, msg) = if command == "job-poll" {
                let off = opts.values.get("offset").and_then(Value::as_f64).filter(|v| *v >= 0.0).unwrap_or(0.0);
                p.insert("offset".into(), json!(off as u64));
                ("netcatty/jobPoll", "JOB_POLL_FAILED", "Failed to poll long-running command")
            } else {
                ("netcatty/jobStop", "JOB_STOP_FAILED", "Failed to stop long-running command")
            };
            let r = call(client, method, p).await?;
            if r["ok"] != json!(true) {
                return Err(err(r["code"].as_str().unwrap_or(code), r["error"].as_str().unwrap_or(msg)));
            }
            return Ok(Out(if opts.json { pj(&r) } else { format_job_text(&r) }));
        }
        "sftp" => {
            let chat = require_chat(&opts, "sftp")?;
            if sub.is_empty() || sub == "help" {
                return Ok(Out(help_text()));
            }
            let host = resolve_host(client, &opts).await?;
            if let Some(e) = sftp_capability_error(&host) {
                return Err(err("SFTP_UNSUPPORTED_SESSION", e));
            }
            let mut p = scope_params(&opts);
            p.insert("sessionId".into(), host["sessionId"].clone());
            p.insert("chatSessionId".into(), json!(chat));
            let remote = opts.s("remotePath");
            if let Some(r) = &remote {
                p.insert("remotePath".into(), json!(r));
                p.insert("path".into(), json!(r));
            }
            if let Some(l) = opts.s("localPath") {
                p.insert("localPath".into(), json!(crate::host::absolutize(&l)));
            }
            for (k, key) in [("oldRemotePath", "oldPath"), ("newRemotePath", "newPath"), ("content", "content"), ("mode", "mode")] {
                if let Some(v) = opts.s(k) {
                    p.insert(key.into(), json!(v));
                }
            }
            if let Some(e) = &opts.encoding {
                p.insert("encoding".into(), json!(e));
            }
            let need = |c: bool, m: &str| if c { Ok(()) } else { Err(err("INVALID_ARGUMENT", m)) };
            let rp = remote.clone().unwrap_or_default();
            let (method, code, msg, text): (&str, &str, &str, Box<dyn Fn(&Value) -> String>) = match sub.as_str() {
                "list" => {
                    need(remote.is_some(), "Missing required --remote-path <remote-path> for sftp list.")?;
                    ("netcatty/sftp/list", "SFTP_LIST_FAILED", "Failed to list remote directory", Box::new(|r| format_sftp_list_text(&r["entries"])))
                }
                "read" => {
                    need(remote.is_some(), "Missing required --remote-path <remote-path> for sftp read.")?;
                    ("netcatty/sftp/read", "SFTP_READ_FAILED", "Failed to read remote file", Box::new(|r| {
                        let c = s(r, "content");
                        if c.ends_with('\n') { c } else { format!("{c}\n") }
                    }))
                }
                "write" => {
                    need(remote.is_some(), "Missing required --remote-path <remote-path> for sftp write.")?;
                    need(opts.s("content").is_some(), "Missing required --content <text> for sftp write.")?;
                    let rp2 = rp.clone();
                    ("netcatty/sftp/write", "SFTP_WRITE_FAILED", "Failed to write remote file", Box::new(move |_| format!("Wrote {rp2}.\n")))
                }
                "download" | "upload" => {
                    let local = opts.s("localPath");
                    let label = if sub == "download" { "Missing required --remote-path and --local-path for sftp download." } else { "Missing required --local-path and --remote-path for sftp upload." };
                    need(remote.is_some() && local.is_some(), label)?;
                    let (rp2, lp) = (rp.clone(), local.unwrap_or_default());
                    if sub == "download" {
                        ("netcatty/sftp/download", "SFTP_DOWNLOAD_FAILED", "Failed to download remote file", Box::new(move |_| format!("Downloaded {rp2} -> {lp}.\n")))
                    } else {
                        ("netcatty/sftp/upload", "SFTP_UPLOAD_FAILED", "Failed to upload local file", Box::new(move |_| format!("Uploaded {lp} -> {rp2}.\n")))
                    }
                }
                "mkdir" | "delete" | "stat" => {
                    need(remote.is_some(), &format!("Missing required --remote-path <remote-path> for sftp {sub}."))?;
                    let rp2 = rp.clone();
                    match sub.as_str() {
                        "mkdir" => ("netcatty/sftp/mkdir", "SFTP_MKDIR_FAILED", "Failed to create remote directory", Box::new(move |_| format!("Created {rp2}.\n"))),
                        "delete" => ("netcatty/sftp/delete", "SFTP_DELETE_FAILED", "Failed to delete remote path", Box::new(move |_| format!("Deleted {rp2}.\n"))),
                        _ => ("netcatty/sftp/stat", "SFTP_STAT_FAILED", "Failed to stat remote path", Box::new(|r| json_out(&r["stat"]))),
                    }
                }
                "rename" => {
                    let (o, n) = (opts.s("oldRemotePath"), opts.s("newRemotePath"));
                    need(o.is_some() && n.is_some(), "Missing required --old-remote-path and --new-remote-path for sftp rename.")?;
                    let (o, n) = (o.unwrap(), n.unwrap());
                    ("netcatty/sftp/rename", "SFTP_RENAME_FAILED", "Failed to rename remote path", Box::new(move |_| format!("Renamed {o} -> {n}.\n")))
                }
                "chmod" => {
                    let m = opts.s("mode");
                    need(remote.is_some() && m.is_some(), "Missing required --remote-path and --mode for sftp chmod.")?;
                    let (rp2, m) = (rp.clone(), m.unwrap());
                    ("netcatty/sftp/chmod", "SFTP_CHMOD_FAILED", "Failed to chmod remote path", Box::new(move |_| format!("Changed mode of {rp2} to {m}.\n")))
                }
                "home" => ("netcatty/sftp/home", "SFTP_HOME_FAILED", "Failed to resolve remote home directory", Box::new(|r| format!("{}\n", s(r, "homeDir")))),
                _ => return Err(err("INVALID_ARGUMENT", format!("Unknown command: {}", pos.join(" ")))),
            };
            let r = ensure_ok(call(client, method, p).await?, code, msg)?;
            return Ok(Out(if opts.json { pj(&r) } else { text(&r) }));
        }
        "cancel" | "resume" => {
            let chat = require_chat(&opts, &command)?;
            let cancelled = command == "cancel";
            let mut p = Map::new();
            p.insert("chatSessionId".into(), json!(chat));
            p.insert("cancelled".into(), json!(cancelled));
            let r = call(client, "netcatty/setCancelled", p).await?;
            return Ok(Out(if opts.json {
                pj(&with_ok(&r))
            } else {
                format!("Chat session {chat} {}.\n", if cancelled { "cancelled" } else { "resumed" })
            }));
        }
        _ => {}
    }
    let Some(cap) = capability_by_cli_command(&pos) else {
        return Err(err("INVALID_ARGUMENT", format!("Unknown command: {}", pos.join(" "))));
    };
    let rpc = cli_rpc_method(&pos).ok_or_else(|| err("INVALID_ARGUMENT", format!("No RPC mapping for command: {}", pos.join(" "))))?;
    if cap.policy.requires_chat_session {
        require_chat(&opts, &pos.join(" "))?;
    }
    if let Some(index) = opts.attachment_index.clone() {
        if cap.id != "vault.note.import" {
            return Err(err("INVALID_ARGUMENT", "--attachment-index is only supported for notes import."));
        }
        read_note_from_attachment(client, &mut opts, &index).await?;
    }
    let mut params = build_catalog_cli_params(&cap.id, &opts.values).map_err(|(c, m)| err(&c, m))?;
    if cap.id == "vault.note.import" {
        validate_note_import_size(&params)?;
    }
    if cap.id.starts_with("vault.note.") && Value::Object(params.clone()).to_string().len() > MAX_NOTE_RPC_BYTES {
        return Err(err("INVALID_ARGUMENT", "Note input exceeds the 8 MiB CLI request limit."));
    }
    params.extend(scope_params(&opts));
    let r = ensure_ok(call(client, &rpc, params).await?, "CAPABILITY_RPC_FAILED", &format!("Failed to execute {}", cap.id))?;
    Ok(Out(if opts.json { pj(&with_ok(&r)) } else { pj(&r) }))
}

async fn read_note_from_attachment(client: &NdjsonRpcClient, opts: &mut Opts, index: &str) -> Result<(), CliError> {
    if opts.values.get("content").is_some_and(|v| !v.is_null()) || opts.values.get("documents").is_some_and(|v| !v.is_null()) || opts.content_stdin || opts.documents_stdin {
        return Err(err("INVALID_ARGUMENT", "Do not combine --attachment-index with other note content flags."));
    }
    let Ok(i) = index.parse::<usize>().map_err(|_| ()).and_then(|i| if index.chars().all(|c| c.is_ascii_digit()) { Ok(i) } else { Err(()) }) else {
        return Err(err("INVALID_ARGUMENT", "--attachment-index must be a non-negative integer from attachment list."));
    };
    let chat = require_chat(opts, "notes import --attachment-index")?;
    let mut p = Map::new();
    p.insert("chatSessionId".into(), json!(chat));
    let listed = call(client, "netcatty/listAttachments", p.clone()).await?;
    if listed["ok"] != json!(true) {
        return Err(err("ATTACHMENT_READ_FAILED", listed["error"].as_str().unwrap_or("Could not list chat attachments.")));
    }
    let a = listed["attachments"][i].clone();
    let name = s(&a, "filename").to_lowercase();
    if a.is_null() || !(name.ends_with(".md") || name.ends_with(".markdown")) {
        return Err(err("INVALID_ARGUMENT", "The selected attachment must be a registered Markdown file."));
    }
    if a["sizeBytes"].as_u64().is_some_and(|n| n > MAX_NOTE_ATTACHMENT_BYTES) {
        return Err(err("INVALID_ARGUMENT", "The selected Markdown file exceeds the 1 MiB attachment limit."));
    }
    p.insert("maxBytes".into(), json!(MAX_NOTE_ATTACHMENT_BYTES));
    match a["filePath"].as_str().filter(|s| !s.is_empty()) {
        Some(fp) => p.insert("filePath".into(), json!(fp)),
        None => p.insert("filename".into(), a["filename"].clone()),
    };
    let read = call(client, "netcatty/readAttachment", p).await?;
    let Some(text) = read["text"].as_str().filter(|_| read["ok"] == json!(true)) else {
        return Err(err("ATTACHMENT_READ_FAILED", read["error"].as_str().unwrap_or("The selected Markdown attachment could not be read.")));
    };
    if text.len() as u64 > MAX_NOTE_ATTACHMENT_BYTES {
        return Err(err("INVALID_ARGUMENT", "The selected Markdown file exceeds the 1 MiB attachment limit."));
    }
    opts.values.insert("fileName".into(), read["filename"].clone());
    opts.values.insert("content".into(), json!(text));
    Ok(())
}

fn validate_note_import_size(params: &Map<String, Value>) -> Result<(), CliError> {
    let too_big = || err("INVALID_ARGUMENT", "A Markdown document exceeds the 512,000 character import limit.");
    if params.get("content").and_then(Value::as_str).is_some_and(|c| c.encode_utf16().count() > MAX_NOTE_IMPORT_CHARS) {
        return Err(too_big());
    }
    if let Some(d) = params.get("documents").and_then(Value::as_str) {
        let docs: Value = serde_json::from_str(d).map_err(|_| err("INVALID_ARGUMENT", "--documents must be valid JSON."))?;
        let Some(list) = docs.as_array() else {
            return Err(err("INVALID_ARGUMENT", "--documents must be a JSON array."));
        };
        if list.iter().any(|e| e["content"].as_str().is_some_and(|c| c.encode_utf16().count() > MAX_NOTE_IMPORT_CHARS)) {
            return Err(too_big());
        }
    }
    Ok(())
}

/// Run the CLI; prints to stdout / stderr and returns the exit code.
pub async fn run(args: Vec<String>) -> i32 {
    match run_inner(args).await {
        Ok(Out(text)) => {
            let mut out = std::io::stdout();
            let _ = out.write_all(text.as_bytes());
            let _ = out.flush();
            0
        }
        Err(e) => {
            let mut payload = json!({ "ok": false, "error": { "code": e.code, "message": e.message } });
            if let Some(Value::Object(d)) = e.details {
                for (k, v) in d {
                    payload["error"][k] = v;
                }
            }
            eprintln!("{}", serde_json::to_string_pretty(&payload).unwrap_or_default());
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_flags_and_rejects_chat_session() {
        let (pos, opts) = parse_args(&a(&["vault", "host", "open", "--host-id", "host-1", "--new-tab", "--workspace-id", "current"])).unwrap();
        assert_eq!(pos, a(&["vault", "host", "open"]));
        let p = build_catalog_cli_params("vault.host.open", &opts.values).unwrap();
        assert_eq!(Value::Object(p), json!({ "hostId": "host-1", "newTab": "true", "workspaceId": "current" }));
        assert!(parse_args(&a(&["vault", "host", "open", "--workspace-id"])).is_err());
        let e = parse_args(&a(&["env", "--chat-session", "x"])).unwrap_err();
        assert_eq!(e.code, "INVALID_ARGUMENT");
        assert!(e.message.contains("not a CLI flag"));
        let (pos, opts) = parse_args(&a(&["attachment", "read", "--filename", "hosts.csv", "--json"])).unwrap();
        assert_eq!(pos, a(&["attachment", "read"]));
        assert!(opts.json);
        assert_eq!(opts.s("filename").as_deref(), Some("hosts.csv"));
        let (_, opts) = parse_args(&a(&["exec", "--session", "s", "--", "ls -la"])).unwrap();
        assert_eq!(opts.command, a(&["ls -la"]));
        let (_, opts) = parse_args(&a(&["snippets", "update", "--snippet-id", "s1", "--multi-line-run-mode", "lineDelay"])).unwrap();
        assert_eq!(opts.s("multiLineRunMode").as_deref(), Some("lineDelay"));
    }

    #[test]
    fn formatting() {
        assert_eq!(format_exec_text(&json!({ "stdout": "hi\n", "exitCode": 0 })), "hi\n[exit code: 0]\n");
        assert_eq!(format_exec_text(&json!({})), "[no output]\n");
        let env = format_env_text(&json!({ "hostCount": 1, "hosts": [{ "sessionId": "s", "label": "web", "protocol": "ssh", "connected": false }] }));
        assert!(env.contains("s\tweb\tssh\tunknown\tdisconnected"));
        assert!(sftp_capability_error(&json!({ "protocol": "ssh" })).is_none());
        assert!(sftp_capability_error(&json!({ "protocol": "local" })).unwrap().contains("local sessions"));
        assert!(validate_note_import_size(&json!({ "documents": "{}" }).as_object().unwrap().clone()).is_err());
        assert!(help_text().contains("  netcatty-tool-cli exec"));
    }

    #[tokio::test]
    async fn capabilities_works_without_app_and_missing_discovery_is_app_not_running() {
        let out = run_inner(a(&["capabilities", "--json"])).await.ok().unwrap().0;
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v["capabilities"].as_array().unwrap().iter().any(|c| c["id"] == "terminal.execute"));
        std::env::set_var(TOOL_CLI_DISCOVERY_ENV_VAR, "/nonexistent/netcatty/discovery.json");
        let e = connect_client().await.err().unwrap();
        assert_eq!(e.code, "APP_NOT_RUNNING");
        std::env::remove_var(TOOL_CLI_DISCOVERY_ENV_VAR);
    }
}

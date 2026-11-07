//! tmux management — port of `electron/bridges/systemManager/tmuxOps.cjs`
//! and `tmuxEnv.cjs` plus the tmux wrappers of `systemManagerBridge.cjs`.
//!
//! Every remote script is tried through three wrappers (`exec sh -c`,
//! `bash -lc`, raw) because vendor shells and minimal hosts differ in which
//! one prints anything; tmux itself is tried on the preferred socket, the
//! default socket and every socket found under `$TMUX_TMPDIR`. The detected
//! environment is cached per terminal session for 60 s.

pub mod env;
mod js;
pub mod parse;

use crate::exec::{now_ms, sh_quote, ExecRequest, ExecResult, SessionExec};
use env::{
    build_tmux_invocation, get_list_sessions_format, normalize_exec_result,
    parse_detect_script_output, parse_list_output, parse_tmux_version_string, wrap_login_shell,
    wrap_sh_exec, TmuxVersion, TMUX_DETECT_SCRIPT,
};
use parse::{
    filter_windows_for_session, is_no_tmux_server_message, parse_tmux_clients, parse_tmux_panes,
    parse_tmux_windows, parse_tmux_windows_all, parse_tmux_windows_all_plain,
};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Mutex;

const ENV_TTL_MS: i64 = 60_000;

pub const TMUX_LIST_WINDOWS_FMT: &str =
    r"#{window_index}\t#{window_name}\t#{window_panes}\t#{window_active}\t#{window_layout}";
pub const TMUX_LIST_ALL_WINDOWS_FMT: &str = r"#{session_name}\t#{window_index}\t#{window_name}\t#{window_panes}\t#{window_active}\t#{window_layout}";
pub const TMUX_LIST_PANES_FMT: &str = r"#{pane_index}\t#{pane_title}\t#{pane_current_command}\t#{pane_active}\t#{pane_pid}\t#{pane_width}\t#{pane_height}";
pub const TMUX_LIST_CLIENTS_FMT: &str =
    r"#{client_name}\t#{client_tty}\t#{client_activity}\t#{client_session}";

/// tmux does not expand `\t` inside `-F`; route the format through the
/// remote `printf` so separators become real tabs.
pub fn tmux_format_arg(format: &str) -> String {
    format!("\"$(printf '{format}')\"")
}

/// `'session'`, `'session':W` or `'session':W.P`.
pub fn tmux_target(session_name: &str, window: Option<&Value>, pane: Option<&Value>) -> String {
    let session_ref = sh_quote(session_name);
    let Some(window) = window.filter(|v| !v.is_null()) else {
        return session_ref;
    };
    let win = js::num_string(js::value_number(window));
    match pane.filter(|v| !v.is_null()) {
        None => format!("{session_ref}:{win}"),
        Some(pane) => format!(
            "{session_ref}:{win}.{}",
            js::num_string(js::value_number(pane))
        ),
    }
}

/// Trimmed, non-empty, at most 64 characters.
pub fn sanitize_new_session_name(name: Option<&Value>) -> Option<String> {
    let trimmed = js::string_or_empty(name).trim().to_string();
    (!trimmed.is_empty()).then(|| js::slice(&trimmed, 64))
}

/// Detected tmux environment of one terminal session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TmuxEnv {
    pub version: TmuxVersion,
    pub binary: String,
    pub sockets: Vec<String>,
    pub preferred_socket: Option<String>,
    pub detected_at: i64,
}

impl TmuxEnv {
    /// Preferred socket first, then the default socket (`None`), then the
    /// detected sockets.
    pub fn socket_order(&self) -> Vec<Option<String>> {
        let mut order: Vec<Option<String>> = Vec::new();
        if let Some(p) = &self.preferred_socket {
            order.push(Some(p.clone()));
        }
        order.push(None);
        for socket in &self.sockets {
            let candidate = Some(socket.clone());
            if !socket.is_empty() && !order.contains(&candidate) {
                order.push(candidate);
            }
        }
        order
    }
}

fn sockets_json(order: &[Option<String>]) -> Value {
    Value::Array(
        order
            .iter()
            .map(|s| s.as_ref().map_or(Value::Null, |s| json!(s)))
            .collect(),
    )
}

fn session_id_of(payload: &Value) -> Option<String> {
    let id = match payload {
        Value::String(s) => Some(s.clone()),
        other => other.get("sessionId").map(|v| js::string_or_empty(Some(v))),
    }?;
    (!id.is_empty()).then_some(id)
}

fn fail(error: impl Into<String>) -> Value {
    json!({"success": false, "error": error.into()})
}

/// `{ success: false, error: a || b }` — key omitted when both are empty.
fn fail_either(primary: Option<&str>, secondary: &str) -> Value {
    let error = primary
        .filter(|e| !e.is_empty())
        .unwrap_or(secondary)
        .to_string();
    if error.is_empty() {
        json!({"success": false})
    } else {
        fail(error)
    }
}

/// `String(result.stdout || result.stderr || "").trim()`.
fn output_of(result: &ExecResult) -> String {
    if !result.stdout.is_empty() {
        result.stdout.trim().to_string()
    } else {
        result.stderr.trim().to_string()
    }
}

/// `(result.error || result.stderr || fallback).slice(0, 240)`.
fn short_error(result: &ExecResult, fallback: &str) -> String {
    let raw = result
        .error
        .as_deref()
        .filter(|e| !e.is_empty())
        .or_else(|| (!result.stderr.is_empty()).then_some(result.stderr.as_str()))
        .unwrap_or(fallback);
    js::slice(raw, 240)
}

fn tail(items: &[String], n: usize) -> Vec<String> {
    items[items.len().saturating_sub(n)..].to_vec()
}

/// Per-session tmux operations with the environment cache.
#[derive(Default)]
pub struct TmuxOps {
    env_cache: Mutex<HashMap<String, TmuxEnv>>,
}

impl TmuxOps {
    /// Drop the cached environment of a closed terminal session.
    pub fn forget(&self, session_id: &str) {
        self.env_cache.lock().unwrap().remove(session_id);
    }

    fn cached(&self, session_id: &str) -> Option<TmuxEnv> {
        self.env_cache.lock().unwrap().get(session_id).cloned()
    }

    fn store(&self, session_id: &str, env: TmuxEnv) {
        self.env_cache
            .lock()
            .unwrap()
            .insert(session_id.to_string(), env);
    }

    /// Run `script` through `exec sh -c`, `bash -lc`, then raw. Read
    /// commands retry when the output is empty (a wrapper swallowed it);
    /// mutating commands must not (they would run twice).
    async fn exec_shell(
        exec: &dyn SessionExec,
        script: &str,
        timeout_ms: u64,
        retry_on_empty_output: bool,
    ) -> ExecResult {
        let attempts = [
            wrap_sh_exec(script),
            wrap_login_shell(script),
            script.to_string(),
        ];
        let mut last = ExecResult::fail("No exec result");
        for cmd in attempts {
            last = normalize_exec_result(exec.exec(ExecRequest::new(cmd, timeout_ms)).await);
            if last.success && (!retry_on_empty_output || !last.stdout.trim().is_empty()) {
                return last;
            }
        }
        last
    }

    async fn detect_env(&self, exec: &dyn SessionExec, session_id: &str, force: bool) -> TmuxEnv {
        let cached = self.cached(session_id);
        if let Some(env) = &cached {
            if !force && now_ms() - env.detected_at < ENV_TTL_MS {
                return env.clone();
            }
        }
        let mut env = TmuxEnv {
            binary: "tmux".to_string(),
            preferred_socket: cached.and_then(|c| c.preferred_socket),
            detected_at: now_ms(),
            ..Default::default()
        };

        let version = Self::exec_shell(exec, "tmux -V 2>&1", 5000, true).await;
        if version.success && !version.stdout.is_empty() {
            env.version = parse_tmux_version_string(&version.stdout);
        }

        let bin = Self::exec_shell(
            exec,
            "command -v tmux 2>/dev/null || which tmux 2>/dev/null",
            5000,
            true,
        )
        .await;
        if bin.success && !bin.stdout.is_empty() {
            if let Some(path) = bin
                .stdout
                .split('\n')
                .map(str::trim)
                .find(|l| !l.is_empty())
            {
                env.binary = path.to_string();
            }
        }

        let sockets = Self::exec_shell(exec, TMUX_DETECT_SCRIPT, 8000, true).await;
        if sockets.success {
            let parsed = parse_detect_script_output(&sockets.stdout);
            if !parsed.version.raw.is_empty() {
                env.version = parsed.version;
            }
            if !parsed.binary.is_empty() {
                env.binary = parsed.binary;
            }
            env.sockets = parsed.sockets;
        }

        self.store(session_id, env.clone());
        env
    }

    fn remember_preferred_socket(&self, session_id: &str, env: &TmuxEnv, socket: Option<&str>) {
        let next = TmuxEnv {
            preferred_socket: socket
                .map(str::to_string)
                .or_else(|| env.preferred_socket.clone()),
            detected_at: now_ms(),
            ..env.clone()
        };
        self.store(session_id, next);
    }

    /// Run `tmux <args>` on each socket until one answers.
    async fn exec_tmux(
        &self,
        exec: &dyn SessionExec,
        session_id: &str,
        args: &str,
        timeout_ms: u64,
        retry_on_empty_output: bool,
    ) -> ExecResult {
        let env = self.detect_env(exec, session_id, false).await;
        let mut last: Option<ExecResult> = None;
        for socket in env.socket_order() {
            let cmd = build_tmux_invocation(&env.binary, socket.as_deref(), args);
            let result = Self::exec_shell(exec, &cmd, timeout_ms, retry_on_empty_output).await;
            let ok = result.success;
            let combined = format!("{}\n{}", result.stderr, result.stdout);
            let code = result.code;
            let has_output = !result.stdout.trim().is_empty();
            last = Some(result);
            if !ok || is_no_tmux_server_message(&combined, code) {
                continue;
            }
            if has_output || code == Some(0) {
                if has_output {
                    self.remember_preferred_socket(session_id, &env, socket.as_deref());
                }
                return last.unwrap();
            }
        }
        last.unwrap_or_else(|| ExecResult::fail("tmux command failed"))
    }

    /// `exec_tmux` without empty-output retries; a non-zero exit becomes a
    /// failure carrying tmux's message.
    async fn run_tmux(&self, exec: &dyn SessionExec, session_id: &str, args: &str) -> ExecResult {
        let result = self.exec_tmux(exec, session_id, args, 8000, false).await;
        if !result.success {
            return result;
        }
        match result.code {
            Some(code) if code != 0 => {
                let text = if !result.stderr.is_empty() {
                    result.stderr.as_str()
                } else {
                    result.stdout.as_str()
                };
                let message = text.trim();
                ExecResult {
                    success: false,
                    error: Some(if message.is_empty() {
                        format!("tmux exited with code {code}")
                    } else {
                        message.to_string()
                    }),
                    stderr: result.stderr.clone(),
                    ..Default::default()
                }
            }
            _ => result,
        }
    }

    /// `listTmuxSessions(sessionId)` (payload `{sessionId}` or the id string).
    pub async fn list_sessions(&self, exec: &dyn SessionExec, payload: &Value) -> Value {
        let Some(session_id) = session_id_of(payload) else {
            return fail("Missing sessionId");
        };
        let env = self.detect_env(exec, &session_id, true).await;
        let mut last_output = String::new();
        let with_version = |mut v: Value| {
            if !env.version.raw.is_empty() {
                v["tmuxVersion"] = json!(env.version.raw);
            }
            v
        };

        for socket in env.socket_order() {
            let inv = |args: &str| build_tmux_invocation(&env.binary, socket.as_deref(), args);
            let mut cmds = vec![inv("list-sessions 2>&1"), inv("list-sessions")];
            if let Some(format) = get_list_sessions_format(&env.version) {
                cmds.push(inv(&format!(
                    "list-sessions -F {}",
                    tmux_format_arg(&format)
                )));
            }
            cmds.push(inv("list-sessions -F '#{session_name}'"));
            for cmd in cmds {
                let result = Self::exec_shell(exec, &cmd, 8000, true).await;
                let output = output_of(&result);
                if !output.is_empty() {
                    last_output = output.clone();
                }
                if !result.success || is_no_tmux_server_message(&output, result.code) {
                    continue;
                }
                let sessions = parse_list_output(&output);
                if !sessions.is_empty() {
                    self.remember_preferred_socket(&session_id, &env, socket.as_deref());
                    return with_version(json!({"success": true, "sessions": sessions}));
                }
            }
        }

        if is_no_tmux_server_message(&last_output, Some(1)) {
            return with_version(json!({"success": true, "sessions": []}));
        }

        let mut diag: Vec<String> = vec![if env.version.raw.is_empty() {
            "tmux version unknown".to_string()
        } else {
            env.version.raw.clone()
        }];
        if !env.binary.is_empty() {
            diag.push(format!("bin={}", env.binary));
        }
        diag.push(if env.sockets.is_empty() {
            "sockets=none".to_string()
        } else {
            format!("sockets={}", env.sockets.join(","))
        });
        diag.push(if last_output.is_empty() {
            "last=empty".to_string()
        } else {
            format!("last={}", js::slice(&last_output, 240))
        });
        with_version(fail(format!(
            "Cannot list tmux sessions ({})",
            diag.join("; ")
        )))
    }

    /// `createTmuxSession({sessionId, name, command?})`.
    pub async fn create_session(&self, exec: &dyn SessionExec, payload: &Value) -> Value {
        let session_id = js::string_or_empty(payload.get("sessionId"));
        if session_id.is_empty() || !js::truthy(payload.get("name")) {
            return fail("Missing sessionId or name");
        }
        let Some(safe_name) = sanitize_new_session_name(payload.get("name")) else {
            return fail("Invalid session name");
        };

        self.forget(&session_id);
        let result = self
            .run_tmux(
                exec,
                &session_id,
                &format!("new-session -d -s {}", sh_quote(&safe_name)),
            )
            .await;
        if !result.success {
            return fail_either(result.error.as_deref(), &result.stderr);
        }
        let command = js::string_or_empty(payload.get("command"))
            .trim()
            .to_string();
        if !command.is_empty() {
            let sent = self
                .run_tmux(
                    exec,
                    &session_id,
                    &format!(
                        "send-keys -t {} {} C-m",
                        sh_quote(&safe_name),
                        sh_quote(&command)
                    ),
                )
                .await;
            if !sent.success {
                return fail_either(sent.error.as_deref(), &sent.stderr);
            }
        }
        self.forget(&session_id);
        json!({"success": true, "name": safe_name})
    }

    /// Walk sockets × command variants until `parse` yields rows.
    #[allow(clippy::too_many_arguments)]
    async fn query_rows(
        &self,
        exec: &dyn SessionExec,
        session_id: &str,
        env: &TmuxEnv,
        commands: impl Fn(Option<&str>) -> Vec<String>,
        parse: impl Fn(&str, &str) -> Vec<Value>,
        initial_error: &str,
        rows_key: &str,
    ) -> Value {
        let sockets = env.socket_order();
        let mut last_output = String::new();
        let mut last_error = initial_error.to_string();
        let mut tried: Vec<String> = Vec::new();

        for socket in &sockets {
            for cmd in commands(socket.as_deref()) {
                tried.push(cmd.clone());
                let result = Self::exec_shell(exec, &cmd, 8000, true).await;
                let output = output_of(&result);
                if !output.is_empty() {
                    last_output = js::slice(&output, 500);
                }
                if !result.success && output.is_empty() {
                    last_error = short_error(&result, &last_error);
                    continue;
                }
                if is_no_tmux_server_message(&output, result.code) {
                    continue;
                }
                let rows = parse(&cmd, &output);
                if !rows.is_empty() {
                    self.remember_preferred_socket(session_id, env, socket.as_deref());
                    let mut out = Map::new();
                    out.insert("success".into(), json!(true));
                    out.insert(rows_key.into(), Value::Array(rows));
                    return Value::Object(out);
                }
                if !output.is_empty() {
                    last_error = js::slice(&output, 240);
                }
            }
        }

        json!({
            "success": false,
            "error": last_error,
            "debug": {
                "lastOutput": last_output,
                "tried": tail(&tried, 8),
                "sockets": sockets_json(&sockets),
            },
        })
    }

    /// `listTmuxWindows({sessionId, sessionName})`.
    pub async fn list_windows(&self, exec: &dyn SessionExec, payload: &Value) -> Value {
        let session_id = js::string_or_empty(payload.get("sessionId"));
        if session_id.is_empty() || !js::truthy(payload.get("sessionName")) {
            return fail("Missing params");
        }
        let name = js::string_or_empty(payload.get("sessionName"))
            .trim()
            .to_string();
        let target = tmux_target(&name, None, None);
        let target_exact = tmux_target(&format!("={name}"), None, None);
        let env = self.detect_env(exec, &session_id, true).await;
        let windows_fmt = tmux_format_arg(TMUX_LIST_WINDOWS_FMT);
        let all_fmt = tmux_format_arg(TMUX_LIST_ALL_WINDOWS_FMT);

        let commands = |socket: Option<&str>| {
            let inv = |args: String| build_tmux_invocation(&env.binary, socket, &args);
            vec![
                inv(format!("list-windows -t {target} -F {windows_fmt} 2>&1")),
                inv(format!("list-windows -t {target} 2>&1")),
                inv(format!(
                    "list-windows -t {target_exact} -F {windows_fmt} 2>&1"
                )),
                inv(format!("list-windows -t {target_exact} 2>&1")),
                inv(format!("list-windows -a -F {all_fmt} 2>&1")),
                inv("list-windows -a 2>&1".to_string()),
                inv(format!("list-windows -t {target} -F {windows_fmt}")),
                inv(format!("list-windows -t {target}")),
            ]
        };
        let parse = |cmd: &str, output: &str| {
            if cmd.contains("list-windows -a") {
                let formatted = parse_tmux_windows_all(output);
                if formatted.is_empty() {
                    parse_tmux_windows_all_plain(output, &name)
                } else {
                    filter_windows_for_session(formatted, &name)
                }
            } else {
                parse_tmux_windows(output)
            }
        };
        self.query_rows(
            exec,
            &session_id,
            &env,
            commands,
            parse,
            "Cannot list tmux windows",
            "windows",
        )
        .await
    }

    /// `listTmuxPanes({sessionId, sessionName, windowIndex})`.
    pub async fn list_panes(&self, exec: &dyn SessionExec, payload: &Value) -> Value {
        let session_id = js::string_or_empty(payload.get("sessionId"));
        let window = payload.get("windowIndex");
        if session_id.is_empty() || !js::truthy(payload.get("sessionName")) || window.is_none() {
            return fail("Missing params");
        }
        let name = js::string_or_empty(payload.get("sessionName"))
            .trim()
            .to_string();
        let target = tmux_target(&name, window, None);
        let env = self.detect_env(exec, &session_id, true).await;
        let fmt = tmux_format_arg(TMUX_LIST_PANES_FMT);

        let commands = |socket: Option<&str>| {
            let inv = |args: String| build_tmux_invocation(&env.binary, socket, &args);
            vec![
                inv(format!("list-panes -t {target} -F {fmt} 2>&1")),
                inv(format!("list-panes -t {target} 2>&1")),
                inv(format!("list-panes -t {target} -F {fmt}")),
                inv(format!("list-panes -t {target}")),
            ]
        };
        self.query_rows(
            exec,
            &session_id,
            &env,
            commands,
            |_, output| parse_tmux_panes(output),
            "Cannot list tmux panes",
            "panes",
        )
        .await
    }

    /// `listTmuxClients({sessionId, sessionName?})`.
    pub async fn list_clients(&self, exec: &dyn SessionExec, payload: &Value) -> Value {
        let session_id = js::string_or_empty(payload.get("sessionId"));
        if session_id.is_empty() {
            return fail("Missing sessionId");
        }
        let result = self
            .run_tmux(
                exec,
                &session_id,
                &format!("list-clients -F {}", tmux_format_arg(TMUX_LIST_CLIENTS_FMT)),
            )
            .await;
        if !result.success {
            return match result.error {
                Some(error) => fail(error),
                None => json!({"success": false}),
            };
        }
        let filter = js::string_or_empty(payload.get("sessionName"));
        json!({
            "success": true,
            "clients": parse_tmux_clients(&result.stdout, Some(filter.as_str()).filter(|s| !s.is_empty())),
        })
    }

    /// `tmuxAction({sessionId, action, ...})`, mapped to the bridge reply
    /// `{success}` / `{success: false, error}`.
    pub async fn action(&self, exec: &dyn SessionExec, payload: &Value) -> Value {
        let result = match self.action_args(payload) {
            Err(reply) => return reply,
            Ok((session_id, args)) => self.run_tmux(exec, &session_id, &args).await,
        };
        if result.success {
            return json!({"success": true});
        }
        match result.error.filter(|e| !e.is_empty()) {
            Some(error) => fail(error),
            None => fail(if result.stderr.is_empty() {
                "tmux command failed".to_string()
            } else {
                result.stderr
            }),
        }
    }

    /// Validate an action payload and build its tmux arguments.
    fn action_args(&self, payload: &Value) -> Result<(String, String), Value> {
        let session_id = js::string_or_empty(payload.get("sessionId"));
        let action = payload.get("action");
        if session_id.is_empty() || !js::truthy(action) {
            return Err(fail("Missing sessionId or action"));
        }
        let get = |key: &str| payload.get(key);
        let session_name = get("sessionName");
        let has_session = js::truthy(session_name);
        let name = || session_name.map(js::string).unwrap_or_default();
        let window = get("windowIndex");
        let pane = get("paneIndex");
        let missing = || Err(fail("Missing params"));
        let missing_name = || Err(fail("Missing sessionName"));

        let action = js::string(action.unwrap());
        let args = match action.as_str() {
            "killSession" => {
                if !has_session {
                    return missing_name();
                }
                format!("kill-session -t {}", tmux_target(&name(), None, None))
            }
            "renameSession" => {
                let next = sanitize_new_session_name(get("newName"));
                let Some(next) = next.filter(|_| has_session) else {
                    return missing();
                };
                format!(
                    "rename-session -t {} {}",
                    tmux_target(&name(), None, None),
                    sh_quote(&next)
                )
            }
            "detachSession" => {
                if !has_session {
                    return missing_name();
                }
                format!("detach-client -s {}", tmux_target(&name(), None, None))
            }
            "createWindow" => {
                if !has_session {
                    return missing_name();
                }
                let window_name = js::string_or_empty(get("windowName")).trim().to_string();
                let name_arg = if window_name.is_empty() {
                    String::new()
                } else {
                    format!(" -n {}", sh_quote(&js::slice(&window_name, 64)))
                };
                format!(
                    "new-window -t {}{name_arg}",
                    tmux_target(&name(), None, None)
                )
            }
            "killWindow" => {
                if !has_session || window.is_none() {
                    return missing();
                }
                format!("kill-window -t {}", tmux_target(&name(), window, None))
            }
            "renameWindow" => {
                let next = js::slice(js::string_or_empty(get("newName")).trim(), 64);
                if !has_session || window.is_none() || next.is_empty() {
                    return missing();
                }
                format!(
                    "rename-window -t {} {}",
                    tmux_target(&name(), window, None),
                    sh_quote(&next)
                )
            }
            "killPane" => {
                if !has_session || window.is_none() || pane.is_none() {
                    return missing();
                }
                format!("kill-pane -t {}", tmux_target(&name(), window, pane))
            }
            "splitPane" => {
                if !has_session || window.is_none() {
                    return missing();
                }
                let flag = if get("direction").and_then(Value::as_str) == Some("vertical") {
                    "-v"
                } else {
                    "-h"
                };
                let target = tmux_target(&name(), window, pane.filter(|p| !p.is_null()));
                format!("split-window -t {target} {flag}")
            }
            "sendKeys" => {
                if !has_session || window.is_none() || pane.is_none() {
                    return missing();
                }
                let keys = match get("keys") {
                    None | Some(Value::Null) => String::new(),
                    Some(v) => js::string(v),
                };
                let enter = if get("enter") == Some(&Value::Bool(false)) {
                    ""
                } else {
                    " C-m"
                };
                format!(
                    "send-keys -t {} {}{enter}",
                    tmux_target(&name(), window, pane),
                    sh_quote(&keys)
                )
            }
            "selectWindow" => {
                if !has_session || window.is_none() {
                    return missing();
                }
                format!("select-window -t {}", tmux_target(&name(), window, None))
            }
            "killServer" => "kill-server".to_string(),
            other => return Err(fail(format!("Unknown tmux action: {other}"))),
        };
        Ok((session_id, args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::FakeExec;

    fn ok(stdout: &str) -> ExecResult {
        ExecResult::ok(stdout, "", 0)
    }

    fn is_detect(cmd: &str) -> bool {
        cmd.contains("__TMUX_") || cmd.contains("for d in")
    }

    #[test]
    fn targets_and_names() {
        assert_eq!(tmux_target("demo", None, None), "'demo'");
        assert_eq!(tmux_target("demo", Some(&json!(2)), None), "'demo':2");
        assert_eq!(
            tmux_target("de'mo", Some(&json!("1")), Some(&json!(3))),
            "'de'\"'\"'mo':1.3"
        );
        assert_eq!(tmux_target("demo", Some(&Value::Null), None), "'demo'");
        assert_eq!(
            sanitize_new_session_name(Some(&json!(format!("  {}  ", "x".repeat(80))))),
            Some("x".repeat(64))
        );
        assert_eq!(sanitize_new_session_name(Some(&json!("   "))), None);
        assert_eq!(
            tmux_format_arg(TMUX_LIST_CLIENTS_FMT),
            r#""$(printf '#{client_name}\t#{client_tty}\t#{client_activity}\t#{client_session}')""#
        );
    }

    #[test]
    fn socket_order_prefers_remembered_socket() {
        let env = TmuxEnv {
            sockets: vec!["/tmp/a".into(), "/tmp/b".into()],
            preferred_socket: Some("/tmp/b".into()),
            ..Default::default()
        };
        assert_eq!(
            env.socket_order(),
            vec![Some("/tmp/b".to_string()), None, Some("/tmp/a".to_string())]
        );
    }

    #[tokio::test]
    async fn mutating_commands_run_exactly_once_on_silent_success() {
        let fake = FakeExec::new(|_, _| ok(""));
        let ops = TmuxOps::default();
        let reply = ops
            .action(
                &fake,
                &json!({"sessionId": "s1", "action": "killSession", "sessionName": "demo"}),
            )
            .await;
        assert_eq!(reply, json!({"success": true}));
        let kills = fake
            .commands()
            .into_iter()
            .filter(|c| c.contains("kill-session"))
            .count();
        assert_eq!(kills, 1);
    }

    #[tokio::test]
    async fn list_windows_tries_alternate_socket() {
        let fake = FakeExec::new(|req, _| {
            let cmd = &req.command;
            if is_detect(cmd) {
                return ok("__TMUX_VERSION__=tmux 3.0a\n__SOCKET__=/tmp/tmux-0/custom\n");
            }
            if cmd.contains("-S '/tmp/tmux-0/custom'") && cmd.contains("list-windows") {
                return ok("0: main* (2 panes) [80x24]");
            }
            if cmd.contains("list-windows") {
                return ok("");
            }
            ok("tmux 3.0a")
        });
        let ops = TmuxOps::default();
        let reply = ops
            .list_windows(
                &fake,
                &json!({"sessionId": "s1", "sessionName": "test-session"}),
            )
            .await;
        assert_eq!(reply["success"], true);
        assert_eq!(reply["windows"].as_array().unwrap().len(), 1);
        assert_eq!(reply["windows"][0]["panes"], 2);
        // The working socket is remembered and tried first next time.
        assert_eq!(
            ops.cached("s1").unwrap().preferred_socket.as_deref(),
            Some("/tmp/tmux-0/custom")
        );
    }

    #[tokio::test]
    async fn list_windows_falls_back_to_all_windows() {
        let fake = FakeExec::new(|req, _| {
            let cmd = &req.command;
            if is_detect(cmd) {
                return ok("__TMUX_VERSION__=tmux 3.0a\n");
            }
            if cmd.contains("list-windows -a") {
                return ok("test-session: 0: main* (2 panes) [80x24]\ntest-session: 1: aux (1 pane) [80x24]");
            }
            if cmd.contains("list-windows") {
                return ExecResult::ok("can't find session: test-session", "", 1);
            }
            ok("tmux 3.0a")
        });
        let reply = TmuxOps::default()
            .list_windows(
                &fake,
                &json!({"sessionId": "s1", "sessionName": "test-session"}),
            )
            .await;
        assert_eq!(reply["success"], true);
        assert_eq!(reply["windows"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn list_windows_reads_stderr_and_uses_printf_format() {
        let fake = FakeExec::new(|req, _| {
            let cmd = &req.command;
            if is_detect(cmd) {
                return ok("__TMUX_VERSION__=tmux 3.0a\n");
            }
            if cmd.contains("list-windows") {
                return ExecResult::ok("", "0: remote* (2 panes) [80x24]\n", 0);
            }
            ok("tmux 3.0a")
        });
        let reply = TmuxOps::default()
            .list_windows(
                &fake,
                &json!({"sessionId": "s1", "sessionName": "test-session"}),
            )
            .await;
        assert_eq!(reply["success"], true);
        assert_eq!(reply["windows"][0]["name"], "remote");
        let list_cmd = fake
            .commands()
            .into_iter()
            .find(|c| c.contains("list-windows"))
            .unwrap();
        assert!(list_cmd.contains("$(printf '"), "{list_cmd}");
    }

    #[tokio::test]
    async fn list_windows_failure_reports_debug() {
        let fake = FakeExec::new(|_, _| ExecResult::fail("Not connected"));
        let reply = TmuxOps::default()
            .list_windows(&fake, &json!({"sessionId": "s1", "sessionName": "demo"}))
            .await;
        assert_eq!(reply["success"], false);
        assert_eq!(reply["error"], "Not connected");
        assert_eq!(reply["debug"]["tried"].as_array().unwrap().len(), 8);
        assert_eq!(reply["debug"]["sockets"], json!([null]));
        assert_eq!(reply["debug"]["lastOutput"], "");
    }

    #[tokio::test]
    async fn list_sessions_parses_and_reports_version() {
        let fake = FakeExec::new(|req, _| {
            let cmd = &req.command;
            if is_detect(cmd) {
                return ok("__TMUX_VERSION__=tmux 3.3a\n__TMUX_BIN__=/usr/bin/tmux\n");
            }
            if cmd.contains("list-sessions") {
                return ok("dev: 2 windows (created Thu Jun 11 00:38:14 2026) (attached)");
            }
            ok("tmux 3.3a")
        });
        let reply = TmuxOps::default()
            .list_sessions(&fake, &json!({"sessionId": "s1"}))
            .await;
        assert_eq!(reply["success"], true);
        assert_eq!(reply["tmuxVersion"], "tmux 3.3a");
        assert_eq!(reply["sessions"][0]["name"], "dev");
        assert_eq!(reply["sessions"][0]["attached"], true);
        assert!(fake.commands().iter().any(|c| c.contains("/usr/bin/tmux")));
    }

    #[tokio::test]
    async fn list_sessions_without_server_is_empty_success() {
        let fake = FakeExec::new(|req, _| {
            if req.command.contains("list-sessions") {
                return ExecResult::ok("", "no server running on /tmp/tmux-0/default", 1);
            }
            ok("")
        });
        let reply = TmuxOps::default().list_sessions(&fake, &json!("s1")).await;
        assert_eq!(reply, json!({"success": true, "sessions": []}));
        let missing = TmuxOps::default().list_sessions(&fake, &json!({})).await;
        assert_eq!(
            missing,
            json!({"success": false, "error": "Missing sessionId"})
        );
    }

    #[tokio::test]
    async fn list_sessions_failure_has_diagnostics() {
        let fake = FakeExec::new(|_, _| ok(""));
        let reply = TmuxOps::default()
            .list_sessions(&fake, &json!({"sessionId": "s1"}))
            .await;
        assert_eq!(reply["success"], false);
        assert_eq!(
            reply["error"],
            "Cannot list tmux sessions (tmux version unknown; bin=tmux; sockets=none; last=empty)"
        );
        assert!(reply.get("tmuxVersion").is_none());
    }

    #[tokio::test]
    async fn env_is_cached_between_mutations() {
        let fake = FakeExec::new(|_, _| ok(""));
        let ops = TmuxOps::default();
        let payload = json!({"sessionId": "s1", "action": "killServer"});
        ops.action(&fake, &payload).await;
        let first = fake.commands().len();
        ops.action(&fake, &payload).await;
        let second = fake.commands().len() - first;
        // The second action skips detection: only the kill-server command runs.
        assert_eq!(second, 1);
        ops.forget("s1");
        ops.action(&fake, &payload).await;
        assert_eq!(fake.commands().len() - first - second, first);
    }

    #[tokio::test]
    async fn action_maps_failures_and_validation() {
        let fake = FakeExec::new(|req, _| {
            if req.command.contains("kill-window") {
                return ExecResult::ok("", "can't find window: 9", 1);
            }
            ok("")
        });
        let ops = TmuxOps::default();
        let reply = ops
            .action(
                &fake,
                &json!({"sessionId": "s", "action": "killWindow", "sessionName": "d", "windowIndex": 9}),
            )
            .await;
        assert_eq!(
            reply,
            json!({"success": false, "error": "can't find window: 9"})
        );
        assert_eq!(
            ops.action(&fake, &json!({"sessionId": "s"})).await,
            json!({"success": false, "error": "Missing sessionId or action"})
        );
        assert_eq!(
            ops.action(&fake, &json!({"sessionId": "s", "action": "killSession"}))
                .await,
            json!({"success": false, "error": "Missing sessionName"})
        );
        assert_eq!(
            ops.action(&fake, &json!({"sessionId": "s", "action": "nope"}))
                .await,
            json!({"success": false, "error": "Unknown tmux action: nope"})
        );
        assert_eq!(
            ops.action(
                &fake,
                &json!({"sessionId": "s", "action": "renameWindow", "sessionName": "d", "windowIndex": 0, "newName": "  "})
            )
            .await,
            json!({"success": false, "error": "Missing params"})
        );
    }

    #[tokio::test]
    async fn action_builds_expected_commands() {
        let fake = FakeExec::new(|_, _| ok(""));
        let ops = TmuxOps::default();
        for payload in [
            json!({"sessionId": "s", "action": "sendKeys", "sessionName": "d", "windowIndex": 1, "paneIndex": 2, "keys": "ls -la", "enter": false}),
            json!({"sessionId": "s", "action": "splitPane", "sessionName": "d", "windowIndex": 1, "direction": "vertical"}),
            json!({"sessionId": "s", "action": "createWindow", "sessionName": "d", "windowName": " logs "}),
        ] {
            assert_eq!(ops.action(&fake, &payload).await, json!({"success": true}));
        }
        let cmds = fake.commands();
        assert!(cmds
            .iter()
            .any(|c| c.contains("send-keys -t 'd':1.2 'ls -la'") && !c.contains("C-m")));
        assert!(cmds.iter().any(|c| c.contains("split-window -t 'd':1 -v")));
        assert!(cmds
            .iter()
            .any(|c| c.contains("new-window -t 'd' -n 'logs'")));
    }

    #[tokio::test]
    async fn create_session_sends_command_and_reports_name() {
        let fake = FakeExec::new(|_, _| ok(""));
        let reply = TmuxOps::default()
            .create_session(
                &fake,
                &json!({"sessionId": "s", "name": " work ", "command": "htop"}),
            )
            .await;
        assert_eq!(reply, json!({"success": true, "name": "work"}));
        let cmds = fake.commands();
        assert!(cmds.iter().any(|c| c.contains("new-session -d -s 'work'")));
        assert!(cmds
            .iter()
            .any(|c| c.contains("send-keys -t 'work' 'htop' C-m")));
        assert_eq!(
            TmuxOps::default()
                .create_session(&fake, &json!({"sessionId": "s"}))
                .await,
            json!({"success": false, "error": "Missing sessionId or name"})
        );
        assert_eq!(
            TmuxOps::default()
                .create_session(&fake, &json!({"sessionId": "s", "name": "   "}))
                .await,
            json!({"success": false, "error": "Invalid session name"})
        );
    }

    #[tokio::test]
    async fn list_clients_and_panes() {
        let fake = FakeExec::new(|req, _| {
            if req.command.contains("list-clients") {
                return ok("/dev/pts/1\t/dev/pts/1\t100\tdemo\n/dev/pts/2\t/dev/pts/2\t1\tother");
            }
            if req.command.contains("list-panes") {
                return ok("0\tt\tbash\t1\t42\t80\t24");
            }
            ok("")
        });
        let ops = TmuxOps::default();
        let reply = ops
            .list_clients(&fake, &json!({"sessionId": "s", "sessionName": "demo"}))
            .await;
        assert_eq!(reply["clients"].as_array().unwrap().len(), 1);
        let reply = ops
            .list_panes(
                &fake,
                &json!({"sessionId": "s", "sessionName": "demo", "windowIndex": 0}),
            )
            .await;
        assert_eq!(reply["success"], true);
        assert_eq!(reply["panes"][0]["pid"], 42);
        assert_eq!(
            ops.list_panes(&fake, &json!({"sessionId": "s", "sessionName": "demo"}))
                .await,
            json!({"success": false, "error": "Missing params"})
        );
    }
}

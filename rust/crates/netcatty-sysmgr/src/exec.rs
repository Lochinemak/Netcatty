//! The execution seam between the pure system-manager logic and the
//! transports, plus small helpers shared by every module.
//!
//! [`SessionExec`] mirrors Electron's `execOnSession` / `execOnLocalMachine`
//! (`electron/bridges/systemManager/execOnSession.cjs`): it never fails with
//! an error value — every failure is an [`ExecResult`] with `success: false`
//! and a user-visible `error` string, exactly like the JS result objects.

use async_trait::async_trait;
use serde_json::{json, Map, Value};

/// One command to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    pub command: String,
    /// Bound for opening the channel and for the whole run (ms).
    pub timeout_ms: u64,
    /// Written to the process' stdin, then stdin is closed.
    pub stdin: Option<String>,
    /// Max captured stdout/stderr bytes; exceeding it fails the command with
    /// `"SSH command maxBuffer exceeded"` (remote) like Electron. `None` =
    /// the Electron default (10 MiB).
    pub max_buffer: Option<usize>,
}

/// Electron's `DEFAULT_LOCAL_EXEC_MAX_BUFFER`.
pub const DEFAULT_MAX_BUFFER: usize = 10 * 1024 * 1024;

impl ExecRequest {
    pub fn new(command: impl Into<String>, timeout_ms: u64) -> Self {
        Self {
            command: command.into(),
            timeout_ms,
            stdin: None,
            max_buffer: None,
        }
    }

    pub fn with_stdin(mut self, stdin: impl Into<String>) -> Self {
        self.stdin = Some(stdin.into());
        self
    }

    pub fn with_max_buffer(mut self, bytes: usize) -> Self {
        self.max_buffer = Some(bytes);
        self
    }

    pub fn max_buffer(&self) -> usize {
        self.max_buffer
            .filter(|b| *b > 0)
            .unwrap_or(DEFAULT_MAX_BUFFER)
    }
}

/// Result of one command, shaped like Electron's exec result objects.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecResult {
    /// The command ran (whatever its exit code). `false` = transport /
    /// session failure, see `error`.
    pub success: bool,
    /// Transient "not ready yet" (Electron: Mosh handshake in progress).
    pub pending: bool,
    pub stdout: String,
    pub stderr: String,
    /// Exit code. On success Electron reports `code ?? 0`, so a missing exit
    /// status is `Some(0)`; failures carry `Some(1)` or `None`.
    pub code: Option<i32>,
    pub error: Option<String>,
    /// Machine-readable failure code (`ERR_SINGLE_CHANNEL_BASTION`).
    pub error_code: Option<String>,
}

impl ExecResult {
    /// The command ran and exited with `code`.
    pub fn ok(stdout: impl Into<String>, stderr: impl Into<String>, code: i32) -> Self {
        Self {
            success: true,
            stdout: stdout.into(),
            stderr: stderr.into(),
            code: Some(code),
            ..Default::default()
        }
    }

    /// Transport / session failure with a user-visible message.
    pub fn fail(error: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(error.into()),
            ..Default::default()
        }
    }

    /// `{ success: false, pending: true, error }`.
    pub fn pending(error: impl Into<String>) -> Self {
        Self {
            success: false,
            pending: true,
            error: Some(error.into()),
            ..Default::default()
        }
    }

    /// Electron's `isSuccessfulCommandResult`: ran and exit code 0 / unknown.
    pub fn is_successful(&self) -> bool {
        self.success && matches!(self.code, None | Some(0))
    }

    /// Electron's `commandError(result, fallback)`:
    /// `(stderr || error || "").trim() || fallback`.
    pub fn command_error(&self, fallback: &str) -> String {
        let raw = if !self.stderr.is_empty() {
            self.stderr.as_str()
        } else {
            self.error.as_deref().unwrap_or("")
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            fallback.to_string()
        } else {
            trimmed.to_string()
        }
    }

    /// The raw result as Electron would return it from `execOnSession`
    /// (used by pass-through commands such as `setupOsc7Tracking`).
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("success".into(), json!(self.success));
        if self.pending {
            out.insert("pending".into(), json!(true));
        }
        if let Some(error) = &self.error {
            out.insert("error".into(), json!(error));
        }
        if let Some(code) = &self.error_code {
            out.insert("errorCode".into(), json!(code));
        }
        out.insert("stdout".into(), json!(self.stdout));
        out.insert("stderr".into(), json!(self.stderr));
        out.insert("code".into(), json!(self.code));
        Value::Object(out)
    }
}

/// Platform of the machine Netcatty runs on (Node's `process.platform`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPlatform {
    Linux,
    Darwin,
    Win32,
    Other,
}

impl LocalPlatform {
    pub fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::Darwin
        } else if cfg!(windows) {
            Self::Win32
        } else {
            Self::Other
        }
    }

    /// Node's `process.platform` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Darwin => "darwin",
            Self::Win32 => "win32",
            Self::Other => "unknown",
        }
    }
}

/// Runs commands for one terminal session.
///
/// Implementations serialize commands per session (Electron's exec queue) and
/// map transport failures into `ExecResult::fail` messages.
#[async_trait]
pub trait SessionExec: Send + Sync {
    /// Electron `execOnSession`: run on the session's target — an exec
    /// channel on the SSH connection, or the local shell (`sh -c`, PowerShell
    /// on Windows) for local terminal sessions.
    async fn exec(&self, request: ExecRequest) -> ExecResult;

    /// Electron `execOnLocalMachine`: run on this machine regardless of the
    /// session (`sh -c` on POSIX, `powershell.exe -NoProfile
    /// -NonInteractive -Command` on Windows).
    async fn exec_local(&self, request: ExecRequest) -> ExecResult;

    /// Electron `isLocalSession`: the session is a local terminal.
    fn is_local(&self) -> bool;

    /// Platform of this machine (`process.platform`).
    fn local_platform(&self) -> LocalPlatform;

    /// Electron `session.systemManagerSudoPassword` (the host's
    /// `sudoAutofillPassword`), when set and non-empty.
    fn sudo_password(&self) -> Option<String>;
}

/// POSIX single-quote: `'...'` with embedded quotes as `'"'"'` (Electron's
/// `shQuote` in dockerOps / serviceOps / tmuxEnv).
pub fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// `JSON.stringify(string)` — Electron wraps scripts as
/// `exec sh -c ${JSON.stringify(script)}`.
pub fn json_quote(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

/// `exec sh -c <JSON.stringify(script)>`.
pub fn wrap_sh_json(script: &str) -> String {
    format!("exec sh -c {}", json_quote(script))
}

/// `Date.now()`.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Test double: records every request and answers with a closure.
pub struct FakeExec {
    pub local: bool,
    pub platform: LocalPlatform,
    pub sudo: Option<String>,
    #[allow(clippy::type_complexity)]
    handler: Box<dyn Fn(&ExecRequest, bool) -> ExecResult + Send + Sync>,
    calls: std::sync::Mutex<Vec<(ExecRequest, bool)>>,
}

impl FakeExec {
    /// `handler(request, via_exec_local)` produces each reply.
    pub fn new(handler: impl Fn(&ExecRequest, bool) -> ExecResult + Send + Sync + 'static) -> Self {
        Self {
            local: false,
            platform: LocalPlatform::Linux,
            sudo: None,
            handler: Box::new(handler),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Answer every command in order from `replies`; extra calls get
    /// `ExecResult::fail("no more replies")`.
    pub fn sequence(replies: Vec<ExecResult>) -> Self {
        let queue = std::sync::Mutex::new(std::collections::VecDeque::from(replies));
        Self::new(move |_, _| {
            queue
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| ExecResult::fail("no more replies"))
        })
    }

    pub fn local(mut self, platform: LocalPlatform) -> Self {
        self.local = true;
        self.platform = platform;
        self
    }

    pub fn with_sudo(mut self, password: &str) -> Self {
        self.sudo = Some(password.to_string());
        self
    }

    /// Commands seen so far (`exec` and `exec_local`).
    pub fn commands(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(r, _)| r.command.clone())
            .collect()
    }

    /// Full requests with the `via_exec_local` flag.
    pub fn requests(&self) -> Vec<(ExecRequest, bool)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl SessionExec for FakeExec {
    async fn exec(&self, request: ExecRequest) -> ExecResult {
        let reply = (self.handler)(&request, false);
        self.calls.lock().unwrap().push((request, false));
        reply
    }
    async fn exec_local(&self, request: ExecRequest) -> ExecResult {
        let reply = (self.handler)(&request, true);
        self.calls.lock().unwrap().push((request, true));
        reply
    }
    fn is_local(&self) -> bool {
        self.local
    }
    fn local_platform(&self) -> LocalPlatform {
        self.platform
    }
    fn sudo_password(&self) -> Option<String> {
        self.sudo.clone().filter(|s| !s.is_empty())
    }
}

/// Transport-level failure (Electron `isTransportExecError`): the exec
/// channel could not be used because the connection is gone.
pub fn is_transport_exec_error(message: &str) -> bool {
    let msg = message.to_lowercase();
    [
        "not connected",
        "connection lost",
        "socket hang up",
        "econnreset",
        "closed",
        "destroyed",
        "channel open failure",
        "unable to exec",
        "no response",
    ]
    .iter()
    .any(|needle| msg.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_matches_electron() {
        assert_eq!(sh_quote("it's"), "'it'\"'\"'s'");
        assert_eq!(sh_quote(""), "''");
        assert_eq!(json_quote("a \"b\"\n"), "\"a \\\"b\\\"\\n\"");
        assert_eq!(wrap_sh_json("kill -9 1"), "exec sh -c \"kill -9 1\"");
    }

    #[test]
    fn success_and_error_helpers() {
        assert!(ExecResult::ok("", "", 0).is_successful());
        assert!(!ExecResult::ok("", "", 2).is_successful());
        assert!(!ExecResult::fail("x").is_successful());
        let r = ExecResult {
            stderr: "  boom \n".into(),
            ..ExecResult::ok("", "", 1)
        };
        assert_eq!(r.command_error("fallback"), "boom");
        assert_eq!(ExecResult::fail("  ").command_error("fb"), "fb");
        assert_eq!(ExecResult::fail("net").command_error("fb"), "net");
    }

    #[test]
    fn transport_errors() {
        assert!(is_transport_exec_error("Channel open failure: x"));
        assert!(is_transport_exec_error("Not connected"));
        assert!(!is_transport_exec_error("permission denied"));
    }

    #[tokio::test]
    async fn fake_exec_records_calls() {
        let fake = FakeExec::sequence(vec![ExecResult::ok("a", "", 0)]);
        let r = fake.exec(ExecRequest::new("echo a", 1000)).await;
        assert_eq!(r.stdout, "a");
        let r = fake.exec_local(ExecRequest::new("echo b", 1000)).await;
        assert!(!r.success);
        assert_eq!(fake.commands(), vec!["echo a", "echo b"]);
        assert!(fake.requests()[1].1);
    }
}

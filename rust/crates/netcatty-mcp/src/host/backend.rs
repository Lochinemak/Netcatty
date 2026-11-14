//! What the MCP host needs from the application. The desktop app
//! implements these over its session registry, SFTP layer and event bus;
//! tests implement them with fakes.

use netcatty_ptyexec::job::{OutputRx, PtyInput};
use netcatty_ptyexec::shell_kind::{ExecProbe, ShellKindState};
use netcatty_ptyexec::shell_utils::PromptTracker;
use serde_json::Value;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Output of a side-channel (SSH exec) command.
#[derive(Debug, Clone, Default)]
pub struct ChannelOutput {
    pub stdout: String,
    pub stderr: String,
    /// `None` = terminated without exit status (signal / connection lost).
    pub exit_code: Option<i32>,
}

/// Failure of a side-channel command (`execViaChannel` messages).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    OpenTimeout,
    RunTimeout,
    OutputLimit(usize),
    Failed(String),
}

/// A live terminal session the host can run commands in.
#[async_trait::async_trait]
pub trait TerminalSession: Send + Sync {
    fn session_id(&self) -> &str;
    /// `ssh` | `local` | `telnet` | `serial` | `mosh` | `et`.
    fn protocol(&self) -> &str;
    fn label(&self) -> String;
    fn hostname(&self) -> String;
    fn username(&self) -> String;
    fn host_id(&self) -> String;
    /// Input path of the interactive PTY (`None` when not writable).
    fn writer(&self) -> Option<Arc<dyn PtyInput>>;
    /// Subscribe to decoded output from now on; closed when the session ends.
    fn subscribe(&self) -> OutputRx;
    /// Snapshot of the rolling prompt tracker.
    fn prompt(&self) -> PromptTracker;
    fn shell_kind(&self) -> Arc<ShellKindState>;
    /// Software token of the SSH identification string (`OpenSSH_9.6`).
    fn remote_ssh_version(&self) -> String;
    /// Host was flagged single-channel (`singleChannelSsh`).
    fn single_channel(&self) -> bool;
    /// Silent login-shell probe channel (none for local / bastion sessions).
    fn exec_probe(&self) -> Option<Arc<dyn ExecProbe>>;
    /// Run a command on a fresh SSH exec channel; `None` if unsupported.
    async fn channel_exec(&self, command: &str, timeout_ms: u64, max_output_bytes: usize) -> Option<Result<ChannelOutput, ChannelError>>;
    /// Per-session "previous command never returned its prompt" latch.
    fn prompt_recovery_pending(&self) -> Arc<AtomicBool>;
    /// Resume a paused output pump after Ctrl+C (flow-control recovery).
    fn clear_flow(&self);
    /// Push text to the session's renderer terminal. `synthetic` text
    /// bypasses the renderer's marker filter (`syntheticEcho`).
    fn emit_display(&self, data: &str, synthetic: bool);
    /// Serial file transfer (ZMODEM / YMODEM) in progress.
    fn file_transfer_active(&self) -> bool {
        false
    }
    /// Serial console text encoding (`utf8` default).
    fn serial_encoding(&self) -> String {
        "utf8".into()
    }
}

/// SFTP operations the host performs on a session's connection.
#[derive(Debug, Clone)]
pub enum SftpOp {
    List { path: String },
    /// `max_bytes: None` reads to the end of the file. The result is the
    /// fragment built by [`super::sftp::read_chunk`].
    Read { path: String, offset: u64, max_bytes: Option<u64> },
    /// The result is the fragment built by [`super::find::find`].
    Find { options: super::find::FindOptions },
    Write { path: String, content: String },
    Mkdir { path: String },
    Delete { path: String },
    Rename { old_path: String, new_path: String },
    Stat { path: String },
    Chmod { path: String, mode: String },
    Home,
    Download { remote_path: String, local_path: String, transfer_id: String, host_id: Option<String> },
    Upload { local_path: String, remote_path: String, transfer_id: String, host_id: Option<String> },
}

/// Application services used by the host.
#[async_trait::async_trait]
pub trait HostBackend: Send + Sync {
    fn session(&self, session_id: &str) -> Option<Arc<dyn TerminalSession>>;
    fn session_ids(&self) -> Vec<String>;
    /// Run an SFTP operation on the session's connection, honouring
    /// `cancel` (dropped / cancelled token aborts). Results are the
    /// Electron handler payload fragments (`entries`, `content`, `stat`, ...).
    async fn sftp(&self, session_id: &str, op: SftpOp, cancel: tokio_util::sync::CancellationToken) -> Result<Value, String>;
    /// Emit a renderer event (approval cards, vault-agent requests, transfers).
    fn emit(&self, event: &str, payload: Value);
    /// Whether a renderer window exists to show approval cards.
    fn has_approval_window(&self) -> bool {
        true
    }
    /// Active port-forward tunnels (`portforward/tunnels/list`).
    async fn list_port_forwards(&self) -> Vec<Value>;
    /// External MCP approvals pending (window attention / notification).
    fn sync_external_approval_attention(&self, _pending: usize) {}
}

//! Terminal session registry: owns every live SSH / local / telnet session
//! and pumps their output to the renderer as `netcatty:data` events.

use netcatty_core::ipc::SessionExitEvent;
use netcatty_pty::PtySession;
use netcatty_ssh::{ShellSession, SshConnection};
use std::sync::Arc;
use tauri::AppHandle;

/// Backend of a terminal session.
pub enum SessionBackend {
    Ssh { connection: Arc<SshConnection>, shell: ShellSession },
    Local { pty: PtySession },
}

pub struct SessionEntry {
    pub session_id: String,
    pub host_id: Option<String>,
    pub label: String,
    /// `ssh` | `local` | `telnet`.
    pub protocol: &'static str,
    pub backend: SessionBackend,
    /// Output decoder charset (`utf-8`, `gb18030`, ...).
    pub charset: String,
    /// Shared SSH connection for transport reuse (`sourceSessionId`,
    /// `openSftpForSession`). `None` for local sessions.
    pub connection: Option<Arc<SshConnection>>,
    pub created_at: i64,
}

pub struct SessionRegistry {
    pub app: AppHandle,
    pub(crate) sessions: dashmap::DashMap<String, Arc<tokio::sync::Mutex<SessionEntry>>>,
}

impl SessionRegistry {
    pub fn new(app: AppHandle) -> Self {
        Self { app, sessions: dashmap::DashMap::new() }
    }

    /// Insert a session and start the output pump task. The pump decodes
    /// bytes with the session charset (streaming, so multi-byte sequences
    /// split across chunks are handled), emits `netcatty:data`, and emits
    /// `netcatty:exit` + removes the entry when the backend ends.
    pub fn insert(&self, entry: SessionEntry) {
        let _ = entry;
        todo!("insert + spawn pump (tauri agent task)")
    }

    pub fn get(&self, session_id: &str) -> Option<Arc<tokio::sync::Mutex<SessionEntry>>> {
        self.sessions.get(session_id).map(|e| e.clone())
    }

    /// Connection of a live SSH session, for transport reuse.
    pub fn connection_of(&self, session_id: &str) -> Option<Arc<SshConnection>> {
        let _ = session_id;
        todo!()
    }

    pub async fn write(&self, session_id: &str, data: bytes::Bytes) -> netcatty_core::CoreResult<()> {
        let _ = (session_id, data);
        todo!()
    }

    pub async fn resize(&self, session_id: &str, cols: u16, rows: u16) -> netcatty_core::CoreResult<()> {
        let _ = (session_id, cols, rows);
        todo!()
    }

    /// Close a session: close the shell/pty, disconnect the SSH connection
    /// unless another session or SFTP client still uses it, emit exit.
    pub async fn close(&self, session_id: &str) -> netcatty_core::CoreResult<()> {
        let _ = session_id;
        todo!()
    }

    pub fn emit_exit(&self, event: SessionExitEvent) {
        crate::events::emit(&self.app, netcatty_core::ipc::events::SESSION_EXIT, event);
    }
}

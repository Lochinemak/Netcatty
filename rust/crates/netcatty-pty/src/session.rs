//! A local shell running in a pseudo-terminal.

use crate::error::PtyResult;
use bytes::Bytes;
use std::collections::HashMap;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Default)]
pub struct LocalPtyOptions {
    /// Shell executable; `None` → [`crate::default_shell`].
    pub shell: Option<String>,
    pub shell_args: Vec<String>,
    /// Working directory; `None` → home directory.
    pub cwd: Option<String>,
    pub env: HashMap<String, String>,
    pub cols: u16,
    pub rows: u16,
    /// `TERM` (defaults to `xterm-256color`).
    pub term: Option<String>,
}

#[derive(Debug)]
pub enum PtyEvent {
    Data(Bytes),
    /// The child exited. `None` when the status is unknown.
    Exit { exit_code: Option<i32>, signal: Option<String> },
}

/// A running local terminal. Output arrives on `events`; input goes through
/// [`PtySession::write`]. The reader runs on a blocking thread (portable-pty
/// is synchronous) and forwards into the tokio channel.
pub struct PtySession {
    pub events: mpsc::Receiver<PtyEvent>,
    pub(crate) write_tx: mpsc::Sender<Bytes>,
    pub(crate) control_tx: mpsc::UnboundedSender<PtyControl>,
    pub pid: Option<u32>,
    pub shell: String,
}

pub(crate) enum PtyControl {
    Resize { cols: u16, rows: u16 },
    Kill,
}

impl PtySession {
    pub async fn spawn(options: LocalPtyOptions) -> PtyResult<PtySession> {
        let _ = options;
        todo!("portable-pty openpty + CommandBuilder, reader thread, writer task (pty agent task)")
    }

    pub async fn write(&self, data: Bytes) -> PtyResult<()> {
        self.write_tx.send(data).await.map_err(|_| crate::PtyError::Closed)
    }

    pub fn resize(&self, cols: u16, rows: u16) -> PtyResult<()> {
        self.control_tx
            .send(PtyControl::Resize { cols, rows })
            .map_err(|_| crate::PtyError::Closed)
    }

    /// Terminate the child process (SIGHUP then SIGKILL on Unix).
    pub fn kill(&self) {
        let _ = self.control_tx.send(PtyControl::Kill);
    }

    /// Current working directory of the foreground process, when the
    /// platform supports discovering it (macOS `lsof`/`proc_pidinfo`, Linux
    /// `/proc/<pid>/cwd`). `None` on Windows.
    pub async fn current_dir(&self) -> Option<String> {
        todo!("cwd discovery (pty agent task)")
    }
}

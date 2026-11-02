//! Terminal session registry: owns every live SSH / local session and pumps
//! their output to the renderer as `netcatty:data` events.
//!
//! Design:
//! * Each session has a *pump task* that owns the backend event receiver
//!   (moved out of the `ShellSession` / `PtySession` at insert time), so
//!   writes/resizes — which take the entry's `tokio::sync::Mutex` — never
//!   contend with reading output.
//! * Output bytes are decoded with a streaming [`StreamDecoder`] so
//!   multi-byte sequences split across reads are reassembled.
//! * Bursts are coalesced: whatever is immediately available (up to
//!   [`COALESCE_LIMIT`]) is drained before one event is emitted.
//! * `session_set_flow_paused` flips a lock-free flag; while paused the pump
//!   keeps reading but buffers decoded text (bounded by
//!   [`PAUSE_BUFFER_LIMIT`]; beyond that output is dropped with a warning).
//! * `netcatty:exit` is emitted exactly once per session, either by the pump
//!   (backend ended) or by [`SessionRegistry::close`].
//! * The shared [`SshConnection`] is disconnected only when no other session
//!   or SFTP client references it.

use crate::decoder::{encode_input, StreamDecoder};
use crate::events;
use netcatty_core::ipc::{events as ev, ExitReason, SessionDataEvent, SessionExitEvent};
use netcatty_core::{CoreError, CoreResult};
use netcatty_pty::{PtyEvent, PtySession};
use netcatty_sftp::SftpClient;
use netcatty_ssh::shell::ShellEvent;
use netcatty_ssh::{ShellSession, SshConnection};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::AppHandle;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, Mutex, Notify};

/// Max bytes drained from the backend before one `netcatty:data` is emitted.
pub const COALESCE_LIMIT: usize = 256 * 1024;
/// Max decoded bytes buffered while the renderer has paused the session.
pub const PAUSE_BUFFER_LIMIT: usize = 4 * 1024 * 1024;

/// Backend of a terminal session.
pub enum SessionBackend {
    Ssh {
        connection: Arc<SshConnection>,
        shell: ShellSession,
    },
    Local {
        pty: PtySession,
    },
    /// Backend already torn down (entry is being removed).
    Closed,
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

/// Lock-free per-session flags shared between commands and the pump.
#[derive(Default)]
pub struct SessionFlags {
    pub paused: AtomicBool,
    pub exit_emitted: AtomicBool,
    pub dropped_output: AtomicBool,
    pub wake: Notify,
}

pub type SftpMap = Arc<dashmap::DashMap<String, Arc<SftpClient>>>;

/// State shared by the registry handle and every pump task.
pub(crate) struct Shared {
    pub app: AppHandle,
    pub sessions: dashmap::DashMap<String, Arc<Mutex<SessionEntry>>>,
    pub flags: dashmap::DashMap<String, Arc<SessionFlags>>,
    /// Session id → its SSH connection (lock-free view for transport reuse).
    pub connections: dashmap::DashMap<String, Arc<SshConnection>>,
    /// SFTP clients (owned by `AppState`) — consulted before disconnecting.
    pub sftp: SftpMap,
}

#[derive(Clone)]
pub struct SessionRegistry {
    pub app: AppHandle,
    pub(crate) shared: Arc<Shared>,
}

/// Unified backend event.
enum Pumped {
    Data(bytes::Bytes),
    Eof,
    Exit {
        code: Option<i32>,
        signal: Option<String>,
    },
}

enum Source {
    Ssh(mpsc::Receiver<ShellEvent>),
    Local(mpsc::Receiver<PtyEvent>),
}

impl Source {
    async fn recv(&mut self) -> Option<Pumped> {
        match self {
            Source::Ssh(rx) => rx.recv().await.map(Pumped::from),
            Source::Local(rx) => rx.recv().await.map(Pumped::from),
        }
    }

    fn try_recv(&mut self) -> Result<Pumped, TryRecvError> {
        match self {
            Source::Ssh(rx) => rx.try_recv().map(Pumped::from),
            Source::Local(rx) => rx.try_recv().map(Pumped::from),
        }
    }
}

impl From<ShellEvent> for Pumped {
    fn from(e: ShellEvent) -> Self {
        match e {
            ShellEvent::Data(b) => Pumped::Data(b),
            ShellEvent::Eof => Pumped::Eof,
            ShellEvent::Exit { exit_code, signal } => Pumped::Exit {
                code: exit_code,
                signal,
            },
        }
    }
}

impl From<PtyEvent> for Pumped {
    fn from(e: PtyEvent) -> Self {
        match e {
            PtyEvent::Data(b) => Pumped::Data(b),
            PtyEvent::Exit { exit_code, signal } => Pumped::Exit {
                code: exit_code,
                signal,
            },
        }
    }
}

fn not_found(session_id: &str) -> CoreError {
    CoreError::not_found(format!("session {session_id} not found"))
}

impl SessionRegistry {
    pub fn new(app: AppHandle, sftp: SftpMap) -> Self {
        Self {
            app: app.clone(),
            shared: Arc::new(Shared {
                app,
                sessions: dashmap::DashMap::new(),
                flags: dashmap::DashMap::new(),
                connections: dashmap::DashMap::new(),
                sftp,
            }),
        }
    }

    /// Insert a session and start the output pump task. The pump decodes
    /// bytes with the session charset (streaming, so multi-byte sequences
    /// split across chunks are handled), emits `netcatty:data`, and emits
    /// `netcatty:exit` + removes the entry when the backend ends.
    pub fn insert(&self, mut entry: SessionEntry) {
        let session_id = entry.session_id.clone();
        let source = match &mut entry.backend {
            SessionBackend::Ssh { shell, .. } => {
                let (_tx, rx) = mpsc::channel(1);
                Source::Ssh(std::mem::replace(&mut shell.events, rx))
            }
            SessionBackend::Local { pty } => {
                let (_tx, rx) = mpsc::channel(1);
                Source::Local(std::mem::replace(&mut pty.events, rx))
            }
            SessionBackend::Closed => {
                tracing::warn!(session_id, "refusing to insert a closed session backend");
                return;
            }
        };
        let decoder = StreamDecoder::new(Some(&entry.charset));
        let flags = Arc::new(SessionFlags::default());
        if let Some(conn) = &entry.connection {
            self.shared
                .connections
                .insert(session_id.clone(), conn.clone());
        }
        self.shared.flags.insert(session_id.clone(), flags.clone());
        self.shared
            .sessions
            .insert(session_id.clone(), Arc::new(Mutex::new(entry)));
        let shared = self.shared.clone();
        tauri::async_runtime::spawn(pump(shared, session_id, source, decoder, flags));
    }

    pub fn get(&self, session_id: &str) -> Option<Arc<Mutex<SessionEntry>>> {
        self.shared.sessions.get(session_id).map(|e| e.clone())
    }

    pub fn contains(&self, session_id: &str) -> bool {
        self.shared.sessions.contains_key(session_id)
    }

    /// Connection of a live SSH session, for transport reuse.
    pub fn connection_of(&self, session_id: &str) -> Option<Arc<SshConnection>> {
        self.shared
            .connections
            .get(session_id)
            .map(|c| c.clone())
            .filter(|c| !c.is_closed())
    }

    /// Any live session connection to `user@host:port`.
    pub fn find_connection(
        &self,
        hostname: &str,
        port: u16,
        username: &str,
    ) -> Option<Arc<SshConnection>> {
        self.shared
            .connections
            .iter()
            .find(|c| {
                let t = &c.value().options.target;
                !c.value().is_closed()
                    && t.port == port
                    && t.hostname.eq_ignore_ascii_case(hostname)
                    && t.username == username
            })
            .map(|c| c.value().clone())
    }

    /// Write raw bytes (already in the session charset / binary).
    pub async fn write(&self, session_id: &str, data: bytes::Bytes) -> CoreResult<()> {
        let entry = self.get(session_id).ok_or_else(|| not_found(session_id))?;
        let guard = entry.lock().await;
        match &guard.backend {
            SessionBackend::Ssh { shell, .. } => shell.write(data).await.map_err(CoreError::from),
            SessionBackend::Local { pty } => pty.write(data).await.map_err(CoreError::from),
            SessionBackend::Closed => Err(not_found(session_id)),
        }
    }

    /// Write text, encoding it with the session charset.
    pub async fn write_text(&self, session_id: &str, text: &str) -> CoreResult<()> {
        let entry = self.get(session_id).ok_or_else(|| not_found(session_id))?;
        let guard = entry.lock().await;
        let charset = crate::decoder::resolve_charset(Some(&guard.charset));
        let data = bytes::Bytes::from(encode_input(charset, text));
        match &guard.backend {
            SessionBackend::Ssh { shell, .. } => shell.write(data).await.map_err(CoreError::from),
            SessionBackend::Local { pty } => pty.write(data).await.map_err(CoreError::from),
            SessionBackend::Closed => Err(not_found(session_id)),
        }
    }

    pub async fn resize(&self, session_id: &str, cols: u16, rows: u16) -> CoreResult<()> {
        let entry = self.get(session_id).ok_or_else(|| not_found(session_id))?;
        let guard = entry.lock().await;
        match &guard.backend {
            SessionBackend::Ssh { shell, .. } => shell.resize(cols, rows).map_err(CoreError::from),
            SessionBackend::Local { pty } => pty.resize(cols, rows).map_err(CoreError::from),
            SessionBackend::Closed => Err(not_found(session_id)),
        }
    }

    /// Pause / resume the output pump for a session.
    pub fn set_flow_paused(&self, session_id: &str, paused: bool) -> CoreResult<()> {
        let flags = self
            .shared
            .flags
            .get(session_id)
            .ok_or_else(|| not_found(session_id))?;
        flags.paused.store(paused, Ordering::SeqCst);
        if !paused {
            flags.wake.notify_one();
        }
        Ok(())
    }

    /// Close a session: close the shell/pty, disconnect the SSH connection
    /// unless another session or SFTP client still uses it, emit exit.
    /// Idempotent: closing an unknown session is a no-op.
    pub async fn close(&self, session_id: &str) -> CoreResult<()> {
        let Some(flags) = self.shared.flags.get(session_id).map(|f| f.clone()) else {
            return Ok(());
        };
        if let Some(entry) = self.get(session_id) {
            let guard = entry.lock().await;
            match &guard.backend {
                SessionBackend::Ssh { shell, .. } => shell.close(),
                SessionBackend::Local { pty } => pty.kill(),
                SessionBackend::Closed => {}
            }
        }
        if !flags.exit_emitted.swap(true, Ordering::SeqCst) {
            self.emit_exit(SessionExitEvent::closed(session_id));
        }
        self.shared.remove_and_release(session_id).await;
        Ok(())
    }

    pub fn emit_exit(&self, event: SessionExitEvent) {
        events::emit(&self.app, ev::SESSION_EXIT, event);
    }

    /// Disconnect `conn` unless a session or SFTP client still uses it.
    pub async fn release_connection(&self, conn: Arc<SshConnection>) {
        self.shared.release_connection(conn).await;
    }

    /// Is `conn` referenced by a live session or SFTP client?
    pub fn connection_in_use(&self, conn: &Arc<SshConnection>) -> bool {
        self.shared.connection_in_use(conn)
    }
}

impl Shared {
    fn connection_in_use(&self, conn: &Arc<SshConnection>) -> bool {
        self.connections
            .iter()
            .any(|c| Arc::ptr_eq(c.value(), conn))
            || self
                .sftp
                .iter()
                .any(|c| Arc::ptr_eq(&c.value().connection, conn))
    }

    async fn release_connection(&self, conn: Arc<SshConnection>) {
        if self.connection_in_use(&conn) {
            return;
        }
        // Something outside the registries (a tunnel, an in-flight command)
        // still holds the connection: leave it to that owner.
        if Arc::strong_count(&conn) > 1 {
            tracing::debug!(target = %conn.describe(), "connection still referenced; not disconnecting");
            return;
        }
        if let Err(err) = conn.disconnect().await {
            tracing::debug!(%err, "disconnect failed");
        }
    }

    /// Remove every trace of a session and release its connection.
    async fn remove_and_release(&self, session_id: &str) {
        self.flags.remove(session_id);
        self.connections.remove(session_id);
        let Some((_, entry)) = self.sessions.remove(session_id) else {
            return;
        };
        let connection = {
            let mut guard = entry.lock().await;
            let backend = std::mem::replace(&mut guard.backend, SessionBackend::Closed);
            drop(backend);
            guard.connection.take()
        };
        drop(entry);
        if let Some(conn) = connection {
            self.release_connection(conn).await;
        }
    }
}

/// Deliver decoded text: emit immediately, or buffer while paused.
fn deliver(
    app: &AppHandle,
    session_id: &str,
    flags: &SessionFlags,
    pending: &mut String,
    text: &str,
    force: bool,
) {
    if !force && flags.paused.load(Ordering::SeqCst) {
        if pending.len() + text.len() > PAUSE_BUFFER_LIMIT {
            if !flags.dropped_output.swap(true, Ordering::SeqCst) {
                tracing::warn!(
                    session_id,
                    "paused session exceeded the output buffer; dropping output"
                );
            }
            return;
        }
        pending.push_str(text);
        return;
    }
    if pending.is_empty() && text.is_empty() {
        return;
    }
    let mut data = std::mem::take(pending);
    data.push_str(text);
    events::emit(
        app,
        ev::SESSION_DATA,
        SessionDataEvent {
            session_id: session_id.to_string(),
            data,
        },
    );
}

async fn pump(
    shared: Arc<Shared>,
    session_id: String,
    mut source: Source,
    mut decoder: StreamDecoder,
    flags: Arc<SessionFlags>,
) {
    let mut pending = String::new();
    let mut raw: Vec<u8> = Vec::with_capacity(16 * 1024);
    let exit: (Option<i32>, Option<String>);

    loop {
        let event = tokio::select! {
            ev = source.recv() => ev,
            _ = flags.wake.notified() => {
                // Resumed: flush what was buffered while paused.
                deliver(&shared.app, &session_id, &flags, &mut pending, "", false);
                continue;
            }
        };
        match event {
            None => {
                exit = (None, None);
                break;
            }
            Some(Pumped::Eof) => continue,
            Some(Pumped::Exit { code, signal }) => {
                exit = (code, signal);
                break;
            }
            Some(Pumped::Data(first)) => {
                raw.clear();
                raw.extend_from_slice(&first);
                let mut deferred_exit: Option<(Option<i32>, Option<String>)> = None;
                while raw.len() < COALESCE_LIMIT {
                    match source.try_recv() {
                        Ok(Pumped::Data(b)) => raw.extend_from_slice(&b),
                        Ok(Pumped::Eof) => {}
                        Ok(Pumped::Exit { code, signal }) => {
                            deferred_exit = Some((code, signal));
                            break;
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            deferred_exit = Some((None, None));
                            break;
                        }
                    }
                }
                let text = decoder.decode(&raw, false);
                deliver(&shared.app, &session_id, &flags, &mut pending, &text, false);
                if let Some(e) = deferred_exit {
                    exit = e;
                    break;
                }
            }
        }
    }

    // Flush the decoder and anything buffered while paused.
    let tail = decoder.decode(&[], true);
    deliver(&shared.app, &session_id, &flags, &mut pending, &tail, true);

    if !flags.exit_emitted.swap(true, Ordering::SeqCst) {
        let (code, signal) = exit;
        let mut event = SessionExitEvent::exited(&session_id, code);
        if let Some(sig) = signal {
            event.exit_signal = Some(sig);
            event.reason = ExitReason::Signaled;
        }
        events::emit(&shared.app, ev::SESSION_EXIT, event);
    }
    shared.remove_and_release(&session_id).await;
}

/// Split terminal input into per-line writes for paced (`lineDelayMs`)
/// automated input. Mirrors `splitTerminalInputIntoLineWrites` in
/// `terminalBridge.cjs`: every `\r`, `\n` or `\r\n` terminates a chunk that
/// ends in `\r`; a trailing partial line is kept as-is.
pub fn split_line_writes(data: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut line = String::new();
    let mut chars = data.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' || c == '\n' {
            if c == '\r' && chars.peek() == Some(&'\n') {
                chars.next();
            }
            line.push('\r');
            chunks.push(std::mem::take(&mut line));
            continue;
        }
        line.push(c);
    }
    if !line.is_empty() {
        chunks.push(line);
    }
    if chunks.is_empty() {
        chunks.push(data.to_string());
    }
    chunks
}

/// Clamp the renderer's `lineDelayMs` like the Electron bridge (0 → off, max 2 s).
pub fn line_delay_ms(value: Option<u64>) -> u64 {
    match value {
        Some(ms) if ms > 0 => ms.min(2000),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_lines_with_carriage_returns() {
        assert_eq!(
            split_line_writes("a\nb\r\nc\rd"),
            vec!["a\r", "b\r", "c\r", "d"]
        );
        assert_eq!(split_line_writes("ls\n"), vec!["ls\r"]);
        assert_eq!(split_line_writes("single"), vec!["single"]);
        assert_eq!(split_line_writes(""), vec![""]);
        assert_eq!(split_line_writes("\n\n"), vec!["\r", "\r"]);
    }

    #[test]
    fn line_delay_is_clamped() {
        assert_eq!(line_delay_ms(None), 0);
        assert_eq!(line_delay_ms(Some(0)), 0);
        assert_eq!(line_delay_ms(Some(50)), 50);
        assert_eq!(line_delay_ms(Some(10_000)), 2000);
    }
}

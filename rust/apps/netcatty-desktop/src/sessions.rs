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
use crate::stream::{InputMeta, SessionInput, StreamEvent, StreamExit, StreamTransport};
use netcatty_core::ipc::{
    events as ev, ExitReason, SessionDataEvent, SessionDataMeta, SessionExitEvent,
};
use netcatty_core::{CoreError, CoreResult};
use netcatty_pty::{PtyEvent, PtySession};
use netcatty_sftp::SftpClient;
use netcatty_ssh::shell::ShellEvent;
use netcatty_ssh::{ShellSession, SshConnection};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Runtime};
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
    /// Telnet / serial / Mosh / EternalTerminal: the transport owns its I/O
    /// and streams output on `events` (see [`crate::stream`]).
    Stream {
        transport: Arc<dyn StreamTransport>,
        events: mpsc::Receiver<StreamEvent>,
    },
    /// Backend already torn down (entry is being removed).
    Closed,
}

pub struct SessionEntry {
    pub session_id: String,
    pub host_id: Option<String>,
    pub label: String,
    /// `ssh` | `local` | `telnet` | `serial` | `mosh` | `et`.
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
    /// Charset requested by `session_set_encoding`, applied by the pump
    /// before it decodes the next chunk.
    pub charset_change: parking_lot::Mutex<Option<String>>,
    /// AI exec state: rolling idle-prompt tracker, output taps, shell kind
    /// and the "prompt never returned" latch (see [`AiExecTap`]).
    pub ai: AiExecTap,
}

/// Output tap of a session for AI command execution (`catty exec`, MCP
/// `terminal_execute`). Every decoded chunk of every session kind passes
/// through [`deliver_with_meta`] once; it updates the prompt tracker and is
/// copied to each live subscriber. Subscribers see the channel close when
/// the session ends (the flags are dropped with the pump).
#[derive(Default)]
pub struct AiExecTap {
    pub prompt: parking_lot::Mutex<netcatty_ptyexec::PromptTracker>,
    subscribers: parking_lot::Mutex<Vec<mpsc::UnboundedSender<String>>>,
    pub shell_kind: Arc<netcatty_ptyexec::ShellKindState>,
    pub prompt_recovery_pending: Arc<AtomicBool>,
    /// `(protocol, label, host_id)` recorded at insert (no entry lock needed).
    pub info: parking_lot::Mutex<(&'static str, String, Option<String>)>,
}

impl AiExecTap {
    fn observe(&self, text: &str) {
        if text.is_empty() {
            return;
        }
        self.prompt.lock().track(text, netcatty_core::ids::now_ms());
        let mut subs = self.subscribers.lock();
        if !subs.is_empty() {
            subs.retain(|tx| tx.send(text.to_string()).is_ok());
        }
    }

    /// New subscriber receiving decoded output from now on.
    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.subscribers.lock().push(tx);
        rx
    }
}

pub type SftpMap = Arc<dashmap::DashMap<String, Arc<SftpClient>>>;

/// State shared by the registry handle and every pump task.
pub(crate) struct Shared<R: Runtime> {
    pub app: AppHandle<R>,
    pub sessions: dashmap::DashMap<String, Arc<Mutex<SessionEntry>>>,
    pub flags: dashmap::DashMap<String, Arc<SessionFlags>>,
    /// Session id → its SSH connection (lock-free view for transport reuse).
    pub connections: dashmap::DashMap<String, Arc<SshConnection>>,
    /// SFTP clients (owned by `AppState`) — consulted before disconnecting.
    pub sftp: SftpMap,
    /// Generic output subscribers ([`SessionRegistry::subscribe_output`]).
    pub taps: OutputTaps,
}

/// One event of [`SessionRegistry::subscribe_all_output`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputTapEvent {
    /// Decoded output of a session (every chunk, also while paused).
    Data { session_id: String, text: String },
    /// The session ended; no more data follows for it.
    Closed { session_id: String },
}

/// Generic taps on decoded session output, fed from the same place as the
/// session-log tap. Subscribers get unbounded channels; dropped receivers
/// are pruned on the next publish.
#[derive(Default)]
pub struct OutputTaps {
    per_session:
        parking_lot::Mutex<std::collections::HashMap<String, Vec<mpsc::UnboundedSender<String>>>>,
    all: parking_lot::Mutex<Vec<mpsc::UnboundedSender<OutputTapEvent>>>,
}

impl OutputTaps {
    fn publish(&self, session_id: &str, text: &str) {
        {
            let mut all = self.all.lock();
            if !all.is_empty() {
                all.retain(|tx| {
                    tx.send(OutputTapEvent::Data {
                        session_id: session_id.to_string(),
                        text: text.to_string(),
                    })
                    .is_ok()
                });
            }
        }
        let mut per_session = self.per_session.lock();
        if let Some(subscribers) = per_session.get_mut(session_id) {
            subscribers.retain(|tx| tx.send(text.to_string()).is_ok());
            if subscribers.is_empty() {
                per_session.remove(session_id);
            }
        }
    }

    fn session_closed(&self, session_id: &str) {
        // Dropping the senders ends the per-session receivers.
        self.per_session.lock().remove(session_id);
        self.all.lock().retain(|tx| {
            tx.send(OutputTapEvent::Closed {
                session_id: session_id.to_string(),
            })
            .is_ok()
        });
    }
}

/// Feed decoded output to the generic taps of the app's session registry.
fn publish_output<R: Runtime>(app: &AppHandle<R>, session_id: &str, text: &str) {
    use tauri::Manager;
    if text.is_empty() {
        return;
    }
    if let Some(state) = app.try_state::<crate::state::AppState<R>>() {
        state.sessions.shared.taps.publish(session_id, text);
    }
}

pub struct SessionRegistry<R: Runtime> {
    pub app: AppHandle<R>,
    pub(crate) shared: Arc<Shared<R>>,
}

// Manual impl: `#[derive(Clone)]` would require `R: Clone`.
impl<R: Runtime> Clone for SessionRegistry<R> {
    fn clone(&self) -> Self {
        Self {
            app: self.app.clone(),
            shared: self.shared.clone(),
        }
    }
}

/// Unified backend event.
enum Pumped {
    Data(bytes::Bytes),
    /// Pre-decoded text with renderer hints (stream backends only).
    Text(String, Option<SessionDataMeta>),
    Eof,
    Exit {
        code: Option<i32>,
        signal: Option<String>,
    },
    /// Stream backend exit with explicit reason / error.
    StreamExit(StreamExit),
}

enum Source {
    Ssh(mpsc::Receiver<ShellEvent>),
    Local(mpsc::Receiver<PtyEvent>),
    Stream(mpsc::Receiver<StreamEvent>, Arc<dyn StreamTransport>),
}

impl Source {
    async fn recv(&mut self) -> Option<Pumped> {
        match self {
            Source::Ssh(rx) => rx.recv().await.map(Pumped::from),
            Source::Local(rx) => rx.recv().await.map(Pumped::from),
            Source::Stream(rx, _) => rx.recv().await.map(Pumped::from),
        }
    }

    fn try_recv(&mut self) -> Result<Pumped, TryRecvError> {
        match self {
            Source::Ssh(rx) => rx.try_recv().map(Pumped::from),
            Source::Local(rx) => rx.try_recv().map(Pumped::from),
            Source::Stream(rx, _) => rx.try_recv().map(Pumped::from),
        }
    }

    /// Let a stream transport see decoded output (auto-login).
    fn observe(&self, text: &str, charset: crate::decoder::Charset) {
        if let Source::Stream(_, transport) = self {
            if !text.is_empty() {
                transport.observe_output(text, charset);
            }
        }
    }
}

impl From<StreamEvent> for Pumped {
    fn from(e: StreamEvent) -> Self {
        match e {
            StreamEvent::Data(b) => Pumped::Data(b),
            StreamEvent::Text { text, meta } => Pumped::Text(text, meta),
            StreamEvent::Exit(exit) => Pumped::StreamExit(exit),
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

impl<R: Runtime> SessionRegistry<R> {
    pub fn new(app: AppHandle<R>, sftp: SftpMap) -> Self {
        Self {
            app: app.clone(),
            shared: Arc::new(Shared {
                app,
                sessions: dashmap::DashMap::new(),
                flags: dashmap::DashMap::new(),
                connections: dashmap::DashMap::new(),
                sftp,
                taps: OutputTaps::default(),
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
            SessionBackend::Stream { transport, events } => {
                let (_tx, rx) = mpsc::channel(1);
                Source::Stream(std::mem::replace(events, rx), transport.clone())
            }
            SessionBackend::Closed => {
                tracing::warn!(session_id, "refusing to insert a closed session backend");
                return;
            }
        };
        let decoder = StreamDecoder::new(Some(&entry.charset));
        let charset = crate::decoder::resolve_charset(Some(&entry.charset));
        let flags = Arc::new(SessionFlags::default());
        // Local shells have a confirmed kind from the executable; remote
        // kinds are probed lazily on the first AI exec.
        *flags.ai.info.lock() = (entry.protocol, entry.label.clone(), entry.host_id.clone());
        if entry.protocol == "local" {
            let kind = netcatty_ptyexec::shell_kind::classify_local_shell_type(&entry.label, std::env::consts::OS);
            flags.ai.shell_kind.set_shell_kind(Some(kind.to_string()));
        }
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
        tauri::async_runtime::spawn(pump(shared, session_id, source, decoder, charset, flags));
    }

    /// Decoded output of one session from now on; the receiver ends when
    /// the session does.
    pub fn subscribe_output(&self, session_id: &str) -> mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.shared
            .taps
            .per_session
            .lock()
            .entry(session_id.to_string())
            .or_default()
            .push(tx);
        rx
    }

    /// Decoded output and end of every session.
    pub fn subscribe_all_output(&self) -> mpsc::UnboundedReceiver<OutputTapEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.shared.taps.all.lock().push(tx);
        rx
    }

    pub fn get(&self, session_id: &str) -> Option<Arc<Mutex<SessionEntry>>> {
        self.shared.sessions.get(session_id).map(|e| e.clone())
    }

    /// AI exec tap of a live session (prompt tracker, output subscription,
    /// shell kind). `None` for unknown / ended sessions.
    pub fn flags_of(&self, session_id: &str) -> Option<Arc<SessionFlags>> {
        self.shared.flags.get(session_id).map(|f| f.clone())
    }

    /// Subscribe to decoded output of a live session (closed on exit).
    pub fn tap_output(&self, session_id: &str) -> Option<mpsc::UnboundedReceiver<String>> {
        self.flags_of(session_id).map(|f| f.ai.subscribe())
    }

    /// Ids of every live terminal session.
    pub fn session_ids(&self) -> Vec<String> {
        self.shared.sessions.iter().map(|e| e.key().clone()).collect()
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
            SessionBackend::Stream { transport, .. } => {
                let transport = transport.clone();
                let charset = crate::decoder::resolve_charset(Some(&guard.charset));
                drop(guard);
                transport
                    .write_input(SessionInput::Bytes(data), &InputMeta::user(), charset)
                    .await
            }
            SessionBackend::Closed => Err(not_found(session_id)),
        }
    }

    /// Write renderer input with its `session_write` flags. SSH / local
    /// sessions encode text with the session charset; stream transports
    /// apply their protocol rules (and auto-login takeover detection).
    pub async fn write_input(
        &self,
        session_id: &str,
        input: SessionInput,
        meta: &InputMeta,
    ) -> CoreResult<()> {
        let entry = self.get(session_id).ok_or_else(|| not_found(session_id))?;
        let guard = entry.lock().await;
        let charset = crate::decoder::resolve_charset(Some(&guard.charset));
        if let SessionBackend::Stream { transport, .. } = &guard.backend {
            let transport = transport.clone();
            drop(guard);
            return transport.write_input(input, meta, charset).await;
        }
        let data = match input {
            SessionInput::Bytes(bytes) => bytes,
            SessionInput::Text(text) => bytes::Bytes::from(encode_input(charset, &text)),
        };
        match &guard.backend {
            SessionBackend::Ssh { shell, .. } => shell.write(data).await.map_err(CoreError::from),
            SessionBackend::Local { pty } => pty.write(data).await.map_err(CoreError::from),
            SessionBackend::Stream { .. } | SessionBackend::Closed => Err(not_found(session_id)),
        }
    }

    /// Line-mode "user started typing" notification (auto-login takeover).
    /// Unknown or non-stream sessions are ignored.
    pub async fn notify_user_input(&self, session_id: &str) {
        if let Some(transport) = self.transport_of(session_id).await {
            transport.notify_user_input();
        }
    }

    /// The stream transport of a live session.
    pub async fn transport_of(&self, session_id: &str) -> Option<Arc<dyn StreamTransport>> {
        let entry = self.get(session_id)?;
        let guard = entry.lock().await;
        match &guard.backend {
            SessionBackend::Stream { transport, .. } => Some(transport.clone()),
            _ => None,
        }
    }

    /// Switch the output decoder / input encoder of a live session
    /// (`setSessionEncoding`). Returns the normalised charset label.
    pub async fn set_charset(&self, session_id: &str, label: &str) -> CoreResult<String> {
        let entry = self.get(session_id).ok_or_else(|| not_found(session_id))?;
        let normalized = crate::decoder::resolve_charset(Some(label))
            .label()
            .to_ascii_lowercase();
        entry.lock().await.charset = normalized.clone();
        if let Some(flags) = self.shared.flags.get(session_id) {
            *flags.charset_change.lock() = Some(normalized.clone());
        }
        Ok(normalized)
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
            SessionBackend::Stream { transport, .. } => {
                let transport = transport.clone();
                drop(guard);
                transport
                    .write_input(
                        SessionInput::Text(text.to_string()),
                        &InputMeta::automated(),
                        charset,
                    )
                    .await
            }
            SessionBackend::Closed => Err(not_found(session_id)),
        }
    }

    pub async fn resize(&self, session_id: &str, cols: u16, rows: u16) -> CoreResult<()> {
        let entry = self.get(session_id).ok_or_else(|| not_found(session_id))?;
        let guard = entry.lock().await;
        match &guard.backend {
            SessionBackend::Ssh { shell, .. } => shell.resize(cols, rows).map_err(CoreError::from),
            SessionBackend::Local { pty } => pty.resize(cols, rows).map_err(CoreError::from),
            SessionBackend::Stream { transport, .. } => transport.resize(cols, rows),
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
                SessionBackend::Stream { transport, .. } => transport.close(),
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

impl<R: Runtime> Shared<R> {
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
        // Session-log hook: finalize the session's automatic log (idempotent;
        // runs before the entry is removed).
        crate::commands::sessionlog::session_ended(&self.app, session_id);
        crate::commands::zmodem::session_ended(&self.app, session_id);
        self.taps.session_closed(session_id);
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
fn deliver<R: Runtime>(
    app: &AppHandle<R>,
    session_id: &str,
    flags: &SessionFlags,
    pending: &mut String,
    text: &str,
    force: bool,
) {
    deliver_with_meta(app, session_id, flags, pending, text, force, None);
}

/// [`deliver`] with renderer hints. A chunk carrying `meta` is emitted at
/// once (together with anything buffered) so its hint stays attached.
fn deliver_with_meta<R: Runtime>(
    app: &AppHandle<R>,
    session_id: &str,
    flags: &SessionFlags,
    pending: &mut String,
    text: &str,
    force: bool,
    meta: Option<SessionDataMeta>,
) {
    let force = force || meta.is_some();
    // Session-log tap: every decoded chunk of every session kind goes through
    // here exactly once, before flow-control buffering (paused output is
    // logged too). Only buffers; never blocks on I/O.
    crate::commands::sessionlog::tap_output(app, session_id, text);
    // Generic output taps (script automation, ...): same point, same rules.
    publish_output(app, session_id, text);
    // AI exec tap (prompt tracking + subscribers), same single pass.
    flags.ai.observe(text);
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
            meta,
        },
    );
}

async fn pump<R: Runtime>(
    shared: Arc<Shared<R>>,
    session_id: String,
    mut source: Source,
    mut decoder: StreamDecoder,
    mut charset: crate::decoder::Charset,
    flags: Arc<SessionFlags>,
) {
    let mut pending = String::new();
    let mut raw: Vec<u8> = Vec::with_capacity(16 * 1024);
    let exit: (Option<i32>, Option<String>);
    let mut stream_exit: Option<StreamExit> = None;

    loop {
        let event = tokio::select! {
            ev = source.recv() => ev,
            _ = flags.wake.notified() => {
                // Resumed: flush what was buffered while paused.
                deliver(&shared.app, &session_id, &flags, &mut pending, "", false);
                // ZMODEM hook: a withheld partial header that timed out.
                let flushed = crate::commands::zmodem::poll_flush(&shared.app, &session_id);
                if !flushed.is_empty() {
                    let text = decoder.decode(&flushed, false);
                    deliver(&shared.app, &session_id, &flags, &mut pending, &text, false);
                }
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
            Some(Pumped::StreamExit(e)) => {
                stream_exit = Some(e);
                exit = (None, None);
                break;
            }
            Some(Pumped::Text(text, meta)) => {
                deliver_with_meta(
                    &shared.app,
                    &session_id,
                    &flags,
                    &mut pending,
                    &text,
                    false,
                    meta,
                );
            }
            Some(Pumped::Data(first)) => {
                raw.clear();
                raw.extend_from_slice(&first);
                let mut deferred_exit: Option<(Option<i32>, Option<String>)> = None;
                let mut deferred_text: Option<(String, Option<SessionDataMeta>)> = None;
                while raw.len() < COALESCE_LIMIT {
                    match source.try_recv() {
                        Ok(Pumped::Data(b)) => raw.extend_from_slice(&b),
                        Ok(Pumped::Eof) => {}
                        Ok(Pumped::Exit { code, signal }) => {
                            deferred_exit = Some((code, signal));
                            break;
                        }
                        Ok(Pumped::StreamExit(e)) => {
                            stream_exit = Some(e);
                            deferred_exit = Some((None, None));
                            break;
                        }
                        Ok(Pumped::Text(text, meta)) => {
                            deferred_text = Some((text, meta));
                            break;
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            deferred_exit = Some((None, None));
                            break;
                        }
                    }
                }
                if let Some(label) = flags.charset_change.lock().take() {
                    // Flush the old decoder's partial state with the old
                    // charset, then decode new bytes with the new one.
                    let tail = decoder.decode(&[], true);
                    deliver(&shared.app, &session_id, &flags, &mut pending, &tail, false);
                    decoder = StreamDecoder::new(Some(&label));
                    charset = crate::decoder::resolve_charset(Some(&label));
                }
                // ZMODEM / YMODEM hook: transfer bytes never reach the display.
                crate::commands::zmodem::filter_output(&shared.app, &session_id, &mut raw);
                let text = decoder.decode(&raw, false);
                source.observe(&text, charset);
                deliver(&shared.app, &session_id, &flags, &mut pending, &text, false);
                if let Some((text, meta)) = deferred_text {
                    deliver_with_meta(
                        &shared.app,
                        &session_id,
                        &flags,
                        &mut pending,
                        &text,
                        false,
                        meta,
                    );
                }
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
        let event = match stream_exit {
            Some(stream) => stream_exit_event(&session_id, stream),
            None => {
                let (code, signal) = exit;
                let mut event = SessionExitEvent::exited(&session_id, code);
                if let Some(sig) = signal {
                    event.exit_signal = Some(sig);
                    event.reason = ExitReason::Signaled;
                }
                event
            }
        };
        events::emit(&shared.app, ev::SESSION_EXIT, event);
    }
    shared.remove_and_release(&session_id).await;
}

/// `netcatty:exit` of a stream backend. A numeric signal goes to `signal`
/// (node-pty reports numbers), a named one to `exitSignal`.
pub(crate) fn stream_exit_event(session_id: &str, exit: StreamExit) -> SessionExitEvent {
    let (signal, exit_signal) = match exit.signal {
        Some(sig) => match sig.parse::<i32>() {
            Ok(n) => (Some(n), None),
            Err(_) => (None, Some(sig)),
        },
        None => (None, None),
    };
    SessionExitEvent {
        session_id: session_id.to_string(),
        exit_code: exit.exit_code,
        signal,
        exit_signal,
        error: exit.error,
        reason: exit.reason,
        remote_closed_without_exit_status: None,
    }
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

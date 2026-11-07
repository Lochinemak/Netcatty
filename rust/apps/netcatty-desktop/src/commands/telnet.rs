//! Telnet sessions (`startTelnetSession`, `getTelnetEchoMode`) and the
//! auto-login driver shared with serial sessions.
//!
//! Port of `electron/bridges/terminalBridge/telnetSession.cjs`: a TCP
//! connection whose bytes go through [`netcatty_telnet::TelnetCodec`]
//! (negotiation activates lazily on the first IAC from the peer), with
//! `netcatty:telnet:echo-mode` events, NAWS on resize and the
//! Username / Password auto-login.

use super::CmdResult;
use crate::decoder::{encode_input, Charset};
use crate::sessions::{SessionBackend, SessionEntry};
use crate::state::Ctx;
use crate::stream::{
    is_user_keystroke, InputMeta, SessionInput, StreamEvent, StreamExit, StreamTransport,
};
use bytes::Bytes;
use netcatty_core::ipc::events as ev;
use netcatty_core::ipc::StartSessionResult;
use netcatty_core::{CoreError, CoreResult};
use netcatty_telnet::{
    normalize_nvt_newlines, AutoLogin, AutoLoginAction, AutoLoginOptions, EchoMode, TelnetCodec,
};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Runtime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Electron's telnet connect timeout.
pub const TELNET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_CHUNK: usize = 16 * 1024;
pub(crate) const STREAM_CHANNEL_CAPACITY: usize = 1024;

/// `startTelnetSession` options.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelnetSessionOptions {
    #[serde(default)]
    pub session_id: Option<String>,
    pub hostname: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub cols: Option<u16>,
    #[serde(default)]
    pub rows: Option<u16>,
    #[serde(default)]
    pub charset: Option<String>,
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub host_id: Option<String>,
    #[serde(default)]
    pub boot_epoch: Option<u64>,
    /// Automatic session log (`sessionLog` of the start options).
    #[serde(default)]
    pub session_log: Option<netcatty_core::ipc::SessionLogConfig>,
}

/// `netcatty:telnet:echo-mode` payload and `getTelnetEchoMode` success shape.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelnetEchoModeEvent {
    pub session_id: String,
    pub remote_echo: bool,
    pub local_echo: bool,
}

/// `getTelnetEchoMode` result.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelnetEchoModeResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_echo: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_echo: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `{ sessionId, bootEpoch? }` — auto-login and Mosh ready events.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionBootEvent {
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_epoch: Option<u64>,
}

/// Honor the renderer's `sessionId`, else generate one.
pub(crate) fn session_id_or_new(requested: Option<&String>) -> String {
    requested
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(netcatty_core::new_id)
}

pub(crate) fn ensure_free<R: Runtime>(state: &Ctx<'_, R>, session_id: &str) -> CoreResult<()> {
    if state.sessions.contains(session_id) {
        return Err(CoreError::invalid(format!(
            "session {session_id} already exists"
        )));
    }
    Ok(())
}

pub(crate) fn charset_or_default(charset: Option<&String>) -> String {
    charset
        .filter(|c| !c.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| crate::decoder::DEFAULT_CHARSET.to_string())
}

// ---------------------------------------------------------------------------
// Auto-login driver (telnet + serial)
// ---------------------------------------------------------------------------

/// Runs a [`AutoLogin`] detector for one session: emits the renderer events
/// and arms the expiry timer. Writes are returned to the caller, which
/// knows the wire format.
pub(crate) struct AutoLoginDriver<R: Runtime> {
    app: AppHandle<R>,
    session_id: String,
    boot_epoch: Option<u64>,
    detector: parking_lot::Mutex<Option<AutoLogin>>,
    /// Serial reports a stalled exchange as `auto-login-cancelled`; telnet
    /// leaves `onIncomplete` unset in Electron, so it stays silent.
    report_incomplete: bool,
}

impl<R: Runtime> AutoLoginDriver<R> {
    /// `None` detector when no credentials are saved.
    pub(crate) fn new(
        app: AppHandle<R>,
        session_id: String,
        boot_epoch: Option<u64>,
        username: Option<String>,
        password: Option<String>,
        report_incomplete: bool,
    ) -> Arc<Self> {
        let options = AutoLoginOptions {
            username,
            password,
            ..Default::default()
        };
        let detector = options.has_credentials().then(|| AutoLogin::new(options));
        Arc::new(Self {
            app,
            session_id,
            boot_epoch,
            detector: parking_lot::Mutex::new(detector),
            report_incomplete,
        })
    }

    fn emit(&self, event: &str) {
        crate::events::emit(
            &self.app,
            event,
            SessionBootEvent {
                session_id: self.session_id.clone(),
                boot_epoch: self.boot_epoch,
            },
        );
    }

    /// Emit events for `actions`; return the texts to write.
    fn dispatch(&self, actions: Vec<AutoLoginAction>) -> Vec<String> {
        let mut writes = Vec::new();
        for action in actions {
            match action {
                AutoLoginAction::Write(text) => writes.push(text),
                AutoLoginAction::Complete => self.emit(ev::TELNET_AUTO_LOGIN_COMPLETE),
                AutoLoginAction::UserInput => self.emit(ev::TELNET_AUTO_LOGIN_CANCELLED),
                AutoLoginAction::Incomplete => {
                    if self.report_incomplete {
                        self.emit(ev::TELNET_AUTO_LOGIN_CANCELLED);
                    }
                }
            }
        }
        writes
    }

    pub(crate) fn on_output(&self, text: &str) -> Vec<String> {
        let actions = match self.detector.lock().as_mut() {
            Some(detector) => detector.handle_text(text),
            None => return Vec::new(),
        };
        self.dispatch(actions)
    }

    pub(crate) fn on_user_input(&self, data: Option<&str>) {
        let actions = match self.detector.lock().as_mut() {
            Some(detector) => detector.handle_user_input(data),
            None => return,
        };
        self.dispatch(actions);
    }

    pub(crate) fn cancel(&self) {
        if let Some(detector) = self.detector.lock().as_mut() {
            detector.cancel();
        }
    }

    /// Fire [`AutoLogin::expire`] at its deadline (unless cancelled first).
    pub(crate) fn arm_timer(self: &Arc<Self>, cancel: CancellationToken) {
        let Some(deadline) = self
            .detector
            .lock()
            .as_ref()
            .and_then(|d| d.expiry_deadline())
        else {
            return;
        };
        let driver = self.clone();
        tauri::async_runtime::spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                    let actions = match driver.detector.lock().as_mut() {
                        Some(detector) => detector.expire(),
                        None => return,
                    };
                    driver.dispatch(actions);
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Telnet transport
// ---------------------------------------------------------------------------

struct TelnetState {
    codec: TelnetCodec,
}

pub struct TelnetTransport<R: Runtime> {
    app: AppHandle<R>,
    session_id: String,
    state: parking_lot::Mutex<TelnetState>,
    wire: mpsc::UnboundedSender<Bytes>,
    autologin: Arc<AutoLoginDriver<R>>,
    cancel: CancellationToken,
}

impl<R: Runtime> TelnetTransport<R> {
    pub fn echo_mode(&self) -> EchoMode {
        self.state.lock().codec.echo_mode()
    }

    fn emit_echo(&self, mode: EchoMode) {
        emit_echo(&self.app, &self.session_id, mode);
    }

    /// Text → NVT newlines → charset → IAC escaping.
    fn encode_text(&self, text: &str, charset: Charset) -> Vec<u8> {
        let encoded = encode_input(charset, &normalize_nvt_newlines(text));
        self.state.lock().codec.outgoing(&encoded)
    }

    fn send(&self, bytes: Vec<u8>) -> CoreResult<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.wire
            .send(Bytes::from(bytes))
            .map_err(|_| CoreError::not_found(format!("session {} not found", self.session_id)))
    }
}

fn emit_echo<R: Runtime>(app: &AppHandle<R>, session_id: &str, mode: EchoMode) {
    crate::events::emit(
        app,
        ev::TELNET_ECHO_MODE,
        TelnetEchoModeEvent {
            session_id: session_id.to_string(),
            remote_echo: mode.remote_echo,
            local_echo: mode.local_echo,
        },
    );
}

#[async_trait::async_trait]
impl<R: Runtime> StreamTransport for TelnetTransport<R> {
    async fn write_input(
        &self,
        input: SessionInput,
        meta: &InputMeta,
        charset: Charset,
    ) -> CoreResult<()> {
        if is_user_keystroke(&input, meta) {
            self.autologin.on_user_input(Some(&input.as_text()));
        }
        let wire = match &input {
            SessionInput::Text(text) => self.encode_text(text, charset),
            SessionInput::Bytes(bytes) => self.state.lock().codec.outgoing(bytes),
        };
        self.send(wire)
    }

    fn resize(&self, cols: u16, rows: u16) -> CoreResult<()> {
        if cols == 0 || rows == 0 {
            return Err(CoreError::invalid(format!(
                "invalid terminal size {cols}x{rows}"
            )));
        }
        // NAWS only once telnet is active and the peer enabled it: raw TCP
        // peers would see the subnegotiation bytes as data.
        let frame = self.state.lock().codec.resize(cols, rows);
        match frame {
            Some(bytes) => self.send(bytes),
            None => Ok(()),
        }
    }

    fn close(&self) {
        self.autologin.cancel();
        self.cancel.cancel();
    }

    fn observe_output(&self, text: &str, charset: Charset) {
        for write in self.autologin.on_output(text) {
            let bytes = self.encode_text(&write, charset);
            let _ = self.send(bytes);
        }
    }

    fn notify_user_input(&self) {
        self.autologin.on_user_input(None);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Connect with Electron's timeout and error strings.
async fn connect(hostname: &str, port: u16) -> CoreResult<tokio::net::TcpStream> {
    match tokio::time::timeout(
        TELNET_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect((hostname, port)),
    )
    .await
    {
        Err(_) => Err(CoreError::timeout(format!(
            "Connection timeout to {hostname}:{port}"
        ))),
        Ok(Err(err)) => Err(CoreError::network(format!("Failed to connect: {err}"))),
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            Ok(stream)
        }
    }
}

/// Start a telnet session. Resolves once the TCP connection is up.
#[tauri::command]
pub async fn telnet_start<R: Runtime>(
    state: Ctx<'_, R>,
    payload: TelnetSessionOptions,
) -> CmdResult<StartSessionResult> {
    let session_id = session_id_or_new(payload.session_id.as_ref());
    ensure_free(&state, &session_id)?;
    let hostname = payload.hostname.trim().to_string();
    if hostname.is_empty() {
        return Err(CoreError::invalid("hostname is required"));
    }
    let port = payload.port.filter(|p| *p != 0).unwrap_or(23);
    let cols = payload.cols.filter(|c| *c > 0).unwrap_or(80);
    let rows = payload.rows.filter(|r| *r > 0).unwrap_or(24);
    tracing::info!(%hostname, port, "telnet: connecting");
    let stream = connect(&hostname, port).await?;
    ensure_free(&state, &session_id)?;

    let (reader, writer) = stream.into_split();
    let (events_tx, events_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
    let (wire_tx, wire_rx) = mpsc::unbounded_channel::<Bytes>();
    let cancel = CancellationToken::new();
    let autologin = AutoLoginDriver::new(
        state.app.clone(),
        session_id.clone(),
        payload.boot_epoch,
        payload.username.clone(),
        payload.password.clone(),
        false,
    );
    autologin.arm_timer(cancel.clone());
    let transport = Arc::new(TelnetTransport {
        app: state.app.clone(),
        session_id: session_id.clone(),
        state: parking_lot::Mutex::new(TelnetState {
            codec: TelnetCodec::new(cols, rows),
        }),
        wire: wire_tx.clone(),
        autologin,
        cancel: cancel.clone(),
    });
    spawn_writer(writer, wire_rx, cancel.clone());
    spawn_reader(reader, transport.clone(), wire_tx, events_tx, cancel);

    // Session-log hook (automatic log of this session).
    {
        let host = payload.hostname.trim();
        let label = payload
            .label
            .as_deref()
            .map(str::trim)
            .filter(|l| !l.is_empty());
        super::sessionlog::session_starting(
            &state.app,
            &session_id,
            payload.session_log.as_ref(),
            label.unwrap_or(host),
            host,
        );
    }
    state.sessions.insert(SessionEntry {
        session_id: session_id.clone(),
        host_id: payload.host_id.clone(),
        label: payload
            .label
            .clone()
            .filter(|l| !l.trim().is_empty())
            .unwrap_or_else(|| hostname.clone()),
        protocol: "telnet",
        backend: SessionBackend::Stream {
            transport,
            events: events_rx,
        },
        charset: charset_or_default(payload.charset.as_ref()),
        connection: None,
        created_at: netcatty_core::ids::now_ms(),
    });
    Ok(StartSessionResult { session_id })
}

fn spawn_writer(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut wire_rx: mpsc::UnboundedReceiver<Bytes>,
    cancel: CancellationToken,
) {
    tauri::async_runtime::spawn(async move {
        loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => break,
                next = wire_rx.recv() => next,
            };
            let Some(bytes) = next else { break };
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });
}

fn spawn_reader<R: Runtime>(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    transport: Arc<TelnetTransport<R>>,
    wire: mpsc::UnboundedSender<Bytes>,
    events: mpsc::Sender<StreamEvent>,
    cancel: CancellationToken,
) {
    tauri::async_runtime::spawn(async move {
        let mut buf = vec![0u8; READ_CHUNK];
        let exit = loop {
            let read = tokio::select! {
                _ = cancel.cancelled() => return,
                read = reader.read(&mut buf) => read,
            };
            match read {
                Ok(0) => break StreamExit::closed(),
                Ok(n) => {
                    let incoming = transport.state.lock().codec.incoming(&buf[..n]);
                    if !incoming.reply.is_empty() {
                        let _ = wire.send(Bytes::from(incoming.reply));
                    }
                    for mode in incoming.echo_updates {
                        transport.emit_echo(mode);
                    }
                    if !incoming.data.is_empty()
                        && events
                            .send(StreamEvent::Data(Bytes::from(incoming.data)))
                            .await
                            .is_err()
                    {
                        return;
                    }
                }
                Err(err) => break StreamExit::error(err.to_string()),
            }
        };
        transport.autologin.cancel();
        if !cancel.is_cancelled() {
            let _ = events.send(StreamEvent::Exit(exit)).await;
        }
        cancel.cancel();
    });
}

/// `getTelnetEchoMode`.
#[tauri::command]
pub async fn telnet_get_echo_mode<R: Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
) -> CmdResult<TelnetEchoModeResult> {
    let mode = state
        .sessions
        .transport_of(&session_id)
        .await
        .and_then(|t| {
            t.as_any()
                .downcast_ref::<TelnetTransport<R>>()
                .map(|t| t.echo_mode())
        });
    Ok(match mode {
        Some(mode) => TelnetEchoModeResult {
            success: true,
            session_id: Some(session_id),
            remote_echo: Some(mode.remote_echo),
            local_echo: Some(mode.local_echo),
            error: None,
        },
        None => TelnetEchoModeResult {
            success: false,
            session_id: None,
            remote_echo: None,
            local_echo: None,
            error: Some("Telnet echo mode unavailable".into()),
        },
    })
}

/// `notifySessionUserInput`: the renderer's line-mode buffer received its
/// first keystroke (cancels telnet / serial auto-login).
#[tauri::command]
pub async fn session_notify_user_input<R: Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
) -> CmdResult<()> {
    state.sessions.notify_user_input(&session_id).await;
    Ok(())
}

/// `setSessionEncoding` result.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetEncodingResult {
    pub ok: bool,
    pub encoding: String,
}

/// `setSessionEncoding`: switch a live session's output decoder and input
/// encoder. `{ ok: false }` for unknown sessions.
#[tauri::command]
pub async fn session_set_encoding<R: Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
    encoding: String,
) -> CmdResult<SetEncodingResult> {
    Ok(
        match state.sessions.set_charset(&session_id, &encoding).await {
            Ok(encoding) => SetEncodingResult { ok: true, encoding },
            Err(_) => SetEncodingResult {
                ok: false,
                encoding: if encoding.trim().is_empty() {
                    "utf-8".into()
                } else {
                    encoding
                },
            },
        },
    )
}

//! Serial sessions (`startSerialSession`, `listSerialPorts`).
//!
//! Port of `startSerialSession` / `listSerialPorts` in
//! `electron/bridges/terminalBridge.cjs`: hardware ports, PTY devices and
//! (Windows) `\\.\pipe\...` consoles through [`netcatty_serial`], the
//! byte-oriented Backspace expansion and the shared Username / Password
//! auto-login (`auto-login-cancelled` also reports a stalled exchange).

use super::telnet::{
    charset_or_default, ensure_free, session_id_or_new, AutoLoginDriver, STREAM_CHANNEL_CAPACITY,
};
use super::CmdResult;
use crate::decoder::{encode_input, Charset};
use crate::sessions::{SessionBackend, SessionEntry};
use crate::state::Ctx;
use crate::stream::{
    is_user_keystroke, InputMeta, SessionInput, StreamEvent, StreamExit, StreamTransport,
};
use bytes::Bytes;
use netcatty_core::ipc::StartSessionResult;
use netcatty_core::{CoreError, CoreResult};
use netcatty_serial::{
    expand_backspace, SerialEvent, SerialOptions, SerialPortListing, SerialSession,
};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;
use tauri::Runtime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// `startSerialSession` options.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SerialSessionOptions {
    #[serde(default)]
    pub session_id: Option<String>,
    pub path: String,
    #[serde(default)]
    pub baud_rate: Option<u32>,
    #[serde(default)]
    pub data_bits: Option<u8>,
    #[serde(default)]
    pub stop_bits: Option<f32>,
    #[serde(default)]
    pub parity: Option<String>,
    #[serde(default)]
    pub flow_control: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub charset: Option<String>,
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

pub struct SerialTransport<R: Runtime> {
    session_id: String,
    port: SerialSession,
    autologin: Arc<AutoLoginDriver<R>>,
    cancel: CancellationToken,
}

impl<R: Runtime> SerialTransport<R> {
    async fn send(&self, bytes: Vec<u8>) -> CoreResult<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.port
            .write(Bytes::from(bytes))
            .await
            .map_err(|_| CoreError::not_found(format!("session {} not found", self.session_id)))
    }
}

/// Text input → Backspace expansion → session charset.
pub fn encode_serial_text(text: &str, erase_char: Option<&str>, charset: Charset) -> Vec<u8> {
    let expanded = expand_backspace(text, erase_char, |s| encode_input(charset, s).len());
    encode_input(charset, &expanded)
}

#[async_trait::async_trait]
impl<R: Runtime> StreamTransport for SerialTransport<R> {
    async fn write_input(
        &self,
        input: SessionInput,
        meta: &InputMeta,
        charset: Charset,
    ) -> CoreResult<()> {
        if is_user_keystroke(&input, meta) {
            self.autologin.on_user_input(Some(&input.as_text()));
        }
        let bytes = match input {
            SessionInput::Text(text) => {
                encode_serial_text(&text, meta.serial_erase_char.as_deref(), charset)
            }
            SessionInput::Bytes(bytes) => bytes.to_vec(),
        };
        self.send(bytes).await
    }

    fn resize(&self, _cols: u16, _rows: u16) -> CoreResult<()> {
        // A serial line has no window size.
        Ok(())
    }

    fn close(&self) {
        self.autologin.cancel();
        self.cancel.cancel();
        self.port.close();
    }

    fn observe_output(&self, text: &str, charset: Charset) {
        for write in self.autologin.on_output(text) {
            // Straight to the port: not user input, cannot cancel itself.
            let bytes = Bytes::from(encode_input(charset, &write));
            if let Err(err) = self.port.try_write(bytes) {
                tracing::debug!(%err, "serial auto-login write failed");
            }
        }
    }

    fn notify_user_input(&self) {
        self.autologin.on_user_input(None);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Start a serial session. Resolves once the port is open.
#[tauri::command]
pub async fn serial_start<R: Runtime>(
    state: Ctx<'_, R>,
    payload: SerialSessionOptions,
) -> CmdResult<StartSessionResult> {
    let session_id = session_id_or_new(payload.session_id.as_ref());
    ensure_free(&state, &session_id)?;
    let options = SerialOptions::with_defaults(
        &payload.path,
        payload.baud_rate,
        payload.data_bits,
        payload.stop_bits,
        payload.parity.as_deref(),
        payload.flow_control.as_deref(),
    );
    tracing::info!(path = %options.path, baud = options.baud_rate, "serial: opening");
    let mut port = match SerialSession::open(options.clone()).await {
        Ok(port) => port,
        Err(netcatty_serial::SerialError::InvalidArgument(message)) => {
            return Err(CoreError::invalid(message))
        }
        Err(err) => return Err(CoreError::io(format!("Failed to open serial port: {err}"))),
    };
    if state.sessions.contains(&session_id) {
        port.close();
        return Err(CoreError::invalid(format!(
            "session {session_id} already exists"
        )));
    }

    let (events_tx, events_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
    let (_tx, placeholder) = mpsc::channel(1);
    let port_events = std::mem::replace(&mut port.events, placeholder);
    let cancel = CancellationToken::new();
    let autologin = AutoLoginDriver::new(
        state.app.clone(),
        session_id.clone(),
        payload.boot_epoch,
        payload.username.clone(),
        payload.password.clone(),
        true,
    );
    autologin.arm_timer(cancel.clone());
    let transport = Arc::new(SerialTransport {
        session_id: session_id.clone(),
        port,
        autologin,
        cancel: cancel.clone(),
    });
    spawn_forwarder(port_events, events_tx, transport.clone(), cancel);

    // Session-log hook (automatic log of this session).
    {
        let host = payload.path.trim();
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
            .unwrap_or_else(|| options.path.clone()),
        protocol: "serial",
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

fn spawn_forwarder<R: Runtime>(
    mut port_events: mpsc::Receiver<SerialEvent>,
    events: mpsc::Sender<StreamEvent>,
    transport: Arc<SerialTransport<R>>,
    cancel: CancellationToken,
) {
    tauri::async_runtime::spawn(async move {
        let exit = loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => return,
                next = port_events.recv() => next,
            };
            match next {
                Some(SerialEvent::Data(bytes)) => {
                    if events.send(StreamEvent::Data(bytes)).await.is_err() {
                        return;
                    }
                }
                Some(SerialEvent::Closed) | None => break StreamExit::closed(),
                Some(SerialEvent::Error(message)) => break StreamExit::error(message),
            }
        };
        transport.autologin.cancel();
        transport.port.close();
        if !cancel.is_cancelled() {
            let _ = events.send(StreamEvent::Exit(exit)).await;
        }
        cancel.cancel();
    });
}

/// `listSerialPorts` (hardware ports only; errors yield `[]`).
#[tauri::command]
pub async fn serial_list_ports() -> CmdResult<Vec<SerialPortListing>> {
    tokio::task::spawn_blocking(netcatty_serial::list_ports)
        .await
        .map_err(|err| CoreError::internal(format!("serial port listing failed: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_text_encoding_expands_backspace_per_encoded_byte() {
        let utf8 = crate::decoder::resolve_charset(Some("utf-8"));
        let gb = crate::decoder::resolve_charset(Some("gb18030"));
        assert_eq!(encode_serial_text("\x7f", Some("中"), utf8), vec![0x7f; 3]);
        assert_eq!(encode_serial_text("\x7f", Some("中"), gb), vec![0x7f; 2]);
        assert_eq!(encode_serial_text("\x08", None, utf8), vec![0x08]);
        assert_eq!(encode_serial_text("中", Some("中"), gb), vec![0xd6, 0xd0]);
    }
}

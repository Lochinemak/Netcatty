//! Terminal sessions whose backend owns its own I/O: telnet, serial, Mosh
//! and EternalTerminal.
//!
//! They plug into the [`crate::sessions::SessionRegistry`] as
//! [`crate::sessions::SessionBackend::Stream`]: output arrives as
//! [`StreamEvent`]s on a channel the registry pump drains (so flow pause,
//! charset decoding, coalescing and the single `netcatty:exit` work exactly
//! as for SSH / local sessions), and input / resize / close go through the
//! [`StreamTransport`] trait, which applies the protocol's own rules (telnet
//! NVT newlines and IAC escaping, serial backspace expansion, auto-login
//! takeover detection).

use crate::decoder::Charset;
use bytes::Bytes;
use netcatty_core::ipc::{ExitReason, SessionDataMeta};
use netcatty_core::CoreResult;
use std::any::Any;

/// Output of a stream backend.
#[derive(Debug)]
pub enum StreamEvent {
    /// Raw bytes; decoded by the pump with the session charset.
    Data(Bytes),
    /// Already-decoded text with renderer hints (Mosh bootstrap output).
    /// Delivered immediately, never coalesced with other output.
    Text {
        text: String,
        meta: Option<SessionDataMeta>,
    },
    /// The backend ended; emitted as `netcatty:exit` (exactly once).
    Exit(StreamExit),
}

/// How a stream backend ended (`netcatty:exit` fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamExit {
    pub exit_code: Option<i32>,
    /// Signal name / number of a killed client process.
    pub signal: Option<String>,
    pub error: Option<String>,
    pub reason: ExitReason,
}

impl StreamExit {
    /// Peer closed the connection (`{ exitCode: 0, reason: "closed" }`).
    pub fn closed() -> Self {
        Self {
            exit_code: Some(0),
            signal: None,
            error: None,
            reason: ExitReason::Closed,
        }
    }

    /// Transport error (`{ exitCode: 1, error, reason: "error" }`).
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            exit_code: Some(1),
            signal: None,
            error: Some(message.into()),
            reason: ExitReason::Error,
        }
    }

    /// A client process exited: `exited` for status 0, else `error`
    /// (Mosh / ET semantics).
    pub fn process(exit_code: Option<i32>, signal: Option<String>) -> Self {
        Self {
            exit_code,
            signal,
            error: None,
            reason: if exit_code == Some(0) {
                ExitReason::Exited
            } else {
                ExitReason::Error
            },
        }
    }
}

/// Input as the renderer sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionInput {
    /// Text (encoded with the session charset by the transport).
    Text(String),
    /// Wire bytes (xterm `onBinary`, interrupt).
    Bytes(Bytes),
}

impl SessionInput {
    /// Text view used for auto-login takeover detection.
    pub fn as_text(&self) -> std::borrow::Cow<'_, str> {
        match self {
            SessionInput::Text(t) => std::borrow::Cow::Borrowed(t),
            SessionInput::Bytes(b) => String::from_utf8_lossy(b),
        }
    }
}

/// `session_write` flags relevant to stream transports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputMeta {
    /// Programmatic input (startup command, snippets, auto-fill): never
    /// cancels auto-login.
    pub automated: bool,
    /// Serial: erase character of a byte-oriented device.
    pub serial_erase_char: Option<String>,
}

impl InputMeta {
    pub fn automated() -> Self {
        Self {
            automated: true,
            serial_erase_char: None,
        }
    }

    pub fn user() -> Self {
        Self::default()
    }
}

/// Input side of a stream backend.
#[async_trait::async_trait]
pub trait StreamTransport: Send + Sync + 'static {
    /// Deliver input. `charset` is the session's current charset.
    async fn write_input(
        &self,
        input: SessionInput,
        meta: &InputMeta,
        charset: Charset,
    ) -> CoreResult<()>;

    fn resize(&self, cols: u16, rows: u16) -> CoreResult<()>;

    /// Tear the backend down. No exit event is expected afterwards (the
    /// registry emits `reason: "closed"` itself).
    fn close(&self);

    /// Decoded output, in order, before it is emitted (auto-login).
    fn observe_output(&self, _text: &str, _charset: Charset) {}

    /// The renderer's line-mode "user started typing" notification.
    fn notify_user_input(&self) {}

    /// Downcast hook for protocol-specific queries (telnet echo mode).
    fn as_any(&self) -> &dyn Any;
}

/// `true` for xterm's automatic replies, which never count as user input.
pub fn is_user_keystroke(input: &SessionInput, meta: &InputMeta) -> bool {
    if meta.automated {
        return false;
    }
    match input {
        SessionInput::Text(t) => !netcatty_telnet::is_terminal_report_sequence(t),
        SessionInput::Bytes(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_shapes() {
        assert_eq!(StreamExit::closed().exit_code, Some(0));
        assert_eq!(StreamExit::closed().reason, ExitReason::Closed);
        let e = StreamExit::error("boom");
        assert_eq!((e.exit_code, e.reason), (Some(1), ExitReason::Error));
        assert_eq!(
            StreamExit::process(Some(0), None).reason,
            ExitReason::Exited
        );
        assert_eq!(StreamExit::process(Some(2), None).reason, ExitReason::Error);
        assert_eq!(
            StreamExit::process(None, Some("9".into())).reason,
            ExitReason::Error
        );
    }

    #[test]
    fn keystroke_classification() {
        let user = InputMeta::user();
        assert!(is_user_keystroke(&SessionInput::Text("a".into()), &user));
        assert!(!is_user_keystroke(
            &SessionInput::Text("\x1b[12;3R".into()),
            &user
        ));
        assert!(!is_user_keystroke(
            &SessionInput::Text("a".into()),
            &InputMeta::automated()
        ));
        assert!(is_user_keystroke(
            &SessionInput::Bytes(Bytes::from_static(b"\x03")),
            &user
        ));
    }
}

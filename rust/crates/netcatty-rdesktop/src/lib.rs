//! `netcatty-rdesktop` — embedded remote desktop sessions.
//!
//! A remote desktop session is the graphical counterpart of a terminal
//! session: the backend owns the protocol connection, decodes the server's
//! framebuffer updates and hands them to the renderer as RGBA rectangles; the
//! renderer paints them on a `<canvas>` and sends pointer / keyboard input
//! back. Two protocols are supported:
//!
//! * **VNC** (RFB) through `vnc-rs` — see [`vnc`].
//! * **RDP** through IronRDP — see [`rdp`].
//!
//! Both engines speak the same [`RemoteEvent`] / [`RemoteInput`] vocabulary so
//! the renderer needs a single view for them.

mod net;
pub mod rdp;
pub mod vnc;

use netcatty_core::CoreResult;
use std::fmt;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Smallest and largest desktop size requested from a server. RDP servers
/// reject sizes outside this range; the renderer scales the canvas anyway.
pub const MIN_DESKTOP_SIZE: u16 = 200;
pub const MAX_DESKTOP_SIZE: u16 = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteProtocol {
    Vnc,
    Rdp,
}

impl RemoteProtocol {
    /// Well-known port of the protocol.
    pub fn default_port(self) -> u16 {
        match self {
            Self::Vnc => 5900,
            Self::Rdp => 3389,
        }
    }
}

/// Everything needed to open a remote desktop session.
#[derive(Clone)]
pub struct ConnectOptions {
    pub protocol: RemoteProtocol,
    pub host: String,
    pub port: u16,
    /// RDP user name. Unused by VNC (classic VNC auth has no user name).
    pub username: Option<String>,
    pub password: Option<String>,
    /// RDP logon domain.
    pub domain: Option<String>,
    /// Desktop size requested from an RDP server. VNC servers dictate their
    /// own framebuffer size, so this is only a hint there.
    pub width: u16,
    pub height: u16,
}

impl fmt::Debug for ConnectOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never log the password.
        f.debug_struct("ConnectOptions")
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("domain", &self.domain)
            .field("width", &self.width)
            .field("height", &self.height)
            .finish()
    }
}

/// What the backend tells the renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteEvent {
    /// The session is established; `width`×`height` is the remote desktop size.
    Connected {
        width: u16,
        height: u16,
    },
    /// The remote desktop changed size. The canvas must be reallocated; the
    /// server repaints it afterwards.
    Resize {
        width: u16,
        height: u16,
    },
    /// A rectangle of new pixels: `width * height * 4` bytes of RGBA, rows top
    /// to bottom, alpha always opaque.
    Frame {
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        rgba: Vec<u8>,
    },
    /// Copy a rectangle of the current framebuffer to another position.
    CopyRect {
        src_x: u16,
        src_y: u16,
        dst_x: u16,
        dst_y: u16,
        width: u16,
        height: u16,
    },
    /// The remote clipboard changed.
    Clipboard(String),
    Bell,
    /// The session ended. Emitted exactly once, always last. `error` is
    /// `None` for a deliberate close.
    Closed {
        error: Option<String>,
    },
}

/// What the renderer tells the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteInput {
    /// Pointer position in remote desktop pixels plus the pressed-button
    /// mask: bit 0 left, bit 1 middle, bit 2 right.
    Pointer { x: u16, y: u16, buttons: u8 },
    /// Wheel movement in notches at the given position. Positive `delta_y`
    /// scrolls up (away from the user), positive `delta_x` scrolls right.
    Wheel {
        x: u16,
        y: u16,
        delta_x: i16,
        delta_y: i16,
    },
    /// A key transition. `keysym` is the X11 keysym (used by VNC), `scancode`
    /// the PC set-1 scancode with `0xE000` or-ed in for extended keys (used
    /// by RDP). Either may be 0 when the key has no mapping in that space.
    Key {
        down: bool,
        keysym: u32,
        scancode: u16,
    },
    /// Text placed on the local clipboard, offered to the remote side.
    Clipboard(String),
    /// Ask the server to resend the whole desktop.
    Refresh,
}

/// Receives the events of one session. Called from the session task.
pub type EventSink = Arc<dyn Fn(RemoteEvent) + Send + Sync>;

/// Handle to a running session. Dropping it does **not** end the session;
/// call [`RemoteDesktopHandle::close`].
#[derive(Clone)]
pub struct RemoteDesktopHandle {
    input: mpsc::UnboundedSender<RemoteInput>,
    cancel: CancellationToken,
}

impl RemoteDesktopHandle {
    /// Queue an input for the session. Returns `false` once it has ended.
    pub fn send(&self, input: RemoteInput) -> bool {
        self.input.send(input).is_ok()
    }

    /// End the session. Idempotent; [`RemoteEvent::Closed`] follows.
    pub fn close(&self) {
        self.cancel.cancel();
    }

    pub fn is_closed(&self) -> bool {
        self.input.is_closed()
    }
}

/// Start a session on the current Tokio runtime. Connection progress and
/// failure are both reported through `sink`: a failed connect yields a single
/// [`RemoteEvent::Closed`] carrying the error.
pub fn spawn(options: ConnectOptions, sink: EventSink) -> RemoteDesktopHandle {
    let (input, mut inputs) = mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    let handle = RemoteDesktopHandle {
        input,
        cancel: cancel.clone(),
    };

    tokio::spawn(async move {
        let run = async {
            match options.protocol {
                RemoteProtocol::Vnc => vnc::run(&options, &mut inputs, &sink).await,
                RemoteProtocol::Rdp => rdp::run(&options, &mut inputs, &sink).await,
            }
        };
        let result: CoreResult<()> = tokio::select! {
            _ = cancel.cancelled() => Ok(()),
            result = run => result,
        };
        let error = result.err().map(|err| err.message);
        if let Some(error) = &error {
            tracing::warn!(protocol = ?options.protocol, host = %options.host, %error, "remote desktop session failed");
        }
        sink(RemoteEvent::Closed { error });
    });

    handle
}

/// Clamp a requested desktop dimension into the supported range.
pub fn clamp_desktop_size(value: u16) -> u16 {
    value.clamp(MIN_DESKTOP_SIZE, MAX_DESKTOP_SIZE)
}

/// Force every pixel of an RGBA buffer opaque. Servers leave the fourth byte
/// undefined, and a canvas would otherwise show transparent holes.
pub(crate) fn make_opaque(rgba: &mut [u8]) {
    for pixel in rgba.chunks_exact_mut(4) {
        pixel[3] = 0xFF;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ports_match_the_protocols() {
        assert_eq!(RemoteProtocol::Vnc.default_port(), 5900);
        assert_eq!(RemoteProtocol::Rdp.default_port(), 3389);
    }

    #[test]
    fn desktop_size_is_clamped() {
        assert_eq!(clamp_desktop_size(0), MIN_DESKTOP_SIZE);
        assert_eq!(clamp_desktop_size(1280), 1280);
        assert_eq!(clamp_desktop_size(u16::MAX), MAX_DESKTOP_SIZE);
    }

    #[test]
    fn make_opaque_only_touches_alpha() {
        let mut pixels = vec![1, 2, 3, 0, 4, 5, 6, 7];
        make_opaque(&mut pixels);
        assert_eq!(pixels, vec![1, 2, 3, 255, 4, 5, 6, 255]);
    }

    #[test]
    fn debug_output_never_contains_the_password() {
        let options = ConnectOptions {
            protocol: RemoteProtocol::Rdp,
            host: "example.test".into(),
            port: 3389,
            username: Some("alice".into()),
            password: Some("hunter2".into()),
            domain: None,
            width: 1280,
            height: 800,
        };
        let debug = format!("{options:?}");
        assert!(!debug.contains("hunter2"));
        assert!(debug.contains("<redacted>"));
    }

    #[tokio::test]
    async fn a_failed_connect_reports_one_closed_event_with_the_error() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sink: EventSink = Arc::new(move |event| {
            let _ = tx.send(event);
        });
        // Port 1 on localhost is closed: the connect is refused immediately.
        let handle = spawn(
            ConnectOptions {
                protocol: RemoteProtocol::Vnc,
                host: "127.0.0.1".into(),
                port: 1,
                username: None,
                password: None,
                domain: None,
                width: 800,
                height: 600,
            },
            sink,
        );
        let event = rx.recv().await.expect("a closed event");
        match event {
            RemoteEvent::Closed { error } => assert!(error.is_some()),
            other => panic!("unexpected event {other:?}"),
        }
        assert!(rx.recv().await.is_none(), "closed is the last event");
        assert!(!handle.send(RemoteInput::Refresh));
    }

    #[tokio::test]
    async fn closing_a_session_reports_closed_without_an_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Accept and stay silent, so the handshake never completes.
        tokio::spawn(async move {
            let _held = listener.accept().await;
            std::future::pending::<()>().await;
        });
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sink: EventSink = Arc::new(move |event| {
            let _ = tx.send(event);
        });
        let handle = spawn(
            ConnectOptions {
                protocol: RemoteProtocol::Rdp,
                host: "127.0.0.1".into(),
                port,
                username: Some("user".into()),
                password: Some("pass".into()),
                domain: None,
                width: 800,
                height: 600,
            },
            sink,
        );
        handle.close();
        assert_eq!(rx.recv().await, Some(RemoteEvent::Closed { error: None }));
    }
}

//! Remote desktop (VNC / RDP) commands.
//!
//! A session's output does not go through the global event bus: frames are
//! large and binary, so each session gets a `tauri::ipc::Channel` passed to
//! `rdesktop_connect`. Control messages are sent on it as JSON
//! ([`RemoteDesktopControlEvent`]), pixel data as raw bytes (see
//! [`encode_frame`] / [`encode_copy_rect`]).

use super::CmdResult;
use crate::state::Ctx;
use netcatty_core::ipc::{
    RemoteDesktopControlEvent, RemoteDesktopInputEvent, RemoteDesktopInputPayload,
    RemoteDesktopOptions, StartSessionResult,
};
use netcatty_core::CoreError;
use netcatty_rdesktop::{
    clamp_desktop_size, ConnectOptions, EventSink, RemoteEvent, RemoteInput, RemoteProtocol,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::ipc::{Channel, InvokeResponseBody};

const DEFAULT_WIDTH: u16 = 1280;
const DEFAULT_HEIGHT: u16 = 800;

/// Tag byte of a binary channel message.
const TAG_FRAME: u8 = 1;
const TAG_COPY_RECT: u8 = 2;

/// `[TAG_FRAME][x][y][width][height]` (u16 little endian) followed by
/// `width * height * 4` bytes of RGBA.
pub(crate) fn encode_frame(x: u16, y: u16, width: u16, height: u16, rgba: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + rgba.len());
    out.push(TAG_FRAME);
    for value in [x, y, width, height] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(rgba);
    out
}

/// `[TAG_COPY_RECT][srcX][srcY][dstX][dstY][width][height]` (u16 little endian).
pub(crate) fn encode_copy_rect(
    src_x: u16,
    src_y: u16,
    dst_x: u16,
    dst_y: u16,
    width: u16,
    height: u16,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(13);
    out.push(TAG_COPY_RECT);
    for value in [src_x, src_y, dst_x, dst_y, width, height] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

/// Channel message for one backend event.
pub(crate) fn encode_event(event: RemoteEvent) -> InvokeResponseBody {
    let control = match event {
        RemoteEvent::Frame {
            x,
            y,
            width,
            height,
            rgba,
        } => return InvokeResponseBody::Raw(encode_frame(x, y, width, height, &rgba)),
        RemoteEvent::CopyRect {
            src_x,
            src_y,
            dst_x,
            dst_y,
            width,
            height,
        } => {
            return InvokeResponseBody::Raw(encode_copy_rect(
                src_x, src_y, dst_x, dst_y, width, height,
            ))
        }
        RemoteEvent::Connected { width, height } => {
            RemoteDesktopControlEvent::Connected { width, height }
        }
        RemoteEvent::Resize { width, height } => {
            RemoteDesktopControlEvent::Resize { width, height }
        }
        RemoteEvent::Clipboard(text) => RemoteDesktopControlEvent::Clipboard { text },
        RemoteEvent::Bell => RemoteDesktopControlEvent::Bell,
        RemoteEvent::Closed { error } => RemoteDesktopControlEvent::Closed { error },
    };
    // Serializing a plain tagged enum cannot fail.
    InvokeResponseBody::Json(serde_json::to_string(&control).unwrap_or_else(|_| "null".into()))
}

/// Validate the renderer payload into backend connect options.
pub(crate) fn connect_options(payload: &RemoteDesktopOptions) -> CmdResult<ConnectOptions> {
    let protocol = match payload.protocol.as_str() {
        "vnc" => RemoteProtocol::Vnc,
        "rdp" => RemoteProtocol::Rdp,
        other => {
            return Err(CoreError::invalid(format!(
                "unsupported remote desktop protocol `{other}`"
            )))
        }
    };
    let host = payload.hostname.trim();
    if host.is_empty() {
        return Err(CoreError::invalid("hostname is required"));
    }
    let non_empty = |value: &Option<String>| value.clone().filter(|v| !v.is_empty());
    Ok(ConnectOptions {
        protocol,
        host: host.to_owned(),
        port: payload
            .port
            .filter(|port| *port != 0)
            .unwrap_or_else(|| protocol.default_port()),
        username: non_empty(&payload.username),
        password: non_empty(&payload.password),
        domain: non_empty(&payload.domain),
        width: clamp_desktop_size(payload.width.unwrap_or(DEFAULT_WIDTH)),
        height: clamp_desktop_size(payload.height.unwrap_or(DEFAULT_HEIGHT)),
    })
}

fn to_input(event: RemoteDesktopInputEvent) -> RemoteInput {
    match event {
        RemoteDesktopInputEvent::Pointer { x, y, buttons } => {
            RemoteInput::Pointer { x, y, buttons }
        }
        RemoteDesktopInputEvent::Wheel {
            x,
            y,
            delta_x,
            delta_y,
        } => RemoteInput::Wheel {
            x,
            y,
            delta_x,
            delta_y,
        },
        RemoteDesktopInputEvent::Key {
            down,
            keysym,
            scancode,
        } => RemoteInput::Key {
            down,
            keysym,
            scancode,
        },
        RemoteDesktopInputEvent::Clipboard { text } => RemoteInput::Clipboard(text),
        RemoteDesktopInputEvent::Refresh => RemoteInput::Refresh,
    }
}

/// Start a remote desktop session. Resolves as soon as the session task is
/// running; connection progress, frames and the final `closed` message all
/// arrive on `on_event`.
#[tauri::command]
pub async fn rdesktop_connect<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: RemoteDesktopOptions,
    on_event: Channel<InvokeResponseBody>,
) -> CmdResult<StartSessionResult> {
    let options = connect_options(&payload)?;
    let session_id = payload
        .session_id
        .clone()
        .filter(|id| !id.trim().is_empty())
        .unwrap_or_else(netcatty_core::new_id);
    if state.remote_desktops.contains_key(&session_id) {
        return Err(CoreError::invalid(format!(
            "remote desktop session {session_id} already exists"
        )));
    }

    let registry = state.remote_desktops.clone();
    let closed_id = session_id.clone();
    let ended = Arc::new(AtomicBool::new(false));
    let sink_ended = ended.clone();
    let sink: EventSink = Arc::new(move |event| {
        let closed = matches!(event, RemoteEvent::Closed { .. });
        if let Err(err) = on_event.send(encode_event(event)) {
            tracing::debug!(%err, "remote desktop channel send failed");
        }
        if closed {
            sink_ended.store(true, Ordering::SeqCst);
            registry.remove(&closed_id);
        }
    });

    tracing::info!(session_id, protocol = %payload.protocol, host = %options.host, port = options.port, "remote desktop session starting");
    let handle = netcatty_rdesktop::spawn(options, sink);
    state.remote_desktops.insert(session_id.clone(), handle);
    // The session can end (connection refused) before the entry above is
    // inserted; the sink's removal would then have been a no-op.
    if ended.load(Ordering::SeqCst) {
        state.remote_desktops.remove(&session_id);
    }
    Ok(StartSessionResult { session_id })
}

/// Forward a batch of input events. Unknown or ended sessions are ignored:
/// input races with the session closing.
#[tauri::command]
pub async fn rdesktop_input<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: RemoteDesktopInputPayload,
) -> CmdResult<()> {
    if let Some(handle) = state.remote_desktops.get(&payload.session_id) {
        for event in payload.events {
            if !handle.send(to_input(event)) {
                break;
            }
        }
    }
    Ok(())
}

/// Close a session. Idempotent; the channel receives `closed` when the
/// session task has stopped.
#[tauri::command]
pub async fn rdesktop_close<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
) -> CmdResult<()> {
    if let Some(handle) = state.remote_desktops.get(&session_id) {
        handle.close();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(protocol: &str) -> RemoteDesktopOptions {
        RemoteDesktopOptions {
            protocol: protocol.into(),
            hostname: " desk.example.test ".into(),
            ..Default::default()
        }
    }

    #[test]
    fn connect_options_apply_protocol_defaults() {
        let vnc = connect_options(&options("vnc")).unwrap();
        assert_eq!(vnc.protocol, RemoteProtocol::Vnc);
        assert_eq!(vnc.host, "desk.example.test");
        assert_eq!(vnc.port, 5900);
        assert_eq!((vnc.width, vnc.height), (DEFAULT_WIDTH, DEFAULT_HEIGHT));

        let rdp = connect_options(&RemoteDesktopOptions {
            port: Some(13389),
            username: Some("alice".into()),
            password: Some(String::new()),
            width: Some(1),
            ..options("rdp")
        })
        .unwrap();
        assert_eq!(rdp.protocol, RemoteProtocol::Rdp);
        assert_eq!(rdp.port, 13389);
        assert_eq!(rdp.username.as_deref(), Some("alice"));
        assert_eq!(rdp.password, None, "an empty password means none");
        assert_eq!(rdp.width, netcatty_rdesktop::MIN_DESKTOP_SIZE);
    }

    #[test]
    fn connect_options_reject_bad_input() {
        assert!(connect_options(&options("ssh")).is_err());
        assert!(connect_options(&RemoteDesktopOptions {
            hostname: "  ".into(),
            ..options("vnc")
        })
        .is_err());
    }

    #[test]
    fn frames_are_tagged_binary_messages() {
        let body = encode_event(RemoteEvent::Frame {
            x: 0x0102,
            y: 3,
            width: 1,
            height: 1,
            rgba: vec![9, 8, 7, 255],
        });
        match body {
            InvokeResponseBody::Raw(bytes) => {
                assert_eq!(bytes, vec![1, 0x02, 0x01, 3, 0, 1, 0, 1, 0, 9, 8, 7, 255]);
            }
            InvokeResponseBody::Json(_) => panic!("frames must be binary"),
        }

        let body = encode_event(RemoteEvent::CopyRect {
            src_x: 1,
            src_y: 2,
            dst_x: 3,
            dst_y: 4,
            width: 5,
            height: 6,
        });
        match body {
            InvokeResponseBody::Raw(bytes) => {
                assert_eq!(bytes, vec![2, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0]);
            }
            InvokeResponseBody::Json(_) => panic!("copy rects must be binary"),
        }
    }

    #[test]
    fn control_events_are_json_messages() {
        match encode_event(RemoteEvent::Closed {
            error: Some("gone".into()),
        }) {
            InvokeResponseBody::Json(json) => {
                assert_eq!(json, r#"{"type":"closed","error":"gone"}"#);
            }
            InvokeResponseBody::Raw(_) => panic!("control events must be JSON"),
        }
    }
}

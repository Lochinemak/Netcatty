//! VNC (RFB) sessions on top of `vnc-rs`.

use crate::net::{connect_tcp, with_handshake_timeout};
use crate::{make_opaque, ConnectOptions, EventSink, RemoteEvent, RemoteInput};
use netcatty_core::{CoreError, CoreResult};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedReceiver;
use vnc::{PixelFormat, VncClient, VncConnector, VncEncoding, VncError, VncEvent, X11Event};

/// How often an incremental framebuffer update is requested. RFB is pull
/// based: the server only sends changes the client asked for.
const REFRESH_INTERVAL: Duration = Duration::from_millis(33);
/// Idle wait between two polls of the decoder queue.
const IDLE_POLL: Duration = Duration::from_millis(4);

// Pointer button mask bits of the RFB PointerEvent message.
const WHEEL_UP: u8 = 1 << 3;
const WHEEL_DOWN: u8 = 1 << 4;
const WHEEL_LEFT: u8 = 1 << 5;
const WHEEL_RIGHT: u8 = 1 << 6;
/// Most wheel notches forwarded for one input event.
const MAX_WHEEL_NOTCHES: u16 = 8;

pub(crate) async fn run(
    options: &ConnectOptions,
    inputs: &mut UnboundedReceiver<RemoteInput>,
    sink: &EventSink,
) -> CoreResult<()> {
    let tcp = connect_tcp(&options.host, options.port).await?;
    let password = options.password.clone().unwrap_or_default();

    let handshake = async {
        VncConnector::new(tcp)
            // Only polled when the server asks for VNC authentication.
            .set_auth_method(async move { Ok(password) })
            .add_encoding(VncEncoding::Zrle)
            .add_encoding(VncEncoding::CopyRect)
            .add_encoding(VncEncoding::Raw)
            .add_encoding(VncEncoding::DesktopSizePseudo)
            .allow_shared(true)
            .set_pixel_format(PixelFormat::rgba())
            .build()
            .map_err(vnc_error)?
            .try_start()
            .await
            .map_err(vnc_error)?
            .finish()
            .map_err(vnc_error)
    };
    let client = with_handshake_timeout("VNC", handshake).await?;

    let result = pump(&client, inputs, sink).await;
    let _ = client.close().await;
    result
}

async fn pump(
    client: &VncClient,
    inputs: &mut UnboundedReceiver<RemoteInput>,
    sink: &EventSink,
) -> CoreResult<()> {
    let mut connected = false;
    let mut buttons = 0u8;
    let mut last_refresh = Instant::now() - REFRESH_INTERVAL;

    loop {
        // `VncClient::recv_event` holds the client lock while it waits, which
        // would block `input`; poll the decoder queue instead.
        let mut idle = true;
        while let Some(event) = client.poll_event().await.map_err(vnc_error)? {
            idle = false;
            handle_event(event, &mut connected, sink)?;
        }

        while let Ok(input) = inputs.try_recv() {
            idle = false;
            send_input(client, input, &mut buttons).await?;
        }

        if last_refresh.elapsed() >= REFRESH_INTERVAL {
            client.input(X11Event::Refresh).await.map_err(vnc_error)?;
            last_refresh = Instant::now();
        }

        if idle {
            tokio::select! {
                _ = tokio::time::sleep(IDLE_POLL) => {}
                input = inputs.recv() => match input {
                    Some(input) => send_input(client, input, &mut buttons).await?,
                    // Every handle is gone: nobody can drive or close the
                    // session any more.
                    None => return Ok(()),
                },
            }
        }
    }
}

fn handle_event(event: VncEvent, connected: &mut bool, sink: &EventSink) -> CoreResult<()> {
    match event {
        VncEvent::SetResolution(screen) => {
            let (width, height) = (screen.width, screen.height);
            if *connected {
                sink(RemoteEvent::Resize { width, height });
            } else {
                *connected = true;
                sink(RemoteEvent::Connected { width, height });
            }
        }
        VncEvent::RawImage(rect, mut rgba) => {
            let expected = usize::from(rect.width) * usize::from(rect.height) * 4;
            if rgba.len() != expected {
                tracing::debug!(
                    len = rgba.len(),
                    expected,
                    "dropping malformed VNC rectangle"
                );
                return Ok(());
            }
            make_opaque(&mut rgba);
            sink(RemoteEvent::Frame {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: rect.height,
                rgba,
            });
        }
        VncEvent::Copy(dst, src) => sink(RemoteEvent::CopyRect {
            src_x: src.x,
            src_y: src.y,
            dst_x: dst.x,
            dst_y: dst.y,
            width: dst.width,
            height: dst.height,
        }),
        VncEvent::Bell => sink(RemoteEvent::Bell),
        VncEvent::Text(text) => sink(RemoteEvent::Clipboard(text)),
        VncEvent::Error(message) => return Err(CoreError::network(message)),
        // Cursor shapes, JPEG rectangles and layout notifications are never
        // requested (see the encodings in `run`).
        _ => {}
    }
    Ok(())
}

async fn send_input(client: &VncClient, input: RemoteInput, buttons: &mut u8) -> CoreResult<()> {
    match input {
        RemoteInput::Pointer {
            x,
            y,
            buttons: mask,
        } => {
            *buttons = mask & 0b111;
            pointer(client, x, y, *buttons).await
        }
        RemoteInput::Wheel {
            x,
            y,
            delta_x,
            delta_y,
        } => {
            // RFB models a wheel notch as a press and release of a virtual button.
            for (delta, positive, negative) in [
                (delta_y, WHEEL_UP, WHEEL_DOWN),
                (delta_x, WHEEL_RIGHT, WHEEL_LEFT),
            ] {
                let bit = if delta > 0 { positive } else { negative };
                for _ in 0..delta.unsigned_abs().min(MAX_WHEEL_NOTCHES) {
                    pointer(client, x, y, *buttons | bit).await?;
                    pointer(client, x, y, *buttons).await?;
                }
            }
            Ok(())
        }
        RemoteInput::Key { down, keysym, .. } => {
            if keysym == 0 {
                return Ok(());
            }
            client
                .input(X11Event::KeyEvent((keysym, down).into()))
                .await
                .map_err(vnc_error)
        }
        RemoteInput::Clipboard(text) => {
            // An over-long clipboard is not worth ending the session for.
            if let Err(err) = client.input(X11Event::CopyText(text)).await {
                tracing::debug!(%err, "VNC clipboard text rejected");
            }
            Ok(())
        }
        RemoteInput::Refresh => client.input(X11Event::FullRefresh).await.map_err(vnc_error),
    }
}

async fn pointer(client: &VncClient, x: u16, y: u16, buttons: u8) -> CoreResult<()> {
    client
        .input(X11Event::PointerEvent((x, y, buttons).into()))
        .await
        .map_err(vnc_error)
}

fn vnc_error(err: VncError) -> CoreError {
    match err {
        VncError::WrongPassword | VncError::NoPassword => {
            CoreError::auth("VNC authentication failed: wrong or missing password")
        }
        VncError::ClientNotRunning => CoreError::network("the VNC server closed the connection"),
        other => CoreError::network(format!("VNC error: {other}")),
    }
}

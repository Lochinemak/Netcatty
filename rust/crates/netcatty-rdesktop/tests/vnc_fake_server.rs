//! End-to-end check of the VNC engine against a minimal in-process RFB 3.8
//! server: handshake without authentication, one raw rectangle, then input.

use netcatty_rdesktop::{
    spawn, ConnectOptions, EventSink, RemoteEvent, RemoteInput, RemoteProtocol,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const WIDTH: u16 = 4;
const HEIGHT: u16 = 2;

/// Messages the fake server saw from the client after the handshake.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Pointer { buttons: u8, x: u16, y: u16 },
    Key { down: bool, keysym: u32 },
}

async fn serve(mut socket: TcpStream, seen: mpsc::UnboundedSender<Seen>) -> std::io::Result<()> {
    socket.write_all(b"RFB 003.008\n").await?;
    let mut version = [0u8; 12];
    socket.read_exact(&mut version).await?;

    // One security type on offer: None (1).
    socket.write_all(&[1, 1]).await?;
    let mut chosen = [0u8; 1];
    socket.read_exact(&mut chosen).await?;
    assert_eq!(chosen[0], 1, "client must pick security type None");
    socket.write_all(&0u32.to_be_bytes()).await?; // SecurityResult: OK

    let mut shared = [0u8; 1];
    socket.read_exact(&mut shared).await?; // ClientInit

    // ServerInit: size, a 32bpp true-colour pixel format, desktop name.
    let mut init = Vec::new();
    init.extend_from_slice(&WIDTH.to_be_bytes());
    init.extend_from_slice(&HEIGHT.to_be_bytes());
    init.extend_from_slice(&[32, 24, 0, 1]);
    for max in [255u16, 255, 255] {
        init.extend_from_slice(&max.to_be_bytes());
    }
    init.extend_from_slice(&[16, 8, 0, 0, 0, 0]);
    let name = b"fake";
    init.extend_from_slice(&(name.len() as u32).to_be_bytes());
    init.extend_from_slice(name);
    socket.write_all(&init).await?;

    let mut sent_frame = false;
    loop {
        let mut kind = [0u8; 1];
        socket.read_exact(&mut kind).await?;
        match kind[0] {
            // SetPixelFormat: 3 padding + 16 bytes.
            0 => {
                let mut rest = [0u8; 19];
                socket.read_exact(&mut rest).await?;
            }
            // SetEncodings: padding, count, count * i32.
            2 => {
                let mut head = [0u8; 3];
                socket.read_exact(&mut head).await?;
                let count = u16::from_be_bytes([head[1], head[2]]) as usize;
                let mut encodings = vec![0u8; count * 4];
                socket.read_exact(&mut encodings).await?;
            }
            // FramebufferUpdateRequest.
            3 => {
                let mut rest = [0u8; 9];
                socket.read_exact(&mut rest).await?;
                if sent_frame {
                    continue;
                }
                sent_frame = true;
                // One raw rectangle covering the whole desktop. Pixel (x, y)
                // is [10 + x, 20 + y, 30, 0] in the client's RGBA format.
                let mut update = vec![0u8, 0, 0, 1];
                for value in [0u16, 0, WIDTH, HEIGHT] {
                    update.extend_from_slice(&value.to_be_bytes());
                }
                update.extend_from_slice(&0i32.to_be_bytes());
                for y in 0..HEIGHT {
                    for x in 0..WIDTH {
                        update.extend_from_slice(&[10 + x as u8, 20 + y as u8, 30, 0]);
                    }
                }
                socket.write_all(&update).await?;
            }
            // KeyEvent.
            4 => {
                let mut rest = [0u8; 7];
                socket.read_exact(&mut rest).await?;
                let _ = seen.send(Seen::Key {
                    down: rest[0] != 0,
                    keysym: u32::from_be_bytes([rest[3], rest[4], rest[5], rest[6]]),
                });
            }
            // PointerEvent.
            5 => {
                let mut rest = [0u8; 5];
                socket.read_exact(&mut rest).await?;
                let _ = seen.send(Seen::Pointer {
                    buttons: rest[0],
                    x: u16::from_be_bytes([rest[1], rest[2]]),
                    y: u16::from_be_bytes([rest[3], rest[4]]),
                });
            }
            // ClientCutText.
            6 => {
                let mut head = [0u8; 7];
                socket.read_exact(&mut head).await?;
                let len = u32::from_be_bytes([head[3], head[4], head[5], head[6]]) as usize;
                let mut text = vec![0u8; len];
                socket.read_exact(&mut text).await?;
            }
            other => panic!("unexpected client message type {other}"),
        }
    }
}

async fn next<T>(rx: &mut mpsc::UnboundedReceiver<T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("timed out waiting for an event")
        .expect("channel closed")
}

#[tokio::test]
async fn vnc_session_receives_frames_and_forwards_input() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen_tx, mut seen) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        // The client closing the socket ends the server loop with an error.
        let _ = serve(socket, seen_tx).await;
    });

    let (event_tx, mut events) = mpsc::unbounded_channel();
    let sink: EventSink = Arc::new(move |event| {
        let _ = event_tx.send(event);
    });
    let handle = spawn(
        ConnectOptions {
            protocol: RemoteProtocol::Vnc,
            host: "127.0.0.1".into(),
            port,
            username: None,
            password: None,
            domain: None,
            width: 800,
            height: 600,
        },
        sink,
    );

    assert_eq!(
        next(&mut events).await,
        RemoteEvent::Connected {
            width: WIDTH,
            height: HEIGHT
        }
    );

    let frame = loop {
        match next(&mut events).await {
            RemoteEvent::Frame {
                x,
                y,
                width,
                height,
                rgba,
            } => break (x, y, width, height, rgba),
            RemoteEvent::Closed { error } => panic!("session closed early: {error:?}"),
            _ => {}
        }
    };
    let (x, y, width, height, rgba) = frame;
    assert_eq!((x, y, width, height), (0, 0, WIDTH, HEIGHT));
    assert_eq!(rgba.len(), usize::from(WIDTH) * usize::from(HEIGHT) * 4);
    // First pixel and the last one; alpha is forced opaque.
    assert_eq!(&rgba[..4], &[10, 20, 30, 255]);
    assert_eq!(&rgba[rgba.len() - 4..], &[13, 21, 30, 255]);

    assert!(handle.send(RemoteInput::Pointer {
        x: 3,
        y: 1,
        buttons: 0b001
    }));
    assert_eq!(
        next(&mut seen).await,
        Seen::Pointer {
            buttons: 1,
            x: 3,
            y: 1
        }
    );

    assert!(handle.send(RemoteInput::Key {
        down: true,
        keysym: 0x61,
        scancode: 0x1E
    }));
    assert_eq!(
        next(&mut seen).await,
        Seen::Key {
            down: true,
            keysym: 0x61
        }
    );

    // One wheel notch up is a press and release of button 4 on top of the
    // currently held buttons.
    assert!(handle.send(RemoteInput::Wheel {
        x: 3,
        y: 1,
        delta_x: 0,
        delta_y: 1
    }));
    assert_eq!(
        next(&mut seen).await,
        Seen::Pointer {
            buttons: 0b1001,
            x: 3,
            y: 1
        }
    );
    assert_eq!(
        next(&mut seen).await,
        Seen::Pointer {
            buttons: 0b0001,
            x: 3,
            y: 1
        }
    );

    handle.close();
    loop {
        if let RemoteEvent::Closed { error } = next(&mut events).await {
            assert_eq!(error, None);
            break;
        }
    }
}

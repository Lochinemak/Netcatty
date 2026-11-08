//! Minimal scripted HTTP/1.1 server for the fetch / stream tests: one
//! connection per scripted response, raw bytes written in timed parts, then
//! the connection is closed (no `Content-Length` needed for streams).

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

pub struct ScriptedResponse {
    pub parts: Vec<(Duration, Vec<u8>)>,
}

impl ScriptedResponse {
    pub fn text(text: &str) -> Self {
        Self { parts: vec![(Duration::ZERO, text.as_bytes().to_vec())] }
    }

    pub fn parts(parts: Vec<(Duration, Vec<u8>)>) -> Self {
        Self { parts }
    }
}

/// Start the server; returns the `http://127.0.0.1:port` base and a receiver
/// for the raw bytes of the first request.
pub async fn serve_once(responses: Vec<ScriptedResponse>) -> (String, oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        for response in responses {
            let Ok((mut socket, _)) = listener.accept().await else { return };
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            // Headers.
            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // Body (Content-Length only).
            let header_end = request
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .unwrap_or(request.len());
            let head = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            let content_length: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            while request.len() - header_end < content_length {
                let n = match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                request.extend_from_slice(&buf[..n]);
            }
            if let Some(tx) = tx.take() {
                let _ = tx.send(request);
            }
            for (delay, bytes) in response.parts {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if socket.write_all(&bytes).await.is_err() {
                    break;
                }
                let _ = socket.flush().await;
            }
            let _ = socket.shutdown().await;
        }
    });
    (format!("http://127.0.0.1:{}", addr.port()), rx)
}

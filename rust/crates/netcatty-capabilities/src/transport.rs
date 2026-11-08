//! Newline-delimited JSON-RPC 2.0 over TCP (Electron
//! `capabilities/rpcTransport.cjs`): one request per line, responses
//! matched by `id`, per-call timeouts from [`crate::registry::resolve_rpc_timeout_ms`].

use crate::registry::{resolve_rpc_timeout_ms, BridgeTimeouts};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::oneshot;

/// Max bytes of one NDJSON line accepted from a peer (10 MiB).
pub const MAX_LINE_BYTES: usize = 10 * 1024 * 1024;

/// Tagged RPC error (`code` is `RPC_ERROR`, `RPC_TIMEOUT`, `CONNECTION_CLOSED`, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

impl RpcError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into() }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, RpcError>>>>>;

/// Client side of an NDJSON JSON-RPC connection.
pub struct NdjsonRpcClient {
    writer: tokio::sync::Mutex<OwnedWriteHalf>,
    pending: Pending,
    next_id: AtomicU64,
    closed: Arc<std::sync::atomic::AtomicBool>,
    surface: String,
    bridge: Mutex<BridgeTimeouts>,
    reader_task: tokio::task::JoinHandle<()>,
}

impl Drop for NdjsonRpcClient {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

impl NdjsonRpcClient {
    pub fn new(stream: TcpStream, surface: &str) -> Arc<Self> {
        let (read, write) = stream.into_split();
        let pending: Pending = Default::default();
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let p = pending.clone();
        let c = closed.clone();
        let reader_task = tokio::spawn(async move {
            let mut reader = BufReader::new(read);
            let mut line = Vec::new();
            loop {
                line.clear();
                match reader.read_until(b'\n', &mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let Ok(msg) = serde_json::from_slice::<Value>(&line) else {
                    continue;
                };
                let Some(id) = msg.get("id").and_then(Value::as_u64) else {
                    continue;
                };
                let Some(tx) = p.lock().remove(&id) else {
                    continue;
                };
                let outcome = if let Some(error) = msg.get("error").filter(|e| !e.is_null()) {
                    let message = error
                        .get("message")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| error.to_string());
                    Err(RpcError::new("RPC_ERROR", message))
                } else {
                    Ok(msg.get("result").cloned().unwrap_or(Value::Null))
                };
                let _ = tx.send(outcome);
            }
            c.store(true, Ordering::SeqCst);
            for (_, tx) in p.lock().drain() {
                let _ = tx.send(Err(RpcError::new("CONNECTION_CLOSED", "RPC connection closed.")));
            }
        });
        Arc::new(Self {
            writer: tokio::sync::Mutex::new(write),
            pending,
            next_id: AtomicU64::new(1),
            closed,
            surface: surface.to_string(),
            bridge: Mutex::new(BridgeTimeouts::default()),
            reader_task,
        })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Adopt `commandTimeoutMs` / `permissionMode` / `approvalTimeoutMs`
    /// from a `netcatty/getStatus` result.
    pub fn ingest_bridge_status(&self, status: &Value) {
        let mut b = self.bridge.lock();
        if let Some(v) = status.get("commandTimeoutMs").and_then(Value::as_u64).filter(|v| *v > 0) {
            b.command_timeout_ms = Some(v);
        }
        if let Some(v) = status.get("permissionMode").and_then(Value::as_str) {
            b.permission_mode = Some(v.to_string());
        }
        if let Some(v) = status.get("approvalTimeoutMs").and_then(Value::as_u64).filter(|v| *v > 0) {
            b.approval_timeout_ms = Some(v);
        }
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        if self.is_closed() {
            return Err(RpcError::new("CONNECTION_CLOSED", "RPC connection closed."));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let timeout_ms = resolve_rpc_timeout_ms(method, &self.surface, &self.bridge.lock().clone());
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(id, tx);
        let mut payload = serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
            .map_err(|e| RpcError::new("WRITE_FAILED", e.to_string()))?;
        payload.push(b'\n');
        let write = async {
            let mut w = self.writer.lock().await;
            w.write_all(&payload).await?;
            w.flush().await
        };
        if let Err(err) = write.await {
            self.pending.lock().remove(&id);
            return Err(RpcError::new("WRITE_FAILED", format!("Failed to send RPC \"{method}\": {err}")));
        }
        match tokio::time::timeout(Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => Err(RpcError::new("CONNECTION_CLOSED", "RPC connection closed.")),
            Err(_) => {
                self.pending.lock().remove(&id);
                Err(RpcError::new(
                    "RPC_TIMEOUT",
                    format!("Timed out waiting for RPC response to \"{method}\" after {timeout_ms}ms."),
                ))
            }
        }
    }

    pub async fn close(&self) {
        let _ = self.writer.lock().await.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn round_trip_errors_and_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut lines = BufReader::new(r).lines();
            let mut n = 0;
            while let Ok(Some(line)) = lines.next_line().await {
                let msg: Value = serde_json::from_str(&line).unwrap();
                n += 1;
                let reply = if n == 1 {
                    json!({ "jsonrpc": "2.0", "id": msg["id"], "result": { "echo": msg["params"] } })
                } else {
                    json!({ "jsonrpc": "2.0", "id": msg["id"], "error": { "code": -32000, "message": "boom" } })
                };
                w.write_all(format!("garbage\n{reply}\n").as_bytes()).await.unwrap();
                if n == 2 {
                    break;
                }
            }
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let client = NdjsonRpcClient::new(stream, "builtin");
        let r = client.call("netcatty/getStatus", json!({ "a": 1 })).await.unwrap();
        assert_eq!(r["echo"]["a"], 1);
        let e = client.call("netcatty/getStatus", json!({})).await.unwrap_err();
        assert_eq!(e, RpcError::new("RPC_ERROR", "boom"));
        server.await.unwrap();
        let e = client.call("netcatty/getStatus", json!({})).await.unwrap_err();
        assert!(e.code == "CONNECTION_CLOSED" || e.code == "WRITE_FAILED", "{e:?}");
    }
}

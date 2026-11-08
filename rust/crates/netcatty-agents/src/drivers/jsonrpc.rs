//! JSON-RPC 2.0 client over a child's stdio, used by Grok ACP (newline
//! delimited) and the Copilot CLI (`Content-Length` framed, vscode-jsonrpc).

use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Ndjson,
    ContentLength,
}

#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: Option<i64>,
    pub message: String,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Messages initiated by the server.
#[derive(Debug)]
pub enum Incoming {
    Notification(Value),
    Request(Value),
    /// Response to a request (already routed; surfaced for observers).
    Response(Value),
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, RpcError>>>>>;

pub struct RpcClient {
    framing: Framing,
    stdin_tx: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    pending: Pending,
    next_id: AtomicU64,
}

fn encode(framing: Framing, message: &Value) -> Vec<u8> {
    let body = message.to_string();
    match framing {
        Framing::Ndjson => format!("{body}\n").into_bytes(),
        Framing::ContentLength => format!("Content-Length: {}\r\n\r\n{body}", body.len()).into_bytes(),
    }
}

async fn read_message(reader: &mut BufReader<ChildStdout>, framing: Framing, max: usize) -> Option<Result<Value, String>> {
    match framing {
        Framing::Ndjson => {
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match reader.read_until(b'\n', &mut buf).await {
                    Ok(0) | Err(_) => return None,
                    Ok(_) if buf.len() > max => return Some(Err(format!("message exceeded {max} bytes"))),
                    Ok(_) => {
                        let line = String::from_utf8_lossy(&buf).trim().to_string();
                        if line.is_empty() {
                            continue;
                        }
                        match serde_json::from_str::<Value>(&line) {
                            Ok(v) => return Some(Ok(v)),
                            Err(_) => continue,
                        }
                    }
                }
            }
        }
        Framing::ContentLength => {
            let mut length: Option<usize> = None;
            loop {
                let mut header = String::new();
                match reader.read_line(&mut header).await {
                    Ok(0) | Err(_) => return None,
                    Ok(_) => {}
                }
                let h = header.trim();
                if h.is_empty() {
                    if length.is_some() {
                        break;
                    }
                    continue;
                }
                if let Some(v) = h.strip_prefix("Content-Length:").or_else(|| h.strip_prefix("content-length:")) {
                    length = v.trim().parse().ok();
                }
            }
            let len = length?;
            if len > max {
                return Some(Err(format!("message exceeded {max} bytes")));
            }
            let mut body = vec![0u8; len];
            if reader.read_exact(&mut body).await.is_err() {
                return None;
            }
            Some(serde_json::from_slice(&body).map_err(|e| e.to_string()))
        }
    }
}

impl RpcClient {
    /// Start the reader/writer tasks. Server-initiated messages arrive on the
    /// returned channel, which closes when stdout ends.
    pub fn start(stdin: ChildStdin, stdout: ChildStdout, framing: Framing, max_message_bytes: usize) -> (Arc<Self>, mpsc::UnboundedReceiver<Incoming>) {
        let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut stdin = stdin;
        tokio::spawn(async move {
            while let Some(bytes) = stdin_rx.recv().await {
                if stdin.write_all(&bytes).await.is_err() || stdin.flush().await.is_err() {
                    break;
                }
            }
            let _ = stdin.shutdown().await;
        });
        let client = Arc::new(Self { framing, stdin_tx: Mutex::new(Some(stdin_tx)), pending: Arc::new(Mutex::new(HashMap::new())), next_id: AtomicU64::new(1) });
        let (tx, rx) = mpsc::unbounded_channel();
        let pending = client.pending.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::with_capacity(64 * 1024, stdout);
            while let Some(message) = read_message(&mut reader, framing, max_message_bytes).await {
                let Ok(message) = message else { break };
                let has_method = message.get("method").and_then(|m| m.as_str()).is_some();
                let id = message.get("id").filter(|v| !v.is_null());
                if !has_method && id.is_some() {
                    if let Some(waiter) = id.and_then(|v| v.as_u64()).and_then(|id| pending.lock().remove(&id)) {
                        let result = match message.get("error").filter(|e| !e.is_null()) {
                            Some(err) => Err(RpcError {
                                code: err["code"].as_i64(),
                                message: err["message"].as_str().map(str::to_string).or_else(|| err["data"].as_str().map(str::to_string)).unwrap_or_else(|| err.to_string()),
                            }),
                            None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
                        };
                        let _ = waiter.send(result);
                    }
                    let _ = tx.send(Incoming::Response(message));
                } else if has_method && id.is_some() {
                    let _ = tx.send(Incoming::Request(message));
                } else if has_method {
                    let _ = tx.send(Incoming::Notification(message));
                }
            }
            for (_, w) in pending.lock().drain() {
                let _ = w.send(Err(RpcError { code: None, message: "process closed".into() }));
            }
        });
        (client, rx)
    }

    fn write(&self, message: &Value) -> bool {
        match self.stdin_tx.lock().as_ref() {
            Some(tx) => tx.send(encode(self.framing, message)).is_ok(),
            None => false,
        }
    }

    /// Next request id (to correlate the response with a known request).
    pub fn peek_next_id(&self) -> u64 {
        self.next_id.load(Ordering::SeqCst)
    }

    pub async fn request(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, RpcError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(id, tx);
        if !self.write(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })) {
            self.pending.lock().remove(&id);
            return Err(RpcError { code: None, message: "stdin is unavailable".into() });
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(RpcError { code: None, message: "process closed".into() }),
            Err(_) => {
                self.pending.lock().remove(&id);
                Err(RpcError { code: None, message: format!("request timed out: {method}") })
            }
        }
    }

    pub fn notify(&self, method: &str, params: Value) {
        self.write(&json!({ "jsonrpc": "2.0", "method": method, "params": params }));
    }

    pub fn respond(&self, id: &Value, result: Value) {
        self.write(&json!({ "jsonrpc": "2.0", "id": id, "result": result }));
    }

    pub fn respond_error(&self, id: &Value, code: i64, message: &str) {
        self.write(&json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }));
    }

    pub fn reject_all(&self, message: &str) {
        for (_, w) in self.pending.lock().drain() {
            let _ = w.send(Err(RpcError { code: None, message: message.into() }));
        }
    }

    pub fn close_stdin(&self) {
        self.stdin_tx.lock().take();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::cli::SpawnSpec;
    use crate::process::{build_command, Stdin};

    async fn echo_server(script: &str, framing: Framing) -> (tokio::process::Child, Arc<RpcClient>, mpsc::UnboundedReceiver<Incoming>) {
        let spec = SpawnSpec { command: "python3".into(), args: vec!["-c".into(), script.into()], shell: false };
        let env: crate::EnvMap = std::env::vars().collect();
        let mut child = build_command(&spec, &env, None, Stdin::Piped).spawn().unwrap();
        let (client, rx) = RpcClient::start(child.stdin.take().unwrap(), child.stdout.take().unwrap(), framing, 1 << 20);
        (child, client, rx)
    }

    #[tokio::test]
    async fn ndjson_round_trip() {
        let script = "import sys,json\nfor l in sys.stdin:\n  m=json.loads(l)\n  print(json.dumps({'jsonrpc':'2.0','method':'note','params':{'m':m['method']}}),flush=True)\n  print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':{'ok':m['params']['x']}}),flush=True)\n";
        let (_child, client, mut rx) = echo_server(script, Framing::Ndjson).await;
        let r = client.request("ping", json!({ "x": 7 }), Duration::from_secs(5)).await.unwrap();
        assert_eq!(r["ok"], 7);
        let Incoming::Notification(n) = rx.recv().await.unwrap() else { panic!() };
        assert_eq!(n["params"]["m"], "ping");
    }

    #[tokio::test]
    async fn content_length_round_trip_and_errors() {
        let script = r#"
import sys,json
def read():
    h={}
    while True:
        line=sys.stdin.buffer.readline()
        if not line: return None
        line=line.strip()
        if not line: break
        k,v=line.split(b':',1); h[k.lower()]=int(v)
    return json.loads(sys.stdin.buffer.read(h[b'content-length']))
def send(o):
    b=json.dumps(o).encode(); sys.stdout.buffer.write(b'Content-Length: %d\r\n\r\n'%len(b)+b); sys.stdout.flush()
while True:
    m=read()
    if m is None: break
    if m['method']=='fail': send({'jsonrpc':'2.0','id':m['id'],'error':{'code':-32601,'message':'nope'}})
    else:
        send({'jsonrpc':'2.0','id':99,'method':'perm','params':{}})
        send({'jsonrpc':'2.0','id':m['id'],'result':'ok'})
"#;
        let (_child, client, mut rx) = echo_server(script, Framing::ContentLength).await;
        assert_eq!(client.request("a", json!({}), Duration::from_secs(5)).await.unwrap(), "ok");
        let Incoming::Request(req) = rx.recv().await.unwrap() else { panic!() };
        assert_eq!(req["method"], "perm");
        let err = client.request("fail", json!({}), Duration::from_secs(5)).await.unwrap_err();
        assert_eq!((err.code, err.message.as_str()), (Some(-32601), "nope"));
    }
}

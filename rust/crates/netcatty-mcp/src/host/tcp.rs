//! Loopback NDJSON JSON-RPC TCP host (Electron `getOrCreateHost`,
//! `handleConnection`, `handleMessage`, discovery file + self-heal).
//!
//! The first message of a connection must be `auth/verify { token }` with
//! the shared token (managed agents / tool CLI) or the External MCP token.
//! External-token connections always operate in the reserved
//! `__external_mcp__` scope.

use super::{McpHost, EXTERNAL_MCP_CHAT_SESSION_ID};
use netcatty_capabilities::DispatchContext;
use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

pub const MAX_TCP_BUFFER: usize = 10 * 1024 * 1024;
pub const DISCOVERY_SELF_HEAL_INTERVAL: Duration = Duration::from_secs(15);

pub(crate) struct TcpInner {
    port: Option<u16>,
    token: Option<String>,
    external_token: Option<String>,
    listener_task: Option<tokio::task::JoinHandle<()>>,
    heal_task: Option<tokio::task::JoinHandle<()>>,
}

pub struct TcpState {
    inner: Mutex<TcpInner>,
    start_lock: tokio::sync::Mutex<()>,
    discovery_path: Option<PathBuf>,
}

impl TcpState {
    pub(crate) fn new(discovery_path: Option<PathBuf>) -> Self {
        Self {
            inner: Mutex::new(TcpInner { port: None, token: None, external_token: None, listener_task: None, heal_task: None }),
            start_lock: tokio::sync::Mutex::new(()),
            discovery_path,
        }
    }

    pub fn port(&self) -> Option<u16> {
        self.inner.lock().port
    }

    pub fn token(&self) -> Option<String> {
        self.inner.lock().token.clone()
    }

    pub fn discovery_path(&self) -> Option<PathBuf> {
        std::env::var_os(crate::discovery::TOOL_CLI_DISCOVERY_ENV_VAR)
            .map(PathBuf::from)
            .or_else(|| self.discovery_path.clone())
    }
}

pub(crate) fn random_token() -> String {
    let a: [u8; 32] = rand::random();
    hex::encode(a)
}

fn write_private_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    let mut f = opts.open(path)?;
    f.write_all(contents.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub(crate) fn write_json_private(path: &std::path::Path, value: &Value) -> std::io::Result<()> {
    write_private_file(path, &format!("{}\n", serde_json::to_string_pretty(value).unwrap_or_default()))
}

impl McpHost {
    /// Start the TCP host once (idempotent) and return its port.
    pub async fn get_or_create_host(&self) -> std::io::Result<u16> {
        if let Some(port) = self.tcp.port() {
            self.ensure_cli_discovery_file();
            return Ok(port);
        }
        let _g = self.tcp.start_lock.lock().await;
        if let Some(port) = self.tcp.port() {
            return Ok(port);
        }
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let token = random_token();
        let weak = self.me.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                let Some(host) = weak.upgrade() else {
                    break;
                };
                tokio::spawn(host.handle_connection(sock));
            }
        });
        {
            let mut inner = self.tcp.inner.lock();
            inner.port = Some(port);
            inner.token = Some(token);
            inner.listener_task = Some(task);
        }
        self.write_cli_discovery_file();
        self.start_discovery_self_heal();
        if let Some(h) = self.external.lock().clone() {
            h.on_bridge_host_ready(port);
        }
        Ok(port)
    }

    fn start_discovery_self_heal(&self) {
        let weak = self.me.clone();
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(DISCOVERY_SELF_HEAL_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                match weak.upgrade() {
                    Some(h) => h.ensure_cli_discovery_file(),
                    None => break,
                }
            }
        });
        if let Some(old) = self.tcp.inner.lock().heal_task.replace(task) {
            old.abort();
        }
    }

    /// Rewrite the tool-CLI discovery file (`{ port, token, pid, permissionMode, updatedAt }`).
    pub fn write_cli_discovery_file(&self) {
        let (Some(port), Some(token), Some(path)) = (self.tcp.port(), self.tcp.token(), self.tcp.discovery_path()) else {
            return;
        };
        let payload = json!({
            "port": port,
            "token": token,
            "pid": std::process::id(),
            "permissionMode": self.permission_mode(),
            "updatedAt": crate::discovery::iso_now(),
        });
        if let Err(err) = write_json_private(&path, &payload) {
            tracing::warn!(%err, "failed to write AI CLI discovery file");
        }
    }

    fn is_cli_discovery_file_current(&self) -> bool {
        let Some(path) = self.tcp.discovery_path() else {
            return true;
        };
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return false;
        };
        let Ok(parsed) = serde_json::from_str::<Value>(&raw) else {
            return false;
        };
        parsed["port"].as_u64() == self.tcp.port().map(u64::from)
            && parsed["token"].as_str() == self.tcp.token().as_deref()
            && parsed["pid"].as_u64() == Some(std::process::id() as u64)
    }

    /// Self-heal: recreate a deleted / stale discovery file.
    pub fn ensure_cli_discovery_file(&self) {
        if self.tcp.port().is_none() || self.tcp.token().is_none() {
            return;
        }
        if !self.is_cli_discovery_file_current() {
            self.write_cli_discovery_file();
        }
    }

    /// Stop the host: remove discovery, deny approvals, cancel work.
    pub fn shutdown_host(&self, preserve_scoped_metadata: bool) {
        let (listener, heal) = {
            let mut inner = self.tcp.inner.lock();
            inner.port = None;
            inner.token = None;
            (inner.listener_task.take(), inner.heal_task.take())
        };
        if let Some(t) = listener {
            t.abort();
        }
        if let Some(t) = heal {
            t.abort();
        }
        if let Some(path) = self.tcp.discovery_path() {
            let _ = std::fs::remove_file(path);
        }
        self.clear_pending_approvals(None);
        self.active_execs.cancel_all();
        self.cancel_all_sftp_ops();
        {
            let mut st = self.st.lock();
            st.cancelled_chats.clear();
            st.active_chat_execs.clear();
            if !preserve_scoped_metadata {
                st.scoped.clear();
                st.attachments.clear();
                st.live.clear();
            }
        }
        for job in self.jobs.jobs.lock().values() {
            if let Some(h) = &job.handle {
                h.cancel();
            }
        }
        self.jobs.jobs.lock().clear();
        self.idle.clear_all();
    }

    // ── External MCP token ───────────────────────────────────────────

    /// Rotate the External MCP token (enable / rotate).
    pub fn issue_external_mcp_auth_token(&self) -> String {
        let token = random_token();
        self.tcp.inner.lock().external_token = Some(token.clone());
        token
    }

    pub fn external_mcp_auth_token(&self) -> Option<String> {
        self.tcp.inner.lock().external_token.clone()
    }

    /// Soft revoke on disable: sockets stay open but are rejected.
    pub fn revoke_external_mcp_auth_token(&self) {
        self.tcp.inner.lock().external_token = None;
        self.revoke_external_session_approvals();
    }

    // ── connections ──────────────────────────────────────────────────

    async fn handle_connection(self: Arc<Self>, sock: tokio::net::TcpStream) {
        let (read, write) = sock.into_split();
        let writer = Arc::new(tokio::sync::Mutex::new(write));
        let mut reader = BufReader::new(read);
        let client_id = self.new_external_client_id();
        let authenticated = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let external = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = match (&mut reader).take(MAX_TCP_BUFFER as u64 + 1).read_until(b'\n', &mut line).await {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            if line.len() > MAX_TCP_BUFFER {
                tracing::warn!("MCP bridge TCP buffer exceeded max size, dropping connection");
                break;
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let Ok(msg) = serde_json::from_slice::<Value>(&line) else {
                continue;
            };
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            let Some(method) = msg.get("method").and_then(Value::as_str).map(str::to_string) else {
                continue;
            };
            if id.is_null() {
                continue;
            }
            let params = msg.get("params").and_then(Value::as_object).cloned().unwrap_or_default();
            if !authenticated.load(std::sync::atomic::Ordering::SeqCst) {
                let presented = params.get("token").and_then(Value::as_str).unwrap_or("");
                let shared = self.tcp.token().is_some_and(|t| !presented.is_empty() && t == presented);
                let ext = self.external_mcp_auth_token().is_some_and(|t| !presented.is_empty() && t == presented);
                if method == "auth/verify" && (shared || ext) {
                    if ext && !self.external_enabled() {
                        let resp = json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32001, "message": "External MCP is disabled. Re-enable it in Netcatty Settings → AI." } });
                        let _ = write_line(&writer, &resp).await;
                        break;
                    }
                    authenticated.store(true, std::sync::atomic::Ordering::SeqCst);
                    if ext {
                        external.store(true, std::sync::atomic::Ordering::SeqCst);
                        self.attach_external_client(client_id);
                    }
                    let _ = write_line(&writer, &json!({ "jsonrpc": "2.0", "id": id, "result": { "ok": true } })).await;
                    continue;
                }
                tracing::warn!(method, "MCP bridge auth/verify failed or unexpected first method");
                let resp = json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32001, "message": "Authentication required. Send auth/verify with valid token first." } });
                let _ = write_line(&writer, &resp).await;
                break;
            }
            let host = self.clone();
            let writer = writer.clone();
            let is_external = external.clone();
            tokio::spawn(async move {
                let result = host.handle_authenticated(&method, params, client_id, &is_external).await;
                let resp = match result {
                    Ok(v) => json!({ "jsonrpc": "2.0", "id": id, "result": v }),
                    Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": e } }),
                };
                let _ = write_line(&writer, &resp).await;
            });
        }
        if external.load(std::sync::atomic::Ordering::SeqCst) {
            self.detach_external_client(client_id);
        }
    }

    async fn handle_authenticated(&self, method: &str, mut params: Map<String, Value>, client_id: u64, external: &std::sync::atomic::AtomicBool) -> Result<Value, String> {
        use std::sync::atomic::Ordering;
        if external.load(Ordering::SeqCst) {
            params.insert("chatSessionId".into(), json!(EXTERNAL_MCP_CHAT_SESSION_ID));
        }
        let is_external_scope = params.get("chatSessionId").and_then(Value::as_str) == Some(EXTERNAL_MCP_CHAT_SESSION_ID);
        if is_external_scope && !external.swap(true, Ordering::SeqCst) {
            self.attach_external_client(client_id);
        }
        if (is_external_scope || external.load(Ordering::SeqCst)) && !self.external_enabled() {
            return Err("External MCP is disabled. Re-enable it in Netcatty Settings → AI.".into());
        }
        if is_external_scope {
            if let Some(h) = self.external.lock().clone() {
                h.record_activity();
            }
        }
        let ctx = DispatchContext { external_client: Some(client_id), before_execute: None };
        self.dispatch(method, params, ctx).await
    }

    /// Dispatch for a synthetic external client (External MCP HTTP).
    pub async fn dispatch_external(&self, method: &str, mut params: Map<String, Value>, client_id: u64) -> Result<Value, String> {
        if !self.external_enabled() {
            return Err("External MCP is disabled. Re-enable it in Netcatty Settings → AI.".into());
        }
        params.insert("chatSessionId".into(), json!(EXTERNAL_MCP_CHAT_SESSION_ID));
        if let Some(h) = self.external.lock().clone() {
            h.record_activity();
        }
        self.dispatch(method, params, DispatchContext { external_client: Some(client_id), before_execute: None }).await
    }
}

async fn write_line(writer: &tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>, value: &Value) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(value).unwrap_or_default();
    bytes.push(b'\n');
    let mut w = writer.lock().await;
    w.write_all(&bytes).await?;
    w.flush().await
}

use tokio::io::AsyncReadExt as _;

//! Stdio MCP server helper mode (Electron `electron/mcp/netcatty-mcp-server.cjs`
//! and `netcatty-external-mcp-server.cjs`).
//!
//! The Netcatty executable started with `--mcp-server` (managed SDK agents;
//! env `NETCATTY_MCP_PORT` / `NETCATTY_MCP_TOKEN` / `NETCATTY_MCP_CHAT_SESSION_ID`
//! / `NETCATTY_MCP_SESSION_IDS` / `NETCATTY_MCP_PERMISSION_MODE`) or by an
//! External MCP client (`NETCATTY_MCP_HELPER=external` /
//! `--external-mcp-server`, discovery file in
//! `NETCATTY_EXTERNAL_MCP_DISCOVERY_FILE`) speaks MCP over stdio and
//! forwards tool calls to the running app's TCP host. Managed children fail
//! fast when the host goes away; external clients reconnect on the next
//! call after re-reading discovery, and their results pass through the
//! External MCP privacy boundary.

use crate::discovery::{read_external_discovery, EXTERNAL_MCP_DISCOVERY_ENV_VAR};
use crate::protocol::{McpSession, RpcCaller};
use crate::redaction::PrivacyBoundary;
use netcatty_capabilities::transport::NdjsonRpcClient;
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

/// How to reach the host.
#[derive(Clone)]
pub enum Endpoint {
    Managed { port: u16, token: String },
    External { discovery: PathBuf },
}

/// Lazily (re)connecting TCP RPC caller.
pub struct TcpRpc {
    endpoint: Endpoint,
    client: Mutex<Option<Arc<NdjsonRpcClient>>>,
}

impl TcpRpc {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint, client: Mutex::new(None) }
    }

    async fn connect(&self) -> Result<Arc<NdjsonRpcClient>, String> {
        let (port, token) = match &self.endpoint {
            Endpoint::Managed { port, token } => (*port, token.clone()),
            Endpoint::External { discovery } => {
                let d = read_external_discovery(discovery)
                    .map_err(|_| "Netcatty is temporarily unavailable: discovery file is missing or unreadable".to_string())?;
                (d.port, d.token)
            }
        };
        let unavailable = |e: String| {
            if e.starts_with("Netcatty is temporarily unavailable") {
                e
            } else {
                format!("Netcatty is temporarily unavailable: {e}")
            }
        };
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| unavailable(e.to_string()))?;
        let client = NdjsonRpcClient::new(stream, "builtin");
        let auth = client.call("auth/verify", json!({ "token": token })).await.map_err(|e| unavailable(e.message))?;
        if auth.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err("Netcatty is temporarily unavailable: TCP bridge authentication failed".into());
        }
        eprintln!("[netcatty-mcp] Authenticated with TCP bridge");
        Ok(client)
    }

    /// Connect now (startup).
    pub async fn ensure_connected(&self) -> Result<(), String> {
        let mut slot = self.client.lock().await;
        if slot.as_ref().is_some_and(|c| !c.is_closed()) {
            return Ok(());
        }
        *slot = Some(self.connect().await?);
        Ok(())
    }
}

#[async_trait::async_trait]
impl RpcCaller for TcpRpc {
    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let client = {
            let mut slot = self.client.lock().await;
            match (&*slot, &self.endpoint) {
                (Some(c), _) if !c.is_closed() => c.clone(),
                (_, Endpoint::Managed { .. }) => return Err("Not connected to Netcatty".into()),
                (_, Endpoint::External { .. }) => {
                    let c = self.connect().await?;
                    *slot = Some(c.clone());
                    c
                }
            }
        };
        client.call(method, params).await.map_err(|e| match (&self.endpoint, e.code.as_str()) {
            (Endpoint::Managed { .. }, "CONNECTION_CLOSED" | "CONNECTION_ERROR") => "Not connected to Netcatty".to_string(),
            (_, "CONNECTION_CLOSED") => "TCP connection closed".to_string(),
            _ => e.message,
        })
    }
}

/// Privacy boundary around the TCP caller (external clients only).
struct ProtectedRpc {
    inner: Arc<TcpRpc>,
    boundary: PrivacyBoundary,
}

#[async_trait::async_trait]
impl RpcCaller for ProtectedRpc {
    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let (restored, protection) = self.boundary.restore(params)?;
        let outcome = self.inner.call(method, restored).await;
        self.boundary.finish(method, outcome, protection)
    }
}

/// Configuration of a stdio server run, read from the environment.
pub struct StdioConfig {
    pub endpoint: Endpoint,
    pub scope: Map<String, Value>,
    pub delegated_tools: Option<Vec<String>>,
    /// Toolsets loaded from the start (`NETCATTY_MCP_TOOLSETS=a,b` or `all`).
    pub toolsets: Vec<String>,
}

impl StdioConfig {
    /// `external`: launched by an External MCP client.
    pub fn from_env(external: bool, default_external_discovery: Option<PathBuf>) -> Result<Self, String> {
        let env = |k: &str| std::env::var(k).ok();
        let discovery = env(EXTERNAL_MCP_DISCOVERY_ENV_VAR)
            .map(PathBuf::from)
            .or_else(|| default_external_discovery.filter(|_| external));
        let endpoint = match (&discovery, external) {
            (Some(path), _) => Endpoint::External { discovery: path.clone() },
            (None, true) => return Err("Discovery file not found. Enable External MCP in Netcatty Settings → AI and keep the app running.".into()),
            (None, false) => {
                let port = env("NETCATTY_MCP_PORT").and_then(|p| p.parse().ok()).ok_or("NETCATTY_MCP_PORT not set")?;
                let token = env("NETCATTY_MCP_TOKEN").filter(|t| !t.is_empty()).ok_or("NETCATTY_MCP_TOKEN not set")?;
                Endpoint::Managed { port, token }
            }
        };
        let chat = match &endpoint {
            Endpoint::External { discovery } => read_external_discovery(discovery).map(|d| d.chat_session_id).ok().or(env("NETCATTY_MCP_CHAT_SESSION_ID")),
            Endpoint::Managed { .. } => env("NETCATTY_MCP_CHAT_SESSION_ID"),
        }
        .filter(|c| !c.is_empty());
        let mut scope = Map::new();
        match chat {
            Some(c) => {
                scope.insert("chatSessionId".into(), json!(c));
            }
            None => {
                let ids: Option<Vec<String>> = env("NETCATTY_MCP_SESSION_IDS").map(|s| s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect());
                scope.insert("scopedSessionIds".into(), json!(ids));
                scope.insert("chatSessionId".into(), Value::Null);
            }
        }
        let delegated_tools = match env("NETCATTY_MCP_DELEGATED_TOOLS") {
            None => None,
            Some(raw) => {
                let names: Vec<String> = serde_json::from_str(&raw).map_err(|_| "Invalid delegated tool profile")?;
                if names.len() > 128 {
                    return Err("Invalid delegated tool profile".into());
                }
                Some(names)
            }
        };
        let toolsets = env(crate::discovery::TOOLSETS_ENV_VAR)
            .map(|raw| raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect())
            .unwrap_or_default();
        Ok(Self { endpoint, scope, delegated_tools, toolsets })
    }
}

fn read_permission_mode(endpoint: &Endpoint, delegated: bool) -> String {
    if delegated {
        return "confirm".into();
    }
    if let Endpoint::External { discovery } = endpoint {
        if let Ok(d) = read_external_discovery(discovery) {
            if !d.permission_mode.trim().is_empty() {
                return d.permission_mode.trim().to_string();
            }
        }
    }
    std::env::var("NETCATTY_MCP_PERMISSION_MODE").unwrap_or_else(|_| "confirm".into())
}

/// Serve MCP on stdin / stdout until stdin closes. Returns the exit code.
pub async fn run(config: StdioConfig) -> i32 {
    let tcp = Arc::new(TcpRpc::new(config.endpoint.clone()));
    if let Err(e) = tcp.ensure_connected().await {
        eprintln!("[netcatty-mcp] Fatal: {e}");
        return 1;
    }
    let delegated = config.delegated_tools.is_some();
    let rpc: Arc<dyn RpcCaller> = match &config.endpoint {
        Endpoint::External { discovery } => {
            let path = discovery.clone();
            Arc::new(ProtectedRpc {
                inner: tcp.clone(),
                boundary: PrivacyBoundary::new(move || {
                    let raw = std::fs::read_to_string(&path).ok()?;
                    let v: Value = serde_json::from_str(&raw).ok()?;
                    Some(v.get("redaction").cloned().unwrap_or(json!({})))
                }),
            })
        }
        Endpoint::Managed { .. } => tcp.clone(),
    };
    let endpoint = config.endpoint.clone();
    let observer = Arc::new(move || read_permission_mode(&endpoint, delegated) == "observer");
    let session = Arc::new(McpSession::new(rpc, config.scope, observer, config.delegated_tools).with_toolsets(&config.toolsets));
    serve_lines(session, tokio::io::stdin(), tokio::io::stdout()).await;
    0
}

/// Serve newline-delimited JSON-RPC on any reader / writer pair.
pub async fn serve_lines<Rd, Wr>(session: Arc<McpSession>, reader: Rd, writer: Wr)
where
    Rd: tokio::io::AsyncRead + Unpin,
    Wr: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let writer = Arc::new(Mutex::new(writer));
    let mut lines = BufReader::new(reader).lines();
    let mut tasks = tokio::task::JoinSet::new();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            let err = json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } });
            write_message(&writer, &err).await;
            continue;
        };
        let messages = match msg {
            Value::Array(items) => items,
            other => vec![other],
        };
        for m in messages {
            let session = session.clone();
            let writer = writer.clone();
            tasks.spawn(async move {
                let handled = session.handle(m).await;
                if let Some(r) = handled.response {
                    write_message(&writer, &r).await;
                }
                for n in handled.notifications {
                    write_message(&writer, &n).await;
                }
            });
        }
    }
    while tasks.join_next().await.is_some() {}
}

async fn write_message<W: tokio::io::AsyncWrite + Unpin>(writer: &Mutex<W>, value: &Value) {
    let mut bytes = serde_json::to_vec(value).unwrap_or_default();
    bytes.push(b'\n');
    let mut w = writer.lock().await;
    let _ = w.write_all(&bytes).await;
    let _ = w.flush().await;
}

/// Entry point used by `main.rs`: returns `Some(exit_code)` when the
/// process was started as an MCP helper.
///
/// `data_dir` is the application data directory (default discovery files).
pub fn run_if_requested(data_dir: &std::path::Path) -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    let managed = args.iter().any(|a| a == crate::discovery::MCP_SERVER_FLAG);
    let external = args.iter().any(|a| a == crate::discovery::EXTERNAL_MCP_SERVER_FLAG)
        || (args.len() <= 1 && std::env::var(crate::discovery::HELPER_MODE_ENV_VAR).ok().as_deref() == Some(crate::discovery::HELPER_MODE_EXTERNAL));
    if args.iter().any(|a| a == crate::discovery::TOOL_CLI_FLAG) {
        let pos = args.iter().position(|a| a == crate::discovery::TOOL_CLI_FLAG).unwrap();
        let rest = args[pos + 1..].to_vec();
        crate::tool_cli::set_default_discovery_path(crate::discovery::tool_cli_discovery_path(data_dir));
        return Some(block_on(crate::tool_cli::run(rest)));
    }
    if !managed && !external {
        return None;
    }
    let default_discovery = Some(crate::discovery::external_mcp_discovery_path(data_dir));
    let config = match StdioConfig::from_env(external && !managed, default_discovery) {
        Ok(c) => c,
        Err(e) => {
            let prefix = if external { "netcatty-external-mcp" } else { "netcatty-mcp" };
            eprintln!("[{prefix}] {e}");
            return Some(1);
        }
    };
    Some(block_on(run(config)))
}

fn block_on<F: std::future::Future<Output = i32>>(f: F) -> i32 {
    match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt.block_on(f),
        Err(e) => {
            eprintln!("[netcatty-mcp] Fatal: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::backend::*;
    use crate::host::McpHost;
    use tokio::io::AsyncBufReadExt;

    struct NoBackend;
    #[async_trait::async_trait]
    impl HostBackend for NoBackend {
        fn session(&self, _id: &str) -> Option<Arc<dyn TerminalSession>> {
            None
        }
        fn session_ids(&self) -> Vec<String> {
            Vec::new()
        }
        async fn sftp(&self, _id: &str, _op: SftpOp, _c: tokio_util::sync::CancellationToken) -> Result<Value, String> {
            Err("no".into())
        }
        fn emit(&self, _e: &str, _p: Value) {}
        async fn list_port_forwards(&self) -> Vec<Value> {
            Vec::new()
        }
    }

    #[tokio::test]
    async fn stdio_server_forwards_tool_calls_to_the_tcp_host() {
        let host = McpHost::new(Arc::new(NoBackend), None);
        let port = host.get_or_create_host().await.unwrap();
        host.update_session_metadata(&[json!({ "sessionId": "s1", "label": "web", "connected": true })], Some("chat"));
        let tcp = Arc::new(TcpRpc::new(Endpoint::Managed { port, token: host.tcp.token().unwrap() }));
        tcp.ensure_connected().await.unwrap();
        let scope = json!({ "chatSessionId": "chat" }).as_object().unwrap().clone();
        let session = Arc::new(McpSession::new(tcp, scope, Arc::new(|| false), None));
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (sr, sw) = tokio::io::split(server);
        tokio::spawn(serve_lines(session, sr, sw));
        let (cr, mut cw) = tokio::io::split(client);
        let mut lines = tokio::io::BufReader::new(cr).lines();
        cw.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"get_environment\"}}\n").await.unwrap();
        let resp: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"hostCount\": 1"), "{text}");
        cw.write_all(b"not json\n").await.unwrap();
        let resp: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(resp["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn external_endpoint_reports_unavailable_without_discovery() {
        let rpc = TcpRpc::new(Endpoint::External { discovery: PathBuf::from("/nonexistent/discovery.json") });
        let e = rpc.call("netcatty/getContext", json!({})).await.unwrap_err();
        assert!(e.starts_with("Netcatty is temporarily unavailable"));
        let managed = TcpRpc::new(Endpoint::Managed { port: 1, token: "x".into() });
        assert_eq!(managed.call("x", json!({})).await.unwrap_err(), "Not connected to Netcatty");
    }
}

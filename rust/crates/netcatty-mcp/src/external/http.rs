//! External MCP streamable-HTTP endpoint (Electron
//! `externalMcp/httpServer.cjs` + `httpSecurity.cjs`).
//!
//! `POST /mcp` with JSON-RPC, `Mcp-Session-Id` sessions created by
//! `initialize`, `DELETE` to end a session. A request is answered with plain
//! JSON (like the SDK's `enableJsonResponse`) unless handling it produced a
//! notification — `notifications/tools/list_changed` after a toolset load —
//! in which case the answer is a short `text/event-stream` carrying the
//! notification and then the response, as the streamable-HTTP transport
//! allows. Without that the notification had nowhere to go and a client
//! never learned about the tools it had just loaded. The standalone SSE
//! stream (`GET`) is not offered (405, which the spec allows).
//!
//! `initialize` may carry `?toolsets=sftp_advanced,vault_hosts` (or `all`) to
//! start the session with those toolsets loaded, for clients that do not
//! re-read the tool list at all. Every request needs
//! `Authorization: Bearer <external token>` and a Host / Origin matching the
//! bind address (DNS-rebinding protection).

use crate::host::McpHost;
use crate::protocol::{McpSession, RpcCaller};
use crate::redaction::PrivacyBoundary;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

pub const DEFAULT_EXTERNAL_MCP_HTTP_PORT: u16 = 47391;
pub const DEFAULT_EXTERNAL_MCP_HTTP_HOST: &str = "127.0.0.1";
pub const EXTERNAL_MCP_HTTP_PATH: &str = "/mcp";
pub const MIN_PORT: u16 = 1024;
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const SESSION_IDLE: Duration = Duration::from_secs(15 * 60);
const SESSION_SWEEP: Duration = Duration::from_secs(60);

pub fn is_wildcard_bind(addr: &str) -> bool {
    addr == "0.0.0.0" || addr == "::"
}

fn unbracket(host: &str) -> &str {
    if host.len() > 2 && host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

pub fn is_loopback_host(host: &str) -> bool {
    matches!(unbracket(host).to_lowercase().as_str(), "localhost" | "127.0.0.1" | "::1")
}

fn is_ip(host: &str) -> bool {
    unbracket(host).parse::<IpAddr>().is_ok()
}

/// `Ok(port)` or `(errorCode, message)`.
pub fn normalize_http_port(v: &Value) -> Result<u16, (String, String)> {
    let n = match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    };
    match n {
        Some(p) if p.fract() == 0.0 && (MIN_PORT as f64..=65535.0).contains(&p) => Ok(p as u16),
        _ => Err(("invalid_port".into(), "Enter a port from 1024 to 65535.".into())),
    }
}

pub fn normalize_listen_address(v: &str) -> Result<String, (String, String)> {
    let a = v.trim();
    if a.parse::<IpAddr>().is_err() {
        return Err(("invalid_address".into(), "Listen address must be an IP address such as 0.0.0.0 or a vEthernet address.".into()));
    }
    Ok(a.to_string())
}

pub fn normalize_client_host(v: &str) -> Result<String, (String, String)> {
    let a = v.trim();
    if a.is_empty() {
        return Ok(String::new());
    }
    if a.parse::<IpAddr>().is_err() || is_wildcard_bind(a) {
        return Err(("invalid_client_host".into(), "Client address must be a reachable IP, not 0.0.0.0 or ::.".into()));
    }
    Ok(a.to_string())
}

pub fn build_client_url(listen: &str, port: u16, client_host: &str) -> Option<String> {
    let host = if is_wildcard_bind(listen) { client_host.trim() } else { listen };
    if host.is_empty() || is_wildcard_bind(host) || host.parse::<IpAddr>().is_err() {
        return None;
    }
    let h = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host.to_string() };
    Some(format!("http://{h}:{port}{EXTERNAL_MCP_HTTP_PATH}"))
}

/// `(hostname, port)` of a Host header.
pub fn parse_host_header(raw: &str) -> Option<(String, Option<String>)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some(rest) = raw.strip_prefix('[') {
        let end = rest.find(']')?;
        if end == 0 {
            return None;
        }
        let host = &rest[..end];
        let after = &rest[end + 1..];
        if after.is_empty() {
            return Some((host.into(), None));
        }
        let port = after.strip_prefix(':')?;
        return port.chars().all(|c| c.is_ascii_digit()).then(|| (host.to_string(), Some(port.to_string()))).filter(|_| !port.is_empty());
    }
    match raw.rfind(':') {
        None => Some((raw.into(), None)),
        Some(i) => {
            let (h, p) = (&raw[..i], &raw[i + 1..]);
            (!h.is_empty() && !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())).then(|| (h.to_string(), Some(p.to_string())))
        }
    }
}

pub fn is_allowed_hostname(host: &str, listen: &str) -> bool {
    let h = unbracket(host);
    if is_loopback_host(h) {
        return true;
    }
    if is_wildcard_bind(listen) {
        return is_ip(h);
    }
    h.eq_ignore_ascii_case(listen)
}

/// `Err((status, message))` for rejected headers.
pub fn validate_request_headers(host: &str, origin: Option<&str>, listen: &str, port: u16) -> Result<(), (u16, &'static str)> {
    let bad_host = Err((421, "Invalid Host header"));
    match parse_host_header(host) {
        Some((h, Some(p))) if p == port.to_string() && is_allowed_hostname(&h, listen) => {}
        _ => return bad_host,
    }
    if let Some(o) = origin.filter(|o| !o.is_empty()) {
        let Ok(url) = url_parse(o) else {
            return Err((403, "Invalid Origin header"));
        };
        if !is_allowed_hostname(&url, listen) {
            return Err((403, "Invalid Origin header"));
        }
    }
    Ok(())
}

/// Hostname of an `http(s)://` origin without credentials.
fn url_parse(origin: &str) -> Result<String, ()> {
    let rest = origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://")).ok_or(())?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') || authority.is_empty() {
        return Err(());
    }
    let (h, _) = parse_host_header(authority).ok_or(())?;
    Ok(h)
}

pub fn read_bearer_token(header: Option<&str>) -> String {
    let Some(h) = header else {
        return String::new();
    };
    let t = h.trim();
    let mut parts = t.splitn(2, char::is_whitespace);
    match (parts.next(), parts.next()) {
        (Some(scheme), Some(tok)) if scheme.eq_ignore_ascii_case("bearer") && !tok.trim().is_empty() && !tok.trim().contains(char::is_whitespace) => tok.trim().to_string(),
        _ => String::new(),
    }
}

pub fn tokens_equal(presented: &str, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    let a = Sha256::digest(presented.as_bytes());
    let b = Sha256::digest(expected.as_bytes());
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Hooks the HTTP runtime needs from the controller.
pub trait HttpHooks: Send + Sync {
    fn token(&self) -> String;
    fn is_enabled(&self) -> bool;
    fn redaction_config(&self) -> Value;
}

struct HttpSession {
    mcp: Arc<McpSession>,
    client_id: u64,
    last_activity: Mutex<Instant>,
    in_flight: std::sync::atomic::AtomicUsize,
}

struct HttpRpc {
    host: Arc<McpHost>,
    client_id: u64,
    boundary: PrivacyBoundary,
    hooks: Arc<dyn HttpHooks>,
}

#[async_trait::async_trait]
impl RpcCaller for HttpRpc {
    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        if !self.hooks.is_enabled() {
            return Err("External MCP is disabled. Re-enable it in Netcatty Settings → AI.".into());
        }
        let (restored, protection) = self.boundary.restore(params)?;
        let p = restored.as_object().cloned().unwrap_or_default();
        let outcome = self.host.dispatch_external(method, p, self.client_id).await;
        self.boundary.finish(method, outcome, protection)
    }
}

/// A running HTTP listener.
pub struct HttpRuntime {
    pub host: String,
    pub port: u16,
    task: tokio::task::JoinHandle<()>,
    sweep: tokio::task::JoinHandle<()>,
    sessions: Arc<Mutex<HashMap<String, Arc<HttpSession>>>>,
    mcp_host: Arc<McpHost>,
}

impl HttpRuntime {
    pub async fn stop(self) {
        self.task.abort();
        self.sweep.abort();
        for (_, s) in self.sessions.lock().drain() {
            self.mcp_host.detach_external_client(s.client_id);
        }
    }
}

fn json_response(status: u16, body: Value, extra: &[(&str, String)]) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    let mut b = Response::builder().status(status).header("Content-Type", "application/json").header("Cache-Control", "no-store");
    for (k, v) in extra {
        b = b.header(*k, v);
    }
    b.body(Full::new(Bytes::from(bytes))).unwrap()
}

/// The messages of one POST as a finished event stream.
fn sse_response(messages: &[Value], extra: &[(&str, String)]) -> Response<Full<Bytes>> {
    let mut body = String::new();
    for m in messages {
        body.push_str("event: message\ndata: ");
        body.push_str(&serde_json::to_string(m).unwrap_or_default());
        body.push_str("\n\n");
    }
    let mut b = Response::builder().status(200).header("Content-Type", "text/event-stream").header("Cache-Control", "no-store");
    for (k, v) in extra {
        b = b.header(*k, v);
    }
    b.body(Full::new(Bytes::from(body))).unwrap()
}

/// `Accept` lists `text/event-stream` (the transport requires clients to).
pub fn accepts_event_stream(accept: Option<&str>) -> bool {
    accept.is_some_and(|a| a.split(',').any(|part| part.split(';').next().is_some_and(|t| t.trim().eq_ignore_ascii_case("text/event-stream"))))
}

/// Toolset names of a `?toolsets=a,b` query (the comma may be `%2C`).
pub fn toolsets_from_query(query: Option<&str>) -> Vec<String> {
    let Some(value) = query.and_then(|q| q.split('&').find_map(|pair| pair.strip_prefix("toolsets="))) else {
        return Vec::new();
    };
    value.replace("%2C", ",").replace("%2c", ",").split(',').map(str::trim).filter(|v| !v.is_empty()).map(str::to_string).collect()
}

fn rpc_error(message: &str, code: i64) -> Value {
    json!({ "jsonrpc": "2.0", "error": { "code": code, "message": message }, "id": null })
}

/// Bind and serve. `Err((errorCode, message))` on bind failure.
pub async fn start(host_addr: &str, port: u16, mcp_host: Arc<McpHost>, hooks: Arc<dyn HttpHooks>) -> Result<HttpRuntime, (String, String)> {
    let ip: IpAddr = host_addr.parse().map_err(|_| ("invalid_address".to_string(), "Listen address must be an IP address such as 0.0.0.0 or a vEthernet address.".to_string()))?;
    let listener = tokio::net::TcpListener::bind((ip, port)).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            ("port_in_use".to_string(), format!("Port {port} is already in use."))
        } else {
            ("listen_failed".to_string(), e.to_string())
        }
    })?;
    let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    let sessions: Arc<Mutex<HashMap<String, Arc<HttpSession>>>> = Default::default();
    let listen = host_addr.to_string();
    let (s2, h2, mh) = (sessions.clone(), hooks.clone(), mcp_host.clone());
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let (s3, h3, mh3, l3) = (s2.clone(), h2.clone(), mh.clone(), listen.clone());
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = hyper::service::service_fn(move |req| {
                    let (s4, h4, mh4, l4) = (s3.clone(), h3.clone(), mh3.clone(), l3.clone());
                    async move { Ok::<_, std::convert::Infallible>(route(req, &s4, &h4, &mh4, &l4, bound_port).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    let (s5, mh5) = (sessions.clone(), mcp_host.clone());
    let sweep = tokio::spawn(async move {
        let mut tick = tokio::time::interval(SESSION_SWEEP);
        loop {
            tick.tick().await;
            let expired: Vec<String> = s5
                .lock()
                .iter()
                .filter(|(_, s)| s.in_flight.load(std::sync::atomic::Ordering::SeqCst) == 0 && s.last_activity.lock().elapsed() >= SESSION_IDLE)
                .map(|(k, _)| k.clone())
                .collect();
            for id in expired {
                if let Some(s) = s5.lock().remove(&id) {
                    mh5.detach_external_client(s.client_id);
                }
            }
        }
    });
    Ok(HttpRuntime { host: host_addr.to_string(), port: bound_port, task, sweep, sessions, mcp_host })
}

async fn route(
    req: Request<Incoming>,
    sessions: &Arc<Mutex<HashMap<String, Arc<HttpSession>>>>,
    hooks: &Arc<dyn HttpHooks>,
    mcp_host: &Arc<McpHost>,
    listen: &str,
    port: u16,
) -> Response<Full<Bytes>> {
    if req.uri().path() != EXTERNAL_MCP_HTTP_PATH {
        return json_response(404, rpc_error("Not found", -32000), &[]);
    }
    if !hooks.is_enabled() {
        return json_response(503, rpc_error("External MCP is disabled.", -32000), &[]);
    }
    let header = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
    let presented = read_bearer_token(header("authorization").as_deref());
    if !tokens_equal(&presented, &hooks.token()) {
        return json_response(401, rpc_error("Unauthorized", -32001), &[]);
    }
    if let Err((status, msg)) = validate_request_headers(&header("host").unwrap_or_default(), header("origin").as_deref(), listen, port) {
        return json_response(status, rpc_error(msg, -32000), &[]);
    }
    let session_header = header("mcp-session-id");
    let wants_stream = accepts_event_stream(header("accept").as_deref());
    let preload = toolsets_from_query(req.uri().query());
    match req.method().as_str() {
        "POST" => {
            let body = match Limited::new(req.into_body(), MAX_BODY_BYTES).collect().await {
                Ok(b) => b.to_bytes(),
                Err(_) => return json_response(413, rpc_error("Payload too large", -32000), &[]),
            };
            if !tokens_equal(&presented, &hooks.token()) {
                return json_response(401, rpc_error("Unauthorized", -32001), &[]);
            }
            let Ok(msg) = serde_json::from_slice::<Value>(&body) else {
                return json_response(400, rpc_error("Invalid JSON", -32000), &[]);
            };
            let (session, created) = match session_header {
                Some(id) => match sessions.lock().get(&id).cloned() {
                    Some(s) => (s, None),
                    None => return json_response(404, rpc_error("Session not found", -32000), &[]),
                },
                None => {
                    let is_init = msg.get("method").and_then(Value::as_str) == Some("initialize")
                        || msg.as_array().is_some_and(|a| a.iter().any(|m| m["method"] == "initialize"));
                    if !is_init {
                        return json_response(400, rpc_error("Bad Request: missing session", -32000), &[]);
                    }
                    let client_id = mcp_host.new_external_client_id();
                    mcp_host.attach_external_client(client_id);
                    let h = hooks.clone();
                    let rpc = Arc::new(HttpRpc {
                        host: mcp_host.clone(),
                        client_id,
                        boundary: PrivacyBoundary::new(move || Some(h.redaction_config())),
                        hooks: hooks.clone(),
                    });
                    let mut scope = Map::new();
                    scope.insert("chatSessionId".into(), json!(crate::host::EXTERNAL_MCP_CHAT_SESSION_ID));
                    let mh = mcp_host.clone();
                    let observer = Arc::new(move || mh.permission_mode() == "observer");
                    let s = Arc::new(HttpSession {
                        mcp: Arc::new(McpSession::new(rpc, scope, observer, None).with_toolsets(&preload)),
                        client_id,
                        last_activity: Mutex::new(Instant::now()),
                        in_flight: Default::default(),
                    });
                    let id = crate::host::vault_agent::uuid_v4();
                    (s, Some(id))
                }
            };
            session.in_flight.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *session.last_activity.lock() = Instant::now();
            let messages = match msg {
                Value::Array(a) => a,
                other => vec![other],
            };
            let batch = messages.len() > 1;
            let mut responses = Vec::new();
            let mut notifications = Vec::new();
            for m in messages {
                let handled = session.mcp.handle(m).await;
                notifications.extend(handled.notifications);
                if let Some(r) = handled.response {
                    responses.push(r);
                }
            }
            session.in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            *session.last_activity.lock() = Instant::now();
            let mut extra = Vec::new();
            if let Some(id) = created {
                sessions.lock().insert(id.clone(), session);
                extra.push(("mcp-session-id", id));
            }
            if responses.is_empty() {
                let mut b = Response::builder().status(StatusCode::ACCEPTED);
                for (k, v) in &extra {
                    b = b.header(*k, v);
                }
                return b.body(Full::new(Bytes::new())).unwrap();
            }
            if wants_stream && !notifications.is_empty() {
                notifications.extend(responses);
                return sse_response(&notifications, &extra);
            }
            let body = if batch { Value::Array(responses) } else { responses.into_iter().next().unwrap() };
            json_response(200, body, &extra)
        }
        "GET" | "DELETE" => {
            let Some(id) = session_header else {
                return json_response(400, rpc_error("Bad Request: missing session", -32000), &[]);
            };
            if !sessions.lock().contains_key(&id) {
                return json_response(404, rpc_error("Session not found", -32000), &[]);
            }
            if req.method() == "GET" {
                return json_response(405, rpc_error("Method not allowed", -32000), &[("Allow", "POST, DELETE".into())]);
            }
            if let Some(s) = sessions.lock().remove(&id) {
                mcp_host.detach_external_client(s.client_id);
            }
            Response::builder().status(200).body(Full::new(Bytes::new())).unwrap()
        }
        _ => json_response(405, rpc_error("Method not allowed", -32000), &[("Allow", "GET, POST, DELETE".into())]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_origin_validation() {
        assert!(validate_request_headers("127.0.0.1:47391", None, "127.0.0.1", 47391).is_ok());
        assert!(validate_request_headers("localhost:47391", Some("http://localhost:3000"), "127.0.0.1", 47391).is_ok());
        assert_eq!(validate_request_headers("evil.com:47391", None, "127.0.0.1", 47391).unwrap_err().0, 421);
        assert_eq!(validate_request_headers("127.0.0.1", None, "127.0.0.1", 47391).unwrap_err().0, 421);
        assert_eq!(validate_request_headers("127.0.0.1:1", None, "127.0.0.1", 47391).unwrap_err().0, 421);
        assert_eq!(validate_request_headers("127.0.0.1:47391", Some("http://evil.com"), "127.0.0.1", 47391).unwrap_err().0, 403);
        assert_eq!(validate_request_headers("127.0.0.1:47391", Some("http://u:p@127.0.0.1"), "127.0.0.1", 47391).unwrap_err().0, 403);
        assert!(validate_request_headers("192.168.1.5:47391", None, "0.0.0.0", 47391).is_ok());
        assert!(validate_request_headers("myhost:47391", None, "0.0.0.0", 47391).is_err());
        assert!(validate_request_headers("[::1]:47391", None, "127.0.0.1", 47391).is_ok());
    }

    #[test]
    fn tokens_ports_urls() {
        assert_eq!(read_bearer_token(Some("Bearer abc")), "abc");
        assert_eq!(read_bearer_token(Some("bearer  abc ")), "abc");
        assert_eq!(read_bearer_token(Some("Basic abc")), "");
        assert!(tokens_equal("a", "a") && !tokens_equal("a", "b") && !tokens_equal("", ""));
        assert_eq!(normalize_http_port(&json!(47391)).unwrap(), 47391);
        assert!(normalize_http_port(&json!(80)).is_err());
        assert!(normalize_http_port(&json!("x")).is_err());
        assert_eq!(build_client_url("127.0.0.1", 47391, "").unwrap(), "http://127.0.0.1:47391/mcp");
        assert_eq!(build_client_url("0.0.0.0", 1, ""), None);
        assert_eq!(build_client_url("0.0.0.0", 1, "10.0.0.2").unwrap(), "http://10.0.0.2:1/mcp");
        assert_eq!(build_client_url("::1", 1, "").unwrap(), "http://[::1]:1/mcp");
        assert!(normalize_client_host("0.0.0.0").is_err());
        assert!(normalize_listen_address("nope").is_err());
    }

    #[test]
    fn accept_header_and_toolset_query() {
        assert!(accepts_event_stream(Some("application/json, text/event-stream")));
        assert!(accepts_event_stream(Some("Text/Event-Stream;q=0.9")));
        assert!(!accepts_event_stream(Some("application/json")));
        assert!(!accepts_event_stream(None));
        assert_eq!(toolsets_from_query(Some("toolsets=sftp_advanced,vault_hosts")), ["sftp_advanced", "vault_hosts"]);
        assert_eq!(toolsets_from_query(Some("x=1&toolsets=all")), ["all"]);
        assert_eq!(toolsets_from_query(Some("toolsets=snippets%2Cscripts")), ["snippets", "scripts"]);
        assert!(toolsets_from_query(Some("other=1")).is_empty());
        assert!(toolsets_from_query(None).is_empty());
    }

    #[test]
    fn event_stream_carries_notifications_before_the_response() {
        let note = json!({ "jsonrpc": "2.0", "method": "notifications/tools/list_changed" });
        let resp = json!({ "jsonrpc": "2.0", "id": 1, "result": {} });
        let r = sse_response(&[note.clone(), resp.clone()], &[]);
        assert_eq!(r.headers()["content-type"], "text/event-stream");
        let body = body_text(r);
        assert_eq!(body, format!("event: message\ndata: {note}\n\nevent: message\ndata: {resp}\n\n"));
    }

    fn body_text(r: Response<Full<Bytes>>) -> String {
        let bytes = tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async { r.into_body().collect().await.unwrap().to_bytes() });
        String::from_utf8(bytes.to_vec()).unwrap()
    }
}

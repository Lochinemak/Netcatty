//! Controller tests (ported cases from `externalMcpController.test.cjs` and
//! `externalMcp/httpServer.test.cjs`).

use super::*;
use crate::host::backend::{HostBackend, SftpOp, TerminalSession};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct NoBackend;

#[async_trait::async_trait]
impl HostBackend for NoBackend {
    fn session(&self, _id: &str) -> Option<Arc<dyn TerminalSession>> {
        None
    }
    fn session_ids(&self) -> Vec<String> {
        vec![]
    }
    async fn sftp(&self, _id: &str, _op: SftpOp, _c: tokio_util::sync::CancellationToken) -> Result<Value, String> {
        Err("no sftp".into())
    }
    fn emit(&self, _event: &str, _payload: Value) {}
    async fn list_port_forwards(&self) -> Vec<Value> {
        vec![]
    }
}

fn controller(dir: &std::path::Path) -> Arc<ExternalMcpController> {
    let host = McpHost::new(Arc::new(NoBackend), None);
    ExternalMcpController::new(host, dir.join("external-mcp.json"), PathBuf::from("/bin/netcatty"), None)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn http(port: u16, host_header: &str, token: Option<&str>, session: Option<&str>, body: &str) -> (u16, String, String) {
    let (status, sid, _, body) = http_at(port, "/mcp", "application/json, text/event-stream", host_header, token, session, body).await;
    (status, sid, body)
}

/// `(status, session id, content type, body)` of one POST.
async fn http_at(port: u16, path: &str, accept: &str, host_header: &str, token: Option<&str>, session: Option<&str>, body: &str) -> (u16, String, String, String) {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut req = format!("POST {path} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/json\r\nAccept: {accept}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    if let Some(t) = token {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    if let Some(id) = session {
        req.push_str(&format!("Mcp-Session-Id: {id}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    let status: u16 = out.split_whitespace().nth(1).unwrap().parse().unwrap();
    let header = |name: &str| out.lines().find_map(|l| l.to_lowercase().strip_prefix(name).map(|_| l[name.len()..].trim().to_string())).unwrap_or_default();
    let (sid, content_type) = (header("mcp-session-id: "), header("content-type: "));
    let body = out.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (status, sid, content_type, body)
}

#[test]
fn normalizers() {
    assert_eq!(normalize_mode(Some("persistent")), MODE_PERSISTENT);
    assert_eq!(normalize_mode(Some("x")), MODE_TEMPORARY);
    assert_eq!(normalize_idle_timeout_minutes(&json!(0)), 1);
    assert_eq!(normalize_idle_timeout_minutes(&json!(99999)), 1440);
    assert_eq!(normalize_idle_timeout_minutes(&json!("abc")), 10);
    assert_eq!(normalize_idle_timeout_minutes(&json!(2.6)), 3);
}

#[tokio::test]
async fn enable_writes_discovery_and_disable_soft_revokes() {
    let dir = tempfile::tempdir().unwrap();
    let c = controller(dir.path());
    assert_eq!(c.status()["state"], "disabled");
    assert!(!c.is_enabled());
    let s = c.set_enabled(true).await;
    assert_eq!(s["state"], "running", "{s}");
    assert!(c.is_enabled());
    let d = crate::discovery::read_external_discovery(&dir.path().join("external-mcp.json")).unwrap();
    assert_eq!(Some(d.token.clone()), c.host.external_mcp_auth_token());
    assert_eq!(d.chat_session_id, EXTERNAL_MCP_CHAT_SESSION_ID);
    assert_eq!(s["port"], json!(d.port));
    assert!(s["idleExpiresAt"].is_u64(), "temporary mode schedules idle shutdown");

    let s = c.set_enabled(false).await;
    assert_eq!(s["state"], "disabled");
    assert!(!dir.path().join("external-mcp.json").exists());
    assert!(c.host.external_mcp_auth_token().is_none());
    assert!(c.host.is_chat_session_cancelled(Some(EXTERNAL_MCP_CHAT_SESSION_ID)));

    // Re-enable rotates the token and clears the cancel flag.
    c.set_enabled(true).await;
    let d2 = crate::discovery::read_external_discovery(&dir.path().join("external-mcp.json")).unwrap();
    assert_ne!(d2.token, d.token);
    assert!(!c.host.is_chat_session_cancelled(Some(EXTERNAL_MCP_CHAT_SESSION_ID)));
    c.cleanup().await;
}

#[tokio::test]
async fn set_config_redaction_mode_and_timeouts() {
    let dir = tempfile::tempdir().unwrap();
    let c = controller(dir.path());
    c.set_enabled(true).await;
    let bad = c.set_config(&json!({ "redaction": { "enabled": true, "cidrs": ["nope"] } })).await;
    assert_eq!(bad["ok"], false);
    assert_eq!(bad["error"], "Invalid privacy rules. Check CIDRs and regular expressions.");
    let s = c.set_config(&json!({ "redaction": { "enabled": true, "cidrs": ["10.1.0.0/16"] }, "mode": "persistent", "idleTimeoutMinutes": 5, "sessionIdleTimeoutMinutes": 30 })).await;
    assert_eq!(s["ok"], true);
    assert_eq!(s["mode"], "persistent");
    assert_eq!(s["idleTimeoutMinutes"], 5);
    assert_eq!(s["sessionIdleTimeoutMinutes"], 30);
    assert!(s["idleExpiresAt"].is_null(), "persistent mode has no idle shutdown");
    let d = crate::discovery::read_external_discovery(&dir.path().join("external-mcp.json")).unwrap();
    assert_eq!(d.redaction.unwrap()["cidrs"], json!(["10.1.0.0/16"]));
    let before = c.host.external_mcp_auth_token();
    c.set_config(&json!({ "rotateHttpToken": true })).await;
    assert_ne!(c.host.external_mcp_auth_token(), before);
    c.cleanup().await;
}

#[tokio::test(start_paused = true)]
async fn temporary_mode_auto_disables_after_idle_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let c = controller(dir.path());
    c.set_config(&json!({ "idleTimeoutMinutes": 1 })).await;
    c.set_enabled(true).await;
    assert!(c.is_enabled());
    tokio::time::sleep(std::time::Duration::from_secs(61)).await;
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    assert_eq!(c.status()["state"], "disabled");
}

#[tokio::test]
async fn http_endpoint_auth_host_check_and_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let c = controller(dir.path());
    let port = free_port();
    c.set_enabled(true).await;
    let s = c.set_config(&json!({ "httpEnabled": true, "httpPort": port })).await;
    assert_eq!(s["http"]["state"], "running", "{s}");
    assert_eq!(s["http"]["url"], format!("http://127.0.0.1:{port}/mcp"));
    let token = s["http"]["bearerToken"].as_str().unwrap().to_string();
    let host = format!("127.0.0.1:{port}");
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;

    assert_eq!(http(port, &host, None, None, init).await.0, 401);
    assert_eq!(http(port, &host, Some("wrong"), None, init).await.0, 401);
    assert_eq!(http(port, &format!("evil.example:{port}"), Some(&token), None, init).await.0, 421);
    let (status, _, _) = http(port, &host, Some(&token), None, r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).await;
    assert_eq!(status, 400, "non-initialize without a session is rejected");

    let (status, sid, body) = http(port, &host, Some(&token), None, init).await;
    assert_eq!(status, 200, "{body}");
    assert!(!sid.is_empty());
    assert!(body.contains("serverInfo"));
    let (status, _, body) = http(port, &host, Some(&token), Some(&sid), r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).await;
    assert_eq!(status, 200);
    assert!(body.contains("get_environment"), "{body}");
    assert_eq!(http(port, &host, Some(&token), Some("unknown"), r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#).await.0, 404);

    // Disabling stops the listener.
    c.set_enabled(false).await;
    assert_eq!(c.status()["http"]["listening"], false);
    // The port may be re-bound at once by a parallel test, so only check
    // that our endpoint no longer answers an authenticated request.
    if let Ok(mut stream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
        let req = format!(
            "POST /mcp HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nMcp-Session-Id: {sid}\r\nContent-Type: application/json\r\nContent-Length: 40\r\nConnection: close\r\n\r\n{{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"ping\"}}"
        );
        let _ = stream.write_all(req.as_bytes()).await;
        let mut out = String::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read_to_string(&mut out)).await;
        assert!(!out.starts_with("HTTP/1.1 200"), "disabled endpoint still answered: {out}");
    }
    c.cleanup().await;
}

#[tokio::test]
async fn http_port_in_use_reports_error() {
    let dir = tempfile::tempdir().unwrap();
    let c = controller(dir.path());
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = busy.local_addr().unwrap().port();
    c.set_enabled(true).await;
    let s = c.set_config(&json!({ "httpEnabled": true, "httpPort": port })).await;
    assert_eq!(s["http"]["state"], "error");
    assert_eq!(s["http"]["errorCode"], "port_in_use");
    let s = c.set_config(&json!({ "httpAllowCustomBind": true, "httpListenAddress": "0.0.0.0", "httpPort": free_port() })).await;
    assert_eq!(s["http"]["listenAddress"], "0.0.0.0");
    assert_eq!(s["http"]["errorCode"], "client_host_required");
    c.cleanup().await;
}

#[tokio::test]
async fn universal_prompt_and_unknown_client() {
    let dir = tempfile::tempdir().unwrap();
    let c = controller(dir.path());
    let p = c.universal_setup_prompt().await;
    assert_eq!(p["ok"], true);
    assert!(p["prompt"].as_str().unwrap().contains("/bin/netcatty"));
    assert!(p["prompt"].as_str().unwrap().contains("NETCATTY_MCP_HELPER"));
    assert_eq!(c.client_status("vim").await["ok"], false);
}

/// Loading a toolset changes the tool list. Over HTTP the only place that
/// notification can travel is the response to the call that caused it.
#[tokio::test]
async fn http_delivers_list_changed_and_preloads_toolsets() {
    let dir = tempfile::tempdir().unwrap();
    let c = controller(dir.path());
    let port = free_port();
    c.set_enabled(true).await;
    let s = c.set_config(&json!({ "httpEnabled": true, "httpPort": port })).await;
    assert_eq!(s["http"]["state"], "running", "{s}");
    let token = s["http"]["bearerToken"].as_str().unwrap().to_string();
    let host = format!("127.0.0.1:{port}");
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;
    let load = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"load_netcatty_tools","arguments":{"toolset":"snippets"}}}"#;
    let list = r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#;
    let stream = "application/json, text/event-stream";

    let (_, sid, content_type, _) = http_at(port, "/mcp", stream, &host, Some(&token), None, init).await;
    assert_eq!(content_type, "application/json", "a plain response stays JSON");
    let (status, _, content_type, body) = http_at(port, "/mcp", stream, &host, Some(&token), Some(&sid), load).await;
    assert_eq!(status, 200);
    assert_eq!(content_type, "text/event-stream");
    let events: Vec<Value> = body.lines().filter_map(|l| l.strip_prefix("data: ")).map(|d| serde_json::from_str(d).unwrap()).collect();
    assert_eq!(events.len(), 2, "{body}");
    assert_eq!(events[0]["method"], "notifications/tools/list_changed");
    assert_eq!(events[1]["id"], 2);
    assert!(events[1]["result"]["content"][0]["text"].as_str().unwrap().contains("snippets_list"));
    let (_, _, _, body) = http_at(port, "/mcp", stream, &host, Some(&token), Some(&sid), list).await;
    assert!(body.contains("\"snippets_run\""), "{body}");
    // Loading it again changes nothing, so there is nothing to stream.
    let (_, _, content_type, _) = http_at(port, "/mcp", stream, &host, Some(&token), Some(&sid), load).await;
    assert_eq!(content_type, "application/json");

    // A client that cannot take a stream still gets its answer as JSON.
    let (_, sid, _, _) = http_at(port, "/mcp", "application/json", &host, Some(&token), None, init).await;
    let (status, _, content_type, body) = http_at(port, "/mcp", "application/json", &host, Some(&token), Some(&sid), load).await;
    assert_eq!((status, content_type.as_str()), (200, "application/json"));
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["id"], 2);

    // …and one that never re-reads the list can ask for toolsets up front.
    let (status, sid, _, _) = http_at(port, "/mcp?toolsets=portforward,sftp_advanced", stream, &host, Some(&token), None, init).await;
    assert_eq!(status, 200);
    let (_, _, _, body) = http_at(port, "/mcp", stream, &host, Some(&token), Some(&sid), list).await;
    let names: Vec<String> = serde_json::from_str::<Value>(&body).unwrap()["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
    assert!(names.contains(&"portforward_start".to_string()) && names.contains(&"sftp_stat".to_string()), "{names:?}");
    assert!(!names.contains(&"snippets_list".to_string()));
    c.cleanup().await;
}

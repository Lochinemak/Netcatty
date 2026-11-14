//! Headless IPC tests of the AI core commands (`commands/ai.rs`) through
//! `tauri::test`'s `MockRuntime`: provider sync + allowlist, `ai_fetch` and
//! `ai_chat_stream` against an in-process HTTP server (events included),
//! cancellation, privacy, and the sessions backup. Same harness shape as
//! `ipc_smoke.rs` (portable data dir per test, injected cipher).

use netcatty_desktop_lib::{configure_with, SetupOptions};
use netcatty_store::CredentialCipher;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::time::Duration;
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::{App, WebviewWindow};

use crate::support::{collect, install_pump, wait_for};
use crate::BUILD_LOCK;
const TEST_KEY: [u8; 32] = [0x5a; 32];

struct Harness {
    app: App<MockRuntime>,
    main: WebviewWindow<MockRuntime>,
    data_dir: tempfile::TempDir,
}

fn build_app() -> Harness {
    let data_dir = tempfile::Builder::new().prefix("netcatty-ipc-ai-").tempdir().expect("temp data dir");
    let app = {
        let _guard = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NETCATTY_PORTABLE_DATA_DIR", data_dir.path());
        let options = SetupOptions { cipher: Some(CredentialCipher::with_key(TEST_KEY)) };
        let mut app = configure_with(mock_builder(), options)
            .build(mock_context(noop_assets()))
            .expect("build mock app");
        install_pump(&app);
        #[allow(deprecated)]
        app.run_iteration(|_, _| {});
        app
    };
    let main = tauri::WebviewWindowBuilder::new(&app, "main", Default::default()).build().expect("main webview");
    Harness { app, main, data_dir }
}

fn invoke(webview: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) -> Value {
    let request = InvokeRequest {
        cmd: cmd.to_string(),
        callback: CallbackFn(0),
        error: CallbackFn(1),
        url: if cfg!(any(windows, target_os = "android")) { "http://tauri.localhost" } else { "tauri://localhost" }
            .parse()
            .unwrap(),
        body: InvokeBody::Json(args),
        headers: Default::default(),
        invoke_key: INVOKE_KEY.to_string(),
    };
    get_ipc_response(webview, request)
        .map(|body| body.deserialize::<Value>().expect("json response"))
        .unwrap_or_else(|err| panic!("{cmd} rejected: {err:?}"))
}

/// One-connection HTTP server writing `parts` (with delays) after reading
/// the request; returns the port and the raw request.
fn serve(parts: Vec<(u64, String)>) -> (u16, std::sync::mpsc::Receiver<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut socket, _)) = listener.accept() else { return };
        socket.set_read_timeout(Some(Duration::from_millis(500))).ok();
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match socket.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    request.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&request);
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text[..end]
                            .lines()
                            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                            .unwrap_or(0);
                        if request.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&request).into_owned());
        for (delay, part) in parts {
            std::thread::sleep(Duration::from_millis(delay));
            if socket.write_all(part.as_bytes()).is_err() {
                return;
            }
            let _ = socket.flush();
        }
    });
    (port, rx)
}

#[test]
fn fetch_injects_the_provider_key_and_enforces_the_allowlist() {
    let h = build_app();
    let sealed = invoke(&h.main, "credentials_encrypt", json!({ "plaintext": "sk-real-key" }));
    let sealed = sealed.as_str().expect("encrypted key").to_owned();
    assert!(sealed.starts_with("enc:v2:"));

    // Not allowed before the provider is synced (port is not a built-in one).
    let (port, requests) = serve(vec![(0, "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"data\":[]}".into())]);
    let url = format!("http://127.0.0.1:{port}/v1/models");
    let denied = invoke(&h.main, "ai_fetch", json!({ "payload": { "url": url } }));
    assert_eq!(denied, json!({ "ok": false, "status": 0, "data": "", "error": "URL host is not in the allowed list" }));

    let synced = invoke(&h.main, "ai_sync_providers", json!({ "payload": { "providers": [
        { "id": "local", "providerId": "custom", "apiKey": sealed, "baseURL": format!("http://127.0.0.1:{port}/v1"), "enabled": true }
    ] } }));
    assert_eq!(synced, json!({ "ok": true }));
    let result = invoke(&h.main, "ai_fetch", json!({ "payload": {
        "url": url, "method": "GET", "headers": { "Authorization": "Bearer __IPC_SECURED__" }, "providerId": "local"
    } }));
    assert_eq!(result, json!({ "ok": true, "status": 200, "data": "{\"data\":[]}" }));
    let request = requests.recv_timeout(Duration::from_secs(5)).unwrap().to_ascii_lowercase();
    assert!(request.contains("authorization: bearer sk-real-key"), "{request}");

    // Scheme / URL validation and delegated ids.
    let bad = invoke(&h.main, "ai_fetch", json!({ "payload": { "url": "file:///etc/passwd" } }));
    assert_eq!(bad["error"], "Only HTTP(S) URLs are allowed");
    let delegated = invoke(&h.main, "ai_fetch", json!({ "payload": { "url": url, "requestId": "x" } }));
    assert_eq!(delegated["error"], "Delegated request identity invalid");
    let add = invoke(&h.main, "ai_allowlist_add_host", json!({ "payload": { "baseURL": "nope" } }));
    assert_eq!(add, json!({ "ok": false, "error": "Invalid URL" }));
}

#[test]
fn chat_stream_emits_data_and_end_to_the_calling_window() {
    let h = build_app();
    let data = collect(&h.app, "netcatty:ai:stream:data");
    let end = collect(&h.app, "netcatty:ai:stream:end");
    let (port, _) = serve(vec![
        (0, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n".into()),
        (10, "data: {\"choices\":[{\"delta\":{\"content\":\"环境\"}}]}\n\n".into()),
        (10, "data:[DONE]\n".into()),
    ]);
    invoke(&h.main, "ai_sync_providers", json!({ "payload": { "providers": [{ "id": "p", "baseURL": format!("http://127.0.0.1:{port}") }] } }));
    let result = invoke(&h.main, "ai_chat_stream", json!({ "payload": {
        "requestId": "req-1", "url": format!("http://127.0.0.1:{port}/v1/chat/completions"),
        "headers": { "content-type": "application/json" }, "body": "{\"stream\":true}", "providerId": "p"
    } }));
    assert_eq!(result, json!({ "ok": true, "statusCode": 200, "statusText": "OK" }));
    assert!(wait_for(&end, Duration::from_secs(5), |e| e.iter().any(|p| p["requestId"] == "req-1")));
    let payloads: Vec<Value> = data.lock().iter().filter(|p| p["requestId"] == "req-1").map(|p| p["data"].clone()).collect();
    assert_eq!(payloads, vec![json!("{\"choices\":[{\"delta\":{\"content\":\"环境\"}}]}"), json!("[DONE]")]);
}

#[test]
fn chat_stream_cancel_and_http_errors() {
    let h = build_app();
    let errors = collect(&h.app, "netcatty:ai:stream:error");
    let (port, _) = serve(vec![
        (0, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n".into()),
        (3_000, "data: late\n".into()),
    ]);
    invoke(&h.main, "ai_sync_providers", json!({ "payload": { "providers": [{ "id": "p", "baseURL": format!("http://127.0.0.1:{port}") }] } }));
    let started = invoke(&h.main, "ai_chat_stream", json!({ "payload": { "requestId": "req-c", "url": format!("http://127.0.0.1:{port}/x") } }));
    assert_eq!(started["ok"], true);
    assert_eq!(invoke(&h.main, "ai_chat_cancel", json!({ "payload": { "requestId": "req-c" } })), json!(true));
    assert!(wait_for(&errors, Duration::from_secs(5), |e| e.iter().any(|p| p["requestId"] == "req-c" && p["error"] == "Aborted")));
    assert_eq!(invoke(&h.main, "ai_chat_cancel", json!({ "payload": { "requestId": "req-c" } })), json!(false));

    let (port, _) = serve(vec![(0, "HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n{\"error\":{\"message\":\"slow down\"}}".into())]);
    invoke(&h.main, "ai_sync_providers", json!({ "payload": { "providers": [{ "id": "p", "baseURL": format!("http://127.0.0.1:{port}") }] } }));
    let result = invoke(&h.main, "ai_chat_stream", json!({ "payload": { "requestId": "req-e", "url": format!("http://127.0.0.1:{port}/x") } }));
    assert_eq!(result, json!({ "ok": true, "statusCode": 429, "statusText": "429 slow down" }));
    assert!(wait_for(&errors, Duration::from_secs(5), |e| e.iter().any(|p| p["requestId"] == "req-e" && p["error"] == "HTTP 429: slow down")));

    let denied = invoke(&h.main, "ai_chat_stream", json!({ "payload": { "requestId": "req-d", "url": "https://evil.example/x" } }));
    assert_eq!(denied, json!({ "ok": false, "error": "URL host is not in the allowed list" }));
}

#[test]
fn privacy_is_pending_until_initialized_and_round_trips() {
    let h = build_app();
    let status = invoke(&h.main, "ai_privacy_status", json!({}));
    assert_eq!(status, json!({ "ok": false, "error": "AI privacy settings are still loading; try again" }));
    let init = invoke(&h.main, "ai_privacy_initialize", json!({ "payload": { "redaction": { "enabled": true } } }));
    assert_eq!(init, json!({ "ok": true, "applied": true }));
    // A second startup push does not override an applied policy.
    let again = invoke(&h.main, "ai_privacy_initialize", json!({ "payload": { "redaction": { "enabled": false } } }));
    assert_eq!(again, json!({ "ok": true, "applied": false }));
    assert_eq!(invoke(&h.main, "ai_privacy_status", json!({})), json!({ "ok": true, "enabled": true }));

    let value = json!(["password=synthetic-secret", "192.0.2.1"]);
    let masked = invoke(&h.main, "ai_privacy_transform", json!({ "payload": { "chatSessionId": "chat", "operation": "redact", "value": value } }));
    assert_eq!(masked["ok"], true);
    assert!(!masked["value"].to_string().contains("synthetic-secret"));
    let restored = invoke(&h.main, "ai_privacy_transform", json!({ "payload": { "chatSessionId": "chat", "operation": "restore", "value": masked["value"] } }));
    assert_eq!(restored, json!({ "ok": true, "value": value }));
    assert_eq!(invoke(&h.main, "ai_privacy_clear", json!({ "chatSessionId": "chat" })), json!({ "ok": true }));
    let after = invoke(&h.main, "ai_privacy_transform", json!({ "payload": { "chatSessionId": "chat", "operation": "restore", "value": masked["value"] } }));
    assert_eq!(after["ok"], false);
    let bad_op = invoke(&h.main, "ai_privacy_transform", json!({ "payload": { "chatSessionId": "chat", "operation": "x" } }));
    assert_eq!(bad_op, json!({ "ok": false, "error": "Invalid AI privacy operation." }));
}

#[test]
fn backup_skills_cancel_flag_and_sender_checks() {
    let h = build_app();
    assert_eq!(invoke(&h.main, "ai_sessions_backup_read_latest", json!({})), json!({ "ok": false }));
    let session = json!([{ "id": "s1", "title": "T", "agentId": "a", "scope": { "type": "global" }, "messages": [], "updatedAt": 1 }]);
    let written = invoke(&h.main, "ai_sessions_backup_write", json!({ "payload": { "json": session.to_string() } }));
    assert_eq!(written["ok"], true);
    assert!(h.data_dir.path().join("ai-sessions-backup").join(written["file"].as_str().unwrap()).is_file());
    let latest = invoke(&h.main, "ai_sessions_backup_read_latest", json!({}));
    assert_eq!(latest["json"], json!(session.to_string()));
    let invalid = invoke(&h.main, "ai_sessions_backup_write", json!({ "payload": {} }));
    assert_eq!(invalid, json!({ "ok": false, "error": "invalid-json" }));

    let status = invoke(&h.main, "ai_user_skills_status", json!({}));
    assert_eq!(status["ok"], true);
    assert_eq!(status["readyCount"], 0);
    assert!(h.data_dir.path().join("Skills").join("README.txt").is_file());
    let context = invoke(&h.main, "ai_user_skills_build_context", json!({ "payload": { "prompt": "hi", "selectedSkillSlugs": [] } }));
    assert_eq!(context["ok"], true);
    assert_eq!(context["context"], "");
    let cli = invoke(&h.main, "ai_skills_cli_invocation", json!({}));
    assert_eq!(cli["ok"], true);
    assert!(cli["commandPrefix"].as_str().unwrap().ends_with(" --tool-cli"));

    let cancelled = invoke(&h.main, "ai_set_chat_session_cancelled", json!({ "payload": { "chatSessionId": "c1" } }));
    assert_eq!(cancelled, json!({ "ok": true, "chatSessionId": "c1", "cancelled": true }));
    let missing = invoke(&h.main, "ai_set_chat_session_cancelled", json!({ "payload": {} }));
    assert_eq!(missing, json!({ "ok": false, "error": "chatSessionId is required" }));

    // Other windows (e.g. the tray panel) are rejected like Electron's sender check.
    let other = tauri::WebviewWindowBuilder::new(&h.app, "trayPanel", Default::default()).build().unwrap();
    assert_eq!(invoke(&other, "ai_privacy_status", json!({})), json!({ "ok": false, "error": "Unauthorized" }));
    assert_eq!(invoke(&other, "ai_sync_providers", json!({ "payload": { "providers": [] } })), json!({ "ok": false }));
}

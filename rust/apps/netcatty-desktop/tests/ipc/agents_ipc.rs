//! Headless IPC tests for the managed-agent commands (`commands/agents.rs`):
//! real command dispatch and event emission through `tauri::test`'s
//! MockRuntime, with fake agent CLIs written to a temp dir.

use netcatty_desktop_lib::{configure_with, SetupOptions};
use netcatty_store::CredentialCipher;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::{App, Listener, WebviewWindow};

use crate::BUILD_LOCK;

struct Harness {
    app: App<MockRuntime>,
    webview: WebviewWindow<MockRuntime>,
    data_dir: tempfile::TempDir,
}

fn build_app() -> Harness {
    let data_dir = tempfile::Builder::new().prefix("netcatty-agents-ipc-").tempdir().unwrap();
    let app = {
        let _guard = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NETCATTY_PORTABLE_DATA_DIR", data_dir.path());
        let options = SetupOptions { cipher: Some(CredentialCipher::with_key([0x5a; 32])) };
        let mut app = configure_with(mock_builder(), options).build(mock_context(noop_assets())).unwrap();
        #[allow(deprecated)]
        app.run_iteration(|_, _| {});
        app
    };
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default()).build().unwrap();
    Harness { app, webview, data_dir }
}

fn invoke(webview: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) -> Value {
    let request = InvokeRequest {
        cmd: cmd.to_string(),
        callback: CallbackFn(0),
        error: CallbackFn(1),
        url: if cfg!(windows) { "http://tauri.localhost" } else { "tauri://localhost" }.parse().unwrap(),
        body: InvokeBody::Json(args),
        headers: Default::default(),
        invoke_key: INVOKE_KEY.to_string(),
    };
    match get_ipc_response(webview, request) {
        Ok(body) => body.deserialize::<Value>().unwrap(),
        Err(e) => panic!("{cmd} failed: {e}"),
    }
}

fn collect(app: &App<MockRuntime>, event: &str) -> Arc<Mutex<Vec<Value>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    app.listen_any(event.to_string(), move |e| {
        sink.lock().unwrap().push(serde_json::from_str(e.payload()).unwrap_or(Value::Null));
    });
    seen
}

fn wait_for(seen: &Arc<Mutex<Vec<Value>>>, timeout: Duration, pred: impl Fn(&[Value]) -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if pred(&seen.lock().unwrap()) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[cfg(unix)]
fn write_script(dir: &std::path::Path, name: &str, body: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.to_string_lossy().into_owned()
}

#[test]
fn bookkeeping_commands_without_turns() {
    let h = build_app();
    assert_eq!(invoke(&h.webview, "ai_sdk_agent_cancel", json!({ "requestId": "r", "chatSessionId": "c" })), json!({ "ok": false, "error": "Stream not found" }));
    assert_eq!(invoke(&h.webview, "ai_sdk_agent_cleanup", json!({ "chatSessionId": "c" })), json!({ "ok": true }));
    assert_eq!(invoke(&h.webview, "ai_sdk_agent_steer", json!({ "payload": { "requestId": "r", "chatSessionId": "c", "clientUserMessageId": "u" } })), json!({ "status": "inactive" }));
    assert_eq!(invoke(&h.webview, "ai_codex_get_login_session", json!({ "sessionId": "x" }))["ok"], false);
    assert_eq!(invoke(&h.webview, "ai_codex_cancel_login", json!({ "sessionId": "x" })), json!({ "ok": true, "found": false }));
    assert_eq!(invoke(&h.webview, "codex_app_server_respond", json!({ "payload": { "interactionId": "x", "decision": "once" } }))["ok"], false);
    assert_eq!(invoke(&h.webview, "codex_app_server_cancel_timeout", json!({ "interactionId": "x" })), json!({ "ok": true, "cancelled": false }));
    assert_eq!(invoke(&h.webview, "ai_sdk_agent_elicitation_response", json!({ "payload": { "elicitationId": "e", "action": "accept" } }))["ok"], false);
    let errors = collect(&h.app, "netcatty:ai:sdk-agent:error");
    let r = invoke(&h.webview, "ai_sdk_agent_stream", json!({ "payload": { "requestId": "bad", "chatSessionId": "c", "sdkBackend": "nope", "prompt": "x" } }));
    assert_eq!(r["ok"], false);
    assert!(wait_for(&errors, Duration::from_secs(5), |e| e.iter().any(|p| p["requestId"] == "bad" && p["error"] == "Unknown SDK backend: nope")));
    drop(h.data_dir);
}

#[cfg(unix)]
#[test]
fn resolve_cli_and_claude_turn_with_fake_binaries() {
    let h = build_app();
    let bin = tempfile::tempdir().unwrap();
    let codex = write_script(bin.path(), "codex", "echo 'codex-cli 0.44.0'");
    let resolved = invoke(&h.webview, "ai_resolve_cli", json!({ "payload": { "command": "codex", "customPath": codex } }));
    assert_eq!(resolved, json!({ "path": codex, "binPath": codex, "version": "codex-cli 0.44.0", "available": true, "installed": true }));
    let claude = write_script(
        bin.path(),
        "claude",
        r#"while IFS= read -r line; do
  case "$line" in
    *'"type":"user"'*)
      printf '%s\n' '{"type":"system","subtype":"init","session_id":"native-9"}'
      printf '%s\n' '{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"text_delta","text":"pong"}}}'
      printf '%s\n' '{"type":"result","subtype":"success","session_id":"native-9"}'
      ;;
  esac
done"#,
    );
    let events = collect(&h.app, "netcatty:ai:sdk-agent:event");
    let done = collect(&h.app, "netcatty:ai:sdk-agent:done");
    let r = invoke(&h.webview, "ai_sdk_agent_stream", json!({ "payload": { "requestId": "req-1", "chatSessionId": "chat-1", "sdkBackend": "claude", "prompt": "ping", "agentCommand": claude, "toolIntegrationMode": "mcp" } }));
    assert_eq!(r, json!({ "ok": true }));
    assert!(wait_for(&done, Duration::from_secs(10), |d| d.iter().any(|p| p["requestId"] == "req-1")));
    let events = events.lock().unwrap();
    assert!(events.iter().any(|e| e["requestId"] == "req-1" && e["event"] == json!({ "type": "text-delta", "textDelta": "pong" })));
    let sid = events.iter().find(|e| e["event"]["type"] == "session-id").unwrap();
    assert_eq!(sid["event"]["sessionId"], "native-9");
    assert_eq!(sid["event"]["sdkBackend"], "claude");
}

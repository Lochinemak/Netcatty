//! Headless IPC tests for `commands/transfers2.rs` (transfer queue controls,
//! artifact cleanup, compressed-upload control paths, native drag request
//! validation, session cwd) through `tauri::test`'s `MockRuntime`.
//! Same harness conventions as `ipc_smoke.rs`.

use netcatty_desktop_lib::{configure_with, SetupOptions};
use netcatty_store::CredentialCipher;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{
    get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY,
};
use tauri::webview::InvokeRequest;
use tauri::{App, Listener, WebviewWindow};

static BUILD_LOCK: Mutex<()> = Mutex::new(());
const TEST_KEY: [u8; 32] = [0x5a; 32];

struct Harness {
    app: App<MockRuntime>,
    webview: WebviewWindow<MockRuntime>,
    _data_dir: tempfile::TempDir,
}

fn build_app() -> Harness {
    let data_dir = tempfile::Builder::new()
        .prefix("netcatty-ipc-transfers-")
        .tempdir()
        .expect("temp data dir");
    let app = {
        let _guard = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NETCATTY_PORTABLE_DATA_DIR", data_dir.path());
        let options = SetupOptions {
            cipher: Some(CredentialCipher::with_key(TEST_KEY)),
        };
        let mut app = configure_with(mock_builder(), options)
            .build(mock_context(noop_assets()))
            .expect("build mock app");
        #[allow(deprecated)]
        app.run_iteration(|_, _| {});
        app
    };
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("build mock webview");
    Harness {
        app,
        webview,
        _data_dir: data_dir,
    }
}

fn invoke(webview: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) -> Result<Value, Value> {
    let request = InvokeRequest {
        cmd: cmd.to_string(),
        callback: CallbackFn(0),
        error: CallbackFn(1),
        url: if cfg!(any(windows, target_os = "android")) {
            "http://tauri.localhost"
        } else {
            "tauri://localhost"
        }
        .parse()
        .unwrap(),
        body: InvokeBody::Json(args),
        headers: Default::default(),
        invoke_key: INVOKE_KEY.to_string(),
    };
    get_ipc_response(webview, request).map(|body| body.deserialize::<Value>().expect("json"))
}

fn ok(webview: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) -> Value {
    invoke(webview, cmd, args).unwrap_or_else(|e| panic!("{cmd} failed: {e}"))
}

fn collect(app: &App<MockRuntime>, event: &str) -> Arc<Mutex<Vec<Value>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    app.listen_any(event.to_string(), move |e| {
        let payload: Value = serde_json::from_str(e.payload()).unwrap_or(Value::Null);
        sink.lock().unwrap().push(payload);
    });
    seen
}

fn wait_for(seen: &Arc<Mutex<Vec<Value>>>, timeout: Duration, pred: impl Fn(&[Value]) -> bool) -> bool {
    let start = Instant::now();
    loop {
        if pred(&seen.lock().unwrap()) {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn has(events: &[Value], kind: &str, id: &str) -> bool {
    events
        .iter()
        .any(|e| e["type"] == kind && e["transferId"] == id)
}

#[test]
fn concurrency_limit_accepts_integers_in_range() {
    let h = build_app();
    assert_eq!(
        ok(&h.webview, "transfer_set_concurrency", json!({ "limit": 3 })),
        json!({ "success": true, "limit": 3 })
    );
    for bad in [json!(0), json!(17), json!(2.5), json!("4"), Value::Null] {
        assert_eq!(
            ok(&h.webview, "transfer_set_concurrency", json!({ "limit": bad })),
            json!({ "success": true, "limit": 3 })
        );
    }
    assert_eq!(
        ok(&h.webview, "transfer_prioritize", json!({ "transferId": "missing" })),
        json!({ "success": false })
    );
}

#[test]
fn local_transfer_is_queued_then_started() {
    let h = build_app();
    let events = collect(&h.app, "netcatty:sftp:global-transfer");
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("a.bin");
    std::fs::write(&source, vec![7u8; 4096]).unwrap();
    let target = dir.path().join("b.bin");
    let result = ok(
        &h.webview,
        "transfer_start",
        json!({ "payload": {
            "transferId": "t-local",
            "sourcePath": source.to_string_lossy(),
            "targetPath": target.to_string_lossy(),
            "sourceType": "local",
            "targetType": "local",
            "totalBytes": 4096
        }}),
    );
    assert_eq!(result["totalBytes"], 4096);
    assert_eq!(std::fs::read(&target).unwrap().len(), 4096);
    assert!(wait_for(&events, Duration::from_secs(5), |e| has(e, "completed", "t-local")));
    let seen = events.lock().unwrap();
    let kinds: Vec<&str> = seen
        .iter()
        .filter(|e| e["transferId"] == "t-local")
        .filter_map(|e| e["type"].as_str())
        .collect();
    assert_eq!(kinds.first(), Some(&"queued"));
    assert_eq!(kinds.get(1), Some(&"started"));
    let queued = &seen[0];
    assert_eq!(queued["lifecycleState"], "queued");
    assert_eq!(queued["controlKind"], "stream");
}

/// A FIFO source keeps the first transfer running, so the second one waits
/// in the queue where it can be prioritized, paused and cancelled.
#[cfg(unix)]
#[test]
fn queued_transfers_can_be_prioritized_paused_and_cancelled() {
    let h = build_app();
    let events = collect(&h.app, "netcatty:sftp:global-transfer");
    ok(&h.webview, "transfer_set_concurrency", json!({ "limit": 1 }));
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("hold.fifo");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let plain = dir.path().join("plain.bin");
    std::fs::write(&plain, b"queued payload").unwrap();

    let start = |id: &str, source: &std::path::Path, extra: Value| {
        let webview = h.webview.clone();
        let mut payload = json!({
            "transferId": id,
            "sourcePath": source.to_string_lossy(),
            "targetPath": dir.path().join(format!("{id}.out")).to_string_lossy(),
            "sourceType": "local",
            "targetType": "local",
            "checkpointBytes": 0
        });
        if let (Some(p), Some(e)) = (payload.as_object_mut(), extra.as_object()) {
            p.extend(e.clone());
        }
        std::thread::spawn(move || invoke(&webview, "transfer_start", json!({ "payload": payload })))
    };

    let holder = start("hold", &fifo, json!({}));
    assert!(wait_for(&events, Duration::from_secs(5), |e| has(e, "started", "hold")));
    let cancelled = start("q-cancel", &plain, json!({}));
    let paused = start("q-pause", &plain, json!({ "uploadCheckpointBytes": 9 }));
    assert!(wait_for(&events, Duration::from_secs(5), |e| {
        has(e, "queued", "q-cancel") && has(e, "queued", "q-pause")
    }));
    assert!(!has(&events.lock().unwrap(), "started", "q-cancel"));

    assert_eq!(
        ok(&h.webview, "transfer_prioritize", json!({ "transferId": "q-pause" })),
        json!({ "success": true })
    );
    assert_eq!(
        ok(&h.webview, "transfer_pause", json!({ "transferId": "q-pause" })),
        json!({ "success": true })
    );
    let paused = paused.join().unwrap().unwrap();
    assert_eq!(paused["cancelled"], true);
    assert_eq!(paused["warning"], "paused");
    assert!(wait_for(&events, Duration::from_secs(5), |e| e
        .iter()
        .any(|ev| ev["type"] == "paused" && ev["transferId"] == "q-pause" && ev["checkpointBytes"] == 9)));

    ok(&h.webview, "transfer_cancel", json!({ "transferId": "q-cancel" }));
    let cancelled = cancelled.join().unwrap().unwrap();
    assert_eq!(cancelled["cancelled"], true);
    assert!(has(&events.lock().unwrap(), "cancelled", "q-cancel"));

    // Release the holder: open the FIFO for writing and close it.
    std::fs::write(&fifo, b"done").unwrap();
    // (A FIFO stats as 0 bytes, so the engine reports a size mismatch; only
    // the release of the slot matters here.)
    let held = holder.join().unwrap().unwrap();
    assert_eq!(held["transferId"], "hold");
}

#[test]
fn cleanup_removes_only_this_tasks_artifacts() {
    let h = build_app();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("site");
    let target_str = target.to_string_lossy().into_owned();
    let part = dir.path().join(".site.netcatty-part");
    std::fs::write(&part, b"partial").unwrap();
    let stage = dir.path().join("site.netcatty-task_1.part");
    std::fs::create_dir_all(stage.join("nested")).unwrap();
    std::fs::write(stage.join("nested/x"), b"x").unwrap();
    let foreign = dir.path().join("keep-me");
    std::fs::create_dir_all(&foreign).unwrap();

    // A staged path that is not this task's stage name is refused.
    assert_eq!(
        ok(
            &h.webview,
            "transfer_cleanup",
            json!({ "payload": {
                "transferId": "task:1",
                "sourcePath": "/remote/site",
                "targetPath": target_str,
                "stagedTargetPath": foreign.to_string_lossy(),
            }}),
        ),
        json!({ "success": true })
    );
    assert!(foreign.exists());
    assert!(!part.exists(), "engine stage of the target is removed");

    ok(
        &h.webview,
        "transfer_cleanup",
        json!({ "payload": {
            "transferId": "task:1",
            "sourcePath": "/remote/site",
            "targetPath": target_str,
            "stagedTargetPath": stage.to_string_lossy(),
        }}),
    );
    assert!(!stage.exists());
    assert!(foreign.exists());
    assert_eq!(
        ok(&h.webview, "transfer_cleanup", json!({ "payload": { "transferId": "" } })),
        json!({ "success": false, "error": "transferId is required" })
    );
}

#[test]
fn compressed_upload_control_paths() {
    let h = build_app();
    let support = ok(&h.webview, "compress_check_support", json!({ "sftpId": "nope" }));
    assert_eq!(support["supported"], false);
    assert!(support["error"].as_str().unwrap().contains("not found"));
    assert_eq!(
        ok(&h.webview, "compress_cancel", json!({ "compressionId": "c1" })),
        json!({ "success": true, "inactive": true })
    );
    assert_eq!(
        ok(&h.webview, "compress_pause", json!({ "compressionId": "c1" })),
        json!({ "success": false, "reason": "Compression is not active" })
    );
    assert_eq!(
        ok(&h.webview, "compress_resume", json!({ "compressionId": "c1" })),
        json!({ "success": false, "reason": "Compression is not active" })
    );

    // A start against a missing SFTP session fails and publishes `failed`.
    let events = collect(&h.app, "netcatty:sftp:global-transfer");
    let result = ok(
        &h.webview,
        "compress_start",
        json!({ "payload": {
            "compressionId": "c2",
            "folderPath": "/tmp/folder",
            "targetPath": "/srv",
            "sftpId": "missing",
            "folderName": "folder",
            "totalBytes": 7
        }}),
    );
    assert_eq!(result["compressionId"], "c2");
    assert!(result["error"].as_str().unwrap().contains("not found"));
    let seen = events.lock().unwrap();
    let started = seen.iter().find(|e| e["type"] == "started").expect("started");
    assert_eq!(started["controlKind"], "compressed-upload");
    assert_eq!(started["fileName"], "folder (compressed)");
    assert_eq!(started["targetPath"], "/srv/folder");
    assert_eq!(started["lifecycleState"], "transferring");
    assert!(seen.iter().any(|e| e["type"] == "failed" && e["transferId"] == "c2"));
    assert_eq!(seen.iter().filter(|e| e["type"] == "failed").count(), 1);
}

#[test]
fn drag_requests_are_validated_before_any_native_call() {
    let h = build_app();
    let result = ok(
        &h.webview,
        "local_drag_start",
        json!({ "payload": { "requestId": "r1", "paths": ["relative/path"] } }),
    );
    assert_eq!(result["started"], false);
    assert_eq!(result["error"], "Drag paths must be absolute filesystem paths");
    let result = ok(
        &h.webview,
        "local_drag_start",
        json!({ "payload": { "requestId": "", "paths": ["/tmp"] } }),
    );
    assert_eq!(result["error"], "Invalid local file drag request");
    let missing = std::env::temp_dir().join("netcatty-missing-drag-file");
    let result = ok(
        &h.webview,
        "local_drag_start",
        json!({ "payload": { "requestId": "r2", "paths": [missing.to_string_lossy()] } }),
    );
    assert_eq!(result["started"], false);
    assert!(invoke(&h.webview, "local_drag_cancel", json!({ "requestId": "r2" })).is_ok());
}

#[test]
fn session_pwd_accepts_renderer_options() {
    let h = build_app();
    let result = ok(
        &h.webview,
        "session_pwd",
        json!({ "sessionId": "nope", "allowHomeFallback": false, "timeoutMs": 250 }),
    );
    assert_eq!(result["success"], false);
}

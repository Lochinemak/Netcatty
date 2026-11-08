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

fn wait_for(
    seen: &Arc<Mutex<Vec<Value>>>,
    timeout: Duration,
    pred: impl Fn(&[Value]) -> bool,
) -> bool {
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
        ok(
            &h.webview,
            "transfer_set_concurrency",
            json!({ "limit": 3 })
        ),
        json!({ "success": true, "limit": 3 })
    );
    for bad in [json!(0), json!(17), json!(2.5), json!("4"), Value::Null] {
        assert_eq!(
            ok(
                &h.webview,
                "transfer_set_concurrency",
                json!({ "limit": bad })
            ),
            json!({ "success": true, "limit": 3 })
        );
    }
    assert_eq!(
        ok(
            &h.webview,
            "transfer_prioritize",
            json!({ "transferId": "missing" })
        ),
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
    assert!(wait_for(&events, Duration::from_secs(5), |e| has(
        e,
        "completed",
        "t-local"
    )));
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
    ok(
        &h.webview,
        "transfer_set_concurrency",
        json!({ "limit": 1 }),
    );
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
        std::thread::spawn(move || {
            invoke(&webview, "transfer_start", json!({ "payload": payload }))
        })
    };

    let holder = start("hold", &fifo, json!({}));
    assert!(wait_for(&events, Duration::from_secs(5), |e| has(
        e, "started", "hold"
    )));
    let cancelled = start("q-cancel", &plain, json!({}));
    let paused = start("q-pause", &plain, json!({ "uploadCheckpointBytes": 9 }));
    assert!(wait_for(&events, Duration::from_secs(5), |e| {
        has(e, "queued", "q-cancel") && has(e, "queued", "q-pause")
    }));
    assert!(!has(&events.lock().unwrap(), "started", "q-cancel"));

    assert_eq!(
        ok(
            &h.webview,
            "transfer_prioritize",
            json!({ "transferId": "q-pause" })
        ),
        json!({ "success": true })
    );
    assert_eq!(
        ok(
            &h.webview,
            "transfer_pause",
            json!({ "transferId": "q-pause" })
        ),
        json!({ "success": true })
    );
    let paused = paused.join().unwrap().unwrap();
    assert_eq!(paused["cancelled"], true);
    assert_eq!(paused["warning"], "paused");
    assert!(wait_for(&events, Duration::from_secs(5), |e| e.iter().any(
        |ev| ev["type"] == "paused" && ev["transferId"] == "q-pause" && ev["checkpointBytes"] == 9
    )));

    ok(
        &h.webview,
        "transfer_cancel",
        json!({ "transferId": "q-cancel" }),
    );
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
        ok(
            &h.webview,
            "transfer_cleanup",
            json!({ "payload": { "transferId": "" } })
        ),
        json!({ "success": false, "error": "transferId is required" })
    );
}

#[test]
fn compressed_upload_control_paths() {
    let h = build_app();
    let support = ok(
        &h.webview,
        "compress_check_support",
        json!({ "sftpId": "nope" }),
    );
    assert_eq!(support["supported"], false);
    assert!(support["error"].as_str().unwrap().contains("not found"));
    assert_eq!(
        ok(
            &h.webview,
            "compress_cancel",
            json!({ "compressionId": "c1" })
        ),
        json!({ "success": true, "inactive": true })
    );
    assert_eq!(
        ok(
            &h.webview,
            "compress_pause",
            json!({ "compressionId": "c1" })
        ),
        json!({ "success": false, "reason": "Compression is not active" })
    );
    assert_eq!(
        ok(
            &h.webview,
            "compress_resume",
            json!({ "compressionId": "c1" })
        ),
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
    let started = seen
        .iter()
        .find(|e| e["type"] == "started")
        .expect("started");
    assert_eq!(started["controlKind"], "compressed-upload");
    assert_eq!(started["fileName"], "folder (compressed)");
    assert_eq!(started["targetPath"], "/srv/folder");
    assert_eq!(started["lifecycleState"], "transferring");
    assert!(seen
        .iter()
        .any(|e| e["type"] == "failed" && e["transferId"] == "c2"));
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
    assert_eq!(
        result["error"],
        "Drag paths must be absolute filesystem paths"
    );
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
    assert!(invoke(
        &h.webview,
        "local_drag_cancel",
        json!({ "requestId": "r2" })
    )
    .is_ok());
}

/// Telnet sessions (like serial / Mosh / ET) feed the automatic session log
/// through the shared `session_starting` / `deliver` / `remove_and_release`
/// hooks.
#[test]
fn telnet_session_output_reaches_the_automatic_log() {
    use std::io::Write;
    let h = build_app();
    let exits = collect(&h.app, "netcatty:exit");
    let logs = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.write_all(b"hello from telnet log\r\n").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        s.shutdown(std::net::Shutdown::Both).ok();
    });
    ok(
        &h.webview,
        "telnet_start",
        json!({ "payload": {
            "sessionId": "tel-log",
            "hostname": "127.0.0.1",
            "port": port,
            "label": "Router",
            "sessionLog": { "enabled": true, "directory": logs.path().to_string_lossy(), "format": "raw" }
        }}),
    );
    server.join().unwrap();
    assert!(wait_for(&exits, Duration::from_secs(10), |e| e
        .iter()
        .any(|ev| ev["sessionId"] == "tel-log")));
    let host_dir = logs.path().join("Router");
    let found = (0..100).any(|_| {
        let text: String = std::fs::read_dir(&host_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .collect();
        if text.contains("hello from telnet log") {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
        false
    });
    assert!(found, "no telnet output in {}", host_dir.display());
}

/// Opt-in end-to-end run against a real sshd (skipped unless
/// `NETCATTY_TRANSFERS_E2E_KEY` names a private key authorized for the
/// current user on `127.0.0.1:${NETCATTY_TRANSFERS_E2E_PORT:-22}`; the
/// server's filesystem must be this machine's, e.g. a private sshd):
/// interactive-shell cwd discovery and a compressed folder upload.
#[test]
fn e2e_cwd_probe_and_compressed_upload() {
    let Ok(key_path) = std::env::var("NETCATTY_TRANSFERS_E2E_KEY") else {
        return;
    };
    let port: u16 = std::env::var("NETCATTY_TRANSFERS_E2E_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(22);
    let user = std::env::var("USER").expect("USER");
    let key = std::fs::read_to_string(key_path).expect("key");
    let h = build_app();
    let data = collect(&h.app, "netcatty:data");
    let transfers = collect(&h.app, "netcatty:sftp:global-transfer");
    let base = json!({
        "hostname": "127.0.0.1",
        "port": port,
        "username": user,
        "authMethod": "key",
        "privateKey": key,
        "verifyHostKeys": false,
    });
    let mut ssh = base.clone();
    ssh["sessionId"] = json!("e2e-ssh");
    ok(&h.webview, "session_start_ssh", json!({ "payload": ssh }));
    let work = tempfile::tempdir().unwrap();
    let work_path = std::fs::canonicalize(work.path()).unwrap();
    ok(
        &h.webview,
        "session_write",
        json!({ "payload": {
            "sessionId": "e2e-ssh",
            "data": format!("cd '{}' && echo CWD-$((40+2))\n", work_path.display()),
        }}),
    );
    assert!(wait_for(&data, Duration::from_secs(10), |e| e
        .iter()
        .filter_map(|ev| ev["data"].as_str())
        .collect::<String>()
        .contains("CWD-42")));
    let pwd = ok(&h.webview, "session_pwd", json!({ "sessionId": "e2e-ssh" }));
    assert_eq!(pwd["success"], true, "{pwd}");
    assert_eq!(
        pwd["cwd"].as_str().map(std::path::PathBuf::from),
        Some(work_path.clone())
    );

    // Compressed upload of a local folder into `<work>/remote`.
    let mut sftp = base.clone();
    sftp["sessionId"] = json!("e2e-sftp");
    let sftp_id = ok(&h.webview, "sftp_open", json!({ "payload": sftp }))["sftpId"]
        .as_str()
        .unwrap()
        .to_string();
    let support = ok(
        &h.webview,
        "compress_check_support",
        json!({ "sftpId": sftp_id }),
    );
    assert_eq!(support["supported"], true, "{support}");
    let folder = work_path.join("local").join("my folder");
    std::fs::create_dir_all(folder.join("sub")).unwrap();
    std::fs::write(folder.join("a.txt"), "alpha").unwrap();
    std::fs::write(folder.join("sub/b.txt"), "beta").unwrap();
    let remote = work_path.join("remote");
    std::fs::create_dir_all(remote.join("my folder")).unwrap();
    std::fs::write(remote.join("my folder/old.txt"), "old").unwrap();
    let result = ok(
        &h.webview,
        "compress_start",
        json!({ "payload": {
            "compressionId": "e2e-c1",
            "folderPath": folder.to_string_lossy(),
            "targetPath": remote.to_string_lossy(),
            "sftpId": sftp_id,
            "folderName": "my folder",
            "totalBytes": 9
        }}),
    );
    assert_eq!(result["success"], true, "{result}");
    let out = remote.join("my folder");
    assert_eq!(std::fs::read_to_string(out.join("a.txt")).unwrap(), "alpha");
    assert_eq!(
        std::fs::read_to_string(out.join("sub/b.txt")).unwrap(),
        "beta"
    );
    assert_eq!(
        std::fs::read_to_string(out.join("old.txt")).unwrap(),
        "old",
        "merge semantics"
    );
    let leftovers: Vec<String> = std::fs::read_dir(&remote)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("netcatty"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    let seen = transfers.lock().unwrap();
    let mine: Vec<&Value> = seen
        .iter()
        .filter(|e| e["transferId"] == "e2e-c1")
        .collect();
    assert_eq!(mine.first().unwrap()["type"], "started");
    assert_eq!(mine.last().unwrap()["type"], "completed");
    assert!(mine.iter().any(|e| e["phase"] == "uploading"));
    assert!(mine.iter().any(|e| e["phase"] == "extracting"));
    assert!(
        !seen.iter().any(|e| e["transferId"] == "compress-e2e-c1"),
        "the internal archive transfer stays silent"
    );
    drop(seen);
    ok(&h.webview, "sftp_close", json!({ "sftpId": sftp_id }));
    ok(
        &h.webview,
        "session_close",
        json!({ "sessionId": "e2e-ssh" }),
    );
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

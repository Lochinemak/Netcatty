//! Headless IPC smoke tests: drive the real command dispatch, managed state
//! and event emission of `netcatty-desktop` through `tauri::test`'s
//! `MockRuntime` (no window, no webview process).
//!
//! Each test builds its own `App<MockRuntime>` and points
//! `NETCATTY_PORTABLE_DATA_DIR` at a private temp dir so the store never
//! touches the user's real data directory. Tests run in one process, so the
//! env var is set per test *before* the app (and thus `AppState`) is built.
//! The credential cipher is injected with a fixed key: loading the real
//! master key would hit the OS keychain (an interactive prompt on macOS for
//! every freshly built test binary, tens of seconds per app).

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

/// Serialise app construction: `NETCATTY_PORTABLE_DATA_DIR` is process
/// global, so two tests must not build their apps at the same time.
static BUILD_LOCK: Mutex<()> = Mutex::new(());

/// Fixed AES-256-GCM master key for the injected test cipher.
const TEST_KEY: [u8; 32] = [0x5a; 32];

struct Harness {
    app: App<MockRuntime>,
    webview: WebviewWindow<MockRuntime>,
    _data_dir: tempfile::TempDir,
}

fn build_app() -> Harness {
    let data_dir = tempfile::Builder::new()
        .prefix("netcatty-ipc-smoke-")
        .tempdir()
        .expect("temp data dir");
    let app = {
        let _guard = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Read once by `AppPaths::resolve` inside the setup hook below; the
        // lock keeps two tests from racing on the process-global variable.
        std::env::set_var("NETCATTY_PORTABLE_DATA_DIR", data_dir.path());
        // `mock_context` rather than `generate_context!`: the latter would
        // embed a second `__info_plist` section next to the library's one
        // (duplicate-symbol link warning on macOS) and would auto-create the
        // configured "main" window during setup.
        let options = SetupOptions {
            cipher: Some(CredentialCipher::with_key(TEST_KEY)),
        };
        let app = configure_with(mock_builder(), options)
            .build(mock_context(noop_assets()))
            .expect("build mock app");
        run_setup(app)
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

/// Run the app's `setup` hook (plugins are initialised by `build`, but Tauri
/// only runs `setup` from its event loop). `MockRuntime::run_iteration` is a
/// no-op, so this returns immediately with the managed state in place.
fn run_setup(mut app: App<MockRuntime>) -> App<MockRuntime> {
    #[allow(deprecated)]
    app.run_iteration(|_, _| {});
    app
}

fn request(cmd: &str, body: InvokeBody, headers: tauri::http::HeaderMap) -> InvokeRequest {
    InvokeRequest {
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
        body,
        headers,
        invoke_key: INVOKE_KEY.to_string(),
    }
}

/// Invoke `cmd` with JSON `args` and return the deserialised response.
fn invoke(webview: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) -> Result<Value, Value> {
    get_ipc_response(
        webview,
        request(cmd, InvokeBody::Json(args), Default::default()),
    )
    .map(|body| body.deserialize::<Value>().expect("json response"))
}

/// Invoke `cmd` with a raw binary body and string headers.
fn invoke_raw(
    webview: &WebviewWindow<MockRuntime>,
    cmd: &str,
    body: Vec<u8>,
    headers: &[(&str, &str)],
) -> Result<Value, Value> {
    let mut map = tauri::http::HeaderMap::new();
    for (name, value) in headers {
        map.insert(
            tauri::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            tauri::http::HeaderValue::from_str(value).unwrap(),
        );
    }
    get_ipc_response(webview, request(cmd, InvokeBody::Raw(body), map))
        .map(|body| body.deserialize::<Value>().expect("json response"))
}

fn ok(result: Result<Value, Value>) -> Value {
    match result {
        Ok(v) => v,
        Err(e) => panic!("command failed: {e}"),
    }
}

/// Record every payload of `event` emitted by the app.
fn collect(app: &App<MockRuntime>, event: &str) -> Arc<Mutex<Vec<Value>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    app.listen_any(event.to_string(), move |e| {
        let payload: Value = serde_json::from_str(e.payload()).unwrap_or(Value::Null);
        sink.lock().unwrap().push(payload);
    });
    seen
}

/// Poll `pred` over the collected payloads until it holds or `timeout` passes.
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
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn session_id_of(v: &Value) -> Option<&str> {
    v.get("sessionId").and_then(Value::as_str)
}

#[cfg(unix)]
#[test]
fn local_shell_round_trip() {
    let h = build_app();
    let data = collect(&h.app, "netcatty:data");
    let exits = collect(&h.app, "netcatty:exit");

    // Unknown session → NOT_FOUND, with the `{ code, message }` error shape.
    let err = invoke(
        &h.webview,
        "session_write",
        json!({ "payload": { "sessionId": "nope", "data": "x" } }),
    )
    .expect_err("write to unknown session must fail");
    assert_eq!(err["code"], "NOT_FOUND", "error payload: {err}");
    assert!(err["message"].as_str().unwrap().contains("nope"));

    let started = ok(invoke(
        &h.webview,
        "session_start_local",
        json!({ "payload": { "shell": "/bin/sh", "cols": 80, "rows": 24 } }),
    ));
    let id = started["sessionId"]
        .as_str()
        .expect("sessionId in start result")
        .to_string();
    assert!(!id.is_empty());

    ok(invoke(
        &h.webview,
        "session_write",
        json!({ "payload": { "sessionId": id, "data": "echo hello-from-pty\n" } }),
    ));
    let got_output = wait_for(&data, Duration::from_secs(10), |events| {
        events.iter().any(|e| {
            session_id_of(e) == Some(id.as_str())
                && e["data"]
                    .as_str()
                    .is_some_and(|d| d.contains("hello-from-pty"))
        })
    });
    assert!(
        got_output,
        "no netcatty:data containing the echo for {id}; got {:?}",
        data.lock().unwrap()
    );

    ok(invoke(
        &h.webview,
        "session_resize",
        json!({ "payload": { "sessionId": id, "cols": 100, "rows": 30 } }),
    ));
    ok(invoke(
        &h.webview,
        "session_close",
        json!({ "sessionId": id }),
    ));

    let exited = wait_for(&exits, Duration::from_secs(10), |events| {
        events.iter().any(|e| session_id_of(e) == Some(id.as_str()))
    });
    assert!(
        exited,
        "no netcatty:exit for {id}; got {:?}",
        exits.lock().unwrap()
    );
    // The pump task also notices the PTY ending; it must not emit a second exit.
    std::thread::sleep(Duration::from_millis(300));
    let mine: Vec<Value> = exits
        .lock()
        .unwrap()
        .iter()
        .filter(|e| session_id_of(e) == Some(id.as_str()))
        .cloned()
        .collect();
    assert_eq!(mine.len(), 1, "exactly one exit event expected: {mine:?}");
    let reason = mine[0]["reason"].as_str().unwrap_or("");
    assert!(
        reason == "closed" || reason == "exited",
        "unexpected exit reason: {:?}",
        mine[0]
    );

    // The session is gone: further writes are NOT_FOUND and close is idempotent.
    let err = invoke(
        &h.webview,
        "session_write",
        json!({ "payload": { "sessionId": id, "data": "x" } }),
    )
    .expect_err("closed session must be gone");
    assert_eq!(err["code"], "NOT_FOUND");
    ok(invoke(
        &h.webview,
        "session_close",
        json!({ "sessionId": id }),
    ));
}

#[test]
fn store_and_credentials_round_trip() {
    let h = build_app();
    let key = "netcatty.test";
    let value = r#"{"a":1}"#;

    ok(invoke(
        &h.webview,
        "store_set",
        json!({ "key": key, "value": value }),
    ));
    assert_eq!(
        ok(invoke(&h.webview, "store_get", json!({ "key": key }))),
        json!(value)
    );
    let keys = ok(invoke(&h.webview, "store_keys", json!({})));
    assert!(
        keys.as_array().unwrap().iter().any(|k| k == key),
        "store_keys: {keys}"
    );
    ok(invoke(&h.webview, "store_remove", json!({ "key": key })));
    assert_eq!(
        ok(invoke(&h.webview, "store_get", json!({ "key": key }))),
        Value::Null
    );

    // The injected cipher is always available, so this branch is deterministic.
    assert_eq!(
        ok(invoke(&h.webview, "credentials_available", json!({}))),
        json!(true)
    );
    let enc = ok(invoke(
        &h.webview,
        "credentials_encrypt",
        json!({ "plaintext": "secret" }),
    ));
    let enc = enc.as_str().expect("ciphertext string");
    assert!(enc.starts_with("enc:v2:"), "ciphertext: {enc}");
    assert_eq!(
        ok(invoke(
            &h.webview,
            "credentials_decrypt",
            json!({ "value": enc })
        )),
        json!("secret")
    );
    // Plaintext / unknown prefixes pass through unchanged (Electron parity).
    assert_eq!(
        ok(invoke(
            &h.webview,
            "credentials_decrypt",
            json!({ "value": "plain" })
        )),
        json!("plain")
    );
}

#[test]
fn local_fs_commands() {
    let h = build_app();

    let home = ok(invoke(&h.webview, "local_home_dir", json!({})));
    assert!(!home.as_str().unwrap().is_empty());

    let dir = tempfile::Builder::new()
        .prefix("netcatty-ipc-fs-")
        .tempdir()
        .unwrap();
    std::fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let dir_path = dir.path().to_string_lossy().into_owned();

    let listed = ok(invoke(
        &h.webview,
        "local_list_dir",
        json!({ "path": dir_path }),
    ));
    let names: Vec<&str> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"a.txt"), "listing: {listed}");
    assert!(names.contains(&"sub"), "listing: {listed}");
    let sub = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "sub")
        .unwrap();
    assert_eq!(sub["type"], "directory", "entry: {sub}");

    let file_path = dir.path().join("a.txt").to_string_lossy().into_owned();
    let stat = ok(invoke(
        &h.webview,
        "local_stat",
        json!({ "path": file_path }),
    ));
    assert_eq!(stat["size"], 5, "stat: {stat}");
    assert_eq!(stat["type"], "file", "stat: {stat}");
    assert_eq!(stat["name"], "a.txt", "stat: {stat}");

    // Raw-body write: content in the body, destination in the `path` header
    // (percent-encoded like the renderer does with `encodeURIComponent`).
    let written = dir.path().join("written 中.txt");
    let encoded: String = percent_encode_for_test(&written.to_string_lossy());
    ok(invoke_raw(
        &h.webview,
        "local_write_file",
        b"raw body bytes".to_vec(),
        &[("path", &encoded)],
    ));
    assert_eq!(std::fs::read(&written).unwrap(), b"raw body bytes");

    // Raw read: the response is an ArrayBuffer (raw bytes), not JSON.
    let read = get_ipc_response(
        &h.webview,
        request(
            "local_read_file",
            InvokeBody::Json(json!({ "path": written.to_string_lossy() })),
            Default::default(),
        ),
    )
    .unwrap_or_else(|e| panic!("local_read_file failed: {e}"));
    match read {
        tauri::ipc::InvokeResponseBody::Raw(bytes) => assert_eq!(bytes, b"raw body bytes"),
        other => panic!("expected a raw response, got {other:?}"),
    }
}

/// `encodeURIComponent`-compatible encoding of a header value.
fn percent_encode_for_test(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'~'
            | b'*'
            | b'\''
            | b'('
            | b')' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[test]
fn discover_shells_and_system_info() {
    let h = build_app();

    let shells = ok(invoke(&h.webview, "local_discover_shells", json!({})));
    let shells = shells.as_array().expect("array of shells");
    assert!(!shells.is_empty());
    let defaults = shells.iter().filter(|s| s["isDefault"] == true).count();
    assert_eq!(defaults, 1, "exactly one default shell: {shells:?}");

    let info = ok(invoke(&h.webview, "system_info", json!({})));
    assert!(
        info["username"].as_str().is_some_and(|u| !u.is_empty()),
        "{info}"
    );
    assert!(
        info["hostname"].as_str().is_some_and(|h| !h.is_empty()),
        "{info}"
    );

    let version = ok(invoke(&h.webview, "app_get_version", json!({})));
    assert!(version.as_str().is_some_and(|v| !v.is_empty()));
}

#[test]
fn temp_upload_staging_round_trip() {
    let h = build_app();
    let temp_dir = ok(invoke(&h.webview, "app_get_temp_dir_path", json!({})));
    let temp_dir = std::path::PathBuf::from(temp_dir.as_str().unwrap());

    let path = ok(invoke(
        &h.webview,
        "temp_upload_begin",
        json!({ "transferId": "t-1/x", "fileName": "report 中.zip" }),
    ));
    let path = path.as_str().unwrap().to_string();
    assert!(std::path::Path::new(&path).starts_with(&temp_dir), "{path}");
    assert!(
        path.ends_with(".transfer_t-1_x_report 中.zip.part"),
        "{path}"
    );

    let encoded = percent_encode_for_test(&path);
    let len = ok(invoke_raw(
        &h.webview,
        "temp_upload_chunk",
        b"hello ".to_vec(),
        &[("path", &encoded)],
    ));
    assert_eq!(len, 6);
    let len = ok(invoke_raw(
        &h.webview,
        "temp_upload_chunk",
        b"world".to_vec(),
        &[("path", &encoded)],
    ));
    assert_eq!(len, 11);
    assert_eq!(std::fs::read(&path).unwrap(), b"hello world");

    // A second begin with the same id is refused (file exists).
    let err = invoke(
        &h.webview,
        "temp_upload_begin",
        json!({ "transferId": "t-1/x", "fileName": "report 中.zip" }),
    )
    .unwrap_err();
    assert_eq!(err["code"], "INVALID_ARGUMENT", "{err}");

    // Deleting outside the temp dir is refused; inside succeeds and is idempotent.
    let outside = ok(invoke(
        &h.webview,
        "temp_delete_file",
        json!({ "filePath": "/etc/hosts" }),
    ));
    assert_eq!(outside["success"], false);
    let inside = ok(invoke(
        &h.webview,
        "temp_delete_file",
        json!({ "filePath": path }),
    ));
    assert_eq!(inside["success"], true);
    assert!(!std::path::Path::new(&path).exists());
    let again = ok(invoke(
        &h.webview,
        "temp_delete_file",
        json!({ "filePath": path }),
    ));
    assert_eq!(again["success"], true);
}

#[test]
fn cloud_sync_password_and_oauth_commands() {
    let h = build_app();
    let available = collect(&h.app, "netcatty:cloudsync:password-available");

    // Session master password: set → persisted encrypted → get → clear.
    assert_eq!(
        ok(invoke(&h.webview, "cloudsync_password_get", json!({}))),
        Value::Null
    );
    assert_eq!(
        ok(invoke(
            &h.webview,
            "cloudsync_password_set",
            json!({ "password": "hunter2" })
        )),
        json!(true)
    );
    assert!(wait_for(&available, Duration::from_secs(2), |seen| seen
        .len()
        == 1));
    let persisted = std::fs::read_to_string(h._data_dir.path().join("cloud-sync-session.enc"))
        .expect("password persisted");
    assert!(
        persisted.starts_with("enc:v2:"),
        "persisted encrypted: {persisted}"
    );
    assert!(!persisted.contains("hunter2"));
    assert_eq!(
        ok(invoke(&h.webview, "cloudsync_password_get", json!({}))),
        json!("hunter2")
    );
    assert_eq!(
        ok(invoke(&h.webview, "cloudsync_password_clear", json!({}))),
        json!(true)
    );
    assert_eq!(
        ok(invoke(&h.webview, "cloudsync_password_get", json!({}))),
        Value::Null
    );
    assert!(!h._data_dir.path().join("cloud-sync-session.enc").exists());

    // OAuth loopback: prepare returns a loopback redirect URI; cancel is
    // reported by the next await.
    let prepared = ok(invoke(&h.webview, "oauth_prepare_callback", json!({})));
    let redirect = prepared["redirectUri"].as_str().unwrap();
    assert!(redirect.starts_with("http://127.0.0.1:") && redirect.ends_with("/oauth/callback"));
    let session_id = prepared["sessionId"].as_str().unwrap().to_owned();
    ok(invoke(
        &h.webview,
        "oauth_cancel_callback",
        json!({ "sessionId": session_id }),
    ));
    let err = invoke(
        &h.webview,
        "oauth_await_callback",
        json!({ "expectedState": "s", "sessionId": session_id }),
    )
    .unwrap_err();
    assert_eq!(err["message"], "OAuth flow cancelled");

    // Argument validation happens before any network access.
    let err = invoke(&h.webview, "webdav_initialize", json!({})).unwrap_err();
    assert_eq!(err["message"], "Missing WebDAV config");
    let err = invoke(
        &h.webview,
        "s3_upload",
        json!({ "config": { "endpoint": "https://s3.example.com", "bucket": "b" } }),
    )
    .unwrap_err();
    assert_eq!(err["message"], "Missing syncedFile");
    let err = invoke(
        &h.webview,
        "google_drive_find_sync_file",
        json!({ "payload": {} }),
    )
    .unwrap_err();
    assert_eq!(err["message"], "Missing accessToken");
    let err = invoke(
        &h.webview,
        "github_device_flow_poll",
        json!({ "payload": { "pollId": "p" } }),
    )
    .unwrap_err();
    assert_eq!(err["message"], "Missing deviceCode");
    ok(invoke(
        &h.webview,
        "github_device_flow_cancel",
        json!({ "pollId": "unknown" }),
    ));
}

#[test]
fn remote_desktop_commands() {
    let h = build_app();
    // A channel argument crosses the IPC boundary as `__CHANNEL__:<id>`.
    let channel = "__CHANNEL__:7";

    let err = invoke(
        &h.webview,
        "rdesktop_connect",
        json!({ "payload": { "protocol": "ssh", "hostname": "127.0.0.1" }, "onEvent": channel }),
    )
    .expect_err("only vnc and rdp are remote desktop protocols");
    assert_eq!(err["code"], "INVALID_ARGUMENT", "error payload: {err}");

    let err = invoke(
        &h.webview,
        "rdesktop_connect",
        json!({ "payload": { "protocol": "vnc", "hostname": " " }, "onEvent": channel }),
    )
    .expect_err("hostname is required");
    assert_eq!(err["code"], "INVALID_ARGUMENT");

    // Port 1 refuses the connection: the command still resolves, the failure
    // is reported on the channel and the session unregisters itself.
    let started = ok(invoke(
        &h.webview,
        "rdesktop_connect",
        json!({
            "payload": { "sessionId": "rd-1", "protocol": "vnc", "hostname": "127.0.0.1", "port": 1 },
            "onEvent": channel,
        }),
    ));
    assert_eq!(started["sessionId"], "rd-1");

    // Input and close for a finished or unknown session are accepted.
    ok(invoke(
        &h.webview,
        "rdesktop_input",
        json!({ "payload": { "sessionId": "rd-1", "events": [
            { "type": "pointer", "x": 1, "y": 2, "buttons": 0 },
            { "type": "key", "down": true, "keysym": 97, "scancode": 30 },
        ] } }),
    ));
    ok(invoke(
        &h.webview,
        "rdesktop_close",
        json!({ "sessionId": "rd-1" }),
    ));
    ok(invoke(
        &h.webview,
        "rdesktop_close",
        json!({ "sessionId": "nope" }),
    ));

    // Once the refused session has unregistered, its id can be used again.
    let reusable = (0..100).any(|_| {
        std::thread::sleep(Duration::from_millis(50));
        invoke(
            &h.webview,
            "rdesktop_connect",
            json!({
                "payload": { "sessionId": "rd-1", "protocol": "vnc", "hostname": "127.0.0.1", "port": 1 },
                "onEvent": channel,
            }),
        )
        .is_ok()
    });
    assert!(reusable, "a finished session must free its id");
}

// ---------------------------------------------------------------------------
// System manager / server stats / monitor (commands/system.rs, monitor.rs)

#[cfg(unix)]
#[test]
fn system_manager_commands_on_a_local_session() {
    let h = build_app();
    let started = ok(invoke(
        &h.webview,
        "session_start_local",
        json!({ "payload": { "shell": "/bin/sh", "cols": 80, "rows": 24 } }),
    ));
    let id = started["sessionId"].as_str().unwrap().to_string();

    // Local sessions run the probes on this machine.
    let caps = ok(invoke(
        &h.webview,
        "system_probe_capabilities",
        json!({ "payload": { "sessionId": id } }),
    ));
    assert_eq!(caps["success"], true, "{caps}");
    let expected_os = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    assert_eq!(caps["capabilities"]["targetOs"], expected_os);

    let procs = ok(invoke(
        &h.webview,
        "system_list_processes",
        json!({ "payload": { "sessionId": id } }),
    ));
    assert_eq!(procs["success"], true, "{procs}");
    assert!(procs["processes"].as_array().unwrap().len() > 1);

    // A command started from the shell shows up as a PTY child.
    ok(invoke(
        &h.webview,
        "session_write",
        json!({ "payload": { "sessionId": id, "data": "sleep 30\n" } }),
    ));
    let start = Instant::now();
    let mut children = Value::Null;
    while start.elapsed() < Duration::from_secs(10) {
        children = ok(invoke(
            &h.webview,
            "pty_child_processes",
            json!({ "sessionId": id }),
        ));
        if children.to_string().contains("sleep 30") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        children.to_string().contains("sleep 30"),
        "children: {children}"
    );
    assert_eq!(
        ok(invoke(
            &h.webview,
            "pty_child_processes",
            json!({ "sessionId": "nope" })
        )),
        json!([])
    );

    // Stats / distro / history need an SSH connection.
    let stats = ok(invoke(
        &h.webview,
        "session_server_stats",
        json!({ "sessionId": id }),
    ));
    assert_eq!(
        stats,
        json!({ "success": false, "error": "Session not found or not connected" })
    );
    let history = ok(invoke(
        &h.webview,
        "session_read_remote_history",
        json!({ "sessionId": "nope", "limit": 10 }),
    ));
    assert_eq!(history["error"], "Session not found");

    // Unknown sessions fail like Electron's execOnSession.
    let missing = ok(invoke(
        &h.webview,
        "system_list_listening_ports",
        json!({ "payload": { "sessionId": "nope" } }),
    ));
    assert_eq!(missing["success"], false);
    assert_eq!(missing["error"], "Session not found");
    let no_id = ok(invoke(
        &h.webview,
        "system_list_tmux_sessions",
        json!({ "payload": {} }),
    ));
    assert_eq!(no_id["error"], "Missing sessionId");

    ok(invoke(
        &h.webview,
        "session_close",
        json!({ "sessionId": id }),
    ));
}

#[test]
fn monitor_commands_track_panels_per_window() {
    let h = build_app();
    let err = invoke(&h.webview, "monitor_update", json!({ "panels": {} }))
        .expect_err("non-array demand is rejected");
    assert_eq!(err["code"], "INVALID_ARGUMENT");

    // Hosts without connect options are reported, never dialed.
    let snap = ok(invoke(
        &h.webview,
        "monitor_update",
        json!({ "panels": [{
            "id": "p1", "runId": "r1", "interval": 7,
            "hosts": [{ "id": "a" }, { "id": "b", "status": "login" }]
        }] }),
    ));
    assert_eq!(snap["running"], json!(["p1"]));
    assert_eq!(snap["count"], 1);
    assert_eq!(snap["hostCount"], 0);
    assert_eq!(snap["hosts"]["a"]["status"], "unsupported");
    assert_eq!(snap["hosts"]["b"]["status"], "login");
    assert_eq!(snap["historyMode"], "replace");
    let started_at = snap["startedAt"]["p1"].as_i64().unwrap();
    assert!(started_at > 0);

    let cursor = json!({ "runtimeId": snap["runtimeId"], "epoch": snap["epoch"], "after": {} });
    let next = ok(invoke(
        &h.webview,
        "monitor_snapshot",
        json!({ "cursor": cursor }),
    ));
    assert_eq!(next["historyMode"], "append");
    assert_eq!(next["startedAt"]["p1"], started_at);

    ok(invoke(
        &h.webview,
        "monitor_retry",
        json!({ "hostId": "a" }),
    ));
    ok(invoke(&h.webview, "monitor_stop_all", json!({})));
    let after = ok(invoke(&h.webview, "monitor_snapshot", json!({})));
    assert_eq!(after["running"], json!([]));
    assert_eq!(after["epoch"], snap["epoch"].as_u64().unwrap() + 1);
}

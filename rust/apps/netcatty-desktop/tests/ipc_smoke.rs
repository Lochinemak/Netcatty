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

#[test]
fn settings_window_and_cross_window_events() {
    use tauri::Manager;
    let h = build_app();
    let settings_changed = collect(&h.app, "netcatty:settings:changed");
    let language = collect(&h.app, "netcatty:language-changed");

    // Opening twice reuses one window; closing hides it (Electron parity).
    assert_eq!(
        ok(invoke(&h.webview, "window_open_settings", json!({}))),
        json!(true)
    );
    assert!(h.app.get_webview_window("settings").is_some());
    assert_eq!(
        ok(invoke(&h.webview, "window_open_settings", json!({}))),
        json!(true)
    );
    assert_eq!(h.app.webview_windows().len(), 2);
    assert_eq!(
        ok(invoke(&h.webview, "window_close_settings", json!({}))),
        json!(true)
    );
    assert!(h.app.get_webview_window("settings").is_some());

    assert_eq!(
        ok(invoke(
            &h.webview,
            "app_set_background_color",
            json!({ "color": "216 33% 96%" })
        )),
        json!(true)
    );
    assert_eq!(
        ok(invoke(
            &h.webview,
            "app_set_background_color",
            json!({ "color": "red" })
        )),
        json!(false)
    );
    assert_eq!(
        ok(invoke(
            &h.webview,
            "window_set_title",
            json!({ "title": "  " })
        )),
        json!(true)
    );

    ok(invoke(
        &h.webview,
        "app_set_language",
        json!({ "language": "zh-CN" }),
    ));
    assert!(wait_for(&language, Duration::from_secs(2), |seen| seen
        .iter()
        .any(|v| v == &json!("zh-CN"))));

    ok(invoke(
        &h.webview,
        "app_broadcast_settings_changed",
        json!({ "payload": { "key": "k", "value": 1 } }),
    ));
    assert!(wait_for(
        &settings_changed,
        Duration::from_secs(2),
        |seen| seen
            .iter()
            .any(|v| v == &json!({ "source": "main", "payload": { "key": "k", "value": 1 } }))
    ));
}

#[test]
fn vault_backups_round_trip() {
    let h = build_app();
    let changed = collect(&h.app, "netcatty:vault-backups:changed");
    assert_eq!(
        ok(invoke(&h.webview, "vault_backup_capabilities", json!({}))),
        json!({ "encryptionAvailable": true })
    );
    let payload = json!({ "hosts": [{ "id": "h1" }], "syncedAt": 1 });
    let created = ok(invoke(
        &h.webview,
        "vault_backup_create",
        json!({ "payload": { "payload": payload, "reason": "before_restore" } }),
    ));
    assert_eq!(created["created"], json!(true));
    assert_eq!(created["backup"]["preview"]["hostCount"], json!(1));
    assert!(wait_for(&changed, Duration::from_secs(2), |seen| seen
        .len()
        == 1));
    let id = created["backup"]["id"].clone();

    let listed = ok(invoke(&h.webview, "vault_backup_list", json!({})));
    assert_eq!(listed.as_array().unwrap().len(), 1);
    let read = ok(invoke(
        &h.webview,
        "vault_backup_read",
        json!({ "payload": { "id": id } }),
    ));
    assert_eq!(read["payload"], payload);
    assert_eq!(
        ok(invoke(&h.webview, "vault_backup_clear", json!({}))),
        json!({ "deletedCount": 1 })
    );
}

#[test]
fn file_watch_polls_reports_and_cleans_up() {
    let h = build_app();
    let errors = collect(&h.app, "netcatty:filewatch:error");
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("edit.txt");

    let err = invoke(
        &h.webview,
        "filewatch_start",
        json!({ "localPath": file, "remotePath": "/r/edit.txt", "sftpId": "s1" }),
    )
    .unwrap_err();
    assert!(err["message"]
        .as_str()
        .unwrap()
        .starts_with("Cannot watch file:"));

    std::fs::write(&file, "v1").unwrap();
    let args = json!({ "localPath": file, "remotePath": "/r/edit.txt", "sftpId": "s1" });
    let started = ok(invoke(&h.webview, "filewatch_start", args.clone()));
    let watch_id = started["watchId"].as_str().unwrap().to_owned();
    assert_eq!(
        ok(invoke(&h.webview, "filewatch_start", args))["reused"],
        json!(true)
    );
    assert_eq!(
        ok(invoke(&h.webview, "filewatch_list", json!({})))
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // A save is picked up by the poller; with no SFTP session the sync fails
    // and is reported like Electron.
    std::fs::write(&file, "version two").unwrap();
    assert!(wait_for(&errors, Duration::from_secs(6), |seen| seen
        .iter()
        .any(|e| {
            e["watchId"] == json!(watch_id)
                && e["error"] == json!("SFTP session not found or expired")
        })));

    assert_eq!(
        ok(invoke(
            &h.webview,
            "filewatch_stop",
            json!({ "watchId": watch_id, "cleanupTempFile": false })
        )),
        json!({ "success": true })
    );
    assert!(ok(invoke(&h.webview, "filewatch_list", json!({})))
        .as_array()
        .unwrap()
        .is_empty());

    ok(invoke(
        &h.webview,
        "filewatch_register_temp_file",
        json!({ "sftpId": "s1", "localPath": file }),
    ));
    let unregistered = ok(invoke(
        &h.webview,
        "filewatch_unregister_temp_file",
        json!({ "sftpId": "s1", "localPath": file }),
    ));
    assert_eq!(
        unregistered,
        json!({ "success": true, "retained": false, "wasTracked": true })
    );
    assert!(!file.exists());
}

/// Session logs: a manual recording and an automatic log both capture live
/// PTY output through the session pump tap; prepare / stop / status /
/// clear-all follow the Electron contract.
#[cfg(unix)]
#[test]
fn session_logs_record_live_session_output() {
    use netcatty_desktop_lib::commands::sessionlog::SessionLogState;
    use tauri::Manager;

    let h = build_app();
    let data = collect(&h.app, "netcatty:data");
    let exits = collect(&h.app, "netcatty:exit");
    let logs_dir = tempfile::tempdir().unwrap();
    let auto_dir = logs_dir.path().join("auto");
    let manual_path = logs_dir.path().join("manual").join("recording.log");

    let id = ok(invoke(
        &h.webview,
        "session_start_local",
        json!({ "payload": {
            "shell": "/bin/sh", "cols": 80, "rows": 24,
            "sessionLog": { "enabled": true, "directory": auto_dir, "format": "txt" }
        } }),
    ))["sessionId"]
        .as_str()
        .unwrap()
        .to_string();
    let status = |id: &str| {
        ok(invoke(
            &h.webview,
            "session_log_manual_status",
            json!({ "payload": { "sessionId": id } }),
        ))
    };
    // The automatic log is openable; nothing is recorded manually yet.
    assert_eq!(
        status(&id),
        json!({ "success": true, "isLogging": false, "hasSessionLog": true })
    );
    assert_eq!(
        status(" "),
        json!({ "success": false, "isLogging": false, "hasSessionLog": false, "error": "Missing sessionId" })
    );

    // Renderer-supplied paths and unknown tokens are refused.
    let refused = ok(invoke(
        &h.webview,
        "session_log_manual_start",
        json!({ "payload": { "sessionId": id, "filePath": "/etc/passwd" } }),
    ));
    assert_eq!(
        refused,
        json!({ "success": false, "started": false, "error": "Session log path must be chosen via the save dialog" })
    );
    let expired = ok(invoke(
        &h.webview,
        "session_log_manual_start",
        json!({ "payload": { "sessionId": id, "selectionToken": "nope" } }),
    ));
    assert_eq!(expired["error"], "Invalid or expired session log selection");

    // Stand in for the save dialog, then start recording with the token.
    let token = h.app.state::<SessionLogState>().register_selection(
        &id,
        manual_path.clone(),
        netcatty_sessionlog::LogFormat::Raw,
        Some("main".into()),
    );
    let started = ok(invoke(
        &h.webview,
        "session_log_manual_start",
        json!({ "payload": { "sessionId": id, "selectionToken": token, "initialLine": "$ " } }),
    ));
    assert_eq!(
        started,
        json!({ "success": true, "started": true, "filePath": manual_path })
    );
    assert_eq!(
        status(&id),
        json!({ "success": true, "isLogging": true, "hasSessionLog": true })
    );
    let again = ok(invoke(
        &h.webview,
        "session_log_manual_start",
        json!({ "payload": { "sessionId": id, "selectionToken": token } }),
    ));
    assert_eq!(again["error"], "Session log is already active");

    ok(invoke(
        &h.webview,
        "session_write",
        json!({ "payload": { "sessionId": id, "data": "echo hello-$((40+2))-log\n" } }),
    ));
    assert!(wait_for(&data, Duration::from_secs(10), |events| events
        .iter()
        .any(|e| e["data"]
            .as_str()
            .is_some_and(|d| d.contains("hello-42-log")))));

    // Prepare flushes the live recording (the manual log wins over the
    // automatic one) without stopping it.
    let prepared = ok(invoke(
        &h.webview,
        "session_log_prepare",
        json!({ "payload": { "sessionId": id } }),
    ));
    assert_eq!(
        prepared,
        json!({ "success": true, "filePath": manual_path })
    );
    let content = std::fs::read_to_string(&manual_path).unwrap();
    assert!(content.starts_with("$ "), "{content:?}");
    assert!(content.contains("hello-42-log"), "{content:?}");

    // Clear-all keeps the live automatic log (and its host folder).
    let cleared = ok(invoke(
        &h.webview,
        "session_log_clear_dir",
        json!({ "directory": auto_dir }),
    ));
    assert_eq!(
        cleared,
        json!({ "success": true, "deletedCount": 0, "failedCount": 0 })
    );

    let stopped = ok(invoke(
        &h.webview,
        "session_log_manual_stop",
        json!({ "payload": { "sessionId": id } }),
    ));
    assert_eq!(
        stopped,
        json!({ "success": true, "stopped": true, "filePath": manual_path })
    );
    assert_eq!(
        ok(invoke(
            &h.webview,
            "session_log_manual_stop",
            json!({ "payload": { "sessionId": id } }),
        )),
        json!({ "success": true, "stopped": false })
    );
    assert_eq!(
        status(&id),
        json!({ "success": true, "isLogging": false, "hasSessionLog": true })
    );

    // Closing the session finalizes the automatic txt log.
    ok(invoke(
        &h.webview,
        "session_close",
        json!({ "sessionId": id }),
    ));
    assert!(wait_for(&exits, Duration::from_secs(10), |events| events
        .iter()
        .any(|e| session_id_of(e) == Some(id.as_str()))));
    let host_dir = auto_dir.join("Local");
    let deadline = Instant::now() + Duration::from_secs(10);
    let auto_log = loop {
        let found = std::fs::read_dir(&host_dir).ok().and_then(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .find(|p| p.extension().is_some_and(|e| e == "txt"))
        });
        if let Some(path) =
            found.filter(|p| std::fs::read_to_string(p).is_ok_and(|c| c.contains("hello-42-log")))
        {
            break path;
        }
        assert!(Instant::now() < deadline, "automatic log was not written");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(!std::fs::read_to_string(&auto_log).unwrap().contains('\x1b'));

    // Once nothing is live, clear-all removes the host folder as one artifact.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let cleared = ok(invoke(
            &h.webview,
            "session_log_clear_dir",
            json!({ "directory": auto_dir }),
        ));
        if cleared["deletedCount"] == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "auto log stayed active: {cleared}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!host_dir.exists());
}

#[test]
fn session_log_file_commands() {
    let h = build_app();
    let dir = tempfile::tempdir().unwrap();

    let saved = ok(invoke(
        &h.webview,
        "session_log_auto_save",
        json!({ "payload": {
            "terminalData": "a\x1b[31mb\x1b[0m\r\n", "hostLabel": "web/01", "hostname": "h",
            "hostId": "id", "startTime": 0, "format": "txt", "directory": dir.path()
        } }),
    ));
    assert_eq!(saved["success"], true);
    let path = std::path::PathBuf::from(saved["filePath"].as_str().unwrap());
    assert_eq!(path.parent().unwrap().file_name().unwrap(), "web_01");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "ab");
    assert_eq!(
        ok(invoke(
            &h.webview,
            "session_log_auto_save",
            json!({ "payload": { "terminalData": "", "directory": dir.path() } }),
        )),
        json!({ "success": false, "error": "Missing terminal data or directory" })
    );

    let missing = dir.path().join("missing");
    let opened = ok(invoke(
        &h.webview,
        "session_log_open_dir",
        json!({ "directory": missing }),
    ));
    assert_eq!(opened["success"], false);
    assert!(opened["error"].as_str().unwrap().starts_with("ENOENT"));
    assert_eq!(
        ok(invoke(
            &h.webview,
            "session_log_open_dir",
            json!({ "directory": "" })
        )),
        json!({ "success": false, "error": "No directory specified" })
    );

    assert_eq!(
        ok(invoke(
            &h.webview,
            "session_log_clear_dir",
            json!({ "directory": missing }),
        )),
        json!({ "success": true, "deletedCount": 0, "failedCount": 0 })
    );
    assert_eq!(
        ok(invoke(&h.webview, "session_log_clear_dir", json!({}))),
        json!({ "success": false, "deletedCount": 0, "failedCount": 0, "error": "No directory specified" })
    );
    assert_eq!(
        ok(invoke(
            &h.webview,
            "session_log_clear_dir",
            json!({ "directory": dir.path() }),
        )),
        json!({ "success": true, "deletedCount": 1, "failedCount": 0 })
    );

    assert_eq!(
        ok(invoke(
            &h.webview,
            "session_log_prepare",
            json!({ "payload": { "sessionId": "unknown" } }),
        )),
        json!({ "success": false, "error": "No saved log is available for this session" })
    );
    assert_eq!(
        ok(invoke(
            &h.webview,
            "session_log_reveal",
            json!({ "payload": {} }),
        )),
        json!({ "success": false, "error": "Missing sessionId" })
    );

    let err = invoke(
        &h.webview,
        "session_log_export",
        json!({ "payload": { "terminalData": "", "hostLabel": "h", "startTime": 0, "format": "txt" } }),
    )
    .expect_err("empty export must be rejected");
    assert_eq!(err["message"], "No terminal data to export");
}

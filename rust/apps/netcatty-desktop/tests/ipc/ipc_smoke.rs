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
use crate::BUILD_LOCK;

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

/// Tray preferences, tray data, tray panel actions, global hotkey edge cases
/// and autostart. Nothing here creates a native tray icon or registers an OS
/// hotkey: the mock runtime never runs main-thread tasks, which both need.
#[test]
fn tray_hotkey_and_autostart_commands() {
    let h = build_app();
    let jump = collect(&h.app, "netcatty:trayPanel:jumpToSession");
    let connect = collect(&h.app, "netcatty:trayPanel:connectToHost");
    let close = collect(&h.app, "netcatty:trayPanel:closeSession");
    let start = collect(&h.app, "netcatty:trayPanel:startPortForward");

    // Defaults match Electron: icon shown, close-to-tray off.
    assert_eq!(
        ok(invoke(&h.webview, "tray_is_show_icon", json!({}))),
        json!({ "enabled": true })
    );
    assert_eq!(
        ok(invoke(&h.webview, "tray_is_close_to_tray", json!({}))),
        json!({ "enabled": false })
    );
    assert_eq!(
        ok(invoke(
            &h.webview,
            "tray_set_show_icon",
            json!({ "enabled": false })
        )),
        json!({ "success": true, "enabled": false })
    );
    // With the icon hidden by preference this does not create a tray.
    assert_eq!(
        ok(invoke(
            &h.webview,
            "tray_set_close_to_tray",
            json!({ "enabled": true })
        )),
        json!({ "success": true, "enabled": true })
    );
    assert_eq!(
        ok(invoke(&h.webview, "tray_is_close_to_tray", json!({}))),
        json!({ "enabled": true })
    );
    assert_eq!(
        ok(invoke(&h.webview, "tray_is_show_icon", json!({}))),
        json!({ "enabled": false })
    );

    // Partial menu-data updates merge; the panel reads the result back.
    let session = json!({ "id": "s1", "label": "web", "hostLabel": "Web", "status": "connected" });
    ok(invoke(
        &h.webview,
        "tray_update_menu_data",
        json!({ "payload": { "sessions": [session.clone()] } }),
    ));
    assert_eq!(
        ok(invoke(
            &h.webview,
            "tray_update_menu_data",
            json!({ "payload": { "hosts": [{ "id": "h1" }] } })
        )),
        json!({ "success": true })
    );
    assert_eq!(
        ok(invoke(&h.webview, "tray_get_menu_data", json!({}))),
        json!({ "sessions": [session], "portForwardRules": [], "hosts": [{ "id": "h1" }] })
    );

    // Tray panel actions are forwarded to the main window as events.
    assert_eq!(
        ok(invoke(&h.webview, "tray_panel_hide", json!({}))),
        json!({ "success": true })
    );
    for (cmd, args) in [
        ("tray_panel_jump_to_session", json!({ "sessionId": "s1" })),
        ("tray_panel_connect_to_host", json!({ "hostId": "h1" })),
        ("tray_panel_close_session", json!({ "sessionId": "s1" })),
        ("tray_panel_start_port_forward", json!({ "ruleId": "r1" })),
    ] {
        assert_eq!(
            ok(invoke(&h.webview, cmd, args)),
            json!({ "success": true }),
            "{cmd}"
        );
    }
    for (seen, expected) in [
        (&jump, "s1"),
        (&connect, "h1"),
        (&close, "s1"),
        (&start, "r1"),
    ] {
        assert!(wait_for(seen, Duration::from_secs(2), |events| events
            .iter()
            .any(|v| v == &json!(expected))));
    }

    // Global hotkey: disabled / unparseable hotkeys never reach the OS.
    assert_eq!(
        ok(invoke(&h.webview, "hotkey_status", json!({}))),
        json!({ "enabled": false, "hotkey": null })
    );
    assert_eq!(
        ok(invoke(
            &h.webview,
            "hotkey_register",
            json!({ "hotkey": "Disabled" })
        )),
        json!({ "success": true, "enabled": false })
    );
    assert_eq!(
        ok(invoke(
            &h.webview,
            "hotkey_register",
            json!({ "hotkey": "Ctrl + ä" })
        )),
        json!({ "success": false, "error": "Invalid hotkey format" })
    );
    assert_eq!(
        ok(invoke(&h.webview, "hotkey_unregister", json!({}))),
        json!({ "success": true })
    );

    // Autostart is unsupported in debug builds (Electron: dev runs).
    if cfg!(debug_assertions) {
        let unsupported = json!({ "success": true, "enabled": false, "supported": false });
        assert_eq!(
            ok(invoke(&h.webview, "autostart_get", json!({}))),
            unsupported
        );
        assert_eq!(
            ok(invoke(
                &h.webview,
                "autostart_set",
                json!({ "enabled": true })
            )),
            unsupported
        );
    }
}

// ---------------------------------------------------------------------------
// Telnet / serial / Mosh / EternalTerminal sessions
// ---------------------------------------------------------------------------

/// Read from `stream` until `needle` has been seen (or panic after 10 s).
fn read_until(stream: &mut std::net::TcpStream, seen: &mut Vec<u8>, needle: &[u8]) {
    use std::io::Read;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = [0u8; 1024];
    while !seen.windows(needle.len()).any(|w| w == needle) {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {needle:?}; got {seen:?}"
        );
        match stream.read(&mut buf) {
            Ok(0) => panic!("client closed while waiting for {needle:?}"),
            Ok(n) => seen.extend_from_slice(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("read failed: {e}"),
        }
    }
}

#[test]
fn telnet_session_against_fake_server() {
    use std::io::Write;
    const IAC: u8 = 255;
    const WILL: u8 = 251;
    const WONT: u8 = 252;
    const DO: u8 = 253;
    const SB: u8 = 250;
    const SE: u8 = 240;
    const ECHO: u8 = 1;
    const NAWS: u8 = 31;

    let h = build_app();
    let data = collect(&h.app, "netcatty:data");
    let exits = collect(&h.app, "netcatty:exit");
    let echo = collect(&h.app, "netcatty:telnet:echo-mode");
    let complete = collect(&h.app, "netcatty:telnet:auto-login-complete");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (server_tx, server_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (step_tx, step_rx) = std::sync::mpsc::channel::<&'static str>();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut seen = Vec::new();
        // Negotiate NAWS + echo, then prompt for credentials.
        s.write_all(&[IAC, DO, NAWS, IAC, WILL, ECHO]).unwrap();
        s.write_all(b"\r\nUsername: ").unwrap();
        read_until(&mut s, &mut seen, b"admin\r\n");
        s.write_all(b"\r\nPassword: ").unwrap();
        read_until(&mut s, &mut seen, b"secret\r\n");
        s.write_all(b"\r\nWelcome\r\nrouter# ").unwrap();
        // Wait for the test to type a command and resize.
        assert_eq!(step_rx.recv().unwrap(), "typed");
        read_until(&mut s, &mut seen, b"show ver\r\n");
        read_until(&mut s, &mut seen, &[IAC, SB, NAWS, 0, 132, 0, 43, IAC, SE]);
        s.write_all(&[IAC, WONT, ECHO]).unwrap();
        assert_eq!(step_rx.recv().unwrap(), "close");
        server_tx.send(seen).unwrap();
        // Half-close and drain so the client sees a clean EOF (an RST
        // would be reported as an error exit, like in Electron).
        s.shutdown(std::net::Shutdown::Write).unwrap();
        let mut sink = [0u8; 256];
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match std::io::Read::read(&mut s, &mut sink) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
    });

    let started = ok(invoke(
        &h.webview,
        "telnet_start",
        json!({ "payload": {
            "sessionId": "tel-1",
            "hostname": "127.0.0.1",
            "port": port,
            "username": "admin",
            "password": "secret",
            "cols": 100,
            "rows": 30,
            "bootEpoch": 7
        } }),
    ));
    assert_eq!(started["sessionId"], "tel-1");

    assert!(
        wait_for(&complete, Duration::from_secs(10), |events| {
            events
                .iter()
                .any(|e| session_id_of(e) == Some("tel-1") && e["bootEpoch"] == 7)
        }),
        "auto-login-complete not emitted: {:?}",
        complete.lock().unwrap()
    );
    assert!(wait_for(&data, Duration::from_secs(10), |events| {
        let all: String = events
            .iter()
            .filter(|e| session_id_of(e) == Some("tel-1"))
            .filter_map(|e| e["data"].as_str())
            .collect();
        // Telnet commands never leak into the terminal output.
        all.contains("Username: ") && all.contains("router# ") && !all.contains('\u{1f}')
    }));
    assert!(wait_for(&echo, Duration::from_secs(5), |events| {
        events.iter().any(|e| {
            session_id_of(e) == Some("tel-1") && e["remoteEcho"] == true && e["localEcho"] == false
        })
    }));
    let mode = ok(invoke(
        &h.webview,
        "telnet_get_echo_mode",
        json!({ "sessionId": "tel-1" }),
    ));
    assert_eq!(mode["success"], true);
    assert_eq!(mode["sessionId"], "tel-1");
    assert_eq!(mode["remoteEcho"], true);
    let missing = ok(invoke(
        &h.webview,
        "telnet_get_echo_mode",
        json!({ "sessionId": "nope" }),
    ));
    assert_eq!(missing["success"], false);
    assert_eq!(missing["error"], "Telnet echo mode unavailable");

    ok(invoke(
        &h.webview,
        "session_write",
        json!({ "payload": { "sessionId": "tel-1", "data": "show ver\r" } }),
    ));
    ok(invoke(
        &h.webview,
        "session_resize",
        json!({ "payload": { "sessionId": "tel-1", "cols": 132, "rows": 43 } }),
    ));
    step_tx.send("typed").unwrap();
    assert!(wait_for(&echo, Duration::from_secs(5), |events| {
        events
            .iter()
            .any(|e| session_id_of(e) == Some("tel-1") && e["remoteEcho"] == false)
    }));
    step_tx.send("close").unwrap();
    let seen = server_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    server.join().unwrap();
    // Client negotiation: DO SGA, WILL TTYPE, WILL NAWS, then the size.
    assert!(seen.windows(3).any(|w| w == [IAC, DO, 3]));
    assert!(seen
        .windows(9)
        .any(|w| w == [IAC, SB, NAWS, 0, 100, 0, 30, IAC, SE]));

    assert!(wait_for(&exits, Duration::from_secs(10), |events| {
        events.iter().any(|e| session_id_of(e) == Some("tel-1"))
    }));
    let exit = exits
        .lock()
        .unwrap()
        .iter()
        .find(|e| session_id_of(e) == Some("tel-1"))
        .cloned()
        .unwrap();
    assert_eq!(exit["reason"], "closed", "{exit}");
    assert_eq!(exit["exitCode"], 0, "{exit}");
}

#[test]
fn telnet_connect_errors_match_electron() {
    let h = build_app();
    // Bind then drop: nothing listens on this port any more.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let err = invoke(
        &h.webview,
        "telnet_start",
        json!({ "payload": { "hostname": "127.0.0.1", "port": port } }),
    )
    .expect_err("connection must be refused");
    assert_eq!(err["code"], "NETWORK", "{err}");
    assert!(
        err["message"]
            .as_str()
            .unwrap()
            .starts_with("Failed to connect: "),
        "{err}"
    );
}

#[cfg(unix)]
#[test]
fn serial_session_over_pty_pair() {
    use serialport::SerialPort;
    use std::io::{Read, Write};

    let h = build_app();
    let data = collect(&h.app, "netcatty:data");
    let exits = collect(&h.app, "netcatty:exit");
    let cancelled = collect(&h.app, "netcatty:telnet:auto-login-cancelled");

    let listed = ok(invoke(&h.webview, "serial_list_ports", json!({})));
    assert!(listed.is_array());

    let (mut master, slave) = serialport::TTYPort::pair().expect("pty pair");
    let path = slave.name().unwrap();
    drop(slave);
    master.set_timeout(Duration::from_millis(100)).unwrap();

    let started = ok(invoke(
        &h.webview,
        "serial_start",
        json!({ "payload": {
            "sessionId": "ser-1",
            "path": path,
            "baudRate": 9600,
            "username": "root",
            "charset": "gb18030"
        } }),
    ));
    assert_eq!(started["sessionId"], "ser-1");

    let read_master = |master: &mut serialport::TTYPort, needle: &[u8]| {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        let mut buf = [0u8; 256];
        while !seen.windows(needle.len()).any(|w| w == needle) {
            assert!(Instant::now() < deadline, "timed out: {seen:?}");
            if let Ok(n) = master.read(&mut buf) {
                seen.extend_from_slice(&buf[..n]);
            }
        }
        seen
    };
    // Device output decoded with GB18030, and the auto-login answers.
    master.write_all(b"\xd6\xd0 login: ").unwrap();
    read_master(&mut master, b"root\r");
    assert!(wait_for(&data, Duration::from_secs(5), |events| {
        events.iter().any(|e| {
            session_id_of(e) == Some("ser-1") && e["data"].as_str().unwrap_or("").contains('中')
        })
    }));
    // No password saved and the device asks for one: reported as cancelled.
    master.write_all(b"\r\nPassword: ").unwrap();
    assert!(wait_for(&cancelled, Duration::from_secs(5), |events| {
        events.iter().any(|e| session_id_of(e) == Some("ser-1"))
    }));

    // Byte-oriented backspace: one DEL per encoded byte of the erase char.
    ok(invoke(
        &h.webview,
        "session_write",
        json!({ "payload": { "sessionId": "ser-1", "data": "\u{7f}", "serialEraseChar": "中" } }),
    ));
    read_master(&mut master, b"\x7f\x7f");
    ok(invoke(
        &h.webview,
        "session_notify_user_input",
        json!({ "sessionId": "ser-1" }),
    ));
    let enc = ok(invoke(
        &h.webview,
        "session_set_encoding",
        json!({ "sessionId": "ser-1", "encoding": "UTF-8" }),
    ));
    assert_eq!(enc, json!({ "ok": true, "encoding": "utf-8" }));
    ok(invoke(
        &h.webview,
        "session_close",
        json!({ "sessionId": "ser-1" }),
    ));
    assert!(wait_for(&exits, Duration::from_secs(5), |events| {
        events
            .iter()
            .any(|e| session_id_of(e) == Some("ser-1") && e["reason"] == "closed")
    }));
}

#[test]
fn serial_open_failure_message() {
    let h = build_app();
    let err = invoke(
        &h.webview,
        "serial_start",
        json!({ "payload": { "path": "/definitely/not/a/serial/port" } }),
    )
    .expect_err("missing device must fail");
    assert!(
        err["message"]
            .as_str()
            .unwrap()
            .starts_with("Failed to open serial port: "),
        "{err}"
    );
}

/// Write an executable script into `dir`.
#[cfg(unix)]
fn write_script(dir: &std::path::Path, name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn mosh_handshake_swaps_to_mosh_client() {
    let h = build_app();
    let data = collect(&h.app, "netcatty:data");
    let exits = collect(&h.app, "netcatty:exit");
    let ready = collect(&h.app, "netcatty:mosh:ready");

    let bin = tempfile::tempdir().unwrap();
    // Fake ssh: prompt for the password, then print the protocol lines.
    write_script(
        bin.path(),
        "ssh",
        "printf 'alice@h password: '; read pw; \
         printf '\\r\\nbanner %s\\r\\nMOSH IP 127.0.0.1\\r\\nMOSH CONNECT 60001 ABCDEFGHIJKLMNOPQRSTUV==\\r\\n' \"$pw\"",
    );
    // Fake mosh-client: report what it was started with, echo one line.
    write_script(
        bin.path(),
        "mosh-client",
        "printf 'client %s %s key=%s noinit=%s\\r\\n' \"$1\" \"$2\" \"$MOSH_KEY\" \"$MOSH_NO_TERM_INIT\"; read line; printf 'got %s\\r\\n' \"$line\"",
    );
    let path = format!("{}:/usr/bin:/bin", bin.path().display());

    ok(invoke(
        &h.webview,
        "mosh_start",
        json!({ "payload": {
            "sessionId": "mosh-1",
            "hostname": "h.example",
            "username": "alice",
            "password": "pw123",
            "authMethod": "password",
            "verifyHostKeys": false,
            "env": { "PATH": path },
            "bootEpoch": 2
        } }),
    ));
    assert!(
        wait_for(&ready, Duration::from_secs(15), |events| {
            events
                .iter()
                .any(|e| session_id_of(e) == Some("mosh-1") && e["bootEpoch"] == 2)
        }),
        "no mosh ready; data: {:?}",
        data.lock().unwrap()
    );
    assert!(wait_for(&data, Duration::from_secs(10), |events| {
        events.iter().any(|e| {
            session_id_of(e) == Some("mosh-1")
                && e["data"]
                    .as_str()
                    .unwrap_or("")
                    .contains("client 127.0.0.1 60001 key=ABCDEFGHIJKLMNOPQRSTUV== noinit=1")
        })
    }));
    {
        let events = data.lock().unwrap();
        let mine: Vec<&Value> = events
            .iter()
            .filter(|e| session_id_of(e) == Some("mosh-1"))
            .collect();
        // Bootstrap output is tagged and the saved password was typed.
        assert!(mine.iter().any(|e| e["meta"]["moshHandshake"] == true
            && e["data"].as_str().unwrap_or("").contains("banner pw123")));
        let all: String = mine.iter().filter_map(|e| e["data"].as_str()).collect();
        assert!(!all.contains("MOSH CONNECT"), "{all:?}");
        assert!(!all.contains("MOSH IP"), "{all:?}");
    }
    ok(invoke(
        &h.webview,
        "session_write",
        json!({ "payload": { "sessionId": "mosh-1", "data": "hello\r" } }),
    ));
    assert!(
        wait_for(&exits, Duration::from_secs(10), |events| {
            events
                .iter()
                .any(|e| session_id_of(e) == Some("mosh-1") && e["reason"] == "exited")
        }),
        "exits: {:?} data: {:?}",
        exits.lock().unwrap(),
        data.lock().unwrap()
    );
    let all: String = data
        .lock()
        .unwrap()
        .iter()
        .filter(|e| session_id_of(e) == Some("mosh-1"))
        .filter_map(|e| e["data"].as_str())
        .collect();
    assert!(all.contains("got hello"), "{all:?}");
}

#[cfg(unix)]
#[test]
fn mosh_handshake_failure_reports_error() {
    let h = build_app();
    let exits = collect(&h.app, "netcatty:exit");
    let bin = tempfile::tempdir().unwrap();
    write_script(
        bin.path(),
        "ssh",
        "echo 'mosh-server: command not found'; exit 127",
    );
    write_script(bin.path(), "mosh-client", "exit 0");
    let path = format!("{}:/usr/bin:/bin", bin.path().display());
    ok(invoke(
        &h.webview,
        "mosh_start",
        json!({ "payload": { "sessionId": "mosh-2", "hostname": "h", "env": { "PATH": path } } }),
    ));
    assert!(
        wait_for(&exits, Duration::from_secs(10), |events| {
            events.iter().any(|e| {
                session_id_of(e) == Some("mosh-2")
                    && e["reason"] == "error"
                    && e["error"]
                        == "Mosh SSH startup failed: no MOSH CONNECT from mosh-server (UDP client not started)"
            })
        }),
        "{:?}",
        exits.lock().unwrap()
    );
}

#[cfg(unix)]
#[test]
fn et_session_runs_client_with_planned_args() {
    let h = build_app();
    let data = collect(&h.app, "netcatty:data");
    let exits = collect(&h.app, "netcatty:exit");
    let bin = tempfile::tempdir().unwrap();
    write_script(
        bin.path(),
        "et",
        "printf 'et-args:%s\\r\\n' \"$*\"; printf 'telemetry=%s\\r\\n' \"$ET_NO_TELEMETRY\"; sleep 0.2; exit 3",
    );
    let path = format!("{}:/usr/bin:/bin", bin.path().display());
    ok(invoke(
        &h.webview,
        "et_start",
        json!({ "payload": {
            "sessionId": "et-1",
            "hostname": "et.example",
            "username": "carol",
            "etPort": 2023,
            "env": { "PATH": path }
        } }),
    ));
    assert!(
        wait_for(&exits, Duration::from_secs(10), |events| {
            events.iter().any(|e| {
                session_id_of(e) == Some("et-1") && e["reason"] == "error" && e["exitCode"] == 3
            })
        }),
        "{:?}",
        exits.lock().unwrap()
    );
    let all: String = data
        .lock()
        .unwrap()
        .iter()
        .filter(|e| session_id_of(e) == Some("et-1"))
        .filter_map(|e| e["data"].as_str())
        .collect();
    assert!(all.contains("et-args:-p 2023 --ssh-option"), "{all:?}");
    assert!(all.contains("carol@et.example"), "{all:?}");
    assert!(all.contains("telemetry=1"), "{all:?}");

    // Missing client: Electron's error text.
    let err = invoke(
        &h.webview,
        "et_start",
        json!({ "payload": { "hostname": "h", "env": { "PATH": "/nonexistent" } } }),
    )
    .expect_err("et must be missing");
    assert!(err["message"]
        .as_str()
        .unwrap()
        .starts_with("Bundled et client not found."));
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

/// Opt-in: the system manager, stats and monitor over a real SSH session.
/// Skipped unless `NETCATTY_E2E_SSH_HOST` is set (password auth; defaults
/// match `rust/scripts/e2e-sshd`: `tester` / `testpass`). Install `tmux` on
/// the target to cover the tmux commands too.
#[test]
fn system_manager_over_ssh_e2e() {
    let Ok(host) = std::env::var("NETCATTY_E2E_SSH_HOST") else {
        eprintln!("skipped: NETCATTY_E2E_SSH_HOST not set");
        return;
    };
    let port: u16 = std::env::var("NETCATTY_E2E_SSH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(22);
    let user = std::env::var("NETCATTY_E2E_SSH_USER").unwrap_or_else(|_| "tester".into());
    let password = std::env::var("NETCATTY_E2E_SSH_PASSWORD").unwrap_or_else(|_| "testpass".into());
    let h = build_app();
    let options = json!({
        "hostname": host, "port": port, "username": user, "password": password,
        "verifyHostKeys": false, "keepaliveInterval": 10,
    });
    let mut start = options.clone();
    start["sessionId"] = json!("e2e-sys");
    ok(invoke(
        &h.webview,
        "session_start_ssh",
        json!({ "payload": start }),
    ));
    let sid = json!({ "sessionId": "e2e-sys" });
    let payload = json!({ "payload": { "sessionId": "e2e-sys" } });

    let stats = ok(invoke(&h.webview, "session_server_stats", sid.clone()));
    assert_eq!(stats["success"], true, "{stats}");
    assert!(stats["stats"]["memTotal"].as_i64().unwrap() > 0, "{stats}");
    assert!(stats["stats"]["cpuCores"].as_i64().unwrap() > 0);
    assert!(!stats["stats"]["hostname"].as_str().unwrap().is_empty());
    assert!(stats["stats"]["disks"].as_array().is_some());
    assert!(stats["stats"]["responseLatencyMs"].is_number(), "{stats}");
    // keepaliveInterval is set, so the SSH transport ping measures latency.
    assert!(stats["stats"]["latencyMs"].is_number(), "{stats}");
    // Past the 4 s terminal cache the CPU delta is available.
    std::thread::sleep(Duration::from_millis(4300));
    let stats = ok(invoke(&h.webview, "session_server_stats", sid.clone()));
    assert!(stats["stats"]["cpu"].is_number(), "{stats}");
    assert_eq!(stats["stats"]["networkReady"], true);

    let distro = ok(invoke(&h.webview, "session_distro_info", sid.clone()));
    assert_eq!(distro["success"], true, "{distro}");
    assert!(
        distro["stdout"].as_str().unwrap().contains("ID="),
        "{distro}"
    );

    let history = ok(invoke(
        &h.webview,
        "session_read_remote_history",
        json!({ "sessionId": "e2e-sys", "limit": 50 }),
    ));
    assert_eq!(history["success"], true, "{history}");

    let caps = ok(invoke(
        &h.webview,
        "system_probe_capabilities",
        payload.clone(),
    ));
    assert_eq!(caps["capabilities"]["targetOs"], "linux", "{caps}");
    let procs = ok(invoke(&h.webview, "system_list_processes", payload.clone()));
    assert!(procs["processes"].to_string().contains("sshd"), "{procs}");
    let ports = ok(invoke(
        &h.webview,
        "system_list_listening_ports",
        payload.clone(),
    ));
    assert_eq!(ports["success"], true, "{ports}");
    let osc7 = ok(invoke(
        &h.webview,
        "system_setup_osc7_tracking",
        json!({ "payload": { "sessionId": "e2e-sys", "command": "printf ok; exit 3" } }),
    ));
    assert_eq!(osc7["code"], 3, "{osc7}");
    assert_eq!(osc7["stdout"], "ok");

    if caps["capabilities"]["hasTmux"] == true {
        let created = ok(invoke(
            &h.webview,
            "system_create_tmux_session",
            json!({ "payload": { "sessionId": "e2e-sys", "name": "nc-e2e" } }),
        ));
        assert_eq!(created["success"], true, "{created}");
        let listed = ok(invoke(
            &h.webview,
            "system_list_tmux_sessions",
            payload.clone(),
        ));
        assert!(
            listed["sessions"].to_string().contains("nc-e2e"),
            "{listed}"
        );
        let windows = ok(invoke(
            &h.webview,
            "system_list_tmux_windows",
            json!({ "payload": { "sessionId": "e2e-sys", "sessionName": "nc-e2e" } }),
        ));
        assert_eq!(windows["success"], true, "{windows}");
        let killed = ok(invoke(
            &h.webview,
            "system_tmux_action",
            json!({ "payload": { "sessionId": "e2e-sys", "action": "killSession", "sessionName": "nc-e2e" } }),
        ));
        assert_eq!(killed["success"], true, "{killed}");
    }

    // The monitor reuses the live session transport for the same endpoint.
    ok(invoke(
        &h.webview,
        "monitor_update",
        json!({ "panels": [{ "id": "p", "runId": "r", "interval": 1,
                             "hosts": [{ "id": "h", "options": options }] }] }),
    ));
    let start = Instant::now();
    let mut snap = Value::Null;
    while start.elapsed() < Duration::from_secs(20) {
        snap = ok(invoke(&h.webview, "monitor_snapshot", json!({})));
        if snap["hosts"]["h"]["status"] == "live" && snap["hosts"]["h"]["stats"].is_object() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(snap["hosts"]["h"]["status"], "live", "{snap}");
    assert!(!snap["hosts"]["h"]["points"].as_array().unwrap().is_empty());
    ok(invoke(&h.webview, "monitor_stop_all", json!({})));
    ok(invoke(&h.webview, "session_close", sid));

    // Without a live session the monitor logs in on its own connection.
    ok(invoke(
        &h.webview,
        "monitor_update",
        json!({ "panels": [{ "id": "p", "runId": "r2", "interval": 2,
                             "hosts": [{ "id": "h", "options": options }] }] }),
    ));
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        snap = ok(invoke(&h.webview, "monitor_snapshot", json!({})));
        if snap["hosts"]["h"]["status"] == "live" {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(snap["hosts"]["h"]["status"], "live", "{snap}");
    assert!(snap["activeSessions"][0]
        .as_str()
        .unwrap()
        .starts_with("monitor-"));
    ok(invoke(&h.webview, "monitor_stop_all", json!({})));
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

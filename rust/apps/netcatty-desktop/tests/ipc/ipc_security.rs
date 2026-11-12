//! Headless IPC tests of the security module (`commands/security/`) through
//! `tauri::test`'s `MockRuntime`: the app lock lifecycle (enable, lock,
//! title protection, wrong / right password, persistence and startup lock
//! in the Electron file format), FIDO prompt responses, sk key type
//! validation and the SSH debug log info. Touch ID / Windows Hello, real
//! security keys and screen capture need a desktop session and are covered
//! by the manual checks in `rust/docs/ipc-security.md`.

use netcatty_desktop_lib::{configure_with, SetupOptions};
use netcatty_store::CredentialCipher;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::{App, Listener, WebviewWindow};

use crate::BUILD_LOCK;

fn build_app(data_dir: &Path) -> (App<MockRuntime>, WebviewWindow<MockRuntime>) {
    let app = {
        let _guard = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NETCATTY_PORTABLE_DATA_DIR", data_dir);
        let options = SetupOptions {
            cipher: Some(CredentialCipher::with_key([0x5a; 32])),
        };
        let mut app = configure_with(mock_builder(), options)
            .build(mock_context(noop_assets()))
            .expect("build mock app");
        #[allow(deprecated)]
        app.run_iteration(|_, _| {});
        app
    };
    let main = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .title("Netcatty — prod-db")
        .build()
        .expect("main window");
    (app, main)
}

fn invoke(webview: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) -> Result<Value, Value> {
    let request = InvokeRequest {
        cmd: cmd.to_string(),
        callback: CallbackFn(0),
        error: CallbackFn(1),
        url: if cfg!(windows) {
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
    get_ipc_response(webview, request).map(|body| body.deserialize::<Value>().expect("json response"))
}

fn ok(result: Result<Value, Value>) -> Value {
    result.unwrap_or_else(|e| panic!("command failed: {e}"))
}

#[test]
fn app_lock_lifecycle_over_ipc() {
    let data_dir = tempfile::Builder::new()
        .prefix("netcatty-ipc-security-")
        .tempdir()
        .unwrap();
    let (app, main) = build_app(data_dir.path());

    let runtime_events: Arc<Mutex<Vec<Value>>> = Arc::default();
    let settings_events: Arc<Mutex<Vec<Value>>> = Arc::default();
    {
        let sink = runtime_events.clone();
        app.listen_any("netcatty:appLock:runtimeStateChanged", move |e| {
            sink.lock().unwrap().push(serde_json::from_str(e.payload()).unwrap());
        });
        let sink = settings_events.clone();
        app.listen_any("netcatty:appLock:settingsChanged", move |e| {
            sink.lock().unwrap().push(serde_json::from_str(e.payload()).unwrap());
        });
    }

    let state = ok(invoke(&main, "app_lock_get_runtime_state", json!({})));
    assert_eq!(state["initialized"], true);
    assert_eq!(state["locked"], false);
    let settings = ok(invoke(&main, "app_lock_get_settings", json!({})));
    assert_eq!(settings, json!({
        "enabled": false,
        "timeoutMinutes": 15,
        "systemUnlockEnabled": false,
        "systemUnlockAutoPromptEnabled": false,
        "passwordVerifier": null,
    }));

    // Locking while disabled is a no-op.
    let state = ok(invoke(&main, "app_lock_set_locked", json!({ "reason": "manual" })));
    assert_eq!(state["locked"], false);

    // Set a password: enables the lock, redacted verifier in the result.
    let saved = ok(invoke(
        &main,
        "app_lock_request_password_change",
        json!({ "input": { "nextPassword": "s3cret" } }),
    ));
    assert_eq!(saved["enabled"], true);
    assert_eq!(saved["passwordVerifier"]["algorithm"], "PBKDF2-SHA256");
    assert_eq!(saved["passwordVerifier"]["iterations"], 210000);
    assert_eq!(saved["passwordVerifier"]["hash"], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    assert_eq!(settings_events.lock().unwrap().len(), 1);

    // The file on disk is the Electron format with the real verifier.
    let file = data_dir.path().join("app-lock-settings.json");
    let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(on_disk["enabled"], true);
    assert_ne!(on_disk["passwordVerifier"]["hash"], saved["passwordVerifier"]["hash"]);

    let saved = ok(invoke(&main, "app_lock_set_timeout_minutes", json!({ "timeoutMinutes": "5" })));
    assert_eq!(saved["timeoutMinutes"], 5);

    // Lock: event broadcast; title changes are deferred (MockRuntime windows
    // have no real title, so only the deferral result is checked here).
    let state = ok(invoke(&main, "app_lock_set_locked", json!({ "reason": "manual" })));
    assert_eq!(state["locked"], true);
    assert_eq!(state["reason"], "manual");
    assert_eq!(runtime_events.lock().unwrap().last().unwrap()["locked"], true);
    assert_eq!(ok(invoke(&main, "window_set_title", json!({ "title": "Netcatty — staging" }))), false);

    assert_eq!(
        ok(invoke(&main, "app_lock_request_unlock", json!({ "password": "" }))),
        json!({ "ok": false, "error": "empty" })
    );
    assert_eq!(
        ok(invoke(&main, "app_lock_request_unlock", json!({ "password": "wrong" }))),
        json!({ "ok": false, "error": "incorrect" })
    );
    assert_eq!(ok(invoke(&main, "app_lock_get_runtime_state", json!({})))["locked"], true);
    assert_eq!(
        ok(invoke(&main, "app_lock_request_unlock", json!({ "password": "s3cret" }))),
        json!({ "ok": true })
    );
    assert_eq!(runtime_events.lock().unwrap().last().unwrap()["locked"], false);
    ok(invoke(&main, "app_lock_report_activity", json!({})));

    let status = ok(invoke(&main, "app_lock_get_system_unlock_status", json!({})));
    assert!(status["platform"].is_string());
    assert!(status.get("enabled").is_some());

    // Disabling needs the password.
    assert_eq!(
        ok(invoke(&main, "app_lock_request_disable", json!({ "currentPassword": "nope" }))),
        json!({ "ok": false, "error": "incorrect" })
    );
    drop(main);
    drop(app);

    // A new process with the same data directory starts locked.
    let (app, main) = build_app(data_dir.path());
    let state = ok(invoke(&main, "app_lock_get_runtime_state", json!({})));
    assert_eq!(state["locked"], true);
    assert_eq!(state["reason"], "startup");
    let disabled = ok(invoke(&main, "app_lock_request_disable", json!({ "currentPassword": "s3cret" })));
    assert_eq!(disabled["enabled"], false);
    assert_eq!(disabled["passwordVerifier"], Value::Null);
    assert_eq!(ok(invoke(&main, "app_lock_get_runtime_state", json!({})))["locked"], false);
    drop(app);
}

#[test]
fn fido_and_debug_log_commands() {
    let data_dir = tempfile::Builder::new()
        .prefix("netcatty-ipc-security-fido-")
        .tempdir()
        .unwrap();
    let (_app, main) = build_app(data_dir.path());

    assert_eq!(
        ok(invoke(
            &main,
            "fido_prompt_respond",
            json!({ "requestId": "pin-missing", "response": "1234", "cancelled": false })
        )),
        json!({ "success": false, "error": "Request not found" })
    );
    let err = invoke(&main, "fido_generate_key_pair", json!({ "payload": { "type": "RSA" } })).unwrap_err();
    assert_eq!(err["code"], "INVALID_ARGUMENT");

    let info = ok(invoke(&main, "ssh_debug_log_info", json!({})));
    assert!(info["path"].as_str().unwrap().ends_with("netcatty-ssh.log"));
    assert!(info["exists"].is_boolean());
    assert!(info["size"].is_number());
    assert!(info["enabled"].is_boolean());
}

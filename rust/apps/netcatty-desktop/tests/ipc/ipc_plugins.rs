//! Headless IPC tests of the plugin host commands (`commands/plugins.rs`,
//! `rust/docs/ipc-plugins.md`). Harness: see `ipc_smoke.rs`.

use netcatty_desktop_lib::{configure_with, SetupOptions};
use netcatty_store::CredentialCipher;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{
    get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY,
};
use tauri::webview::InvokeRequest;
use tauri::{App, WebviewWindow};

use crate::BUILD_LOCK;
const TEST_KEY: [u8; 32] = [0x5a; 32];

struct Harness {
    app: App<MockRuntime>,
    webview: WebviewWindow<MockRuntime>,
    _data_dir: tempfile::TempDir,
}

fn build_app() -> Harness {
    let data_dir = tempfile::Builder::new()
        .prefix("netcatty-ipc-plugins-")
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

fn ok(result: Result<Value, Value>) -> Value {
    match result {
        Ok(v) => v,
        Err(e) => panic!("command failed: {e}"),
    }
}

fn call(h: &Harness, method: &str, payload: Value) -> Result<Value, Value> {
    invoke(&h.webview, "plugin_call", json!({ "method": method, "payload": payload }))
}

/// Wait for the background host initialization.
fn wait_ready(h: &Harness) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        if ok(call(h, "status", Value::Null))["available"] == json!(true) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("plugin host did not initialize");
}

#[test]
fn plugin_management_round_trip() {
    let h = build_app();
    let _ = &h.app;
    wait_ready(&h);
    assert_eq!(ok(call(&h, "list", Value::Null)), json!([]));
    assert_eq!(ok(call(&h, "host-available-sync", Value::Null)), json!(true));
    assert_eq!(ok(call(&h, "terminal-providers", json!({ "kind": "terminal.completion" }))), json!([]));
    // Scope catalog: the device scope is always present.
    assert_eq!(ok(call(&h, "get-scope-catalog", Value::Null))["device"][0]["id"], json!("device"));
    ok(call(&h, "set-scope-catalog", json!({ "host": [{ "id": "h1", "label": "Host one" }] })));
    assert_eq!(ok(call(&h, "get-scope-catalog", Value::Null))["host"][0]["id"], json!("h1"));
    // Logs.
    let status = ok(call(&h, "log-configure", json!({ "saveToDisk": true, "verbose": false })));
    assert_eq!(status["saveToDisk"], json!(true));
    // Install the hello example (built locally) when available.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let example = root.join("examples/plugins/hello-netcatty");
    if !example.join("dist/index.js").exists() {
        eprintln!("skipping install: run `npm run build:plugin-packages` first");
        return;
    }
    let out = tempfile::tempdir().unwrap();
    let archive = out.path().join("hello.ncpkg");
    netcatty_plugins::package::archive::build_package(&example, &archive).unwrap();
    let plugin = ok(call(&h, "install", json!({ "archivePath": archive.to_string_lossy(), "enable": true })));
    assert_eq!(plugin["id"], json!("com.netcatty.hello"));
    assert_eq!(plugin["enabled"], json!(true));
    let snapshot = ok(call(&h, "contributions", json!({ "locale": "en" })));
    assert_eq!(snapshot["plugins"][0]["commands"][0]["id"], json!("com.netcatty.hello.sayHello"));
    let updated = ok(call(&h, "update-setting", json!({ "pluginId": "com.netcatty.hello", "settingId": "com.netcatty.hello.greeting", "value": "Hey" })));
    assert_eq!(updated["restartRequired"], json!(false));
    let permissions = ok(call(&h, "permissions", json!({ "pluginId": "com.netcatty.hello" })));
    let revision = permissions["policyRevision"].as_str().unwrap().to_string();
    assert!(permissions["policies"].as_array().unwrap().iter().any(|p| p["permission"] == "commands"));
    assert!(call(&h, "set-permission-mode", json!({ "pluginId": "com.netcatty.hello", "permission": "commands", "mode": "ask", "policyRevision": "stale" })).is_err());
    assert_eq!(ok(call(&h, "set-permission-mode", json!({ "pluginId": "com.netcatty.hello", "permission": "commands", "mode": "ask", "policyRevision": revision }))), json!(true));
    assert_eq!(ok(call(&h, "theme-catalog", Value::Null))["entries"], json!([]));
    assert_eq!(ok(call(&h, "brand-icon", json!({ "pluginId": "com.netcatty.hello" }))), Value::Null);
    assert_eq!(ok(call(&h, "terminal-providers", json!({ "kind": "terminal.completion" })))[0]["provider"]["id"], json!("com.netcatty.hello.completion"));
    let disabled = ok(call(&h, "set-enabled", json!({ "pluginId": "com.netcatty.hello", "enabled": false })));
    assert_eq!(disabled["enabled"], json!(false));
    assert_eq!(ok(call(&h, "uninstall", json!({ "pluginId": "com.netcatty.hello" }))), json!(true));
    assert_eq!(ok(call(&h, "list", Value::Null)), json!([]));
    assert!(call(&h, "no-such-method", Value::Null).is_err());
}

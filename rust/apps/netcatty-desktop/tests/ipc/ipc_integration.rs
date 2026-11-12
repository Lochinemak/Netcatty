//! Headless IPC tests of the OS shell integration commands
//! (`commands/integration.rs`, `rust/docs/ipc-integration.md`) through
//! `tauri::test`'s `MockRuntime`: launch-intent queueing and the renderer
//! attach handshake, second-instance routing, deep-link switches and their
//! persisted preferences, Explorer and app icon commands.

use netcatty_desktop_lib::commands::integration::on_second_instance;
use netcatty_desktop_lib::{configure_with, SetupOptions};
use netcatty_store::CredentialCipher;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::{App, Listener, Manager, WebviewWindow};

use crate::BUILD_LOCK;

struct Harness {
    app: App<MockRuntime>,
    main: WebviewWindow<MockRuntime>,
    data_dir: tempfile::TempDir,
}

fn build_app() -> Harness {
    let data_dir = tempfile::Builder::new()
        .prefix("netcatty-ipc-integration-")
        .tempdir()
        .expect("temp data dir");
    let app = {
        // The setup hook resolves the data dir from the process-global env
        // var, so building and setup both run under the lock.
        let _guard = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NETCATTY_PORTABLE_DATA_DIR", data_dir.path());
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
        .build()
        .expect("build mock webview");
    Harness { app, main, data_dir }
}

fn invoke(webview: &WebviewWindow<MockRuntime>, cmd: &str, args: Value) -> Value {
    let request = InvokeRequest {
        cmd: cmd.to_string(),
        callback: CallbackFn(0),
        error: CallbackFn(1),
        url: if cfg!(windows) { "http://tauri.localhost" } else { "tauri://localhost" }
            .parse()
            .unwrap(),
        body: InvokeBody::Json(args),
        headers: Default::default(),
        invoke_key: INVOKE_KEY.to_string(),
    };
    match get_ipc_response(webview, request) {
        Ok(body) => body.deserialize::<Value>().expect("json response"),
        Err(err) => panic!("{cmd} failed: {err}"),
    }
}

fn collect(app: &App<MockRuntime>, event: &str) -> Arc<Mutex<Vec<Value>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    app.listen_any(event.to_string(), move |e| {
        sink.lock()
            .unwrap()
            .push(serde_json::from_str(e.payload()).unwrap_or(Value::Null));
    });
    seen
}

fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn launch_intents_wait_for_the_main_renderer_then_go_live() {
    let h = build_app();
    let handle = h.app.handle().clone();
    let live = collect(&h.app, "netcatty:deepLink:ssh");

    // A PuTTY-style second launch before the renderer attached is queued,
    // even with ssh:// handling switched off (command-line launches bypass it).
    assert_eq!(
        invoke(&h.main, "integration_set_ssh_deep_link_enabled", json!({ "enabled": false })),
        json!({ "enabled": false, "success": true })
    );
    on_second_instance(
        &handle,
        argv(&["Netcatty", "-ssh", "alice@10.0.0.8", "-P", "2222", "-pw", "s3cret", "-newtab", "Prod"]),
        "/tmp".into(),
    );
    // Scheme links are dropped while disabled.
    on_second_instance(&handle, argv(&["Netcatty", "ssh://bob@example.com"]), "/tmp".into());
    assert!(live.lock().unwrap().is_empty());

    // Another window attaching gets nothing and does not drain the queue.
    let settings = tauri::WebviewWindowBuilder::new(&h.app, "settings", Default::default())
        .build()
        .unwrap();
    assert_eq!(
        invoke(&settings, "integration_renderer_attach", json!({})),
        json!({ "intents": [], "coldStartSettled": true })
    );

    let attached = invoke(&h.main, "integration_renderer_attach", json!({}));
    assert_eq!(
        attached,
        json!({
            "intents": [{
                "channel": "netcatty:deepLink:ssh",
                "payload": { "url": "ssh://alice:s3cret@10.0.0.8:2222", "tabName": "Prod" }
            }],
            "coldStartSettled": true
        })
    );
    // Drained: a renderer reload attaches to an empty queue.
    assert_eq!(
        invoke(&h.main, "integration_renderer_attach", json!({})),
        json!({ "intents": [], "coldStartSettled": true })
    );

    // Attached: later launches are emitted live on the Electron channels.
    assert_eq!(
        invoke(&h.main, "integration_set_ssh_deep_link_enabled", json!({ "enabled": true })),
        json!({ "enabled": true, "success": true })
    );
    on_second_instance(&handle, argv(&["Netcatty", "ssh://bob@example.com"]), "/tmp".into());
    assert_eq!(*live.lock().unwrap(), vec![json!({ "url": "ssh://bob@example.com" })]);

    let opened = collect(&h.app, "netcatty:openTerminalPath");
    let dir = h.data_dir.path().to_string_lossy().into_owned();
    on_second_instance(
        &handle,
        argv(&["Netcatty", "--", "--open-terminal-shell=zsh", "--open-terminal-path", &dir]),
        "/".into(),
    );
    let opened = opened.lock().unwrap().clone();
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0]["shell"], json!("zsh"));
    assert!(opened[0]["path"].as_str().is_some_and(|p| !p.is_empty()));
}

#[test]
fn jms_switch_defaults_off_and_gates_links() {
    let h = build_app();
    let handle = h.app.handle().clone();
    assert_eq!(invoke(&h.main, "integration_get_jms_deep_link_enabled", json!({})), json!(false));
    invoke(&h.main, "integration_renderer_attach", json!({}));
    let jms = collect(&h.app, "netcatty:deepLink:jms");
    on_second_instance(&handle, argv(&["Netcatty", "jms://payload"]), String::new());
    assert!(jms.lock().unwrap().is_empty());

    assert_eq!(
        invoke(&h.main, "integration_set_jms_deep_link_enabled", json!({ "enabled": true })),
        json!({ "enabled": true, "success": true })
    );
    on_second_instance(&handle, argv(&["Netcatty", "jms://payload"]), String::new());
    assert_eq!(*jms.lock().unwrap(), vec![json!({ "url": "jms://payload" })]);

    // Persisted next to the other app data, like Electron's userData files.
    let saved = std::fs::read_to_string(h.data_dir.path().join("jms-deep-link-preferences.json")).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&saved).unwrap(), json!({ "enabled": true }));
}

#[test]
fn ssh_preference_persists_and_defaults_on() {
    let h = build_app();
    assert_eq!(invoke(&h.main, "integration_get_ssh_deep_link_enabled", json!({})), json!(true));
    invoke(&h.main, "integration_set_ssh_deep_link_enabled", json!({ "enabled": false }));
    assert_eq!(invoke(&h.main, "integration_get_ssh_deep_link_enabled", json!({})), json!(false));
    let saved = std::fs::read_to_string(h.data_dir.path().join("ssh-deep-link-preferences.json")).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&saved).unwrap(), json!({ "enabled": false }));
    // Same value again: no change, success.
    assert_eq!(
        invoke(&h.main, "integration_set_ssh_deep_link_enabled", json!({ "enabled": false })),
        json!({ "enabled": false, "success": true })
    );
}

#[test]
fn explorer_and_icon_commands() {
    let h = build_app();
    let status = invoke(&h.main, "integration_get_explorer_context_menu_enabled", json!({}));
    assert_eq!(status["supported"], json!(cfg!(windows)));
    if !cfg!(windows) {
        assert_eq!(status, json!({ "enabled": false, "supported": false }));
        assert_eq!(
            invoke(&h.main, "integration_set_explorer_context_menu_enabled", json!({ "enabled": true })),
            json!({ "success": true, "enabled": false, "supported": false })
        );
        assert!(!h.data_dir.path().join("explorer-context-menu-preferences.json").exists());
    }
    // Debug builds read the variant artwork from `public/`.
    assert_eq!(invoke(&h.main, "integration_set_app_icon_variant", json!({ "variant": "bright" })), json!(true));
    assert_eq!(invoke(&h.main, "integration_set_app_icon_variant", json!({ "variant": "bogus" })), json!(true));
    assert!(h.app.try_state::<netcatty_desktop_lib::commands::integration::IntegrationState>().is_some());
}

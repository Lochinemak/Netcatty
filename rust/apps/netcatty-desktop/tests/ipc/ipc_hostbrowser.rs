//! Headless IPC tests of the host browser commands (`commands/hostbrowser.rs`)
//! through `tauri::test`'s `MockRuntime`: bookmark sync commands, panel
//! requests, the embedded browser lifecycle on a local (direct) route, tab
//! commands, ownership checks and download history commands. Page windows
//! are mock windows here; real webview behaviour is covered by the manual
//! checks listed in `rust/docs/ipc-hostbrowser.md`.

use netcatty_desktop_lib::{configure_with, SetupOptions};
use netcatty_store::CredentialCipher;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::{App, Listener, Manager, WebviewWindow};

use crate::BUILD_LOCK;

struct Harness {
    app: App<MockRuntime>,
    main: WebviewWindow<MockRuntime>,
    other: WebviewWindow<MockRuntime>,
    _data_dir: tempfile::TempDir,
}

fn build_app() -> Harness {
    let data_dir = tempfile::Builder::new()
        .prefix("netcatty-ipc-hostbrowser-")
        .tempdir()
        .expect("temp data dir");
    let app = {
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
        .expect("main window");
    let other = tauri::WebviewWindowBuilder::new(&app, "other", Default::default())
        .build()
        .expect("second window");
    Harness {
        app,
        main,
        other,
        _data_dir: data_dir,
    }
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
    match result {
        Ok(v) => v,
        Err(e) => panic!("command failed: {e}"),
    }
}

fn err_message(result: Result<Value, Value>) -> String {
    match result {
        Ok(v) => panic!("expected an error, got {v}"),
        Err(e) => e.get("message").and_then(Value::as_str).unwrap_or_default().to_string(),
    }
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

fn wait_for(seen: &Arc<Mutex<Vec<Value>>>, pred: impl Fn(&[Value]) -> bool) -> bool {
    let start = Instant::now();
    loop {
        if pred(&seen.lock().unwrap()) {
            return true;
        }
        if start.elapsed() > Duration::from_secs(5) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

const BROWSER: &str = "tab-1:session-1";

#[test]
fn bookmark_sync_commands_round_trip_and_broadcast() {
    let h = build_app();
    let changed = collect(&h.app, "netcatty:host-browser:bookmarks-changed");
    assert_eq!(ok(invoke(&h.main, "hostbrowser_bookmarks_get_all", json!({}))), json!([]));
    let items = json!([
        { "id": "a", "title": "Router", "url": "https://10.0.0.1/", "scope": "host", "hostId": "h1", "order": 0 },
        { "id": "b", "title": "Docs", "url": "https://example.com", "scope": "all-hosts", "hostId": null, "order": 1 }
    ]);
    assert_eq!(ok(invoke(&h.main, "hostbrowser_bookmarks_apply", json!({ "items": items }))), json!(true));
    let all = ok(invoke(&h.main, "hostbrowser_bookmarks_get_all", json!({})));
    assert_eq!(all.as_array().unwrap().len(), 2);
    assert_eq!(all[1]["url"], "https://example.com/");
    assert!(wait_for(&changed, |seen| !seen.is_empty()));
    let message = err_message(invoke(
        &h.main,
        "hostbrowser_bookmarks_apply",
        json!({ "items": [items[0], items[0]] }),
    ));
    assert_eq!(message, "Duplicate bookmark ID");
}

#[test]
fn panel_requests_go_to_the_main_window() {
    let h = build_app();
    let requests = collect(&h.app, "netcatty:host-browser:request-panel");
    let request = json!({ "host": { "id": "h1", "label": "web" }, "sessionId": "s1", "url": "https://example.com/" });
    assert_eq!(
        ok(invoke(&h.other, "hostbrowser_request_panel", json!({ "payload": request }))),
        json!(true)
    );
    assert!(wait_for(&requests, |seen| seen.iter().any(|p| p["targetLabel"] == "main"
        && p["request"]["host"]["id"] == "h1")));
    let message = err_message(invoke(&h.main, "hostbrowser_request_panel", json!({ "payload": { "host": {} } })));
    assert_eq!(message, "Browser opener is unavailable");
}

fn open_local(h: &Harness) -> Value {
    invoke(
        &h.main,
        "hostbrowser_open",
        json!({ "payload": {
            "browserId": BROWSER, "embedded": true, "local": true, "hostId": "local-host",
            "label": "Local", "theme": "light", "themeTokens": { "background": "0 0% 100%", "primary": "nope" }
        } }),
    )
    .expect("open")
}

#[test]
fn embedded_browser_lifecycle_on_a_local_route() {
    let h = build_app();
    let events = collect(&h.app, "netcatty:host-browser:panel-event");

    // Opening before the panel registered a layout does nothing (Electron parity).
    assert_eq!(open_local(&h), json!({ "reused": false }));
    assert!(invoke(&h.main, "hostbrowser_snapshot", json!({ "browserId": BROWSER })).is_err());

    // A URL queued before the browser exists opens once it is connected.
    assert_eq!(
        ok(invoke(&h.main, "hostbrowser_panel_url", json!({ "payload": { "browserId": BROWSER, "url": "localhost:3000" } }))),
        json!(true)
    );
    assert_eq!(
        ok(invoke(&h.main, "hostbrowser_panel_layout", json!({ "payload": {
            "browserId": BROWSER, "visible": true, "bounds": { "x": 10, "y": 20, "width": 400, "height": 300 }
        } }))),
        json!(true)
    );
    assert_eq!(open_local(&h), json!({ "reused": false }));
    let state = ok(invoke(&h.main, "hostbrowser_snapshot", json!({ "browserId": BROWSER })));
    assert_eq!(state["route"], "connected");
    assert_eq!(state["hostId"], "local-host");
    assert_eq!(state["theme"], "light");
    assert_eq!(state["themeTokens"], json!({ "background": "0 0% 100%" }));
    assert_eq!(state["embedded"], true);
    let tabs = state["tabs"].as_array().unwrap();
    assert_eq!(tabs.len(), 1);
    assert_eq!(tabs[0]["url"], "http://localhost:3000/");
    assert_eq!(state["activeTabId"], tabs[0]["id"]);
    assert!(wait_for(&events, |seen| seen.iter().any(|e| e["type"] == "state"
        && e["browserId"] == BROWSER && e["ownerLabel"] == "main")));

    // Reopening reuses the browser.
    assert_eq!(open_local(&h), json!({ "reused": true }));

    // Tab commands.
    let state = ok(invoke(&h.main, "hostbrowser_command", json!({ "browserId": BROWSER, "command": { "type": "new-tab", "url": "example.com" } })));
    assert_eq!(state["tabs"].as_array().unwrap().len(), 2);
    let second = state["tabs"][1]["id"].clone();
    assert_eq!(state["activeTabId"], second);
    assert_eq!(state["tabs"][1]["url"], "https://example.com/");
    let first = state["tabs"][0]["id"].clone();
    let state = ok(invoke(&h.main, "hostbrowser_command", json!({ "browserId": BROWSER, "command": { "type": "reorder", "tabId": second, "beforeTabId": first } })));
    assert_eq!(state["tabs"][0]["id"], second);
    let state = ok(invoke(&h.main, "hostbrowser_command", json!({ "browserId": BROWSER, "command": { "type": "activate", "tabId": first } })));
    assert_eq!(state["activeTabId"], first);
    let state = ok(invoke(&h.main, "hostbrowser_command", json!({ "browserId": BROWSER, "command": { "type": "navigate", "url": "https://example.org/x" } })));
    let active = state["tabs"].as_array().unwrap().iter().find(|t| t["id"] == first).unwrap().clone();
    assert_eq!(active["url"], "https://example.org/x");
    // Navigating creates the tab's page window (a mock window here; the mock
    // owner has no size, so pages are never shown by the layout pass).
    assert!(h.app.webview_windows().keys().any(|label| label.starts_with("hb-tab-")));
    assert_eq!(
        err_message(invoke(&h.main, "hostbrowser_command", json!({ "browserId": BROWSER, "command": { "type": "navigate", "url": "file:///etc/passwd" } }))),
        "Only HTTP and HTTPS pages can open here"
    );
    assert_eq!(
        err_message(invoke(&h.main, "hostbrowser_command", json!({ "browserId": BROWSER, "command": { "type": "bogus" } }))),
        "Unknown browser command"
    );
    let state = ok(invoke(&h.main, "hostbrowser_command", json!({ "browserId": BROWSER, "command": { "type": "close-tab", "tabId": first } })));
    assert_eq!(state["tabs"].as_array().unwrap().len(), 1);
    assert_eq!(state["activeTabId"], second);
    let state = ok(invoke(&h.main, "hostbrowser_command", json!({ "browserId": BROWSER, "command": { "type": "close-tab" } })));
    assert_eq!(state["tabs"].as_array().unwrap().len(), 1, "closing the last tab opens a new one");
    assert_eq!(state["tabs"][0]["url"], "");
    // Custom tab icons need a page.
    assert_eq!(
        err_message(invoke(&h.main, "hostbrowser_command", json!({ "browserId": BROWSER, "command": { "type": "set-icon", "glyph": "A", "color": "#123456" } }))),
        "Open a page before changing its icon"
    );

    // Occluded layouts hide the page and return an (empty) picture list.
    assert_eq!(
        ok(invoke(&h.main, "hostbrowser_panel_layout", json!({ "payload": {
            "browserId": BROWSER, "visible": true, "occluded": true, "bounds": { "x": 0, "y": 0, "width": 10, "height": 10 }
        } }))),
        json!({ "layers": [] })
    );
    assert_eq!(
        err_message(invoke(&h.main, "hostbrowser_panel_layout", json!({ "payload": { "browserId": BROWSER, "visible": true } }))),
        "Invalid browser panel bounds"
    );

    // Another window may not control this browser.
    assert_eq!(
        err_message(invoke(&h.other, "hostbrowser_snapshot", json!({ "browserId": BROWSER }))),
        "Untrusted browser control"
    );
    assert_eq!(
        err_message(invoke(&h.other, "hostbrowser_panel_close", json!({ "browserId": BROWSER }))),
        "Browser belongs to another terminal window"
    );

    // Bookmarks scoped to this host.
    let saved = ok(invoke(&h.main, "hostbrowser_bookmarks_upsert", json!({ "browserId": BROWSER, "bookmark": { "title": "App", "url": "http://localhost:3000/", "scope": "host" } })));
    assert_eq!(saved["hostId"], "local-host");
    let listed = ok(invoke(&h.main, "hostbrowser_bookmarks_list", json!({ "browserId": BROWSER })));
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert!(listed[0].get("siteIconDataUrl").is_some());
    assert_eq!(
        ok(invoke(&h.main, "hostbrowser_bookmarks_remove", json!({ "browserId": BROWSER, "id": saved["id"] }))),
        json!(true)
    );

    // Downloads history commands.
    assert_eq!(ok(invoke(&h.main, "hostbrowser_downloads_list", json!({ "browserId": BROWSER }))), json!([]));
    assert_eq!(
        err_message(invoke(&h.main, "hostbrowser_downloads_command", json!({ "browserId": BROWSER, "command": { "type": "cancel", "id": "x" } }))),
        "Download is no longer active"
    );
    assert_eq!(
        err_message(invoke(&h.main, "hostbrowser_downloads_command", json!({ "browserId": BROWSER, "command": { "type": "open", "id": "x" } }))),
        "File moved or deleted"
    );
    assert_eq!(
        ok(invoke(&h.main, "hostbrowser_downloads_command", json!({ "browserId": BROWSER, "command": { "type": "remove", "id": "x" } }))),
        json!(false)
    );
    assert_eq!(
        ok(invoke(&h.main, "hostbrowser_downloads_command", json!({ "browserId": BROWSER, "command": { "type": "clear" } }))),
        json!(true)
    );

    // Closing the panel destroys the browser (MockRuntime only queues the
    // page windows' destruction: it has no event loop to process it).
    assert_eq!(ok(invoke(&h.main, "hostbrowser_panel_close", json!({ "browserId": BROWSER }))), json!(true));
    assert!(invoke(&h.main, "hostbrowser_snapshot", json!({ "browserId": BROWSER })).is_err());
    assert_eq!(
        err_message(invoke(&h.main, "hostbrowser_command", json!({ "browserId": BROWSER, "command": { "type": "new-tab" } }))),
        "Untrusted browser control"
    );
}

#[test]
fn invalid_open_requests_are_rejected() {
    let h = build_app();
    // SSH hosts need dynamic-forward connection options for the same host.
    let message = err_message(invoke(
        &h.main,
        "hostbrowser_open",
        json!({ "payload": { "browserId": BROWSER, "embedded": true, "hostId": "h1", "label": "web",
            "connectionOptions": { "hostId": "other", "type": "dynamic" } } }),
    ));
    assert_eq!(message, "Invalid host browser request");
    let message = err_message(invoke(
        &h.main,
        "hostbrowser_open",
        json!({ "payload": { "embedded": true, "local": true, "hostId": "h1", "label": "web" } }),
    ));
    assert_eq!(message, "Invalid browser identity");
    assert_eq!(
        err_message(invoke(&h.main, "hostbrowser_panel_url", json!({ "payload": { "browserId": BROWSER, "url": "javascript:alert(1)" } }))),
        "Only HTTP and HTTPS pages can open here"
    );
    assert!(h.app.try_state::<netcatty_desktop_lib::commands::hostbrowser::HostBrowserState>().is_some());
}

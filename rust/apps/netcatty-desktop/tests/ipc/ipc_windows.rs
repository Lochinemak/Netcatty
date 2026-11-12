//! Headless IPC tests of the multi-window commands (`commands/windows`)
//! through `tauri::test`'s `MockRuntime`: the editor window round trips, the
//! attach-popup hand-over (grants, output routes, snapshots, restore on
//! close), session windows and window-owned session lifetime. Mock windows
//! never render, so renderer replies are sent with `windows_report` from the
//! window the backend addressed. `MockRuntime` does not run the window event
//! loop, so `Destroyed` is delivered by calling the window hook directly.

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
use tauri::{App, AppHandle, Listener, Manager, WebviewWindow};

use crate::BUILD_LOCK;

struct Harness {
    app: App<MockRuntime>,
    main: WebviewWindow<MockRuntime>,
    _data_dir: tempfile::TempDir,
}

fn build_app() -> Harness {
    let data_dir = tempfile::Builder::new()
        .prefix("netcatty-ipc-windows-")
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
    Harness {
        app,
        main,
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

fn collect(app: &App<MockRuntime>, event: &str) -> Arc<Mutex<Vec<Value>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    app.listen_any(event.to_string(), move |e| {
        let payload: Value = serde_json::from_str(e.payload()).unwrap_or(Value::Null);
        sink.lock().unwrap().push(payload);
    });
    seen
}

fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    pred()
}

fn window_with_prefix(
    app: &AppHandle<MockRuntime>,
    prefix: &str,
) -> Option<WebviewWindow<MockRuntime>> {
    app.webview_windows()
        .into_iter()
        .find(|(label, _)| label.starts_with(prefix))
        .map(|(_, w)| w)
}

/// Answer every `event` with `windows_report(channel, reply(payload))` from
/// the window labelled `label` (a stand-in for that window's renderer).
fn auto_reply(
    app: &App<MockRuntime>,
    event: &str,
    label: &'static str,
    channel: &'static str,
    reply: impl Fn(&Value) -> Value + Send + Sync + 'static,
) {
    let handle = app.handle().clone();
    let reply = Arc::new(reply);
    app.listen_any(event.to_string(), move |e| {
        let payload: Value = serde_json::from_str(e.payload()).unwrap_or(Value::Null);
        let handle = handle.clone();
        let reply = reply.clone();
        std::thread::spawn(move || {
            let mut body = reply(&payload);
            body["requestId"] = payload["requestId"].clone();
            let window = handle.get_webview_window(label).expect("reply window");
            let _ = invoke(
                &window,
                "windows_report",
                json!({ "channel": channel, "payload": body }),
            );
        });
    });
}

fn destroyed(window: &WebviewWindow<MockRuntime>) {
    netcatty_desktop_lib::commands::window::on_window_event(
        &window.as_ref().window(),
        &tauri::WindowEvent::Destroyed,
    );
}

fn snapshot(editor_id: &str) -> Value {
    json!({
        "editorId": editor_id, "sessionId": "sftp-s", "sftpTabId": "tab-1", "hostId": "h1",
        "remotePath": "/etc/hosts", "fileName": "hosts", "content": "a", "baselineContent": "a",
        "languageId": "plaintext", "wordWrap": false, "viewState": null,
    })
}

#[test]
fn editor_window_open_save_dirty_and_close_round_trip() {
    let h = build_app();
    let handle = h.app.handle().clone();

    let invalid = ok(invoke(
        &h.main,
        "windows_open_editor",
        json!({ "payload": { "editorId": "x" } }),
    ));
    assert_eq!(
        invalid,
        json!({ "success": false, "error": "Invalid editor payload" })
    );
    let focus = ok(invoke(
        &h.main,
        "windows_focus_editor",
        json!({ "editorId": "e1" }),
    ));
    assert_eq!(focus["error"], "Editor window is not open");

    // The editor page reports ready, then accepts the tab.
    auto_reply(
        &h.app,
        "netcatty:window:editorOpenTab",
        "editor",
        "netcatty:window:editorOpenTabResult",
        |_| json!({ "ok": true }),
    );
    {
        let handle = handle.clone();
        std::thread::spawn(move || {
            assert!(wait_until(Duration::from_secs(5), || handle
                .get_webview_window("editor")
                .is_some()));
            let editor = handle.get_webview_window("editor").unwrap();
            ok(invoke(&editor, "windows_editor_ready", json!({})));
        });
    }
    let opened = ok(invoke(
        &h.main,
        "windows_open_editor",
        json!({ "payload": snapshot("e1") }),
    ));
    assert_eq!(opened, json!({ "success": true, "reused": false }));
    let editor = h.app.get_webview_window("editor").expect("editor window");
    let reused = ok(invoke(
        &h.main,
        "windows_open_editor",
        json!({ "payload": snapshot("e2") }),
    ));
    assert_eq!(reused, json!({ "success": true, "reused": true }));

    // Dirty state reaches the source window.
    let dirty = collect(&h.app, "netcatty:window:editorDirtyChanged");
    ok(invoke(
        &editor,
        "windows_report_editor_dirty",
        json!({ "payload": { "editorId": "e1", "dirty": true } }),
    ));
    assert_eq!(
        dirty.lock().unwrap().as_slice(),
        [json!({ "editorId": "e1", "dirty": true })]
    );

    // Saves run in the source window; a live connection id remaps the editor.
    auto_reply(
        &h.app,
        "netcatty:window:editorSaveRequest",
        "main",
        "netcatty:window:editorSaveResult",
        |req| {
            assert_eq!(req["content"], "new text");
            json!({ "ok": true, "liveConnectionId": "live-2" })
        },
    );
    let remaps = collect(&h.app, "netcatty:window:editorRemapSession");
    let saved = ok(invoke(
        &editor,
        "windows_save_editor_tab",
        json!({ "payload": {
            "editorId": "e1", "sessionId": "sftp-s", "sftpTabId": "tab-1", "hostId": "h1",
            "remotePath": "/etc/hosts", "content": "new text",
        } }),
    ));
    assert_eq!(saved, json!({ "ok": true, "liveConnectionId": "live-2" }));
    assert_eq!(
        remaps.lock().unwrap()[0],
        json!({ "fromSessionId": "sftp-s", "toSessionId": "live-2" })
    );
    let unknown = ok(invoke(
        &editor,
        "windows_save_editor_tab",
        json!({ "payload": {
            "editorId": "nope", "sessionId": "s", "sftpTabId": "t", "hostId": "h",
            "remotePath": "/x", "content": "",
        } }),
    ));
    assert_eq!(unknown["ok"], false);

    // Closing a tab runs the editor's flow and tells the source.
    auto_reply(
        &h.app,
        "netcatty:window:editorCloseTabs",
        "editor",
        "netcatty:window:editorCloseTabsResult",
        |req| json!({ "cancelled": false, "closedIds": req["editorIds"].clone() }),
    );
    let closed_events = collect(&h.app, "netcatty:window:editorTabsClosed");
    let closed = ok(invoke(
        &h.main,
        "windows_close_editor_tabs",
        json!({ "payload": { "editorIds": ["e1"] } }),
    ));
    assert_eq!(
        closed,
        json!({ "success": true, "cancelled": false, "closedIds": ["e1"] })
    );
    assert_eq!(
        closed_events.lock().unwrap().as_slice(),
        [json!({ "editorIds": ["e1"] })]
    );

    // The editor window goes away: the remaining tab is released to its source.
    destroyed(&editor);
    let events = closed_events.lock().unwrap().clone();
    assert_eq!(events.last().unwrap(), &json!({ "editorIds": ["e2"] }));
}

#[cfg(unix)]
#[test]
fn attach_popup_hand_over_and_restore() {
    let h = build_app();
    let routes = collect(&h.app, "netcatty:window:session-output-route");
    let started = ok(invoke(
        &h.main,
        "session_start_local",
        json!({ "payload": { "shell": "/bin/sh", "cols": 80, "rows": 24 } }),
    ));
    let sid = started["sessionId"].as_str().unwrap().to_owned();
    ok(invoke(
        &h.main,
        "windows_track_session",
        json!({ "sessionId": sid }),
    ));
    assert_eq!(routes.lock().unwrap().last().unwrap()["label"], "main");

    // A routed session's output is addressed to its display window only.
    let broadcast = collect(&h.app, "netcatty:data");
    let to_main = collect(&h.app, "netcatty:data/main");
    let echo = |marker: &str| {
        ok(invoke(
            &h.main,
            "session_write",
            json!({ "payload": { "sessionId": sid, "data": format!("echo {marker}-$((1+1))\n") } }),
        ));
    };
    let saw = |seen: &Arc<Mutex<Vec<Value>>>, needle: &str| {
        seen.lock().unwrap().iter().any(|e| e["data"].as_str().is_some_and(|d| d.contains(needle)))
    };
    echo("routed-main");
    assert!(wait_until(Duration::from_secs(10), || saw(&to_main, "routed-main-2")), "output reaches netcatty:data/main");
    assert!(!saw(&broadcast, "routed-main"), "routed output is not broadcast");

    let opened = ok(invoke(
        &h.main,
        "windows_open_terminal_popup",
        json!({ "payload": { "title": "Observe", "attachSessionId": sid } }),
    ));
    assert_eq!(opened["success"], true, "{opened}");
    let popup = window_with_prefix(h.app.handle(), "terminal-popup-").expect("popup window");
    let config = ok(invoke(&popup, "windows_terminal_popup_config", json!({})));
    assert_eq!(config["popupId"], opened["popupId"]);
    assert_eq!(config["attachSessionId"], sid.as_str());
    let token = config["attachAuthorization"]
        .as_str()
        .expect("attach token")
        .to_owned();
    assert!(ok(invoke(&h.main, "windows_terminal_popup_config", json!({}))).is_null());

    // One popup per attached session.
    let again = ok(invoke(
        &h.main,
        "windows_open_terminal_popup",
        json!({ "payload": { "attachSessionId": sid } }),
    ));
    assert_eq!(again["reused"], true);

    // The grant is bound to the popup window and the session.
    let args = json!({ "sessionId": sid, "authorization": token });
    let denied = ok(invoke(&h.main, "windows_rebind_output", args.clone()));
    assert_eq!(denied["error"], "Unauthorized attach request");
    let wrong = ok(invoke(
        &popup,
        "windows_rebind_output",
        json!({ "sessionId": sid, "authorization": "x" }),
    ));
    assert_eq!(wrong["error"], "Unauthorized attach request");

    // Snapshot from the current display window (main), then rebind.
    auto_reply(
        &h.app,
        "netcatty:terminal:snapshot-request",
        "main",
        "netcatty:terminal:snapshot-response",
        |req| json!({ "sessionId": req["sessionId"].clone(), "snapshot": "screen", "cwd": "/tmp", "title": null }),
    );
    let snap = ok(invoke(&popup, "windows_request_snapshot", args.clone()));
    assert_eq!(
        snap,
        json!({ "success": true, "snapshot": "screen", "cwd": "/tmp", "title": null })
    );
    let rebound = ok(invoke(&popup, "windows_rebind_output", args.clone()));
    assert_eq!(rebound["success"], true, "{rebound}");
    assert_ne!(rebound["previousWebContentsId"], rebound["webContentsId"]);
    assert_eq!(
        routes.lock().unwrap().last().unwrap()["label"],
        popup.label()
    );
    let to_popup = collect(&h.app, &format!("netcatty:data/{}", popup.label()));
    echo("routed-popup");
    assert!(wait_until(Duration::from_secs(10), || saw(&to_popup, "routed-popup-2")), "output follows the attach popup");
    assert!(!saw(&to_main, "routed-popup"), "the previous display window no longer gets it");
    assert!(!saw(&broadcast, "routed-popup"));

    // Apply the popup state back home before closing.
    auto_reply(
        &h.app,
        "netcatty:terminal:apply-snapshot",
        "main",
        "netcatty:terminal:apply-snapshot-response",
        |req| {
            assert!(req.get("authorization").is_none());
            json!({ "success": true })
        },
    );
    let applied = ok(invoke(
        &popup,
        "windows_apply_snapshot",
        json!({ "payload": {
            "sessionId": sid, "snapshot": "s", "contextSnapshot": "", "contextViewportSnapshot": "",
            "contextScrollbackSnapshot": "", "alternateScreen": false, "authorization": token,
        } }),
    ));
    assert_eq!(applied, json!({ "success": true }));

    let denied = ok(invoke(
        &h.main,
        "windows_mark_attach_close_prepared",
        args.clone(),
    ));
    assert_eq!(denied["success"], false);
    let prepared = ok(invoke(
        &popup,
        "windows_mark_attach_close_prepared",
        args.clone(),
    ));
    assert_eq!(prepared, json!({ "success": true }));

    // Closing the popup restores the display to main without closing the session.
    destroyed(&popup);
    assert_eq!(routes.lock().unwrap().last().unwrap()["label"], "main");
    let after = ok(invoke(&h.main, "windows_output_routes", json!({})));
    assert_eq!(after["routes"][0]["label"], "main");
    ok(invoke(
        &h.main,
        "session_close",
        json!({ "sessionId": sid }),
    ));
}

#[cfg(unix)]
#[test]
fn session_window_takes_its_tab_and_closes_its_sessions() {
    let h = build_app();
    let handle = h.app.handle().clone();
    let invalid = ok(invoke(
        &h.main,
        "windows_open_session",
        json!({ "payload": { "title": "x" } }),
    ));
    assert_eq!(invalid["error"], "Invalid session payload");

    let taken = Arc::new(Mutex::new(Value::Null));
    {
        let taken = taken.clone();
        std::thread::spawn(move || {
            assert!(wait_until(Duration::from_secs(5), || window_with_prefix(
                &handle, "session-"
            )
            .is_some()));
            let window = window_with_prefix(&handle, "session-").unwrap();
            *taken.lock().unwrap() = ok(invoke(&window, "windows_take_open_session", json!({})));
        });
    }
    let opened = ok(invoke(
        &h.main,
        "windows_open_session",
        json!({ "payload": { "title": "  web-1 ", "sourceSession": { "id": "s" }, "localShellType": null } }),
    ));
    assert_eq!(opened, json!({ "success": true }));
    assert_eq!(
        *taken.lock().unwrap(),
        json!({ "title": "web-1", "sourceSession": { "id": "s" } })
    );
    let window = window_with_prefix(h.app.handle(), "session-").unwrap();
    assert!(ok(invoke(&window, "windows_take_open_session", json!({}))).is_null());

    let labels = netcatty_desktop_lib::commands::windows::dirty_editor_windows(h.app.handle());
    assert_eq!(labels, vec!["main".to_owned(), window.label().to_owned()]);

    // Sessions die with the window that started them.
    let exits = collect(&h.app, "netcatty:exit");
    let started = ok(invoke(
        &window,
        "session_start_local",
        json!({ "payload": { "shell": "/bin/sh", "cols": 80, "rows": 24 } }),
    ));
    let sid = started["sessionId"].as_str().unwrap().to_owned();
    ok(invoke(
        &window,
        "windows_track_session",
        json!({ "sessionId": sid }),
    ));
    destroyed(&window);
    assert!(
        wait_until(Duration::from_secs(10), || exits
            .lock()
            .unwrap()
            .iter()
            .any(|e| e["sessionId"] == sid.as_str())),
        "the session window's session must be closed"
    );
}

#[test]
fn window_chrome_commands() {
    let h = build_app();
    assert_eq!(
        ok(invoke(
            &h.main,
            "windows_set_opacity",
            json!({ "opacity": 0.2 })
        )),
        true
    );
    assert_eq!(
        ok(invoke(
            &h.main,
            "windows_set_opacity",
            json!({ "opacity": null })
        )),
        true
    );
    let blur = ok(invoke(
        &h.main,
        "windows_set_background_blur",
        json!({ "enabled": true }),
    ));
    assert_eq!(blur, cfg!(target_os = "macos"));
    ok(invoke(
        &h.main,
        "windows_set_terminal_keyboard_focus",
        json!({ "focused": true }),
    ));
    assert!(
        netcatty_desktop_lib::commands::windows::has_terminal_keyboard_focus(
            h.app.handle(),
            "main"
        )
    );
    // Replies from a window that was not asked are ignored.
    let accepted = ok(invoke(
        &h.main,
        "windows_report",
        json!({ "channel": "netcatty:window:editorOpenTabResult", "payload": { "requestId": "r" } }),
    ));
    assert_eq!(accepted, false);
}

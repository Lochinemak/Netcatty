//! Headless IPC tests of the script automation commands (`commands/scripts.rs`,
//! `rust/docs/ipc-scripts.md`): scripts run against a real local shell
//! through the command dispatch, the session output tap and the
//! `netcatty:script:*` events, with the test standing in for the renderer.
//! Harness: see `ipc_smoke.rs`.

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

use crate::support::{collect, install_pump, Events};
use crate::BUILD_LOCK;
const TEST_KEY: [u8; 32] = [0x5a; 32];

struct Harness {
    app: App<MockRuntime>,
    webview: WebviewWindow<MockRuntime>,
    _data_dir: tempfile::TempDir,
}

fn build_app() -> Harness {
    let data_dir = tempfile::Builder::new()
        .prefix("netcatty-ipc-scripts-")
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
        install_pump(&app);
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

/// Poll `script_get_runs` until `run_id` has ended, answering screen
/// snapshot and dialog requests like the renderer meanwhile.
fn drive_until_ended(
    h: &Harness,
    run_id: &str,
    snapshots: &Events,
    dialogs: &Events,
    dialog_answer: impl Fn(&Value) -> Value,
) -> Value {
    let started = Instant::now();
    let mut answered_snapshots = 0;
    let mut answered_dialogs = 0;
    loop {
        let pending: Vec<Value> = snapshots.lock()[answered_snapshots..].to_vec();
        for request in pending {
            answered_snapshots += 1;
            ok(invoke(
                &h.webview,
                "script_screen_snapshot_response",
                json!({ "payload": {
                    "requestId": request["requestId"],
                    "snapshot": { "rows": 24, "cols": 80, "currentRow": 0, "lines": [] },
                } }),
            ));
        }
        let pending: Vec<Value> = dialogs.lock()[answered_dialogs..].to_vec();
        for request in pending {
            answered_dialogs += 1;
            ok(invoke(
                &h.webview,
                "script_dialog_response",
                json!({ "payload": { "requestId": request["requestId"], "value": dialog_answer(&request) } }),
            ));
        }
        let runs = ok(invoke(&h.webview, "script_get_runs", json!({})));
        if let Some(run) = runs
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["runId"] == run_id && r.get("endedAt").is_some())
        {
            return run.clone();
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "run {run_id} did not end: {runs}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn log_text(run: &Value) -> String {
    run["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["message"].as_str().unwrap_or("").to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(unix)]
#[test]
fn script_drives_a_local_shell() {
    let h = build_app();
    let snapshots = collect(&h.app, "netcatty:script:screen-snapshot-request");
    let dialogs = collect(&h.app, "netcatty:script:dialog-request");
    let inputs = collect(&h.app, "netcatty:script:session-input");
    let updates = collect(&h.app, "netcatty:script:runs-updated");

    let started = ok(invoke(
        &h.webview,
        "session_start_local",
        json!({ "payload": { "shell": "/bin/sh", "cols": 80, "rows": 24 } }),
    ));
    let session_id = started["sessionId"].as_str().unwrap().to_string();

    let queued = ok(invoke(
        &h.webview,
        "script_run",
        json!({ "payload": {
            "runId": "local-shell-run",
            "returnWhenQueued": true,
            "scriptId": "local",
            "scriptLabel": "Local",
            "sessionId": session_id,
            "content": r#"
                await nct.screen.sendLine('echo script-$((40 + 2))');
                const out = await nct.screen.waitForText('script-42', 10000);
                const ok = await nct.dialog.confirm('continue?');
                nct.log('saw ' + out + ' ' + ok + ' ' + nct.session.connected);
            "#,
        } }),
    ));
    assert_eq!(
        queued,
        json!({ "runId": "local-shell-run", "runIds": ["local-shell-run"] })
    );

    let run = drive_until_ended(&h, "local-shell-run", &snapshots, &dialogs, |_| json!(true));
    assert_eq!(run["status"], "completed", "{run}");
    assert!(log_text(&run).contains("saw script-42 true true"), "{run}");
    assert_eq!(run["sessionId"], session_id.as_str());

    // The terminal was told about the automated input (scroll to bottom).
    let inputs = inputs.lock().clone();
    assert!(inputs
        .iter()
        .any(|i| i["sessionId"] == session_id.as_str() && i["data"] == "echo script-$((40 + 2))"));
    assert_eq!(dialogs.lock()[0]["type"], "confirm");
    assert_eq!(dialogs.lock()[0]["message"], "continue?");
    assert!(!updates.lock().is_empty());

    // Filters by session.
    let none = ok(invoke(
        &h.webview,
        "script_get_runs",
        json!({ "sessionId": "other" }),
    ));
    assert_eq!(none, json!([]));

    ok(invoke(
        &h.webview,
        "session_close",
        json!({ "sessionId": session_id }),
    ));
}

#[cfg(unix)]
#[test]
fn stop_pause_resume_and_errors() {
    let h = build_app();
    let snapshots = collect(&h.app, "netcatty:script:screen-snapshot-request");
    let dialogs = collect(&h.app, "netcatty:script:dialog-request");

    // Validation errors keep Electron's messages with the CoreError shape.
    let err = invoke(
        &h.webview,
        "script_run",
        json!({ "payload": { "content": "nct.log(1)" } }),
    )
    .unwrap_err();
    assert_eq!(err["code"], "INVALID_ARGUMENT");
    assert_eq!(err["message"], "No target session for script run");

    ok(invoke(
        &h.webview,
        "script_run",
        json!({ "payload": {
            "runId": "stoppable",
            "returnWhenQueued": true,
            "scriptId": "stoppable",
            "sessionId": "no-such-session",
            "content": "await nct.sleep(10000);",
        } }),
    ));
    // Wait until it runs, then pause / resume / stop it.
    let started = Instant::now();
    loop {
        let runs = ok(invoke(
            &h.webview,
            "script_get_runs",
            json!({ "sessionId": "no-such-session" }),
        ));
        if runs
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["runId"] == "stoppable")
        {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        ok(invoke(
            &h.webview,
            "script_pause",
            json!({ "runId": "stoppable" })
        )),
        json!({ "ok": true })
    );
    let runs = ok(invoke(&h.webview, "script_get_runs", json!({})));
    assert_eq!(runs[0]["status"], "paused");
    assert_eq!(
        ok(invoke(
            &h.webview,
            "script_resume",
            json!({ "runId": "stoppable" })
        )),
        json!({ "ok": true })
    );
    assert_eq!(
        ok(invoke(
            &h.webview,
            "script_stop",
            json!({ "runId": "stoppable" })
        )),
        json!({ "ok": true })
    );
    let run = drive_until_ended(&h, "stoppable", &snapshots, &dialogs, |_| Value::Null);
    assert_eq!(run["status"], "failed");
    assert_eq!(run["error"], "Stopped by user");
    assert_eq!(
        ok(invoke(
            &h.webview,
            "script_stop",
            json!({ "runId": "missing" })
        )),
        json!({ "ok": false })
    );

    // Unknown request ids.
    assert_eq!(
        ok(invoke(
            &h.webview,
            "script_dialog_response",
            json!({ "payload": { "requestId": "x", "value": true } })
        )),
        json!({ "ok": false })
    );
    assert_eq!(
        ok(invoke(
            &h.webview,
            "script_screen_snapshot_response",
            json!({ "payload": { "requestId": "x", "snapshot": null } })
        )),
        json!({ "ok": false })
    );
}

#[test]
fn recording_round_trip() {
    let h = build_app();
    assert_eq!(
        ok(invoke(
            &h.webview,
            "script_recording_start",
            json!({ "sessionId": "rec" })
        )),
        json!({ "ok": true })
    );
    assert_eq!(
        ok(invoke(
            &h.webview,
            "script_recording_append_step",
            json!({ "payload": { "sessionId": "rec", "step": { "type": "send", "value": "uptime" } } }),
        )),
        json!({ "ok": true })
    );
    let stopped = ok(invoke(
        &h.webview,
        "script_recording_stop",
        json!({ "sessionId": "rec" }),
    ));
    assert_eq!(
        stopped["steps"],
        json!([{ "type": "send", "value": "uptime" }])
    );
    assert!(stopped["code"]
        .as_str()
        .unwrap()
        .contains("await nct.screen.sendLine(\"uptime\");"));
    assert_eq!(
        ok(invoke(
            &h.webview,
            "script_recording_append_step",
            json!({ "payload": { "sessionId": "rec", "step": { "type": "sleep", "value": 1 } } }),
        )),
        json!({ "ok": false, "error": "Recording not started" })
    );
    let err = invoke(&h.webview, "script_recording_start", json!({})).unwrap_err();
    assert_eq!(err["message"], "sessionId required");
}

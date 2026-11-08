//! Headless IPC tests of the ZMODEM driver (`commands/zmodem.rs`) and the
//! terminal plumbing / autocomplete commands (`commands/terminal.rs`),
//! against a real local shell. Harness: see `ipc_smoke.rs`.

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
    data_dir: tempfile::TempDir,
}

fn build_app() -> Harness {
    let data_dir = tempfile::Builder::new()
        .prefix("netcatty-ipc-zmodem-")
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
        data_dir,
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

fn text_of(events: &[Value], id: &str) -> String {
    events
        .iter()
        .filter(|e| e["sessionId"] == id)
        .filter_map(|e| e["data"].as_str())
        .collect()
}

fn session_data(data: &Arc<Mutex<Vec<Value>>>, id: &str) -> String {
    text_of(&data.lock().unwrap(), id)
}

fn start_shell(h: &Harness) -> String {
    ok(invoke(
        &h.webview,
        "session_start_local",
        json!({ "payload": { "shell": "/bin/sh", "cols": 80, "rows": 24 } }),
    ))["sessionId"]
        .as_str()
        .unwrap()
        .to_string()
}

/// `printf` format printing `bytes` (octal escapes; the tty's `onlcr`
/// would turn a bare LF into CR LF, so callers use lrzsz's LF | 0x80).
fn printf_octal(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:03o}")).collect()
}

#[cfg(unix)]
#[test]
fn drag_drop_upload_detects_rz_hides_protocol_bytes_and_cancels() {
    use netcatty_zmodem::header::Header;
    let h = build_app();
    let data = collect(&h.app, "netcatty:data");
    let detect = collect(&h.app, "netcatty:zmodem:detect");
    let errors = collect(&h.app, "netcatty:zmodem:error");
    let id = start_shell(&h);

    let file = h.data_dir.path().join("upload.txt");
    std::fs::write(&file, b"payload").unwrap();

    // A fake `rz`: the "upload command" prints a ZRINIT (CANFDX | CANOVIO |
    // CANFC32) and then idles like a receiver waiting for the offer.
    let mut zrinit = Header::zrinit(0x23, 0).to_hex();
    zrinit[19] = 0x8a;
    let command = format!("printf '{}'; sleep 20\r", printf_octal(&zrinit));
    let queued = ok(invoke(
        &h.webview,
        "zmodem_drag_drop_upload",
        json!({ "payload": {
            "sessionId": id,
            "files": [{ "path": file.to_string_lossy(), "remoteName": "upload.txt" }],
            "uploadCommand": command,
        } }),
    ));
    assert_eq!(queued["success"], true, "{queued}");

    // A second queue while one is pending is refused.
    let again = ok(invoke(
        &h.webview,
        "zmodem_drag_drop_upload",
        json!({ "payload": { "sessionId": id, "files": [{ "path": file.to_string_lossy() }] } }),
    ));
    assert_eq!(again["success"], false);

    assert!(
        wait_for(&detect, Duration::from_secs(10), |events| events
            .iter()
            .any(|e| e["sessionId"] == id && e["transferType"] == "upload")),
        "no upload detection; data: {:?}",
        session_data(&data, &id)
    );

    // Terminal input is swallowed while the transfer runs.
    ok(invoke(
        &h.webview,
        "session_write",
        json!({ "payload": { "sessionId": id, "data": "echo SWALLOWED-$((40+2))\r" } }),
    ));
    std::thread::sleep(Duration::from_millis(300));
    ok(invoke(
        &h.webview,
        "zmodem_cancel",
        json!({ "sessionId": id, "options": { "interrupt": true } }),
    ));
    assert!(
        wait_for(&errors, Duration::from_secs(5), |events| events
            .iter()
            .any(|e| e["sessionId"] == id && e["error"] == "Transfer cancelled")),
        "no cancel error: {:?}",
        errors.lock().unwrap()
    );

    // After the cooldown the shell is usable again.
    std::thread::sleep(Duration::from_millis(2300));
    ok(invoke(
        &h.webview,
        "session_write",
        json!({ "payload": { "sessionId": id, "data": "echo after-$((1+1))\r" } }),
    ));
    assert!(
        wait_for(&data, Duration::from_secs(10), |events| text_of(events, &id)
            .contains("after-2")),
        "shell not usable after cancel: {:?}",
        session_data(&data, &id)
    );
    let shown = session_data(&data, &id);
    assert!(!shown.contains('\u{18}'), "protocol bytes reached the terminal: {shown:?}");
    assert!(!shown.contains("B0100000023"), "ZRINIT reached the terminal: {shown:?}");
    assert!(!shown.contains("SWALLOWED-42"), "input was not swallowed: {shown:?}");

    ok(invoke(&h.webview, "session_close", json!({ "sessionId": id })));
}

#[cfg(unix)]
#[test]
fn paste_receipts_and_cancellation() {
    let h = build_app();
    let receipts = collect(&h.app, "netcatty:paste-write");
    let id = start_shell(&h);

    ok(invoke(
        &h.webview,
        "session_write",
        json!({ "payload": { "sessionId": id, "data": "true\r", "pasteRequestId": "p1" } }),
    ));
    assert!(wait_for(&receipts, Duration::from_secs(5), |e| e
        .iter()
        .any(|r| r["requestId"] == "p1" && r["index"] == 0 && r["done"] == true)));

    ok(invoke(
        &h.webview,
        "session_write",
        json!({ "payload": {
            "sessionId": id, "data": "true\rtrue\r", "pasteRequestId": "p2", "lineDelayMs": 20
        } }),
    ));
    assert!(wait_for(&receipts, Duration::from_secs(5), |e| {
        let p2: Vec<&Value> = e.iter().filter(|r| r["requestId"] == "p2").collect();
        p2.len() == 2 && p2[0]["index"] == 0 && p2[1]["index"] == 1 && p2[1]["done"] == true
    }));

    // A slow paced paste is cancelled after its first line.
    ok(invoke(
        &h.webview,
        "session_write",
        json!({ "payload": {
            "sessionId": id, "data": "true\rtrue\rtrue\r", "pasteRequestId": "p3", "lineDelayMs": 1500
        } }),
    ));
    assert!(wait_for(&receipts, Duration::from_secs(5), |e| e
        .iter()
        .any(|r| r["requestId"] == "p3" && r["index"] == 0)));
    ok(invoke(
        &h.webview,
        "terminal_cancel_pending_writes",
        json!({ "sessionId": id }),
    ));
    assert!(wait_for(&receipts, Duration::from_secs(5), |e| e.iter().any(|r| r
        ["requestId"]
        == "p3"
        && r["done"] == true
        && r.get("index").is_none())));
    std::thread::sleep(Duration::from_millis(1800));
    let p3: Vec<Value> = receipts
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["requestId"] == "p3")
        .cloned()
        .collect();
    assert_eq!(p3.len(), 2, "no receipts after cancellation: {p3:?}");

    ok(invoke(&h.webview, "session_close", json!({ "sessionId": id })));
}

#[test]
fn terminal_and_autocomplete_commands() {
    let h = build_app();

    let info = ok(invoke(&h.webview, "terminal_windows_pty_info", json!({})));
    if cfg!(windows) {
        assert_eq!(info["backend"], "conpty");
    } else {
        assert!(info.is_null());
    }

    // Debug builds read the specs from the checkout's node_modules.
    let specs = ok(invoke(&h.webview, "figspec_list", json!({})));
    let specs = specs.as_array().unwrap();
    if !specs.is_empty() {
        assert!(specs.iter().any(|s| s == "git"));
        assert!(!specs.iter().any(|s| s == "aws"));
        assert!(specs.iter().any(|s| s == "yum"), "local electron/specs are merged");
        let git = ok(invoke(&h.webview, "figspec_load", json!({ "commandName": "git" })));
        assert!(git.as_str().unwrap().contains("export"));
    }
    for bad in ["aws", "../package", "/etc/passwd", "nope-not-a-spec"] {
        let r = ok(invoke(&h.webview, "figspec_load", json!({ "commandName": bad })));
        assert!(r.is_null(), "{bad} → {r}");
    }

    std::fs::create_dir_all(h.data_dir.path().join("subdir")).unwrap();
    let local = ok(invoke(
        &h.webview,
        "autocomplete_local_listdir",
        json!({ "payload": {
            "path": h.data_dir.path().to_string_lossy(), "foldersOnly": true, "filterPrefix": "SUB", "limit": 5
        } }),
    ));
    assert_eq!(local["success"], true);
    assert_eq!(local["entries"], json!([{ "name": "subdir", "type": "directory" }]));

    let remote = ok(invoke(
        &h.webview,
        "autocomplete_remote_listdir",
        json!({ "payload": { "sessionId": "nope", "path": "/" } }),
    ));
    assert_eq!(remote, json!({ "success": false, "entries": [], "error": "Session not found" }));

    let ymodem = ok(invoke(
        &h.webview,
        "serial_ymodem_send",
        json!({ "payload": { "sessionId": "nope", "filePath": "/tmp/x" } }),
    ));
    assert_eq!(ymodem["success"], false);
    assert_eq!(ymodem["error"], "YMODEM send requires an active serial session");

    let dd = ok(invoke(
        &h.webview,
        "zmodem_drag_drop_upload",
        json!({ "payload": { "sessionId": "nope", "files": [] } }),
    ));
    assert_eq!(dd["error"], "ZMODEM upload is not available for this session");
    ok(invoke(&h.webview, "zmodem_cancel", json!({ "sessionId": "nope" })));
    ok(invoke(
        &h.webview,
        "zmodem_overwrite_response",
        json!({ "payload": { "requestId": "x", "action": "skip", "applyToRest": false } }),
    ));
}

//! Crash logs and renderer diagnostics (Electron: `crashLogBridge.cjs`).
//!
//! Rust panics are recorded by the hook [`install_panic_hook`] installs in
//! `run()`; the renderer adds entries through `app_log_diagnostic`.

use netcatty_store::crashlog::{CrashLog, CrashLogFile, EntryContext};
use netcatty_store::AppPaths;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Manager, Runtime};

/// Electron routes these to a separate perf log, never the crash log.
const TERMINAL_PERF_SOURCE: &str = "terminal-perf";

pub fn crash_log_for(paths: &AppPaths, version: &str) -> CrashLog {
    CrashLog::new(
        paths.crash_logs_dir(),
        EntryContext {
            version: version.to_owned(),
        },
    )
}

/// Record Rust panics (thread, message, location, backtrace) before the
/// default hook runs. Installed once by the real app, not by tests.
pub fn install_panic_hook(log: CrashLog) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panic".to_owned());
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()));
        let thread = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_owned();
        let backtrace = std::backtrace::Backtrace::force_capture().to_string();
        log.capture(
            "main-panic",
            &message,
            Some(&backtrace),
            Some(serde_json::json!({ "thread": thread, "location": location })),
        );
        previous(info);
    }));
}

fn crash_log<R: Runtime>(app: &AppHandle<R>) -> tauri::State<'_, CrashLog> {
    app.state::<CrashLog>()
}

#[derive(Serialize)]
pub struct Success {
    success: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cleared {
    deleted_count: usize,
}

#[tauri::command]
pub fn crash_logs_list<R: Runtime>(app: AppHandle<R>) -> Vec<CrashLogFile> {
    crash_log(&app).list()
}

#[tauri::command]
pub fn crash_logs_read<R: Runtime>(app: AppHandle<R>, file_name: String) -> Vec<Value> {
    crash_log(&app).read(&file_name)
}

#[tauri::command]
pub fn crash_logs_clear<R: Runtime>(app: AppHandle<R>) -> Cleared {
    Cleared {
        deleted_count: crash_log(&app).clear(),
    }
}

#[tauri::command]
pub fn crash_logs_open_dir<R: Runtime>(app: AppHandle<R>) -> Success {
    use tauri_plugin_opener::OpenerExt;
    let dir = crash_log(&app).dir().to_path_buf();
    let _ = std::fs::create_dir_all(&dir);
    Success {
        success: app
            .opener()
            .open_path(dir.to_string_lossy(), None::<&str>)
            .is_ok(),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticPayload {
    source: Option<String>,
    message: Option<String>,
    extra: Option<Value>,
}

/// `logDiagnostic`: renderer-reported diagnostics land in the crash log.
#[tauri::command]
pub fn app_log_diagnostic<R: Runtime>(
    app: AppHandle<R>,
    payload: Option<DiagnosticPayload>,
) -> Success {
    let payload = payload.unwrap_or_default();
    let source = payload
        .source
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("renderer-diagnostic");
    let message = payload
        .message
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("diagnostic");
    if source == TERMINAL_PERF_SOURCE {
        tracing::debug!(target: "terminal-perf", "{message}");
    } else {
        crash_log(&app).capture(source, message, None, payload.extra);
    }
    Success { success: true }
}

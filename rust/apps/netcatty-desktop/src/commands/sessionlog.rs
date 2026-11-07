//! Session logs (Electron: `sessionLogsBridge.cjs` + the stream wiring in
//! `terminalBridge.cjs` / `sshBridge`): export, auto-save, the logs
//! directory, manual "record session log" and automatic per-session logs.
//!
//! Electron splits streams between two `sessionLogStreamManager` instances:
//! automatic logs (`sessionLog` start option) live in the terminal worker,
//! manual recordings in the main process. [`SessionLogState`] keeps the same
//! split with two [`StreamManager`]s so precedence rules carry over: "open
//! log" prefers the manual log, a live manual recording survives reconnects,
//! and `isLogging` reflects manual recording only.
//!
//! Session output reaches the streams through [`tap_output`], called from the
//! session pump (`sessions.rs`); [`session_starting`] / [`session_ended`]
//! start and stop the automatic log and [`session_input`] registers the
//! command-echo rewrites of `session_write`.
//!
//! Manual log paths are chosen with a save dialog in Rust and handed to the
//! renderer only as an opaque `selectionToken`: renderer-supplied paths are
//! never opened or truncated.

use super::CmdResult;
use netcatty_core::ipc::{LogRewrite, SessionLogConfig};
use netcatty_core::CoreError;
use netcatty_sessionlog::files::{self, AutoSave};
use netcatty_sessionlog::naming::{now_ms, safe_path_segment, to_local_iso_string};
use netcatty_sessionlog::stream::node_io_error;
use netcatty_sessionlog::{
    FileStreamOptions, LogFormat, StreamManager, StreamOptions, StreamToken,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager, Runtime};

const NO_SAVED_LOG: &str = "No saved log is available for this session";
const MISSING_SESSION_ID: &str = "Missing sessionId";

/// A save-dialog result waiting to be redeemed by `session_log_manual_start`.
#[derive(Debug, Clone)]
struct PendingChoice {
    session_id: String,
    file_path: PathBuf,
    format: LogFormat,
    /// Label of the window that opened the dialog (Electron: sender id).
    window: Option<String>,
}

/// Managed state of the session log commands.
#[derive(Default)]
pub struct SessionLogState {
    /// Manual recordings (Electron's main-process manager).
    pub manual: StreamManager,
    /// Automatic logs from the `sessionLog` start option (Electron's worker).
    pub auto: StreamManager,
    manual_tokens: Mutex<HashMap<String, StreamToken>>,
    auto_tokens: Mutex<HashMap<String, StreamToken>>,
    pending_choices: Mutex<HashMap<String, PendingChoice>>,
}

impl SessionLogState {
    /// Store a chosen manual log path and return its one-time selection
    /// token. Only the latest choice per session can be redeemed. Public so
    /// headless tests can stand in for the save dialog.
    pub fn register_selection(
        &self,
        session_id: &str,
        file_path: PathBuf,
        format: LogFormat,
        window: Option<String>,
    ) -> String {
        let token = netcatty_core::ids::new_id().replace('-', "");
        let mut choices = self.pending_choices.lock();
        choices.retain(|_, pending| pending.session_id != session_id);
        choices.insert(
            token.clone(),
            PendingChoice {
                session_id: session_id.to_string(),
                file_path,
                format,
                window,
            },
        );
        token
    }

    fn redeem_selection(
        &self,
        session_id: &str,
        token: &str,
        window: Option<&str>,
    ) -> Option<PendingChoice> {
        let mut choices = self.pending_choices.lock();
        let pending = choices.get(token)?;
        if pending.session_id != session_id {
            return None;
        }
        if let (Some(owner), Some(caller)) = (pending.window.as_deref(), window) {
            if owner != caller {
                return None;
            }
        }
        choices.remove(token)
    }

    fn active_paths(&self) -> HashSet<PathBuf> {
        self.manual
            .active_log_paths()
            .into_iter()
            .chain(self.auto.active_log_paths())
            .collect()
    }
}

fn state<R: Runtime>(app: &AppHandle<R>) -> tauri::State<'_, SessionLogState> {
    app.state::<SessionLogState>()
}

// ---------------------------------------------------------------------------
// Session hooks
// ---------------------------------------------------------------------------

/// Feed decoded session output to the session's log streams. Called by the
/// session pump for every chunk (before flow-control buffering, so paused
/// output is logged too). Never blocks on I/O.
pub fn tap_output<R: Runtime>(app: &AppHandle<R>, session_id: &str, text: &str) {
    if text.is_empty() {
        return;
    }
    if let Some(state) = app.try_state::<SessionLogState>() {
        state.manual.append_data(session_id, text);
        state.auto.append_data(session_id, text);
    }
}

/// A terminal session is about to start (before its pump runs): retire the
/// previous connection's stopped manual log (a live manual recording keeps
/// going across reconnects) and start the automatic log when `config` asks
/// for one. Electron labels: SSH `hostLabel || hostname`, local `Local` /
/// `localhost`.
pub fn session_starting<R: Runtime>(
    app: &AppHandle<R>,
    session_id: &str,
    config: Option<&SessionLogConfig>,
    host_label: &str,
    hostname: &str,
) {
    let Some(state) = app.try_state::<SessionLogState>() else {
        return;
    };
    if !state.manual.has_stream(session_id) {
        state.manual.forget_session_log(session_id);
    }
    state.auto_tokens.lock().remove(session_id);
    let Some(config) = config.filter(|c| c.enabled && !c.directory.is_empty()) else {
        // A replacement without logging retires the previous automatic log.
        state.auto.forget_session_log(session_id);
        return;
    };
    let token = state.auto.start_stream(
        session_id,
        StreamOptions {
            host_label: host_label.to_string(),
            hostname: hostname.to_string(),
            directory: PathBuf::from(&config.directory),
            format: LogFormat::from_setting(&config.format),
            start_time: Some(now_ms()),
            timestamps_enabled: config.timestamps_enabled.unwrap_or(false),
            timestamp_provider: None,
        },
    );
    if let Some(token) = token {
        state
            .auto_tokens
            .lock()
            .insert(session_id.to_string(), token);
    }
}

/// A terminal session ended (backend exit or `session_close`): finalize its
/// automatic log in the background. Manual recordings are left running;
/// the renderer stops them.
pub fn session_ended<R: Runtime>(app: &AppHandle<R>, session_id: &str) {
    let Some(state) = app.try_state::<SessionLogState>() else {
        return;
    };
    let Some(token) = state.auto_tokens.lock().remove(session_id) else {
        return;
    };
    let auto = state.auto.clone();
    let session_id = session_id.to_string();
    tauri::async_runtime::spawn_blocking(move || {
        auto.stop_stream(&session_id, Some(token));
    });
}

/// Register the log-only rewrites of text typed into a session: sudo
/// autofill prompt markers and `logRewrite` command echoes.
pub fn session_input<R: Runtime>(
    app: &AppHandle<R>,
    session_id: &str,
    data: &str,
    log_rewrite: Option<&LogRewrite>,
) {
    let Some(state) = app.try_state::<SessionLogState>() else {
        return;
    };
    for manager in [&state.manual, &state.auto] {
        manager.register_sudo_autofill_input(session_id, data);
        if let Some(rewrite) = log_rewrite {
            manager.register_programmatic_command_log_rewrite(
                session_id,
                &rewrite.sent_command,
                &rewrite.display_command,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Dialog helpers
// ---------------------------------------------------------------------------

async fn save_dialog<R: Runtime>(
    app: &AppHandle<R>,
    directory: Option<&Path>,
    file_name: &str,
    filters: &[(&str, &[&str])],
) -> Option<PathBuf> {
    use tauri_plugin_dialog::DialogExt;
    let mut builder = app.dialog().file().set_file_name(file_name);
    if let Some(directory) = directory {
        builder = builder.set_directory(directory);
    }
    for (name, extensions) in filters {
        builder = builder.add_filter(*name, extensions);
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    builder.save_file(move |path| {
        let _ = tx.send(path);
    });
    rx.await.ok().flatten().and_then(|p| p.into_path().ok())
}

async fn confirm_overwrite<R: Runtime>(
    app: &AppHandle<R>,
    file_path: &Path,
) -> Result<bool, String> {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
    match std::fs::symlink_metadata(file_path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(err) => return Err(node_io_error(&err, "access", file_path)),
        Ok(_) => {}
    }
    let name = file_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .message(format!(
            "\"{name}\" already exists.\n\nChoose Overwrite to replace it, or Cancel to keep the existing file."
        ))
        .title("Overwrite session log?")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Overwrite".into(),
            "Cancel".into(),
        ))
        .show(move |confirmed| {
            let _ = tx.send(confirmed);
        });
    Ok(rx.await.unwrap_or(false))
}

/// Append `.ext` unless the chosen path already has it (case-insensitive).
fn normalize_manual_log_path(file_path: PathBuf, extension: &str) -> PathBuf {
    let matches = file_path
        .extension()
        .is_some_and(|e| e.to_string_lossy().to_lowercase() == extension);
    if matches {
        file_path
    } else {
        let mut raw = file_path.into_os_string();
        raw.push(format!(".{extension}"));
        PathBuf::from(raw)
    }
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.is_empty())
}

fn start_time_ms(value: Option<f64>) -> Option<i64> {
    value.filter(|v| v.is_finite()).map(|v| v as i64)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> CmdResult<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|err| CoreError::internal(format!("session log task failed: {err}")))
}

// ---------------------------------------------------------------------------
// Export / auto-save / directory
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportPayload {
    terminal_data: Option<String>,
    host_label: Option<String>,
    hostname: Option<String>,
    start_time: Option<f64>,
    format: Option<String>,
    /// Already rendered screen text: keep rows as they are.
    plain_text: Option<bool>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    canceled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
}

/// `exportSessionLog`: save dialog, then write txt / raw / html by the
/// chosen extension. Rejects when there is nothing to export.
#[tauri::command]
pub async fn session_log_export<R: Runtime>(
    app: AppHandle<R>,
    payload: ExportPayload,
) -> CmdResult<ExportResult> {
    let plain_text = payload.plain_text == Some(true);
    let data = payload.terminal_data.clone().unwrap_or_default();
    if data.is_empty() && !(plain_text && payload.terminal_data.is_some()) {
        return Err(CoreError::invalid("No terminal data to export"));
    }
    let host_label = payload.host_label.clone().unwrap_or_default();
    let label = non_empty(&payload.host_label)
        .or(non_empty(&payload.hostname))
        .unwrap_or_default();
    let start_time = start_time_ms(payload.start_time);
    let format = payload.format.clone().unwrap_or_default();
    let default_name =
        files::export_default_file_name(label, start_time.unwrap_or_else(now_ms), &format);
    let Some(file_path) = save_dialog(
        &app,
        None,
        &default_name,
        &[
            ("Text Files", &["txt"]),
            ("Log Files", &["log"]),
            ("HTML Files", &["html"]),
            ("All Files", &["*"]),
        ],
    )
    .await
    else {
        return Ok(ExportResult {
            success: false,
            canceled: Some(true),
            file_path: None,
        });
    };
    let actual_format = files::export_actual_format(&file_path, &format);
    let target = file_path.clone();
    blocking(move || {
        let content =
            files::export_content(&actual_format, &data, plain_text, &host_label, start_time);
        std::fs::write(&target, content).map_err(|e| node_io_error(&e, "open", &target))
    })
    .await?
    .map_err(CoreError::io)?;
    Ok(ExportResult {
        success: true,
        canceled: None,
        file_path: Some(file_path.to_string_lossy().into_owned()),
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectDirResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    canceled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    directory: Option<String>,
}

/// `selectSessionLogsDir`: directory picker.
#[tauri::command]
pub async fn session_log_select_dir<R: Runtime>(app: AppHandle<R>) -> SelectDirResult {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title("Select Session Logs Directory")
        .set_can_create_directories(true)
        .pick_folder(move |path| {
            let _ = tx.send(path);
        });
    match rx.await.ok().flatten().and_then(|p| p.into_path().ok()) {
        Some(directory) => SelectDirResult {
            success: true,
            canceled: None,
            directory: Some(directory.to_string_lossy().into_owned()),
        },
        None => SelectDirResult {
            success: false,
            canceled: Some(true),
            directory: None,
        },
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoSavePayload {
    terminal_data: Option<String>,
    host_label: Option<String>,
    hostname: Option<String>,
    host_id: Option<String>,
    start_time: Option<f64>,
    format: Option<String>,
    directory: Option<String>,
}

/// `{ success, error?, filePath? }` (auto-save, prepare, reveal).
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FileResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
}

impl FileResult {
    fn ok(path: &Path) -> Self {
        Self {
            success: true,
            error: None,
            file_path: Some(path.to_string_lossy().into_owned()),
        }
    }
    fn fail(error: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(error.into()),
            file_path: None,
        }
    }
}

/// `autoSaveSessionLog`: write a whole log to `directory/<host>/<time>.<ext>`.
#[tauri::command]
pub async fn session_log_auto_save(payload: AutoSavePayload) -> CmdResult<FileResult> {
    let (Some(data), Some(directory)) = (
        non_empty(&payload.terminal_data).map(str::to_string),
        non_empty(&payload.directory).map(str::to_string),
    ) else {
        return Ok(FileResult::fail("Missing terminal data or directory"));
    };
    blocking(move || {
        let result = files::auto_save(&AutoSave {
            terminal_data: &data,
            host_label: payload.host_label.as_deref().unwrap_or_default(),
            hostname: payload.hostname.as_deref().unwrap_or_default(),
            host_id: payload.host_id.as_deref().unwrap_or_default(),
            start_time: start_time_ms(payload.start_time).unwrap_or_else(now_ms),
            format: payload.format.as_deref().unwrap_or_default(),
            directory: Path::new(&directory),
        });
        match result {
            Ok(path) => FileResult::ok(&path),
            Err(error) => {
                tracing::error!(%error, "failed to auto-save session log");
                FileResult::fail(error)
            }
        }
    })
    .await
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenDirResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// `openSessionLogsDir`: open an existing directory in the file manager.
#[tauri::command]
pub async fn session_log_open_dir<R: Runtime>(
    app: AppHandle<R>,
    directory: Option<String>,
) -> OpenDirResult {
    use tauri_plugin_opener::OpenerExt;
    let fail = |error: String| OpenDirResult {
        success: false,
        error: Some(error),
    };
    let Some(directory) = non_empty(&directory) else {
        return fail("No directory specified".into());
    };
    if let Err(err) = std::fs::metadata(directory) {
        return fail(node_io_error(&err, "access", Path::new(directory)));
    }
    match app.opener().open_path(directory, None::<&str>) {
        Ok(()) => OpenDirResult {
            success: true,
            error: None,
        },
        Err(err) => fail(err.to_string()),
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClearResult {
    success: bool,
    deleted_count: usize,
    failed_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// `clearSessionLogsDir`: delete Netcatty log artifacts only, skipping the
/// files and host folders of live streams.
#[tauri::command]
pub async fn session_log_clear_dir<R: Runtime>(
    app: AppHandle<R>,
    directory: Option<String>,
) -> CmdResult<ClearResult> {
    let Some(directory) = non_empty(&directory).map(PathBuf::from) else {
        return Ok(ClearResult {
            success: false,
            deleted_count: 0,
            failed_count: 0,
            error: Some("No directory specified".into()),
        });
    };
    let active = state(&app).active_paths();
    let outcome = blocking(move || files::clear_session_logs_dir(&directory, &active)).await?;
    Ok(ClearResult {
        success: outcome.error.is_none(),
        deleted_count: outcome.deleted_count,
        failed_count: outcome.failed_count,
        error: outcome.error,
    })
}

// ---------------------------------------------------------------------------
// Manual recording
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChoosePathPayload {
    session_id: Option<String>,
    session_name: Option<String>,
    preferred_directory: Option<String>,
    format: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChoosePathResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    canceled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selection_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<&'static str>,
}

impl ChoosePathResult {
    fn canceled() -> Self {
        Self {
            success: true,
            canceled: Some(true),
            error: None,
            selection_token: None,
            file_path: None,
            format: None,
        }
    }
    fn fail(error: impl Into<String>) -> Self {
        Self {
            success: false,
            canceled: Some(false),
            error: Some(error.into()),
            selection_token: None,
            file_path: None,
            format: None,
        }
    }
}

fn manual_format(value: &Option<String>) -> LogFormat {
    value
        .as_deref()
        .and_then(LogFormat::parse)
        .unwrap_or(LogFormat::Raw)
}

async fn choose_manual_path<R: Runtime>(
    app: &AppHandle<R>,
    window: Option<String>,
    payload: &ChoosePathPayload,
) -> ChoosePathResult {
    let Some(session_id) = non_empty(&payload.session_id) else {
        return ChoosePathResult::fail(MISSING_SESSION_ID);
    };
    let target_directory = payload
        .preferred_directory
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .unwrap_or_default();
    let format = manual_format(&payload.format);
    let extension = format.extension();
    let display_name = non_empty(&payload.session_name).unwrap_or(session_id);
    let default_name = format!(
        "{}_{}.{extension}",
        safe_path_segment(display_name, "session"),
        to_local_iso_string(now_ms())
    );
    let filter_name = match format {
        LogFormat::Txt => "Text Files",
        LogFormat::Html => "HTML Files",
        LogFormat::Raw => "Log Files",
    };
    let Some(chosen) = save_dialog(
        app,
        Some(&target_directory),
        &default_name,
        &[(filter_name, &[extension]), ("All Files", &["*"])],
    )
    .await
    else {
        return ChoosePathResult::canceled();
    };
    let file_path = normalize_manual_log_path(chosen.clone(), extension);
    if file_path != chosen {
        match confirm_overwrite(app, &file_path).await {
            Ok(true) => {}
            Ok(false) => return ChoosePathResult::canceled(),
            Err(error) => return ChoosePathResult::fail(error),
        }
    }
    let token = state(app).register_selection(session_id, file_path.clone(), format, window);
    ChoosePathResult {
        success: true,
        canceled: Some(false),
        error: None,
        selection_token: Some(token),
        // Informational: starting must redeem the token, not this path.
        file_path: Some(file_path.to_string_lossy().into_owned()),
        format: Some(format.as_str()),
    }
}

/// `chooseManualSessionLogPath`: save dialog (+ overwrite confirmation when
/// the extension had to be appended). Returns an opaque `selectionToken`.
#[tauri::command]
pub async fn session_log_manual_choose_path<R: Runtime>(
    app: AppHandle<R>,
    window: tauri::Window<R>,
    payload: ChoosePathPayload,
) -> ChoosePathResult {
    choose_manual_path(&app, Some(window.label().to_string()), &payload).await
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartManualPayload {
    session_id: Option<String>,
    session_name: Option<String>,
    preferred_directory: Option<String>,
    selection_token: Option<String>,
    file_path: Option<String>,
    format: Option<String>,
    timestamps_enabled: Option<bool>,
    initial_line: Option<String>,
    alternate_screen_active: Option<bool>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StartManualResult {
    success: bool,
    started: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    canceled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
}

impl StartManualResult {
    fn fail(error: impl Into<String>) -> Self {
        Self {
            success: false,
            started: false,
            canceled: None,
            error: Some(error.into()),
            file_path: None,
        }
    }
}

/// `startManualSessionLog`: redeem a selection token (or show the dialog
/// when none is given) and start recording the session's output.
#[tauri::command]
pub async fn session_log_manual_start<R: Runtime>(
    app: AppHandle<R>,
    window: tauri::Window<R>,
    payload: StartManualPayload,
) -> StartManualResult {
    const INVALID_SELECTION: &str = "Invalid or expired session log selection";
    let Some(session_id) = non_empty(&payload.session_id).map(str::to_string) else {
        return StartManualResult::fail(MISSING_SESSION_ID);
    };
    let logs = state(&app);
    if logs.manual.has_stream(&session_id) {
        return StartManualResult::fail("Session log is already active");
    }
    let window = window.label().to_string();
    let choice = if let Some(token) = non_empty(&payload.selection_token) {
        match logs.redeem_selection(&session_id, token, Some(&window)) {
            Some(choice) => choice,
            None => return StartManualResult::fail(INVALID_SELECTION),
        }
    } else if payload
        .file_path
        .as_deref()
        .is_some_and(|p| !p.trim().is_empty())
    {
        // Renderer-supplied paths would bypass the dialog and the overwrite
        // confirmation and could truncate arbitrary writable files.
        return StartManualResult::fail("Session log path must be chosen via the save dialog");
    } else {
        // One-shot callers: show the dialog and start immediately.
        let chosen = choose_manual_path(
            &app,
            Some(window.clone()),
            &ChoosePathPayload {
                session_id: Some(session_id.clone()),
                session_name: payload.session_name.clone(),
                preferred_directory: payload.preferred_directory.clone(),
                format: Some(manual_format(&payload.format).as_str().into()),
            },
        )
        .await;
        if !chosen.success {
            return StartManualResult::fail(
                chosen
                    .error
                    .unwrap_or_else(|| "Failed to choose session log path".into()),
            );
        }
        let Some(token) = chosen
            .selection_token
            .filter(|_| chosen.canceled != Some(true))
        else {
            return StartManualResult {
                success: true,
                started: false,
                canceled: Some(true),
                error: None,
                file_path: None,
            };
        };
        match logs.redeem_selection(&session_id, &token, Some(&window)) {
            Some(choice) => choice,
            None => return StartManualResult::fail(INVALID_SELECTION),
        }
    };

    let display_name = non_empty(&payload.session_name)
        .unwrap_or(&session_id)
        .to_string();
    let options = FileStreamOptions {
        file_path: choice.file_path.clone(),
        format: choice.format,
        host_label: display_name,
        start_time: Some(now_ms()),
        timestamps_enabled: payload.timestamps_enabled == Some(true),
        timestamp_provider: None,
        initial_line: payload.initial_line.clone().unwrap_or_default(),
        separate_initial_line_before_leading_carriage_return: true,
        stop_requires_token: true,
        // Sampled by the renderer after the dialog closed.
        alternate_screen_active: payload.alternate_screen_active == Some(true),
    };
    let manual = logs.manual.clone();
    let id = session_id.clone();
    let started = match blocking(move || manual.start_stream_to_file(&id, options)).await {
        Ok(result) => result,
        Err(err) => Err(err.message),
    };
    match started {
        Ok(token) => {
            logs.manual_tokens.lock().insert(session_id, token);
            StartManualResult {
                success: true,
                started: true,
                canceled: None,
                error: None,
                file_path: Some(choice.file_path.to_string_lossy().into_owned()),
            }
        }
        Err(error) => StartManualResult::fail(error),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionIdPayload {
    session_id: Option<String>,
}

impl SessionIdPayload {
    /// The id when it is a non-blank string.
    fn valid_id(&self) -> Option<&str> {
        self.session_id
            .as_deref()
            .filter(|id| !id.trim().is_empty())
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StopManualResult {
    success: bool,
    stopped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
}

/// `stopManualSessionLog`: finalize the manual recording.
#[tauri::command]
pub async fn session_log_manual_stop<R: Runtime>(
    app: AppHandle<R>,
    payload: SessionIdPayload,
) -> StopManualResult {
    let result =
        |success, stopped, error: Option<&str>, file_path: Option<&Path>| StopManualResult {
            success,
            stopped,
            error: error.map(str::to_string),
            file_path: file_path.map(|p| p.to_string_lossy().into_owned()),
        };
    let Some(session_id) = non_empty(&payload.session_id).map(str::to_string) else {
        return result(false, false, Some(MISSING_SESSION_ID), None);
    };
    let logs = state(&app);
    let Some(token) = logs.manual_tokens.lock().get(&session_id).copied() else {
        return result(true, false, None, None);
    };
    let manual = logs.manual.clone();
    let id = session_id.clone();
    let stopped = match blocking(move || manual.stop_stream(&id, Some(token))).await {
        Ok(path) => path,
        Err(err) => return result(false, false, Some(&err.message), None),
    };
    match stopped {
        Some(path) => {
            logs.manual_tokens.lock().remove(&session_id);
            result(true, true, None, Some(&path))
        }
        None if !logs.manual.has_stream(&session_id) => {
            logs.manual_tokens.lock().remove(&session_id);
            result(false, true, Some("Failed to finalize session log"), None)
        }
        None => result(true, false, None, None),
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StatusResult {
    success: bool,
    is_logging: bool,
    has_session_log: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// `getManualSessionLogStatus`: `isLogging` = manual recording active;
/// `hasSessionLog` = a manual or automatic log can be opened.
#[tauri::command]
pub fn session_log_manual_status<R: Runtime>(
    app: AppHandle<R>,
    payload: SessionIdPayload,
) -> StatusResult {
    let Some(session_id) = payload.valid_id() else {
        return StatusResult {
            success: false,
            is_logging: false,
            has_session_log: false,
            error: Some(MISSING_SESSION_ID.into()),
        };
    };
    let logs = state(&app);
    StatusResult {
        success: true,
        is_logging: logs.manual.has_stream(session_id),
        has_session_log: logs.manual.has_session_log(session_id)
            || logs.auto.has_session_log(session_id),
        error: None,
    }
}

async fn prepare<R: Runtime>(app: &AppHandle<R>, payload: &SessionIdPayload) -> FileResult {
    let Some(session_id) = payload.valid_id().map(str::to_string) else {
        return FileResult::fail(MISSING_SESSION_ID);
    };
    let logs = state(app);
    // The manual log takes precedence over the automatic one.
    let manager = if logs.manual.has_session_log(&session_id) {
        logs.manual.clone()
    } else if logs.auto.has_session_log(&session_id) {
        logs.auto.clone()
    } else {
        return FileResult::fail(NO_SAVED_LOG);
    };
    match blocking(move || manager.prepare_session_log(&session_id)).await {
        Ok(Ok(Some(path))) => FileResult::ok(&path),
        Ok(Ok(None)) => FileResult::fail(NO_SAVED_LOG),
        Ok(Err(error)) => FileResult::fail(error),
        Err(err) => FileResult::fail(err.message),
    }
}

/// `prepareSessionLog`: flush the session's current (or last) log to disk and
/// return its path. Paths are never taken from the renderer.
#[tauri::command]
pub async fn session_log_prepare<R: Runtime>(
    app: AppHandle<R>,
    payload: SessionIdPayload,
) -> FileResult {
    prepare(&app, &payload).await
}

/// `revealSessionLog`: [`session_log_prepare`] + reveal in the file manager.
#[tauri::command]
pub async fn session_log_reveal<R: Runtime>(
    app: AppHandle<R>,
    payload: SessionIdPayload,
) -> FileResult {
    use tauri_plugin_opener::OpenerExt;
    let result = prepare(&app, &payload).await;
    let Some(path) = result.file_path.as_deref().filter(|_| result.success) else {
        return result;
    };
    match app.opener().reveal_item_in_dir(path) {
        Ok(()) => result,
        Err(err) => FileResult::fail(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_paths_get_the_format_extension() {
        assert_eq!(
            normalize_manual_log_path(PathBuf::from("/d/manual.txt"), "log"),
            PathBuf::from("/d/manual.txt.log")
        );
        assert_eq!(
            normalize_manual_log_path(PathBuf::from("/d/manual"), "txt"),
            PathBuf::from("/d/manual.txt")
        );
        assert_eq!(
            normalize_manual_log_path(PathBuf::from("/d/MANUAL.LOG"), "log"),
            PathBuf::from("/d/MANUAL.LOG")
        );
    }

    #[test]
    fn selections_are_single_use_and_scoped() {
        let state = SessionLogState::default();
        let first =
            state.register_selection("s", "/a.log".into(), LogFormat::Raw, Some("main".into()));
        let second =
            state.register_selection("s", "/b.log".into(), LogFormat::Txt, Some("main".into()));
        assert!(
            state.redeem_selection("s", &first, Some("main")).is_none(),
            "superseded"
        );
        assert!(state
            .redeem_selection("other", &second, Some("main"))
            .is_none());
        assert!(state
            .redeem_selection("s", &second, Some("settings"))
            .is_none());
        let choice = state.redeem_selection("s", &second, Some("main")).unwrap();
        assert_eq!(choice.file_path, PathBuf::from("/b.log"));
        assert_eq!(choice.format, LogFormat::Txt);
        assert!(
            state.redeem_selection("s", &second, Some("main")).is_none(),
            "single use"
        );
        assert_eq!(second.len(), 32);
    }

    #[test]
    fn manual_format_defaults_to_raw() {
        assert_eq!(manual_format(&None), LogFormat::Raw);
        assert_eq!(manual_format(&Some("html".into())), LogFormat::Html);
        assert_eq!(manual_format(&Some("bogus".into())), LogFormat::Raw);
    }
}

//! Script automation commands (Electron: `electron/bridges/scriptBridge.cjs`).
//! The logic lives in `netcatty-scripts`; this module adapts it to the app:
//! session writes go through the session registry (in order, one writer
//! task), output arrives through the registry's generic output tap, script
//! logs use the manual session-log stream manager, and requests to the
//! renderer are the Electron `netcatty:script:*` events.
//!
//! Contract: `rust/docs/ipc-scripts.md`.

use super::CmdResult;
use crate::sessions::OutputTapEvent;
use crate::state::AppState;
use crate::stream::{InputMeta, SessionInput};
use netcatty_core::CoreError;
use netcatty_scripts::manager::{
    AppendStepResult, HostSessionInfo, ManagerHost, OkResult, RecordingResult, RunParams, RunResult,
};
use netcatty_scripts::{ScriptManager, SerializedRun};
use netcatty_sessionlog::{FileStreamOptions, LogFormat};
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;
use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::mpsc;

/// One queued session write.
struct Write {
    session_id: String,
    data: String,
    automated: bool,
}

/// [`ManagerHost`] backed by the Tauri app.
pub struct TauriScriptHost<R: Runtime> {
    app: AppHandle<R>,
    writes: mpsc::UnboundedSender<Write>,
}

impl<R: Runtime> TauriScriptHost<R> {
    fn state(&self) -> Option<tauri::State<'_, AppState<R>>> {
        self.app.try_state::<AppState<R>>()
    }
}

impl<R: Runtime> ManagerHost for TauriScriptHost<R> {
    fn write_to_session(&self, session_id: &str, data: &str, automated: bool, _sensitive: bool) {
        // Session-log hook (sudo autofill markers), like `session_write`.
        super::sessionlog::session_input(&self.app, session_id, data, None);
        let _ = self.writes.send(Write {
            session_id: session_id.to_string(),
            data: data.to_string(),
            automated,
        });
    }

    fn close_session(&self, session_id: &str) {
        let app = self.app.clone();
        let session_id = session_id.to_string();
        tauri::async_runtime::spawn(async move {
            if let Some(state) = app.try_state::<AppState<R>>() {
                state.prompts.cancel_session(&session_id);
                let _ = state.sessions.close(&session_id).await;
            }
        });
    }

    fn emit(&self, event: &str, payload: Value) {
        crate::events::emit(&self.app, event, payload);
    }

    fn has_renderer(&self) -> bool {
        !self.app.webview_windows().is_empty()
    }

    fn session_info(&self, session_id: &str) -> Option<HostSessionInfo> {
        let state = self.state()?;
        let entry = state.sessions.get(session_id)?;
        let label = entry
            .try_lock()
            .map(|e| e.label.clone())
            .unwrap_or_default();
        let (hostname, username) = state
            .sessions
            .connection_of(session_id)
            .map(|c| {
                (
                    c.options.target.hostname.clone(),
                    c.options.target.username.clone(),
                )
            })
            .unwrap_or_default();
        Some(HostSessionInfo {
            label,
            hostname,
            username,
        })
    }

    fn start_session_log(
        &self,
        session_id: &str,
        file_path: PathBuf,
        host_label: &str,
    ) -> Result<u64, String> {
        let logs = self
            .app
            .try_state::<super::sessionlog::SessionLogState>()
            .ok_or_else(|| "Failed to start script log".to_string())?;
        let mut options = FileStreamOptions::new(file_path, LogFormat::Raw);
        options.host_label = host_label.to_string();
        options.stop_requires_token = true;
        logs.manual.start_stream_to_file(session_id, options)
    }

    fn stop_session_log(&self, session_id: &str, token: u64) {
        if let Some(logs) = self.app.try_state::<super::sessionlog::SessionLogState>() {
            logs.manual.stop_stream(session_id, Some(token));
        }
    }

    fn default_log_dir(&self) -> PathBuf {
        dirs::document_dir()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_default()
    }

    fn app_version(&self) -> String {
        self.app.package_info().version.to_string()
    }
}

/// Managed state: the app's script manager.
pub struct ScriptsState<R: Runtime> {
    pub manager: ScriptManager<TauriScriptHost<R>>,
}

/// Create the manager, start the ordered writer and subscribe to session
/// output. Call after [`AppState`] is managed.
pub fn setup<R: Runtime>(app: &tauri::App<R>) {
    let handle = app.handle().clone();
    let (writes_tx, mut writes_rx) = mpsc::unbounded_channel::<Write>();
    let manager = ScriptManager::new(TauriScriptHost {
        app: handle.clone(),
        writes: writes_tx,
    });

    // Writes are applied in order (sendLine body, then Enter).
    {
        let handle = handle.clone();
        tauri::async_runtime::spawn(async move {
            while let Some(write) = writes_rx.recv().await {
                let Some(state) = handle.try_state::<AppState<R>>() else {
                    continue;
                };
                let meta = InputMeta {
                    automated: write.automated,
                    serial_erase_char: None,
                };
                if let Err(err) = state
                    .sessions
                    .write_input(&write.session_id, SessionInput::Text(write.data), &meta)
                    .await
                {
                    tracing::debug!(session_id = %write.session_id, %err, "script write failed");
                }
            }
        });
    }

    // Session output → script buffers; session end → release resources.
    if let Some(state) = handle.try_state::<AppState<R>>() {
        let mut output = state.sessions.subscribe_all_output();
        let manager = manager.clone();
        tauri::async_runtime::spawn(async move {
            while let Some(event) = output.recv().await {
                match event {
                    OutputTapEvent::Data { session_id, text } => {
                        manager.append_session_output(&session_id, &text)
                    }
                    OutputTapEvent::Closed { session_id } => manager.session_closed(&session_id),
                }
            }
        });
    } else {
        tracing::warn!("script automation: AppState missing, session output is not tapped");
    }

    app.manage(ScriptsState { manager });
}

fn manager<R: Runtime>(app: &AppHandle<R>) -> CmdResult<ScriptManager<TauriScriptHost<R>>> {
    app.try_state::<ScriptsState<R>>()
        .map(|s| s.manager.clone())
        .ok_or_else(|| CoreError::internal("script automation is not initialized"))
}

#[tauri::command]
pub async fn script_run<R: Runtime>(app: AppHandle<R>, payload: RunParams) -> CmdResult<RunResult> {
    manager(&app)?
        .run(payload)
        .await
        .map_err(CoreError::invalid)
}

#[tauri::command]
pub fn script_stop<R: Runtime>(app: AppHandle<R>, run_id: String) -> CmdResult<OkResult> {
    Ok(manager(&app)?.stop(&run_id))
}

#[tauri::command]
pub fn script_pause<R: Runtime>(app: AppHandle<R>, run_id: String) -> CmdResult<OkResult> {
    Ok(manager(&app)?.pause(&run_id))
}

#[tauri::command]
pub fn script_resume<R: Runtime>(app: AppHandle<R>, run_id: String) -> CmdResult<OkResult> {
    Ok(manager(&app)?.resume(&run_id))
}

#[tauri::command]
pub fn script_get_runs<R: Runtime>(
    app: AppHandle<R>,
    session_id: Option<String>,
) -> CmdResult<Vec<SerializedRun>> {
    Ok(manager(&app)?.get_runs(session_id.as_deref()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DialogResponsePayload {
    pub request_id: String,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub cancelled: Option<bool>,
}

#[tauri::command]
pub fn script_dialog_response<R: Runtime>(
    app: AppHandle<R>,
    payload: DialogResponsePayload,
) -> CmdResult<OkResult> {
    Ok(manager(&app)?.dialog_response(
        &payload.request_id,
        payload.value,
        payload.cancelled.unwrap_or(false),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotResponsePayload {
    pub request_id: String,
    #[serde(default)]
    pub snapshot: Option<Value>,
}

#[tauri::command]
pub fn script_screen_snapshot_response<R: Runtime>(
    app: AppHandle<R>,
    payload: SnapshotResponsePayload,
) -> CmdResult<OkResult> {
    Ok(manager(&app)?.screen_snapshot_response(&payload.request_id, payload.snapshot))
}

#[tauri::command]
pub fn script_recording_start<R: Runtime>(
    app: AppHandle<R>,
    session_id: Option<String>,
) -> CmdResult<OkResult> {
    manager(&app)?
        .recording_start(session_id.as_deref().unwrap_or(""))
        .map_err(CoreError::invalid)
}

#[tauri::command]
pub fn script_recording_stop<R: Runtime>(
    app: AppHandle<R>,
    session_id: Option<String>,
) -> CmdResult<RecordingResult> {
    Ok(manager(&app)?.recording_stop(session_id.as_deref().unwrap_or("")))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppendStepPayload {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub step: Option<Value>,
}

#[tauri::command]
pub fn script_recording_append_step<R: Runtime>(
    app: AppHandle<R>,
    payload: AppendStepPayload,
) -> CmdResult<AppendStepResult> {
    Ok(manager(&app)?.recording_append_step(&payload.session_id, payload.step))
}

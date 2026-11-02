//! SFTP browse + transfer commands.

use super::session::SuccessResult;
use super::{header_str, raw_body, require_header, CmdResult};
use crate::connect;
use crate::events;
use crate::state::AppState;
use netcatty_core::ipc::{
    events as ev, EndpointType, OpenSftpResult, SftpConnectionProgress, SshSessionOptions,
    StreamTransferOptions, StreamTransferResult, TransferEvent, TransferEventType,
};
use netcatty_core::models::{
    FileEntryType, RemoteFile, SftpFilenameEncoding, StatResult, TransferDirection, TransferPhase,
};
use netcatty_core::CoreError;
use netcatty_sftp::transfer::{start_transfer, TransferEndpoints, TransferOutcome};
use netcatty_sftp::{SftpClient, TransferProgress, TransferRequest};
use netcatty_ssh::SshConnection;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, State};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HomeDirResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Minimum interval between two `progress` events of one transfer (~10/s).
pub const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

fn progress(app: &AppHandle, session_id: &str, label: &str, status: &str, detail: Option<String>) {
    events::emit(
        app,
        ev::SFTP_CONNECTION_PROGRESS,
        SftpConnectionProgress {
            session_id: session_id.to_string(),
            label: label.to_string(),
            status: status.to_string(),
            detail,
        },
    );
}

/// Filename encoding requested for a browser: the renderer may send
/// `encoding` / `filenameEncoding` alongside the SSH options.
fn encoding_from_payload(payload: &SshSessionOptions) -> SftpFilenameEncoding {
    ["encoding", "filenameEncoding", "sftpEncoding"]
        .iter()
        .filter_map(|key| payload.extra.get(*key))
        .find_map(|v| serde_json::from_value::<SftpFilenameEncoding>(v.clone()).ok())
        .unwrap_or_default()
}

/// Parse a header-borne encoding (`auto` | `utf-8` | `gb18030`).
fn parse_encoding(value: Option<String>) -> Option<SftpFilenameEncoding> {
    value.and_then(|v| serde_json::from_value(serde_json::Value::String(v)).ok())
}

fn label_for(payload: &SshSessionOptions) -> String {
    payload
        .host_label
        .clone()
        .filter(|l| !l.trim().is_empty())
        .unwrap_or_else(|| format!("{}@{}", payload.username, payload.hostname.trim()))
}

/// Open the SFTP subsystem on `connection` and register the client.
async fn open_on_connection(
    state: &AppState,
    connection: Arc<SshConnection>,
    reused: bool,
    encoding: SftpFilenameEncoding,
    session_id: &str,
    label: &str,
) -> CmdResult<OpenSftpResult> {
    let client = match SftpClient::open(connection.clone(), encoding).await {
        Ok(client) => client,
        Err(err) => {
            progress(
                &state.app,
                session_id,
                label,
                "error",
                Some(err.to_string()),
            );
            if !reused {
                let _ = connection.disconnect().await;
            }
            return Err(err.into());
        }
    };
    progress(&state.app, session_id, label, "connected", None);
    let sftp_id = netcatty_core::new_id();
    let home_dir = client.home_dir.clone();
    state.sftp.insert(sftp_id.clone(), Arc::new(client));
    Ok(OpenSftpResult {
        sftp_id,
        home_dir,
        reused_connection: Some(reused),
    })
}

async fn open_inner(
    state: &AppState,
    payload: &SshSessionOptions,
    fallback_session_id: Option<String>,
) -> CmdResult<OpenSftpResult> {
    connect::validate(payload)?;
    let session_id = payload
        .session_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or(fallback_session_id)
        .unwrap_or_else(netcatty_core::new_id);
    let label = label_for(payload);
    progress(&state.app, &session_id, &label, "connecting", None);
    let acquired = match connect::acquire(state, payload, &session_id, true).await {
        Ok(acquired) => acquired,
        Err(err) => {
            progress(
                &state.app,
                &session_id,
                &label,
                "error",
                Some(err.message.clone()),
            );
            return Err(err);
        }
    };
    open_on_connection(
        state,
        acquired.connection,
        acquired.reused,
        encoding_from_payload(payload),
        &session_id,
        &label,
    )
    .await
}

/// Open an SFTP browser on a fresh connection, or on the live connection of
/// `payload.sourceSessionId` (or any live session to the same endpoint) when
/// `reuseTransport != false`.
#[tauri::command]
pub async fn sftp_open(
    state: State<'_, AppState>,
    payload: SshSessionOptions,
) -> CmdResult<OpenSftpResult> {
    open_inner(&state, &payload, None).await
}

/// Open an SFTP browser on the connection of an existing terminal session.
/// Falls back to a regular open with `payload` when the session is gone.
#[tauri::command]
pub async fn sftp_open_for_session(
    state: State<'_, AppState>,
    session_id: String,
    payload: Option<SshSessionOptions>,
) -> CmdResult<OpenSftpResult> {
    if let Some(connection) = state.sessions.connection_of(&session_id) {
        let (label, encoding) = match &payload {
            Some(p) => (label_for(p), encoding_from_payload(p)),
            None => (connection.describe(), SftpFilenameEncoding::default()),
        };
        progress(
            &state.app,
            &session_id,
            &label,
            "connecting",
            Some("reusing session connection".into()),
        );
        return open_on_connection(&state, connection, true, encoding, &session_id, &label).await;
    }
    match payload {
        Some(mut p) => {
            p.source_session_id = Some(session_id.clone());
            open_inner(&state, &p, Some(session_id)).await
        }
        None => Err(CoreError::not_found(format!(
            "session {session_id} is not connected"
        ))),
    }
}

#[tauri::command]
pub async fn sftp_list(
    state: State<'_, AppState>,
    sftp_id: String,
    path: String,
    encoding: Option<SftpFilenameEncoding>,
) -> CmdResult<Vec<RemoteFile>> {
    Ok(state.sftp_client(&sftp_id)?.list(&path, encoding).await?)
}

#[tauri::command]
pub async fn sftp_realpath(
    state: State<'_, AppState>,
    sftp_id: String,
    path: String,
    encoding: Option<SftpFilenameEncoding>,
) -> CmdResult<String> {
    Ok(state
        .sftp_client(&sftp_id)?
        .realpath(&path, encoding)
        .await?)
}

/// Read as UTF-8 text (lossy).
#[tauri::command]
pub async fn sftp_read(
    state: State<'_, AppState>,
    sftp_id: String,
    path: String,
    encoding: Option<SftpFilenameEncoding>,
) -> CmdResult<String> {
    let bytes = state
        .sftp_client(&sftp_id)?
        .read(&path, None, encoding)
        .await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Read raw bytes; returned as an `ArrayBuffer` to the renderer.
#[tauri::command]
pub async fn sftp_read_binary(
    state: State<'_, AppState>,
    sftp_id: String,
    path: String,
    encoding: Option<SftpFilenameEncoding>,
) -> CmdResult<tauri::ipc::Response> {
    let bytes = state
        .sftp_client(&sftp_id)?
        .read(&path, None, encoding)
        .await?;
    Ok(tauri::ipc::Response::new(bytes))
}

#[tauri::command]
pub async fn sftp_write(
    state: State<'_, AppState>,
    sftp_id: String,
    path: String,
    content: String,
    encoding: Option<SftpFilenameEncoding>,
) -> CmdResult<()> {
    Ok(state
        .sftp_client(&sftp_id)?
        .write(&path, content.as_bytes(), encoding)
        .await?)
}

/// Binary write: the renderer invokes with a raw `ArrayBuffer` body and
/// passes `sftpId`, `path`, `encoding` as request headers.
#[tauri::command]
pub async fn sftp_write_binary(
    state: State<'_, AppState>,
    request: tauri::ipc::Request<'_>,
) -> CmdResult<()> {
    let body = raw_body(&request)?;
    let headers = request.headers();
    let sftp_id = require_header(headers, "sftpId")?;
    let path = require_header(headers, "path")?;
    let encoding = parse_encoding(header_str(headers, "encoding"));
    Ok(state
        .sftp_client(&sftp_id)?
        .write(&path, body, encoding)
        .await?)
}

#[tauri::command]
pub async fn sftp_mkdir(
    state: State<'_, AppState>,
    sftp_id: String,
    path: String,
    encoding: Option<SftpFilenameEncoding>,
) -> CmdResult<()> {
    Ok(state.sftp_client(&sftp_id)?.mkdir(&path, encoding).await?)
}

#[tauri::command]
pub async fn sftp_delete(
    state: State<'_, AppState>,
    sftp_id: String,
    path: String,
    encoding: Option<SftpFilenameEncoding>,
    expected_type: Option<FileEntryType>,
) -> CmdResult<()> {
    Ok(state
        .sftp_client(&sftp_id)?
        .delete(&path, expected_type, encoding)
        .await?)
}

#[tauri::command]
pub async fn sftp_rename(
    state: State<'_, AppState>,
    sftp_id: String,
    old_path: String,
    new_path: String,
    encoding: Option<SftpFilenameEncoding>,
) -> CmdResult<()> {
    Ok(state
        .sftp_client(&sftp_id)?
        .rename(&old_path, &new_path, encoding)
        .await?)
}

#[tauri::command]
pub async fn sftp_stat(
    state: State<'_, AppState>,
    sftp_id: String,
    path: String,
    encoding: Option<SftpFilenameEncoding>,
) -> CmdResult<StatResult> {
    Ok(state.sftp_client(&sftp_id)?.stat(&path, encoding).await?)
}

#[tauri::command]
pub async fn sftp_lstat(
    state: State<'_, AppState>,
    sftp_id: String,
    path: String,
    encoding: Option<SftpFilenameEncoding>,
) -> CmdResult<Option<StatResult>> {
    Ok(state.sftp_client(&sftp_id)?.lstat(&path, encoding).await?)
}

#[tauri::command]
pub async fn sftp_chmod(
    state: State<'_, AppState>,
    sftp_id: String,
    path: String,
    mode: String,
    encoding: Option<SftpFilenameEncoding>,
) -> CmdResult<()> {
    Ok(state
        .sftp_client(&sftp_id)?
        .chmod(&path, &mode, encoding)
        .await?)
}

#[tauri::command]
pub async fn sftp_extract(
    state: State<'_, AppState>,
    sftp_id: String,
    path: String,
    encoding: Option<SftpFilenameEncoding>,
) -> CmdResult<SuccessResult> {
    let client = state.sftp_client(&sftp_id)?;
    Ok(match client.extract_archive(&path, encoding).await {
        Ok(()) => SuccessResult::ok(),
        Err(err) => SuccessResult::fail(err.to_string()),
    })
}

#[tauri::command]
pub async fn sftp_home_dir(
    state: State<'_, AppState>,
    sftp_id: String,
    encoding: Option<SftpFilenameEncoding>,
) -> CmdResult<HomeDirResult> {
    let client = state.sftp_client(&sftp_id)?;
    if let Some(home) = client.home_dir.clone() {
        return Ok(HomeDirResult {
            success: true,
            home_dir: Some(home),
            error: None,
        });
    }
    Ok(match client.realpath(".", encoding).await {
        Ok(home) => HomeDirResult {
            success: true,
            home_dir: Some(home),
            error: None,
        },
        Err(err) => HomeDirResult {
            success: false,
            home_dir: None,
            error: Some(err.to_string()),
        },
    })
}

/// Close a browser. Idempotent. The underlying SSH connection is
/// disconnected only when no terminal session or other browser uses it.
#[tauri::command]
pub async fn sftp_close(state: State<'_, AppState>, sftp_id: String) -> CmdResult<SuccessResult> {
    let Some((_, client)) = state.sftp.remove(&sftp_id) else {
        return Ok(SuccessResult::ok());
    };
    let connection = client.connection.clone();
    match Arc::try_unwrap(client) {
        Ok(client) => {
            if let Err(err) = client.close().await {
                tracing::debug!(%err, "sftp close failed");
            }
        }
        Err(_shared) => {
            // A running transfer still holds the client; it closes with it.
            tracing::debug!(sftp_id, "sftp client still referenced by a transfer");
        }
    }
    state.release_connection(connection).await;
    Ok(SuccessResult::ok())
}

// ---------------------------------------------------------------------------
// Transfers
// ---------------------------------------------------------------------------

fn direction_for(source: EndpointType, target: EndpointType) -> TransferDirection {
    match (source, target) {
        (EndpointType::Local, EndpointType::Sftp) => TransferDirection::Upload,
        (EndpointType::Sftp, EndpointType::Local) => TransferDirection::Download,
        (EndpointType::Sftp, EndpointType::Sftp) => TransferDirection::RemoteToRemote,
        (EndpointType::Local, EndpointType::Local) => TransferDirection::LocalCopy,
    }
}

fn file_name_of(path: &str) -> String {
    path.trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
        .to_string()
}

/// The `started` event for a transfer; later events are derived from it.
pub fn started_event(payload: &StreamTransferOptions, now: i64) -> TransferEvent {
    TransferEvent {
        event_type: TransferEventType::Started,
        transfer_id: payload.transfer_id.clone(),
        direction: Some(direction_for(payload.source_type, payload.target_type)),
        file_name: Some(file_name_of(&payload.source_path)),
        source_path: Some(payload.source_path.clone()),
        target_path: Some(payload.target_path.clone()),
        started_at: Some(now),
        ended_at: None,
        error: None,
        transferred: Some(payload.checkpoint_bytes.unwrap_or(0)),
        total_bytes: payload.total_bytes,
        speed: None,
        checkpoint_bytes: payload.checkpoint_bytes,
        is_directory: Some(false),
        phase: Some(TransferPhase::Transferring),
        source_host_id: payload.source_host_id.clone(),
        target_host_id: payload.target_host_id.clone(),
        parent_task_id: payload.parent_task_id.clone(),
        resumable: payload.resumable,
    }
}

pub fn progress_event(base: &TransferEvent, progress: &TransferProgress) -> TransferEvent {
    TransferEvent {
        event_type: TransferEventType::Progress,
        transferred: Some(progress.transferred),
        total_bytes: progress.total.or(base.total_bytes),
        speed: Some(progress.speed),
        ..base.clone()
    }
}

/// Map a transfer outcome to the terminal event and the command result.
pub fn outcome_event(
    base: &TransferEvent,
    outcome: &TransferOutcome,
    now: i64,
) -> (TransferEvent, StreamTransferResult) {
    let mut event = base.clone();
    event.ended_at = Some(now);
    event.speed = None;
    let mut result = StreamTransferResult {
        transfer_id: base.transfer_id.clone(),
        ..Default::default()
    };
    match outcome {
        TransferOutcome::Completed { total } => {
            event.event_type = TransferEventType::Completed;
            event.transferred = Some(*total);
            event.total_bytes = Some(*total);
            result.total_bytes = Some(*total);
        }
        TransferOutcome::Cancelled { checkpoint_bytes } => {
            event.event_type = TransferEventType::Cancelled;
            event.transferred = Some(*checkpoint_bytes);
            event.checkpoint_bytes = Some(*checkpoint_bytes);
            result.cancelled = Some(true);
        }
        TransferOutcome::Paused { checkpoint_bytes } => {
            event.event_type = TransferEventType::Paused;
            event.transferred = Some(*checkpoint_bytes);
            event.checkpoint_bytes = Some(*checkpoint_bytes);
            result.cancelled = Some(true);
            result.warning = Some("paused".to_string());
        }
        TransferOutcome::Failed {
            error,
            checkpoint_bytes,
        } => {
            event.event_type = TransferEventType::Failed;
            event.error = Some(error.clone());
            event.transferred = Some(*checkpoint_bytes);
            event.checkpoint_bytes = Some(*checkpoint_bytes);
            result.error = Some(error.clone());
        }
    }
    result.total_bytes = result.total_bytes.or(event.total_bytes);
    (event, result)
}

fn endpoint(
    state: &AppState,
    kind: EndpointType,
    sftp_id: Option<&String>,
    field: &str,
) -> CmdResult<Option<Arc<SftpClient>>> {
    match kind {
        EndpointType::Local => Ok(None),
        EndpointType::Sftp => {
            let id = sftp_id.filter(|s| !s.is_empty()).ok_or_else(|| {
                CoreError::invalid(format!("{field} is required for an sftp endpoint"))
            })?;
            state.sftp_client(id).map(Some)
        }
    }
}

/// Start a streaming transfer; resolves when it completes, fails, pauses or
/// is cancelled. Progress is pushed on `netcatty:sftp:global-transfer`.
#[tauri::command]
pub async fn transfer_start(
    state: State<'_, AppState>,
    payload: StreamTransferOptions,
) -> CmdResult<StreamTransferResult> {
    if payload.transfer_id.trim().is_empty() {
        return Err(CoreError::invalid("transferId is required"));
    }
    if state.transfers.contains_key(&payload.transfer_id) {
        return Err(CoreError::invalid(format!(
            "transfer {} is already running",
            payload.transfer_id
        )));
    }
    let endpoints = TransferEndpoints {
        source: endpoint(
            &state,
            payload.source_type,
            payload.source_sftp_id.as_ref(),
            "sourceSftpId",
        )?,
        target: endpoint(
            &state,
            payload.target_type,
            payload.target_sftp_id.as_ref(),
            "targetSftpId",
        )?,
    };
    let request = TransferRequest {
        transfer_id: payload.transfer_id.clone(),
        source_type: payload.source_type,
        target_type: payload.target_type,
        source_path: payload.source_path.clone(),
        target_path: payload.target_path.clone(),
        total_bytes: payload.total_bytes,
        checkpoint_bytes: payload.checkpoint_bytes.unwrap_or(0),
        stage_target: true,
    };

    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<(String, TransferProgress)>();
    let mut handle = start_transfer(request, endpoints, Some(progress_tx))?;
    // Take the completion receiver so the handle can live in the registry
    // for cancel/pause while this command awaits the outcome.
    let (_dummy_tx, dummy_rx) = oneshot::channel();
    let done = std::mem::replace(&mut handle.done, dummy_rx);
    let transfer_id = payload.transfer_id.clone();
    state.transfers.insert(transfer_id.clone(), handle);

    let base = started_event(&payload, netcatty_core::ids::now_ms());
    events::emit(&state.app, ev::SFTP_GLOBAL_TRANSFER, base.clone());

    let app = state.app.clone();
    let template = base.clone();
    let forwarder = tokio::spawn(async move {
        let mut last_emit: Option<Instant> = None;
        while let Some((_, progress)) = progress_rx.recv().await {
            if last_emit
                .map(|t| t.elapsed() < PROGRESS_INTERVAL)
                .unwrap_or(false)
            {
                continue;
            }
            last_emit = Some(Instant::now());
            events::emit(
                &app,
                ev::SFTP_GLOBAL_TRANSFER,
                progress_event(&template, &progress),
            );
        }
    });

    let outcome = done.await;
    forwarder.abort();
    state.transfers.remove(&transfer_id);

    let outcome = outcome.unwrap_or_else(|_| TransferOutcome::Failed {
        error: "transfer task ended unexpectedly".to_string(),
        checkpoint_bytes: payload.checkpoint_bytes.unwrap_or(0),
    });
    let (event, result) = outcome_event(&base, &outcome, netcatty_core::ids::now_ms());
    events::emit(&state.app, ev::SFTP_GLOBAL_TRANSFER, event);
    Ok(result)
}

#[tauri::command]
pub async fn transfer_cancel(state: State<'_, AppState>, transfer_id: String) -> CmdResult<()> {
    if let Some(handle) = state.transfers.get(&transfer_id) {
        handle.cancel();
    }
    Ok(())
}

#[tauri::command]
pub async fn transfer_pause(
    state: State<'_, AppState>,
    transfer_id: String,
) -> CmdResult<SuccessResult> {
    Ok(match state.transfers.get(&transfer_id) {
        Some(handle) => {
            handle.pause();
            SuccessResult::ok()
        }
        None => SuccessResult::fail("transfer not found"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> StreamTransferOptions {
        serde_json::from_str(
            r#"{"transferId":"t1","sourcePath":"/local/dir/file.bin","targetPath":"/remote/file.bin",
                "sourceType":"local","targetType":"sftp","targetSftpId":"s1","totalBytes":1000,
                "sourceHostId":"h1","parentTaskId":"p1","resumable":true}"#,
        )
        .unwrap()
    }

    #[test]
    fn started_event_shape() {
        let ev = started_event(&options(), 42);
        assert_eq!(ev.event_type, TransferEventType::Started);
        assert_eq!(ev.direction, Some(TransferDirection::Upload));
        assert_eq!(ev.file_name.as_deref(), Some("file.bin"));
        assert_eq!(ev.started_at, Some(42));
        assert_eq!(ev.transferred, Some(0));
        assert_eq!(ev.total_bytes, Some(1000));
        assert_eq!(ev.parent_task_id.as_deref(), Some("p1"));
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["type"], "started");
        assert_eq!(json["direction"], "upload");
        assert!(json.get("error").is_none());
    }

    #[test]
    fn directions() {
        assert_eq!(
            direction_for(EndpointType::Sftp, EndpointType::Local),
            TransferDirection::Download
        );
        assert_eq!(
            direction_for(EndpointType::Sftp, EndpointType::Sftp),
            TransferDirection::RemoteToRemote
        );
        assert_eq!(
            direction_for(EndpointType::Local, EndpointType::Local),
            TransferDirection::LocalCopy
        );
        assert_eq!(file_name_of("C:\\data\\x.txt"), "x.txt");
        assert_eq!(file_name_of("/a/b/"), "b");
    }

    #[test]
    fn progress_event_carries_counters() {
        let base = started_event(&options(), 1);
        let p = TransferProgress {
            transferred: 500,
            total: Some(1000),
            speed: 2048.0,
        };
        let ev = progress_event(&base, &p);
        assert_eq!(ev.event_type, TransferEventType::Progress);
        assert_eq!(ev.transferred, Some(500));
        assert_eq!(ev.speed, Some(2048.0));
        assert_eq!(ev.transfer_id, "t1");
    }

    #[test]
    fn outcome_mapping() {
        let base = started_event(&options(), 1);
        let (ev, res) = outcome_event(&base, &TransferOutcome::Completed { total: 1000 }, 9);
        assert_eq!(ev.event_type, TransferEventType::Completed);
        assert_eq!(ev.ended_at, Some(9));
        assert_eq!(res.total_bytes, Some(1000));
        assert!(res.error.is_none() && res.cancelled.is_none());

        let (ev, res) = outcome_event(
            &base,
            &TransferOutcome::Cancelled {
                checkpoint_bytes: 300,
            },
            9,
        );
        assert_eq!(ev.event_type, TransferEventType::Cancelled);
        assert_eq!(ev.checkpoint_bytes, Some(300));
        assert_eq!(res.cancelled, Some(true));

        let (ev, res) = outcome_event(
            &base,
            &TransferOutcome::Paused {
                checkpoint_bytes: 300,
            },
            9,
        );
        assert_eq!(ev.event_type, TransferEventType::Paused);
        assert_eq!(res.warning.as_deref(), Some("paused"));

        let (ev, res) = outcome_event(
            &base,
            &TransferOutcome::Failed {
                error: "boom".into(),
                checkpoint_bytes: 7,
            },
            9,
        );
        assert_eq!(ev.event_type, TransferEventType::Failed);
        assert_eq!(ev.error.as_deref(), Some("boom"));
        assert_eq!(res.error.as_deref(), Some("boom"));
        assert_eq!(serde_json::to_value(&ev).unwrap()["type"], "failed");
    }

    #[test]
    fn encoding_parsing() {
        assert_eq!(
            parse_encoding(Some("gb18030".into())),
            Some(SftpFilenameEncoding::Gb18030)
        );
        assert_eq!(
            parse_encoding(Some("utf-8".into())),
            Some(SftpFilenameEncoding::Utf8)
        );
        assert_eq!(parse_encoding(Some("bogus".into())), None);
        assert_eq!(parse_encoding(None), None);
        let p: SshSessionOptions =
            serde_json::from_str(r#"{"hostname":"h","username":"u","encoding":"gb18030"}"#)
                .unwrap();
        assert_eq!(encoding_from_payload(&p), SftpFilenameEncoding::Gb18030);
        let p: SshSessionOptions =
            serde_json::from_str(r#"{"hostname":"h","username":"u"}"#).unwrap();
        assert_eq!(encoding_from_payload(&p), SftpFilenameEncoding::Auto);
    }
}

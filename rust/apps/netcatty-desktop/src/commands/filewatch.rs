//! "Edit locally, sync back" for SFTP files opened with an external app
//! (Electron: `fileWatcherBridge.cjs`).
//!
//! A watch polls the downloaded temp file once a second (like
//! `fs.watchFile`, robust against editors that save via rename). A change in
//! mtime or size is debounced for 500 ms and uploaded with the regular
//! transfer engine; syncs of one watch are serialized and a save that lands
//! during an upload triggers one more. Deleting the local file stops the
//! watch. Closing the SFTP session stops its watches and deletes the temp
//! files registered for it.
//!
//! Events: `netcatty:filewatch:synced`, `…:error`, `…:stopped`.

use super::CmdResult;
use crate::state::{AppState, Ctx};
use netcatty_core::ipc::{EndpointType, StreamTransferOptions};
use netcatty_core::models::SftpFilenameEncoding;
use netcatty_core::CoreError;
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tauri::{AppHandle, Manager, Runtime};
use tokio_util::sync::CancellationToken;

pub const EVENT_SYNCED: &str = "netcatty:filewatch:synced";
pub const EVENT_ERROR: &str = "netcatty:filewatch:error";
pub const EVENT_STOPPED: &str = "netcatty:filewatch:stopped";

const MAX_ACTIVE_FILE_WATCHERS: usize = 256;
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const DEBOUNCE: Duration = Duration::from_millis(500);
const CLEANUP_RETRY_DELAYS_MS: [u64; 5] = [100, 250, 500, 1000, 2000];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchInfo {
    watch_id: String,
    local_path: String,
    remote_path: String,
    sftp_id: String,
}

struct Watch {
    info: WatchInfo,
    encoding: Option<SftpFilenameEncoding>,
    cancel: CancellationToken,
    /// Transfer currently uploading this watch, for cancellation on stop.
    active_transfer: Arc<Mutex<Option<String>>>,
}

#[derive(Default)]
pub struct FileWatchState {
    watches: Mutex<HashMap<String, Watch>>,
    /// `sftpId\0localPath\0remotePath` → watchId (re-used on duplicate starts).
    by_key: Mutex<HashMap<String, String>>,
    /// Temp files downloaded for an SFTP session (deleted when it closes).
    temp_files: Mutex<HashMap<String, HashSet<String>>>,
}

fn watch_key(sftp_id: &str, local_path: &str, remote_path: &str) -> String {
    let local = std::path::absolute(local_path).unwrap_or_else(|_| PathBuf::from(local_path));
    format!("{sftp_id}\0{}\0{remote_path}", local.display())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    modified: Option<SystemTime>,
    size: u64,
}

fn stamp(path: &Path) -> std::io::Result<Stamp> {
    let meta = std::fs::metadata(path)?;
    Ok(Stamp {
        modified: meta.modified().ok(),
        size: meta.len(),
    })
}

/// Electron's test: modified when mtime moved forward or size changed.
fn changed(previous: Stamp, current: Stamp) -> bool {
    current.size != previous.size
        || match (previous.modified, current.modified) {
            (Some(p), Some(c)) => c > p,
            (None, Some(_)) => true,
            _ => false,
        }
}

/// Last component of a remote (POSIX) path.
fn remote_file_name(remote_path: &str) -> &str {
    remote_path.rsplit('/').next().unwrap_or(remote_path)
}

/// Best-effort delete with retries for files still held open (Windows).
pub async fn cleanup_temp_file(path: String) -> bool {
    for delay in std::iter::once(0).chain(CLEANUP_RETRY_DELAYS_MS) {
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        match tokio::fs::remove_file(&path).await {
            Ok(()) => return true,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return true,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => continue,
            Err(_) if cfg!(windows) => continue,
            Err(_) => return false,
        }
    }
    false
}

fn state<R: Runtime>(app: &AppHandle<R>) -> tauri::State<'_, FileWatchState> {
    app.state::<FileWatchState>()
}

// ---------------------------------------------------------------------------
// Sync loop
// ---------------------------------------------------------------------------

async fn sync_once<R: Runtime>(
    app: &AppHandle<R>,
    info: &WatchInfo,
    encoding: Option<SftpFilenameEncoding>,
    active_transfer: &Mutex<Option<String>>,
    sequence: u64,
    size: u64,
) -> Result<Option<String>, String> {
    let app_state = app.state::<AppState<R>>();
    if !app_state.sftp.contains_key(&info.sftp_id) {
        return Err("SFTP session not found or expired".into());
    }
    let transfer_id = format!("filewatch-{}-{sequence}", info.watch_id);
    *active_transfer.lock() = Some(transfer_id.clone());
    let options = StreamTransferOptions {
        transfer_id,
        source_path: info.local_path.clone(),
        target_path: info.remote_path.clone(),
        source_type: EndpointType::Local,
        target_type: EndpointType::Sftp,
        source_sftp_id: None,
        target_sftp_id: Some(info.sftp_id.clone()),
        source_host_id: None,
        target_host_id: None,
        parent_task_id: None,
        total_bytes: Some(size),
        source_encoding: None,
        target_encoding: encoding,
        resumable: Some(false),
        checkpoint_bytes: None,
        extra: Default::default(),
    };
    let result = super::sftp::run_transfer(&app_state, options, false).await;
    *active_transfer.lock() = None;
    let result = result.map_err(|e| e.message)?;
    if result.cancelled == Some(true)
        || result
            .error
            .as_deref()
            .is_some_and(|e| e.to_ascii_lowercase().contains("cancel"))
    {
        return Err("Transfer cancelled".into());
    }
    if let Some(error) = result.error {
        return Err(error);
    }
    Ok(result.warning)
}

async fn run_watch<R: Runtime>(
    app: AppHandle<R>,
    info: WatchInfo,
    encoding: Option<SftpFilenameEncoding>,
    cancel: CancellationToken,
    active_transfer: Arc<Mutex<Option<String>>>,
    mut last: Stamp,
) {
    let path = PathBuf::from(&info.local_path);
    let mut sequence = 0u64;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
        }
        let current = match stamp(&path) {
            Ok(current) => current,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // The local file was deleted: stop (Electron: nlink === 0).
                stop(&app, &info.watch_id, true, true);
                return;
            }
            Err(_) => continue,
        };
        if !changed(last, current) {
            continue;
        }
        // Debounce bursts of saves.
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(DEBOUNCE) => {}
        }
        // Serialized syncs: keep uploading while the file keeps changing.
        while let Ok(observed) = stamp(&path) {
            if !changed(last, observed) {
                break;
            }
            last = observed;
            sequence += 1;
            let outcome = tokio::select! {
                _ = cancel.cancelled() => return,
                outcome = sync_once(&app, &info, encoding, &active_transfer, sequence, observed.size) => outcome,
            };
            if cancel.is_cancelled() {
                return;
            }
            match outcome {
                Ok(warning) => {
                    let file_name = remote_file_name(&info.remote_path);
                    super::notification::show_simple(
                        &app,
                        "Netcatty",
                        warning
                            .as_deref()
                            .unwrap_or(&format!("File synced to remote: {file_name}")),
                    );
                    let mut payload = serde_json::json!({
                        "watchId": info.watch_id,
                        "localPath": info.local_path,
                        "remotePath": info.remote_path,
                        "bytesWritten": observed.size,
                    });
                    if let Some(warning) = warning {
                        payload["warning"] = warning.into();
                    }
                    crate::events::emit(&app, EVENT_SYNCED, payload);
                }
                Err(error) => {
                    // A newer save is retried by the next iteration; only
                    // report a failure for the latest version.
                    if stamp(&path).is_ok_and(|now| changed(last, now)) {
                        continue;
                    }
                    tracing::warn!(path = %info.local_path, %error, "file watch sync failed");
                    super::notification::show_simple(
                        &app,
                        "Netcatty",
                        &format!(
                            "Failed to sync {}: {error}",
                            remote_file_name(&info.remote_path)
                        ),
                    );
                    crate::events::emit(
                        &app,
                        EVENT_ERROR,
                        serde_json::json!({
                            "watchId": info.watch_id,
                            "localPath": info.local_path,
                            "remotePath": info.remote_path,
                            "error": error,
                        }),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public operations
// ---------------------------------------------------------------------------

/// Stop a watch. `forced` stops (deleted file, closed session) are reported
/// with a `stopped` event; `cleanup` deletes the temp file.
pub fn stop<R: Runtime>(app: &AppHandle<R>, watch_id: &str, cleanup: bool, forced: bool) -> bool {
    let files = state(app);
    let Some(watch) = files.watches.lock().remove(watch_id) else {
        return false;
    };
    let key = watch_key(
        &watch.info.sftp_id,
        &watch.info.local_path,
        &watch.info.remote_path,
    );
    {
        let mut by_key = files.by_key.lock();
        if by_key.get(&key).map(String::as_str) == Some(watch_id) {
            by_key.remove(&key);
        }
    }
    watch.cancel.cancel();
    if let Some(transfer_id) = watch.active_transfer.lock().take() {
        if let Some(handle) = app.state::<AppState<R>>().transfers.get(&transfer_id) {
            handle.cancel();
        }
    }
    if forced {
        crate::events::emit(app, EVENT_STOPPED, watch.info.clone());
    }
    if cleanup {
        if let Some(set) = files.temp_files.lock().get_mut(&watch.info.sftp_id) {
            set.remove(&watch.info.local_path);
        }
        tauri::async_runtime::spawn(cleanup_temp_file(watch.info.local_path));
    }
    true
}

/// Called when an SFTP session closes: stop its watches and delete the temp
/// files registered for it.
pub fn stop_for_session<R: Runtime>(app: &AppHandle<R>, sftp_id: &str) {
    let Some(files) = app.try_state::<FileWatchState>() else {
        return;
    };
    let ids: Vec<String> = files
        .watches
        .lock()
        .iter()
        .filter(|(_, w)| w.info.sftp_id == sftp_id)
        .map(|(id, _)| id.clone())
        .collect();
    for id in ids {
        stop(app, &id, true, true);
    }
    let temp = files.temp_files.lock().remove(sftp_id).unwrap_or_default();
    for path in temp {
        tauri::async_runtime::spawn(cleanup_temp_file(path));
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartResult {
    watch_id: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    reused: bool,
}

#[derive(Serialize)]
pub struct Success {
    success: bool,
}

#[tauri::command]
pub async fn filewatch_start<R: Runtime>(
    state: Ctx<'_, R>,
    local_path: String,
    remote_path: String,
    sftp_id: String,
    encoding: Option<SftpFilenameEncoding>,
) -> CmdResult<StartResult> {
    let files = state.app.state::<FileWatchState>();
    let key = watch_key(&sftp_id, &local_path, &remote_path);
    if let Some(existing) = files.by_key.lock().get(&key).cloned() {
        if let Some(watch) = files.watches.lock().get_mut(&existing) {
            watch.encoding = encoding;
            return Ok(StartResult {
                watch_id: existing,
                reused: true,
            });
        }
    }
    if files.watches.lock().len() >= MAX_ACTIVE_FILE_WATCHERS {
        return Err(CoreError::invalid(format!(
            "Too many active external file watches (max {MAX_ACTIVE_FILE_WATCHERS})"
        )));
    }
    let initial = stamp(Path::new(&local_path))
        .map_err(|err| CoreError::io(format!("Cannot watch file: {err}")))?;

    let watch_id = format!("watch-{}", netcatty_core::new_id());
    let info = WatchInfo {
        watch_id: watch_id.clone(),
        local_path,
        remote_path,
        sftp_id,
    };
    let cancel = CancellationToken::new();
    let active_transfer = Arc::new(Mutex::new(None));
    {
        let mut by_key = files.by_key.lock();
        // A concurrent identical start won the race: reuse it.
        if let Some(existing) = by_key.get(&key) {
            return Ok(StartResult {
                watch_id: existing.clone(),
                reused: true,
            });
        }
        by_key.insert(key, watch_id.clone());
        files.watches.lock().insert(
            watch_id.clone(),
            Watch {
                info: info.clone(),
                encoding,
                cancel: cancel.clone(),
                active_transfer: active_transfer.clone(),
            },
        );
    }
    tauri::async_runtime::spawn(run_watch(
        state.app.clone(),
        info,
        encoding,
        cancel,
        active_transfer,
        initial,
    ));
    Ok(StartResult {
        watch_id,
        reused: false,
    })
}

#[tauri::command]
pub fn filewatch_stop<R: Runtime>(
    app: AppHandle<R>,
    watch_id: String,
    cleanup_temp_file: Option<bool>,
) -> Success {
    Success {
        success: stop(&app, &watch_id, cleanup_temp_file.unwrap_or(false), false),
    }
}

#[tauri::command]
pub fn filewatch_list<R: Runtime>(app: AppHandle<R>) -> Vec<WatchInfo> {
    state(&app)
        .watches
        .lock()
        .values()
        .map(|w| w.info.clone())
        .collect()
}

#[tauri::command]
pub fn filewatch_register_temp_file<R: Runtime>(
    app: AppHandle<R>,
    sftp_id: String,
    local_path: String,
) -> Success {
    state(&app)
        .temp_files
        .lock()
        .entry(sftp_id)
        .or_default()
        .insert(local_path);
    Success { success: true }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnregisterResult {
    success: bool,
    retained: bool,
    was_tracked: bool,
}

/// Forget a temp file and delete it unless a watch still uses it.
#[tauri::command]
pub async fn filewatch_unregister_temp_file<R: Runtime>(
    app: AppHandle<R>,
    sftp_id: String,
    local_path: String,
) -> UnregisterResult {
    let files = state(&app);
    let was_tracked = {
        let mut temp = files.temp_files.lock();
        let tracked = temp
            .get_mut(&sftp_id)
            .is_some_and(|s| s.remove(&local_path));
        if temp.get(&sftp_id).is_some_and(HashSet::is_empty) {
            temp.remove(&sftp_id);
        }
        tracked
    };
    let retained = files
        .watches
        .lock()
        .values()
        .any(|w| w.info.sftp_id == sftp_id && w.info.local_path == local_path);
    if !retained {
        cleanup_temp_file(local_path).await;
    }
    UnregisterResult {
        success: true,
        retained,
        was_tracked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64, size: u64) -> Stamp {
        Stamp {
            modified: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs)),
            size,
        }
    }

    #[test]
    fn change_detection_matches_electron() {
        assert!(!changed(at(10, 5), at(10, 5)));
        assert!(!changed(at(10, 5), at(9, 5)));
        assert!(changed(at(10, 5), at(11, 5)));
        assert!(changed(at(10, 5), at(10, 6)));
    }

    #[test]
    fn watch_keys_resolve_relative_paths() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            watch_key("s", "a.txt", "/r"),
            format!("s\0{}\0/r", cwd.join("a.txt").display())
        );
    }

    #[tokio::test]
    async fn cleanup_handles_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x");
        std::fs::write(&file, "1").unwrap();
        assert!(cleanup_temp_file(file.to_string_lossy().into_owned()).await);
        assert!(!file.exists());
        assert!(cleanup_temp_file(file.to_string_lossy().into_owned()).await);
    }
}

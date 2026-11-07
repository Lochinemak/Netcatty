//! Opening remote files in external applications and native confirmations
//! (Electron: the `selectApplication`, `openWithApplication`,
//! `sftp:downloadToTempWithProgress` and `dialog:confirmCloseBusy`
//! handlers in `electron/main/registerBridges.cjs`).

use super::CmdResult;
use crate::state::Ctx;
use netcatty_core::ipc::{EndpointType, StreamTransferOptions};
use netcatty_core::models::SftpFilenameEncoding;
use netcatty_core::CoreError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tauri::{AppHandle, Runtime};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

#[derive(Serialize)]
pub struct SelectedApplication {
    path: String,
    name: String,
}

/// Display name: the file name without its extension (`Visual Studio Code`
/// for `Visual Studio Code.app`).
fn application_name(path: &Path) -> String {
    path.file_stem()
        .or_else(|| path.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Native picker for an application (macOS bundles, Windows executables,
/// anything on Linux).
#[tauri::command]
pub async fn app_select_application<R: Runtime>(
    app: AppHandle<R>,
) -> CmdResult<Option<SelectedApplication>> {
    let mut dialog = app.dialog().file().set_title("Select Application");
    if cfg!(target_os = "macos") {
        dialog = dialog
            .add_filter("Applications", &["app"])
            .set_directory("/Applications");
    } else if cfg!(windows) {
        dialog = dialog
            .add_filter("Executables", &["exe", "com", "bat", "cmd"])
            .set_directory("C:\\Program Files");
    } else {
        dialog = dialog.set_directory("/usr/bin");
    }
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_pick_file())
        .await
        .map_err(|e| CoreError::internal(e.to_string()))?;
    Ok(picked
        .and_then(|p| p.into_path().ok())
        .map(|path| SelectedApplication {
            name: application_name(&path),
            path: path.to_string_lossy().into_owned(),
        }))
}

fn spawn_application(file_path: &str, app_path: &str) -> std::io::Result<std::process::Child> {
    use std::process::{Command, Stdio};
    let mut command = if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg("-a").arg(app_path).arg(file_path);
        c
    } else {
        let mut c = Command::new(app_path);
        c.arg(file_path);
        c
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
}

/// Launch `appPath` on `filePath`. Resolves `true` once the process started
/// (launch failures such as a missing app reject, so the renderer can clean
/// up its temp download). On macOS `open` reports a bad app via its exit
/// status, which is awaited briefly.
#[tauri::command]
pub async fn app_open_with_application(file_path: String, app_path: String) -> CmdResult<bool> {
    if file_path.trim().is_empty() || app_path.trim().is_empty() {
        return Err(CoreError::invalid("filePath and appPath are required"));
    }
    tauri::async_runtime::spawn_blocking(move || {
        let mut child = spawn_application(&file_path, &app_path)
            .map_err(|e| CoreError::io(format!("Failed to start application: {e}")))?;
        if cfg!(target_os = "macos") {
            // `open` exits quickly; a non-zero status means it could not
            // launch the application.
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                match child.try_wait() {
                    Ok(Some(status)) if !status.success() => {
                        let mut stderr = String::new();
                        if let Some(mut pipe) = child.stderr.take() {
                            use std::io::Read;
                            let _ = pipe.read_to_string(&mut stderr);
                        }
                        let detail = stderr.trim();
                        return Err(CoreError::io(if detail.is_empty() {
                            format!("Failed to start application ({status})")
                        } else {
                            detail.to_owned()
                        }));
                    }
                    Ok(Some(_)) => break,
                    Ok(None) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    _ => break,
                }
            }
        } else {
            // Many Windows editors hand the file to a running instance and
            // exit at once; only the spawn itself is a failure signal.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Ok(true)
    })
    .await
    .map_err(|e| CoreError::internal(e.to_string()))?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TempDownload {
    local_path: String,
    cancelled: bool,
}

/// Download a remote file into the temp dir for "open with" / edit-and-sync.
/// Progress and completion arrive as regular global transfer events under
/// `transferId`; a cancelled download resolves `{ cancelled: true }`.
#[tauri::command]
pub async fn sftp_download_to_temp<R: Runtime>(
    state: Ctx<'_, R>,
    sftp_id: String,
    remote_path: String,
    file_name: String,
    encoding: Option<SftpFilenameEncoding>,
    transfer_id: String,
) -> CmdResult<TempDownload> {
    let local: PathBuf = super::tempdir::temp_file_path(&state.app, &file_name);
    let local_path = local.to_string_lossy().into_owned();
    let options = StreamTransferOptions {
        transfer_id,
        source_path: remote_path,
        target_path: local_path.clone(),
        source_type: EndpointType::Sftp,
        target_type: EndpointType::Local,
        source_sftp_id: Some(sftp_id),
        target_sftp_id: None,
        source_host_id: None,
        target_host_id: None,
        parent_task_id: None,
        total_bytes: None,
        source_encoding: encoding,
        target_encoding: None,
        resumable: None,
        checkpoint_bytes: None,
        extra: Default::default(),
    };
    let result = super::sftp::run_transfer(&state, options, true).await;
    let cleanup = || {
        let _ = std::fs::remove_file(&local);
    };
    let result = match result {
        Ok(result) => result,
        Err(err) => {
            cleanup();
            return Err(err);
        }
    };
    if result.cancelled == Some(true) || result.error.as_deref() == Some("Transfer cancelled") {
        cleanup();
        return Ok(TempDownload {
            local_path,
            cancelled: true,
        });
    }
    if let Some(error) = result.error {
        cleanup();
        return Err(CoreError::io(error));
    }
    Ok(TempDownload {
        local_path,
        cancelled: false,
    })
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmCloseBusy {
    command: Option<String>,
    title: Option<String>,
    message: Option<String>,
    cancel_label: Option<String>,
    close_label: Option<String>,
}

/// Warning dialog before closing a terminal with a running process; `true`
/// only when the user picks Close (dismissal is "cancel").
#[tauri::command]
pub async fn dialog_confirm_close_busy<R: Runtime>(
    app: AppHandle<R>,
    payload: Option<ConfirmCloseBusy>,
) -> CmdResult<bool> {
    let p = payload.unwrap_or_default();
    let command = p.command.unwrap_or_else(|| "unknown".into());
    let message = p.message.unwrap_or_else(|| {
        format!("Process \"{command}\" is still running and will be terminated.")
    });
    let dialog = app
        .dialog()
        .message(message)
        .title(p.title.unwrap_or_else(|| "Confirm close".into()))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            p.close_label.unwrap_or_else(|| "Close".into()),
            p.cancel_label.unwrap_or_else(|| "Cancel".into()),
        ));
    tauri::async_runtime::spawn_blocking(move || dialog.blocking_show())
        .await
        .map_err(|e| CoreError::internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_names_drop_extensions() {
        assert_eq!(
            application_name(Path::new("/Applications/Visual Studio Code.app")),
            "Visual Studio Code"
        );
        assert_eq!(application_name(Path::new("/usr/bin/vim")), "vim");
    }

    #[tokio::test]
    async fn open_with_reports_missing_applications() {
        let err =
            app_open_with_application("/tmp/x.txt".into(), "/definitely/not/an/app-xyz".into())
                .await
                .unwrap_err();
        assert!(!err.message.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Same-host directory copy (Electron: `transferBridge.sameHostCopyDirectory`)
// ---------------------------------------------------------------------------

/// POSIX single-quote a path for the remote shell.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// `mkdir -p target && cp -ra source/. target/` (copies the contents, so an
/// existing target is merged rather than nested).
fn same_host_copy_command(source: &str, target: &str) -> String {
    let target = target.replace('\\', "/");
    format!(
        "mkdir -p {} && cp -ra {} {}",
        shell_quote(&target),
        shell_quote(&format!("{source}/.")),
        shell_quote(&format!("{target}/")),
    )
}

#[derive(Serialize)]
pub struct CopyResult {
    success: bool,
}

/// Copy a directory on the remote host with `cp`. Any failure (no exec
/// channel, `cp` missing, non-zero exit) resolves `{ success: false }` and the
/// renderer falls back to its per-file copy, exactly like Electron.
#[tauri::command]
pub async fn sftp_same_host_copy_dir<R: Runtime>(
    state: Ctx<'_, R>,
    sftp_id: String,
    source_path: String,
    target_path: String,
) -> CmdResult<CopyResult> {
    let Ok(client) = state.sftp_client(&sftp_id) else {
        return Ok(CopyResult { success: false });
    };
    let command = same_host_copy_command(&source_path, &target_path);
    let success = match client.connection.exec(&command, None).await {
        Ok(output) => output.exit_code == Some(0),
        Err(err) => {
            tracing::debug!(%err, "same-host copy exec failed; falling back");
            false
        }
    };
    Ok(CopyResult { success })
}

#[cfg(test)]
mod copy_tests {
    use super::*;

    #[test]
    fn builds_a_quoted_copy_command() {
        assert_eq!(
            same_host_copy_command("/srv/it's", "/srv\\backup"),
            "mkdir -p '/srv/backup' && cp -ra '/srv/it'\\''s/.' '/srv/backup/'"
        );
    }
}

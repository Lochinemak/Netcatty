//! Temp-directory commands: staging renderer `File` objects for upload and
//! deleting Netcatty-owned temp files (mirrors `tempDirBridge.cjs` /
//! `netcatty:deleteTempFile`).
//!
//! The webview cannot hand the backend a local path for a dropped or picked
//! `File`, so the adapter streams its bytes here in chunks:
//! `temp_upload_begin` creates an empty `.part` file, `temp_upload_chunk`
//! appends a raw body to it, and the resulting path is then uploaded like
//! any local file. Every path is validated to live inside the temp dir.

use super::session::SuccessResult;
use super::{raw_body, require_header, CmdResult};
use crate::state::Ctx;
use netcatty_core::CoreError;
use std::path::{Path, PathBuf};

fn sanitize_component(value: &str, fallback: &str, pattern: fn(char) -> bool) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| if pattern(c) { '_' } else { c })
        .collect();
    if cleaned.trim().is_empty() {
        fallback.to_string()
    } else {
        cleaned
    }
}

/// `<temp>/.transfer_<transferId>_<fileName>.part`, same naming as Electron.
pub fn transfer_temp_file_path(temp_dir: &Path, transfer_id: &str, file_name: &str) -> PathBuf {
    let safe_id = sanitize_component(transfer_id, "transfer", |c| {
        !(c.is_ascii_alphanumeric() || c == '_' || c == '-')
    });
    let safe_name = sanitize_component(file_name, "file", |c| {
        matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || c.is_control()
    });
    temp_dir.join(format!(".transfer_{safe_id}_{safe_name}.part"))
}

/// True when `path` resolves inside `temp_dir` (symlinks resolved for the
/// parent; the file itself may not exist yet).
pub fn is_inside_temp_dir(temp_dir: &Path, path: &Path) -> bool {
    let Ok(temp) = std::fs::canonicalize(temp_dir) else {
        return false;
    };
    let parent = match path.parent() {
        Some(p) => p,
        None => return false,
    };
    let Ok(parent) = std::fs::canonicalize(parent) else {
        return false;
    };
    parent.starts_with(&temp)
        && path
            .file_name()
            .map(|n| n != "." && n != "..")
            .unwrap_or(false)
}

fn ensure_temp_path(temp_dir: &Path, path: &str) -> CmdResult<PathBuf> {
    let candidate = PathBuf::from(path);
    if !is_inside_temp_dir(temp_dir, &candidate) {
        return Err(CoreError::invalid(
            "refusing to touch a file outside the Netcatty temp directory",
        ));
    }
    Ok(candidate)
}

/// Create an empty staging file for an upload and return its path.
#[tauri::command]
pub async fn temp_upload_begin<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    transfer_id: String,
    file_name: String,
) -> CmdResult<String> {
    let temp_dir = state.paths.temp_dir();
    tokio::fs::create_dir_all(&temp_dir).await?;
    let path = transfer_temp_file_path(&temp_dir, &transfer_id, &file_name);
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    options.open(&path).await.map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            CoreError::invalid("an upload with this id is already being staged")
        } else {
            CoreError::from(err)
        }
    })?;
    Ok(path.to_string_lossy().into_owned())
}

/// Append a raw body to a staging file. Header `path` names the file
/// returned by `temp_upload_begin`.
#[tauri::command]
pub async fn temp_upload_chunk<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    request: tauri::ipc::Request<'_>,
) -> CmdResult<u64> {
    let path = require_header(request.headers(), "path")?;
    let path = ensure_temp_path(&state.paths.temp_dir(), &path)?;
    let body = raw_body(&request)?;
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .await?;
    file.write_all(body).await?;
    file.flush().await?;
    let len = file.metadata().await?.len();
    Ok(len)
}

/// Delete a file inside the temp directory (staged uploads, downloads
/// opened in an editor). Paths elsewhere are refused.
#[tauri::command]
pub async fn temp_delete_file<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    file_path: String,
) -> CmdResult<SuccessResult> {
    let path = match ensure_temp_path(&state.paths.temp_dir(), &file_path) {
        Ok(path) => path,
        Err(err) => {
            tracing::warn!(path = %file_path, "{}", err.message);
            return Ok(SuccessResult::fail(err.message));
        }
    };
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(SuccessResult::ok()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(SuccessResult::ok()),
        Err(err) => Ok(SuccessResult::fail(err.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_file_naming_matches_electron() {
        let p = transfer_temp_file_path(Path::new("/tmp/nc"), "t-1/x", "a:b/c.zip");
        assert_eq!(p, PathBuf::from("/tmp/nc/.transfer_t-1_x_a_b_c.zip.part"));
        let p = transfer_temp_file_path(Path::new("/tmp/nc"), "", "");
        assert_eq!(p, PathBuf::from("/tmp/nc/.transfer_transfer_file.part"));
    }

    #[test]
    fn temp_dir_containment() {
        let dir = tempfile::tempdir().unwrap();
        let inside = dir.path().join("x.part");
        assert!(is_inside_temp_dir(dir.path(), &inside));
        assert!(!is_inside_temp_dir(dir.path(), Path::new("/etc/passwd")));
        assert!(!is_inside_temp_dir(
            dir.path(),
            &dir.path().join("..").join("y")
        ));
        let nested = dir.path().join("sub");
        std::fs::create_dir(&nested).unwrap();
        assert!(is_inside_temp_dir(dir.path(), &nested.join("z")));
    }
}

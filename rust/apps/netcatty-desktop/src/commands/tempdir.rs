//! Temp directory management (Electron: `tempDirBridge.cjs`, minus the AI
//! tool-output store): info, clear, open and a user-chosen root.
//!
//! The effective temp dir is [`current`]: the custom root when one is set,
//! else `AppPaths::temp_dir()`. A custom root follows Electron's rules: an
//! absolute path, `Netcatty` appended unless it is already the last
//! component, no symlinked ancestors, created 0700, and either empty or
//! carrying the `.netcatty-managed-temp` marker (so clearing can never wipe
//! an unrelated directory). The choice persists in `temp-dir-pref.json`.

use crate::state::Ctx;
use netcatty_store::AppPaths;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager, Runtime};

const NETCATTY_TEMP_DIR_NAME: &str = "Netcatty";
pub const MANAGED_TEMP_MARKER: &str = ".netcatty-managed-temp";
const PREF_FILE: &str = "temp-dir-pref.json";

/// Custom temp root (managed state).
#[derive(Default)]
pub struct TempDirState {
    custom: RwLock<Option<PathBuf>>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Pref {
    custom_temp_dir: Option<String>,
}

impl TempDirState {
    /// Restore the persisted custom root; an invalid one is ignored (logged).
    pub fn load(paths: &AppPaths) -> Self {
        let pref: Pref = std::fs::read_to_string(paths.data_dir.join(PREF_FILE))
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();
        let custom = pref
            .custom_temp_dir
            .and_then(|dir| match validate_temp_root(&dir) {
                Ok(dir) => Some(dir),
                Err(err) => {
                    tracing::warn!(%err, "invalid custom temp directory preference");
                    None
                }
            });
        Self {
            custom: RwLock::new(custom),
        }
    }
}

/// Effective temp directory for `app`.
pub fn current<R: Runtime>(app: &AppHandle<R>) -> PathBuf {
    let custom = app
        .try_state::<TempDirState>()
        .and_then(|state| state.custom.read().clone());
    custom.unwrap_or_else(|| app.state::<crate::state::AppState<R>>().paths.temp_dir())
}

/// Electron's `validateTempRoot`: returns the managed directory to use.
pub fn validate_temp_root(input: &str) -> Result<PathBuf, String> {
    let trimmed = input.trim();
    let selected = PathBuf::from(trimmed);
    if trimmed.is_empty() || trimmed.contains('\0') || !selected.is_absolute() {
        return Err("Please enter an absolute directory path.".into());
    }
    let selected: PathBuf = selected.components().collect();
    let dir = if selected
        .file_name()
        .is_some_and(|n| n == NETCATTY_TEMP_DIR_NAME)
    {
        selected
    } else {
        selected.join(NETCATTY_TEMP_DIR_NAME)
    };
    // Reject symlinked ancestors before creating anything beneath them.
    let mut existing = dir.as_path();
    while !existing.exists() {
        match existing.parent() {
            Some(parent) => existing = parent,
            None => break,
        }
    }
    let real = std::fs::canonicalize(existing).map_err(|e| e.to_string())?;
    if real != existing {
        return Err("Temporary directory must not traverse symbolic links.".into());
    }
    create_private_dir(&dir).map_err(|e| e.to_string())?;
    let meta = std::fs::symlink_metadata(&dir).map_err(|e| e.to_string())?;
    if !meta.is_dir() {
        return Err("Netcatty temp path is not a safe directory.".into());
    }
    let marker = dir.join(MANAGED_TEMP_MARKER);
    let has_marker = std::fs::symlink_metadata(&marker).is_ok_and(|m| m.is_file());
    let has_entries = std::fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .next()
        .is_some();
    if has_entries && !has_marker {
        return Err(
            "Existing Netcatty directory is not empty and is not managed by Netcatty.".into(),
        );
    }
    if !has_marker {
        std::fs::write(&marker, b"").map_err(|e| e.to_string())?;
    }
    Ok(dir)
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

fn write_pref(paths: &AppPaths, custom: Option<&Path>) -> Result<(), String> {
    let pref = Pref {
        custom_temp_dir: custom.map(|p| p.to_string_lossy().into_owned()),
    };
    let target = paths.data_dir.join(PREF_FILE);
    let pending = target.with_extension(format!("json.{}.pending", std::process::id()));
    let body = serde_json::to_vec(&pref).map_err(|e| e.to_string())?;
    let result = std::fs::write(&pending, body).and_then(|()| std::fs::rename(&pending, &target));
    let _ = std::fs::remove_file(&pending);
    result.map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TempDirInfo {
    path: String,
    file_count: usize,
    total_size: u64,
    is_custom: bool,
    default_path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClearResult {
    deleted_count: usize,
    failed_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
pub struct SetResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl SetResult {
    fn from(result: Result<PathBuf, String>) -> Self {
        match result {
            Ok(path) => Self {
                ok: true,
                path: Some(path.to_string_lossy().into_owned()),
                error: None,
            },
            Err(error) => Self {
                ok: false,
                path: None,
                error: Some(error),
            },
        }
    }
}

#[derive(Serialize)]
pub struct Success {
    success: bool,
}

/// Top-level regular files (marker excluded), like Electron.
#[tauri::command]
pub fn tempdir_info<R: Runtime>(state: Ctx<'_, R>) -> TempDirInfo {
    let dir = current(&state.app);
    let _ = std::fs::create_dir_all(&dir);
    let (mut file_count, mut total_size) = (0, 0);
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            if entry.file_name() == MANAGED_TEMP_MARKER {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    file_count += 1;
                    total_size += meta.len();
                }
            }
        }
    }
    let is_custom = state
        .app
        .try_state::<TempDirState>()
        .is_some_and(|s| s.custom.read().is_some());
    TempDirInfo {
        path: dir.to_string_lossy().into_owned(),
        file_count,
        total_size,
        is_custom,
        default_path: state.paths.temp_dir().to_string_lossy().into_owned(),
    }
}

/// Delete every entry except the managed marker.
#[tauri::command]
pub fn tempdir_clear<R: Runtime>(state: Ctx<'_, R>) -> ClearResult {
    let dir = current(&state.app);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return ClearResult {
                deleted_count: 0,
                failed_count: 0,
                error: None,
            }
        }
        Err(err) => {
            return ClearResult {
                deleted_count: 0,
                failed_count: 0,
                error: Some(err.to_string()),
            }
        }
    };
    let (mut deleted_count, mut failed_count) = (0, 0);
    for entry in entries.flatten() {
        if entry.file_name() == MANAGED_TEMP_MARKER {
            continue;
        }
        let path = entry.path();
        let result = match entry.file_type() {
            Ok(kind) if kind.is_dir() => std::fs::remove_dir_all(&path),
            Ok(_) => std::fs::remove_file(&path),
            Err(err) => Err(err),
        };
        match result {
            Ok(()) => deleted_count += 1,
            Err(_) => failed_count += 1,
        }
    }
    ClearResult {
        deleted_count,
        failed_count,
        error: None,
    }
}

#[tauri::command]
pub fn tempdir_open<R: Runtime>(state: Ctx<'_, R>) -> Success {
    use tauri_plugin_opener::OpenerExt;
    let dir = current(&state.app);
    let _ = std::fs::create_dir_all(&dir);
    Success {
        success: state
            .app
            .opener()
            .open_path(dir.to_string_lossy(), None::<&str>)
            .is_ok(),
    }
}

#[tauri::command]
pub fn tempdir_set_custom<R: Runtime>(state: Ctx<'_, R>, dir: Option<String>) -> SetResult {
    let result = validate_temp_root(dir.as_deref().unwrap_or("")).and_then(|validated| {
        write_pref(&state.paths, Some(&validated))?;
        if let Some(temp) = state.app.try_state::<TempDirState>() {
            *temp.custom.write() = Some(validated.clone());
        }
        Ok(validated)
    });
    SetResult::from(result)
}

#[tauri::command]
pub fn tempdir_reset_custom<R: Runtime>(state: Ctx<'_, R>) -> SetResult {
    let dir = state.paths.temp_dir();
    let result = create_private_dir(&dir)
        .map_err(|e| e.to_string())
        .and_then(|()| write_pref(&state.paths, None))
        .map(|()| {
            if let Some(temp) = state.app.try_state::<TempDirState>() {
                *temp.custom.write() = None;
            }
            dir
        });
    SetResult::from(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_custom_roots_like_electron() {
        let base = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(base.path()).unwrap();
        assert!(validate_temp_root("relative/dir").is_err());
        assert!(validate_temp_root("").is_err());

        let dir = validate_temp_root(base.join("scratch").to_str().unwrap()).unwrap();
        assert_eq!(dir, base.join("scratch").join("Netcatty"));
        assert!(dir.join(MANAGED_TEMP_MARKER).is_file());
        // Already named Netcatty → used as is; re-validating a managed dir works.
        assert_eq!(validate_temp_root(dir.to_str().unwrap()).unwrap(), dir);

        let foreign = base.join("other").join("Netcatty");
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("keep.txt"), "x").unwrap();
        assert_eq!(
            validate_temp_root(foreign.to_str().unwrap()).unwrap_err(),
            "Existing Netcatty directory is not empty and is not managed by Netcatty."
        );

        #[cfg(unix)]
        {
            let link = base.join("link");
            std::os::unix::fs::symlink(base.join("scratch"), &link).unwrap();
            assert_eq!(
                validate_temp_root(link.join("sub").to_str().unwrap()).unwrap_err(),
                "Temporary directory must not traverse symbolic links."
            );
        }
    }
}

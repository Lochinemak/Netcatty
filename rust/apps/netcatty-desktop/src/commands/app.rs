//! App-level and system commands.

use super::CmdResult;
use crate::state::AppState;
use netcatty_core::ipc::SystemInfo;
use tauri::State;

#[tauri::command]
pub fn app_get_version(app: tauri::AppHandle) -> String {
    app.package_info().version.to_string()
}

#[tauri::command]
pub fn app_get_temp_dir_path(state: State<'_, AppState>) -> String {
    state.paths.temp_dir().to_string_lossy().into_owned()
}

/// Reveal a path in Finder / Explorer / the file manager.
#[tauri::command]
pub async fn app_reveal_in_folder(app: tauri::AppHandle, path: String) -> CmdResult<()> {
    use tauri_plugin_opener::OpenerExt;
    if path.trim().is_empty() {
        return Err(netcatty_core::CoreError::invalid("path is required"));
    }
    app.opener()
        .reveal_item_in_dir(&path)
        .map_err(|err| netcatty_core::CoreError::io(err.to_string()))
}

#[tauri::command]
pub fn system_info() -> SystemInfo {
    netcatty_localfs::system_info()
}

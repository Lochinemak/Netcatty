//! App-level and system commands.

use super::CmdResult;
use crate::state::Ctx;
use netcatty_core::ipc::SystemInfo;

#[tauri::command]
pub fn app_get_version<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> String {
    app.package_info().version.to_string()
}

#[tauri::command]
pub fn app_get_temp_dir_path<R: tauri::Runtime>(state: Ctx<'_, R>) -> String {
    super::tempdir::current(&state.app)
        .to_string_lossy()
        .into_owned()
}

/// Reveal a path in Finder / Explorer / the file manager.
#[tauri::command]
pub async fn app_reveal_in_folder<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    path: String,
) -> CmdResult<()> {
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

/// Renderer diagnostics (uncaught errors, unhandled rejections, console
/// errors) forwarded by the Tauri bridge adapter so they show up next to the
/// backend logs. Messages are truncated; nothing is parsed or acted upon.
#[tauri::command]
pub fn app_renderer_log(level: String, message: String, source: Option<String>) {
    const MAX: usize = 4096;
    let message: String = message.chars().take(MAX).collect();
    let source = source.unwrap_or_default();
    match level.as_str() {
        "error" => tracing::error!(target: "renderer", %source, "{message}"),
        "warn" => tracing::warn!(target: "renderer", %source, "{message}"),
        _ => tracing::info!(target: "renderer", %source, "{message}"),
    }
}

// ---------------------------------------------------------------------------
// App-level HTTP proxy (Electron: `httpNetworkProxyBridge.cjs`). Applies to
// the backend's HTTP calls (cloud sync, OAuth); the renderer re-applies its
// stored setting at startup, so nothing is persisted here.
// ---------------------------------------------------------------------------

use netcatty_sync::proxy::{ProxySettings, RawProxySettings};

#[derive(serde::Serialize)]
pub struct ProxyApplied {
    success: bool,
    settings: ProxySettings,
}

#[derive(serde::Serialize)]
pub struct ProxyCurrent {
    settings: ProxySettings,
}

#[tauri::command]
pub fn app_set_http_proxy(settings: Option<RawProxySettings>) -> ProxyApplied {
    let settings = netcatty_sync::proxy::normalize(&settings.unwrap_or_default());
    netcatty_sync::proxy::set(settings.clone());
    ProxyApplied {
        success: true,
        settings,
    }
}

#[tauri::command]
pub fn app_get_http_proxy() -> ProxyCurrent {
    ProxyCurrent {
        settings: netcatty_sync::proxy::current(),
    }
}

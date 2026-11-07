//! Launch at login, hidden to the tray (Electron: `autoLaunch.cjs`), on
//! `tauri-plugin-autostart`.
//!
//! The login entry starts the app with `--hidden` (see
//! [`super::tray::HIDDEN_LAUNCH_ARG`]): macOS LaunchAgent, Windows `Run`
//! registry value, Linux XDG autostart entry (AppImage path when packaged as
//! one). Debug builds report `supported: false`, like Electron's dev runs, so
//! a login item never points at a transient development binary.
//!
//! `success` means "`enabled` is trustworthy" (Electron semantics): a failed
//! read reports `success: false` so the renderer keeps its cached state.

use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_autostart::AutoLaunchManager;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AutoLaunchResult {
    success: bool,
    enabled: bool,
    supported: bool,
}

const UNSUPPORTED: AutoLaunchResult = AutoLaunchResult {
    success: true,
    enabled: false,
    supported: false,
};

/// Register the autostart plugin (launch arguments: `--hidden`).
pub fn setup<R: Runtime>(app: &tauri::App<R>) {
    let plugin = tauri_plugin_autostart::Builder::new()
        .arg(super::tray::HIDDEN_LAUNCH_ARG)
        .app_name("Netcatty")
        .build();
    if let Err(err) = app.handle().plugin(plugin) {
        tracing::warn!(%err, "autostart unavailable");
    }
}

fn manager<R: Runtime>(app: &AppHandle<R>) -> Option<tauri::State<'_, AutoLaunchManager>> {
    if cfg!(debug_assertions) {
        return None;
    }
    app.try_state::<AutoLaunchManager>()
}

fn read(manager: &AutoLaunchManager) -> AutoLaunchResult {
    match manager.is_enabled() {
        Ok(enabled) => AutoLaunchResult {
            success: true,
            enabled,
            supported: true,
        },
        Err(err) => {
            tracing::warn!(%err, "failed to read the autostart entry");
            AutoLaunchResult {
                success: false,
                enabled: false,
                supported: true,
            }
        }
    }
}

#[tauri::command]
pub async fn autostart_get<R: Runtime>(app: AppHandle<R>) -> AutoLaunchResult {
    match manager(&app) {
        Some(manager) => read(&manager),
        None => UNSUPPORTED,
    }
}

/// Enable / disable; returns the state read back afterwards. When the write
/// fails the read still tells the renderer the real (unchanged) state.
#[tauri::command]
pub async fn autostart_set<R: Runtime>(app: AppHandle<R>, enabled: bool) -> AutoLaunchResult {
    let Some(manager) = manager(&app) else {
        return UNSUPPORTED;
    };
    let written = if enabled {
        manager.enable()
    } else {
        manager.disable()
    };
    if let Err(err) = written {
        tracing::warn!(%err, enabled, "failed to update the autostart entry");
    }
    read(&manager)
}

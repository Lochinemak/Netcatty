//! App lock (Electron `appLockRuntimeBridge.cjs` + `appLockLifecycle.cjs`);
//! logic in `netcatty-applock`.

use crate::commands::CmdResult;
use netcatty_applock::{
    AppLockController, AppLockEvents, AppLockSettings, ControllerOptions, MutationResult, OkResult,
    PlatformSystemAuth, RuntimeState, SettingsStore, SystemUnlockStatus, APP_LOCK_SETTINGS_FILE,
};
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tauri::{AppHandle, Manager, Runtime};

pub const EVENT_RUNTIME_STATE_CHANGED: &str = "netcatty:appLock:runtimeStateChanged";
pub const EVENT_SETTINGS_CHANGED: &str = "netcatty:appLock:settingsChanged";
pub const EVENT_REOPEN: &str = "netcatty:app-lock:reopen";
/// Title every window shows while the app is locked.
const LOCKED_TITLE: &str = "Netcatty";

// ---------------------------------------------------------------------------
// App lock state + lifecycle hooks
// ---------------------------------------------------------------------------

/// Managed app-lock state: the controller plus the real window titles that
/// are hidden while locked (Electron `lockedWindowTitles`).
pub struct AppLockState {
    pub controller: Arc<AppLockController>,
    titles: Arc<Mutex<HashMap<String, String>>>,
}

struct TauriAppLockEvents<R: Runtime> {
    app: AppHandle<R>,
    titles: Arc<Mutex<HashMap<String, String>>>,
}

impl<R: Runtime> TauriAppLockEvents<R> {
    /// Locked: every window shows the bare app name (so a session / file
    /// name never leaks into the window switcher). Unlocked: restore them.
    fn protect_windows(&self, state: &RuntimeState) {
        let windows = self.app.webview_windows();
        let mut titles = self.titles.lock();
        if state.locked {
            for (label, window) in windows {
                if let Ok(current) = window.title() {
                    if current != LOCKED_TITLE && !current.is_empty() {
                        titles.insert(label.clone(), current);
                    }
                }
                let _ = window.set_title(LOCKED_TITLE);
            }
            return;
        }
        for (label, title) in titles.drain() {
            if let Some(window) = windows.get(&label) {
                if window.title().ok().as_deref() == Some(LOCKED_TITLE) {
                    let _ = window.set_title(&title);
                }
            }
        }
    }
}

impl<R: Runtime> AppLockEvents for TauriAppLockEvents<R> {
    fn runtime_state_changed(&self, state: &RuntimeState) {
        self.protect_windows(state);
        crate::events::emit(&self.app, EVENT_RUNTIME_STATE_CHANGED, state.clone());
    }

    fn settings_changed(&self, public_settings: &AppLockSettings) {
        crate::events::emit(&self.app, EVENT_SETTINGS_CHANGED, public_settings.clone());
    }
}

/// Owner window for the Windows Hello dialog: the focused window, else main.
fn native_window_handle<R: Runtime>(app: &AppHandle<R>) -> Option<isize> {
    #[cfg(windows)]
    {
        let windows = app.webview_windows();
        let window = windows
            .values()
            .find(|w| w.is_focused().unwrap_or(false))
            .or_else(|| windows.get(crate::commands::window::MAIN_LABEL))
            .or_else(|| windows.values().next())?;
        window.hwnd().ok().map(|h| h.0 as isize)
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        None
    }
}

/// Load the settings and initialise the runtime (locked with reason
/// `startup` when enabled). Wired once in `lib.rs` setup.
pub fn setup<R: Runtime>(app: &tauri::App<R>) {
    let handle = app.handle().clone();
    let titles = Arc::new(Mutex::new(HashMap::new()));
    let paths = netcatty_store::AppPaths::resolve();
    let window_handle = handle.clone();
    let controller = AppLockController::new(ControllerOptions {
        store: SettingsStore::new(paths.data_dir.join(APP_LOCK_SETTINGS_FILE)),
        system_auth: Arc::new(PlatformSystemAuth::new(Box::new(move || {
            native_window_handle(&window_handle)
        }))),
        events: Arc::new(TauriAppLockEvents {
            app: handle.clone(),
            titles: titles.clone(),
        }),
        clock: netcatty_applock::wall_clock(),
        failure_delay: netcatty_applock::tokio_failure_delay(),
        runtime: tauri::async_runtime::handle().inner().clone(),
        new_verifier_iterations: None,
    });
    let initial = controller.initialize();
    app.manage(AppLockState { controller, titles });
    if initial.locked {
        // Windows created before setup already carry their titles.
        TauriAppLockEvents {
            app: handle,
            titles: app.state::<AppLockState>().titles.clone(),
        }
        .protect_windows(&initial);
    }
}

fn app_lock<R: Runtime>(app: &AppHandle<R>) -> Option<Arc<AppLockController>> {
    app.try_state::<AppLockState>().map(|s| s.controller.clone())
}

/// `true` while the app lock is engaged (other modules can gate on it, like
/// Electron's cloud-sync password reader and plugin host).
pub fn is_app_locked<R: Runtime>(app: &AppHandle<R>) -> bool {
    app_lock(app).map(|c| c.is_locked()).unwrap_or(false)
}

/// Hide-to-tray / hotkey hide / app hide: lock with reason `background`
/// (ignored when the lock is off or set to "Never").
pub fn lock_for_background<R: Runtime>(app: &AppHandle<R>) {
    if let Some(controller) = app_lock(app) {
        controller.set_locked(Some("background"));
    }
}

/// The app was brought back to the foreground (Dock click, tray, hotkey,
/// second instance): tell every window so a background lock can auto-prompt
/// Touch ID / Windows Hello.
pub fn notify_reopen<R: Runtime>(app: &AppHandle<R>) {
    crate::events::emit(app, EVENT_REOPEN, ());
}

/// `window_set_title` while locked: remember the requested title and keep
/// showing the app name. Returns `true` when the title was deferred.
pub fn defer_window_title<R: Runtime>(app: &AppHandle<R>, label: &str, title: &str) -> bool {
    let Some(state) = app.try_state::<AppLockState>() else {
        return false;
    };
    if !state.controller.is_locked() {
        return false;
    }
    state.titles.lock().insert(label.to_string(), title.to_string());
    if let Some(window) = app.get_webview_window(label) {
        let _ = window.set_title(LOCKED_TITLE);
    }
    true
}

fn require<R: Runtime>(app: &AppHandle<R>) -> CmdResult<Arc<AppLockController>> {
    app_lock(app).ok_or_else(|| netcatty_core::CoreError::internal("app lock is not initialised"))
}

// ---------------------------------------------------------------------------
// App lock commands (`netcatty:appLock:*`)
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn app_lock_get_runtime_state<R: Runtime>(app: AppHandle<R>) -> CmdResult<RuntimeState> {
    Ok(require(&app)?.runtime_state())
}

#[tauri::command]
pub fn app_lock_get_settings<R: Runtime>(app: AppHandle<R>) -> CmdResult<AppLockSettings> {
    Ok(require(&app)?.public_settings())
}

#[tauri::command]
pub async fn app_lock_set_timeout_minutes<R: Runtime>(
    app: AppHandle<R>,
    timeout_minutes: Option<Value>,
) -> CmdResult<MutationResult> {
    Ok(require(&app)?
        .set_timeout_minutes(&timeout_minutes.unwrap_or(Value::Null))
        .await)
}

#[tauri::command]
pub async fn app_lock_request_enable<R: Runtime>(app: AppHandle<R>) -> CmdResult<MutationResult> {
    Ok(require(&app)?.request_enable().await)
}

#[tauri::command]
pub async fn app_lock_request_disable<R: Runtime>(
    app: AppHandle<R>,
    current_password: Option<String>,
) -> CmdResult<MutationResult> {
    Ok(require(&app)?
        .request_disable(current_password.as_deref().unwrap_or(""))
        .await)
}

#[tauri::command]
pub async fn app_lock_request_reset<R: Runtime>(
    app: AppHandle<R>,
    current_password: Option<String>,
) -> CmdResult<MutationResult> {
    Ok(require(&app)?
        .request_reset(current_password.as_deref().unwrap_or(""))
        .await)
}

#[tauri::command]
pub async fn app_lock_request_password_change<R: Runtime>(
    app: AppHandle<R>,
    input: Option<Value>,
) -> CmdResult<MutationResult> {
    Ok(require(&app)?
        .request_password_change(&input.unwrap_or(Value::Null))
        .await)
}

#[tauri::command]
pub fn app_lock_set_locked<R: Runtime>(
    app: AppHandle<R>,
    reason: Option<String>,
) -> CmdResult<RuntimeState> {
    Ok(require(&app)?.set_locked(reason.as_deref()))
}

#[tauri::command]
pub async fn app_lock_request_unlock<R: Runtime>(
    app: AppHandle<R>,
    password: Option<String>,
) -> CmdResult<OkResult> {
    Ok(require(&app)?
        .request_unlock(password.unwrap_or_default())
        .await)
}

#[tauri::command]
pub async fn app_lock_get_system_unlock_status<R: Runtime>(
    app: AppHandle<R>,
) -> CmdResult<SystemUnlockStatus> {
    Ok(require(&app)?.system_unlock_status().await)
}

#[tauri::command]
pub async fn app_lock_set_system_unlock_enabled<R: Runtime>(
    app: AppHandle<R>,
    input: Option<Value>,
) -> CmdResult<MutationResult> {
    Ok(require(&app)?
        .set_system_unlock_enabled(&input.unwrap_or(Value::Null))
        .await)
}

#[tauri::command]
pub async fn app_lock_request_system_unlock<R: Runtime>(app: AppHandle<R>) -> CmdResult<OkResult> {
    Ok(require(&app)?.request_system_unlock().await)
}

#[tauri::command]
pub fn app_lock_report_activity<R: Runtime>(app: AppHandle<R>) -> CmdResult<()> {
    require(&app)?.report_activity();
    Ok(())
}

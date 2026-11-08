//! Multi-window support (Electron: `windowManager/editorWindow.cjs`,
//! `terminalPopupWindow.cjs`, `terminalPopupPlacement.cjs`, the
//! `netcatty:window:openSession` handler, `terminalAttachRestore.cjs`, the
//! attach / snapshot handlers of `terminalBridge.cjs`,
//! `rendererSessionLifetime.cjs`, `dirtyEditorGuard.cjs` + the `before-quit`
//! guard, window opacity / background blur, the macOS application menu and
//! its Cmd+W routing). See `rust/docs/ipc-windows.md`.
//!
//! Every extra window loads the same renderer (`index.html`) with the
//! Electron hash route, so the renderer code paths are unchanged:
//!
//! | label | route | Electron |
//! | --- | --- | --- |
//! | `editor` | `#/editor-window` | the single detached SFTP editor window |
//! | `terminal-popup-<n>` | `#/terminal-popup` | system-manager / AI observe popups |
//! | `session-<n>` | `#/session-window` | "open session in new window" |

mod editor;
pub mod placement;
mod replies;
pub mod routes;
pub mod sanitize;

use super::window::{MAIN_LABEL, SETTINGS_LABEL};
use super::CmdResult;
use crate::state::AppState;
use netcatty_core::CoreError;
use parking_lot::Mutex;
use placement::Rect;
use replies::{ReplyBroker, ReplyError};
use routes::{AttachGrants, OutputRoutes, RouteChange};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tauri::{
    AppHandle, Emitter, Manager, PhysicalPosition, PhysicalSize, RunEvent, Runtime, WebviewUrl,
    WebviewWindow, WebviewWindowBuilder, WindowEvent,
};
use tokio::sync::oneshot;

pub const EDITOR_LABEL: &str = "editor";
pub const POPUP_LABEL_PREFIX: &str = "terminal-popup-";
pub const SESSION_LABEL_PREFIX: &str = "session-";

/// Electron: `QUIT_GUARD_TIMEOUT_MS` and the 5 s window-close dirty query.
const DIRTY_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Electron: `TERMINAL_SNAPSHOT_TIMEOUT_MS`.
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(2);
/// Electron: `ATTACH_CLOSE_PREPARE_TIMEOUT_MS`.
const ATTACH_CLOSE_PREPARE_TIMEOUT: Duration = Duration::from_secs(2);
/// Electron: `sendWhenRendererReady(..., { timeoutMs: 8000 })`.
const OPEN_SESSION_DELIVERY_TIMEOUT: Duration = Duration::from_secs(8);
/// Show a hidden window when the renderer never reports ready.
const SHOW_FALLBACK: Duration = Duration::from_secs(3);

const POPUP_WIDTH: f64 = 920.0;
const POPUP_HEIGHT: f64 = 580.0;
const POPUP_MIN_WIDTH: f64 = 480.0;
const POPUP_MIN_HEIGHT: f64 = 320.0;
const SESSION_WIDTH: f64 = 1400.0;
const SESSION_HEIGHT: f64 = 900.0;

/// Renderer-facing events (Electron channel names; the route event is
/// Tauri-only).
pub mod events {
    pub use super::editor::events::*;
    pub const TERMINAL_POPUP_CONFIG: &str = "netcatty:window:terminalPopupConfig";
    pub const TERMINAL_POPUP_PREPARE_CLOSE: &str = "netcatty:terminal-popup:prepare-close";
    pub const OPEN_SESSION: &str = "netcatty:window:openSession";
    pub const SNAPSHOT_REQUEST: &str = "netcatty:terminal:snapshot-request";
    pub const SNAPSHOT_RESPONSE: &str = "netcatty:terminal:snapshot-response";
    pub const APPLY_SNAPSHOT: &str = "netcatty:terminal:apply-snapshot";
    pub const APPLY_SNAPSHOT_RESPONSE: &str = "netcatty:terminal:apply-snapshot-response";
    pub const WINDOW_SHOWN: &str = "netcatty:window:shown";
    pub const WINDOW_WILL_HIDE: &str = "netcatty:window:will-hide";
    pub const WINDOW_FOCUS_REQUESTED: &str = "netcatty:window:focus-requested";
    pub const WINDOW_COMMAND_CLOSE: &str = "netcatty:window:command-close";
    /// Tauri-only: display window of a session's output changed.
    pub const SESSION_OUTPUT_ROUTE: &str = "netcatty:window:session-output-route";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppWindowKind {
    Editor,
    Popup,
    Session,
}

impl AppWindowKind {
    fn route(self) -> &'static str {
        match self {
            AppWindowKind::Editor => "editor-window",
            AppWindowKind::Popup => "terminal-popup",
            AppWindowKind::Session => "session-window",
        }
    }
}

struct PopupRecord {
    popup_id: String,
    attach_session: Option<String>,
    authorization: Option<String>,
    close_requested: bool,
}

struct PendingOpenSession {
    payload: Value,
    delivered: Option<oneshot::Sender<()>>,
}

/// Managed state (runtime independent).
#[derive(Default)]
pub struct WindowsState {
    replies: ReplyBroker,
    editor: Mutex<editor::EditorRegistry>,
    routes: Mutex<OutputRoutes>,
    grants: Mutex<AttachGrants>,
    /// Terminal popups keyed by window label.
    popups: Mutex<HashMap<String, PopupRecord>>,
    /// `onTerminalPopupConfig` payload per popup window (pulled by the page).
    popup_configs: Mutex<HashMap<String, Value>>,
    /// `onOpenSessionInNewWindow` payload per session window.
    open_sessions: Mutex<HashMap<String, PendingOpenSession>>,
    /// Stable numeric ids standing in for Electron's `webContents.id`.
    window_ids: Mutex<HashMap<String, u64>>,
    /// Windows whose unsaved-editor check passed (the next close proceeds).
    close_confirmed: Mutex<HashSet<String>>,
    close_pending: Mutex<HashSet<String>>,
    terminal_focus: Mutex<HashMap<String, bool>>,
    /// Labels switched to a transparent backing for the blur material.
    transparent: Mutex<HashSet<String>>,
    opacity: Mutex<Option<f64>>,
    blur_requested: AtomicBool,
    quitting: AtomicBool,
    quit_confirmed: AtomicBool,
    quit_busy: AtomicBool,
    counter: AtomicU64,
}

impl WindowsState {
    fn quitting(&self) -> bool {
        self.quitting.load(Ordering::SeqCst)
    }

    fn opacity(&self) -> f64 {
        self.opacity.lock().unwrap_or(1.0)
    }

    fn next(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn window_id(&self, label: &str) -> u64 {
        let mut ids = self.window_ids.lock();
        if let Some(id) = ids.get(label) {
            return *id;
        }
        let id = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        ids.insert(label.to_owned(), id);
        id
    }

    fn label_of(&self, id: u64) -> Option<String> {
        self.window_ids
            .lock()
            .iter()
            .find(|(_, v)| **v == id)
            .map(|(k, _)| k.clone())
    }
}

pub(crate) fn state<R: Runtime>(app: &AppHandle<R>) -> tauri::State<'_, WindowsState> {
    app.state::<WindowsState>()
}

fn internal(err: impl std::fmt::Display) -> CoreError {
    CoreError::internal(err.to_string())
}

/// Manage [`WindowsState`] and install the macOS application menu.
pub fn setup<R: Runtime>(app: &tauri::App<R>) {
    app.manage(WindowsState::default());
    #[cfg(target_os = "macos")]
    {
        menu::install(app.handle(), "en");
        app.on_menu_event(|app, event| menu::on_event(app, event.id().as_ref()));
    }
}

fn is_session_window(label: &str) -> bool {
    label.starts_with(SESSION_LABEL_PREFIX)
}

fn is_popup_window(label: &str) -> bool {
    label.starts_with(POPUP_LABEL_PREFIX)
}

/// Windows that render app content (Electron: `getAppContentWindows`).
fn is_app_content_window(label: &str) -> bool {
    label == MAIN_LABEL
        || label == EDITOR_LABEL
        || is_popup_window(label)
        || is_session_window(label)
}

// ---------------------------------------------------------------------------
// Window helpers
// ---------------------------------------------------------------------------

pub(crate) fn show_and_focus<R: Runtime>(window: &WebviewWindow<R>) {
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
    if window.label() == MAIN_LABEL || is_session_window(window.label()) {
        notify_window_shown(window.app_handle(), window.label());
    }
}

fn emit_to_window<R: Runtime>(app: &AppHandle<R>, label: &str, event: &str) {
    if app.get_webview_window(label).is_some() {
        let _ = app.emit_to(label, event, ());
    }
}

/// `onWindowShown`: the window became visible (Electron: `win.on("show")`).
pub(crate) fn notify_window_shown<R: Runtime>(app: &AppHandle<R>, label: &str) {
    emit_to_window(app, label, events::WINDOW_SHOWN);
}

/// `onWindowWillHide`: call right BEFORE hiding a window so the renderer can
/// dismiss transient overlays (Electron: `notifyWindowWillHide`).
pub(crate) fn notify_window_will_hide<R: Runtime>(app: &AppHandle<R>, label: &str) {
    emit_to_window(app, label, events::WINDOW_WILL_HIDE);
}

/// `onWindowFocusRequested`: an explicit foreground request (hotkey, tray,
/// Dock) brought the window forward (Electron: `notifyWindowFocusRequested`).
pub(crate) fn notify_window_focus_requested<R: Runtime>(app: &AppHandle<R>, label: &str) {
    emit_to_window(app, label, events::WINDOW_FOCUS_REQUESTED);
}

fn schedule_show_fallback<R: Runtime>(window: WebviewWindow<R>) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(SHOW_FALLBACK).await;
        if !window.is_visible().unwrap_or(true) {
            show_and_focus(&window);
        }
    });
}

/// Work area of the monitor `source` is on and its outer / inner frames,
/// in physical pixels.
struct SourceGeometry {
    work_area: Rect,
    outer: Rect,
    inner: Rect,
    scale: f64,
}

fn source_geometry<R: Runtime>(source: &WebviewWindow<R>) -> Option<SourceGeometry> {
    let monitor = source.current_monitor().ok().flatten()?;
    let area = monitor.work_area();
    let outer_pos = source.outer_position().ok()?;
    let outer_size = source.outer_size().ok()?;
    let inner_pos = source.inner_position().ok()?;
    let inner_size = source.inner_size().ok()?;
    Some(SourceGeometry {
        work_area: Rect::new(
            area.position.x as f64,
            area.position.y as f64,
            area.size.width as f64,
            area.size.height as f64,
        ),
        outer: Rect::new(
            outer_pos.x as f64,
            outer_pos.y as f64,
            outer_size.width as f64,
            outer_size.height as f64,
        ),
        inner: Rect::new(
            inner_pos.x as f64,
            inner_pos.y as f64,
            inner_size.width as f64,
            inner_size.height as f64,
        ),
        scale: monitor.scale_factor(),
    })
}

fn apply_frame<R: Runtime>(window: &WebviewWindow<R>, frame: Rect) {
    let _ = window.set_size(PhysicalSize::new(
        frame.width.max(1.0) as u32,
        frame.height.max(1.0) as u32,
    ));
    let _ = window.set_position(PhysicalPosition::new(frame.x as i32, frame.y as i32));
}

/// Create a hidden app-content window loading `index.html#/<route>`, with
/// the Electron chrome (inset traffic lights on macOS, frameless elsewhere),
/// the current theme / background / opacity, centred on `source`. The page
/// shows it through `rendererReady` (or the fallback timer).
pub(crate) fn build_app_window<R: Runtime>(
    app: &AppHandle<R>,
    kind: AppWindowKind,
    label: &str,
    title: &str,
    size: (f64, f64),
    min_size: (f64, f64),
    source: Option<&WebviewWindow<R>>,
) -> CmdResult<WebviewWindow<R>> {
    let (theme, background) = super::window::window_appearance(app);
    let url = WebviewUrl::App(format!("index.html#/{}", kind.route()).into());
    let builder = WebviewWindowBuilder::new(app, label, url)
        .title(title)
        .inner_size(size.0, size.1)
        .min_inner_size(min_size.0, min_size.1)
        .resizable(true)
        .visible(false)
        .disable_drag_drop_handler()
        .theme(theme);
    let builder = match background {
        Some(color) => builder.background_color(color),
        None => builder,
    };
    #[cfg(target_os = "macos")]
    let builder = builder
        .title_bar_style(tauri::TitleBarStyle::Overlay)
        .hidden_title(true)
        .traffic_light_position(tauri::LogicalPosition::new(12.0, 12.0));
    #[cfg(not(target_os = "macos"))]
    let builder = builder.decorations(false);
    let window = builder.build().map_err(internal)?;
    state(app).window_id(label);
    if let Some(geometry) = source.and_then(source_geometry) {
        let frame = placement::center_on(
            &geometry.work_area,
            &geometry.outer,
            size.0 * geometry.scale,
            size.1 * geometry.scale,
        );
        apply_frame(&window, frame);
    }
    apply_window_chrome(&window);
    schedule_show_fallback(window.clone());
    Ok(window)
}

fn broadcast_route<R: Runtime>(app: &AppHandle<R>, change: Option<RouteChange>) {
    if let Some(change) = change {
        crate::events::emit(app, events::SESSION_OUTPUT_ROUTE, change);
    }
}

fn session_exists<R: Runtime>(app: &AppHandle<R>, session_id: &str) -> bool {
    app.try_state::<AppState<R>>()
        .is_some_and(|st| st.sessions.contains(session_id))
}

/// Forget routes of sessions that ended.
fn prune_routes<R: Runtime>(app: &AppHandle<R>) {
    let Some(app_state) = app.try_state::<AppState<R>>() else {
        return;
    };
    let changes = state(app)
        .routes
        .lock()
        .retain(|id| app_state.sessions.contains(id));
    for change in changes {
        state(app).grants.lock().release_session(&change.session_id);
        broadcast_route(app, Some(change));
    }
}

// ---------------------------------------------------------------------------
// Unsaved-editor checks (Electron: `dirtyEditorGuard.cjs`)
// ---------------------------------------------------------------------------

/// Windows asked about unsaved work before a quit / update install
/// (Electron: `getDirtyEditorWindows`): the main window, session windows and
/// the editor window. Settings, tray panel and popups do not take part.
pub fn dirty_editor_windows<R: Runtime>(app: &AppHandle<R>) -> Vec<String> {
    let mut labels: Vec<String> = app
        .webview_windows()
        .keys()
        .filter(|l| l.as_str() == MAIN_LABEL || l.as_str() == EDITOR_LABEL || is_session_window(l))
        .cloned()
        .collect();
    labels.sort();
    labels
}

/// Ask one window about unsaved work (fails open without the update state).
async fn query_dirty<R: Runtime>(app: &AppHandle<R>, label: &str) -> super::update::DirtyOutcome {
    match app.try_state::<super::update::UpdateState>() {
        Some(update) => {
            update
                .dirty_guard
                .query(app, label, DIRTY_QUERY_TIMEOUT)
                .await
        }
        None => super::update::DirtyOutcome::Clean,
    }
}

/// Main / session window close: run the Save / Discard / Cancel flow of the
/// editor tabs it owns, then the unsaved-editor query; close only when both
/// pass (Electron: `queryDirtyEditorsBeforeClose`). Returns `true` when the
/// close was prevented.
fn guard_app_window_close<R: Runtime>(window: &tauri::Window<R>) -> bool {
    let app = window.app_handle().clone();
    let label = window.label().to_owned();
    let st = state(&app);
    if st.quitting() {
        return false;
    }
    // Recheck when another editor tab was opened meanwhile.
    if editor::has_tabs_for_source(&app, &label) {
        st.close_confirmed.lock().remove(&label);
    }
    if st.close_confirmed.lock().contains(&label) {
        return false;
    }
    if !st.close_pending.lock().insert(label.clone()) {
        return true;
    }
    tauri::async_runtime::spawn(async move {
        let result = editor::close_tabs_for_source(&app, &label).await;
        let tabs_closed = result.get("success") == Some(&Value::Bool(true))
            && result.get("cancelled") != Some(&Value::Bool(true));
        let clean = tabs_closed && !query_dirty(&app, &label).await.blocks();
        state(&app).close_pending.lock().remove(&label);
        if clean {
            state(&app).close_confirmed.lock().insert(label.clone());
            if let Some(window) = app.get_webview_window(&label) {
                let _ = window.close();
            }
        }
    });
    true
}

// ---------------------------------------------------------------------------
// Lifecycle hooks (wired in `window.rs` / `lib.rs`)
// ---------------------------------------------------------------------------

/// Window events of the extra windows. Called by `window::on_window_event`
/// after the tray hook; returns `true` when the event is fully handled.
pub fn on_window_event<R: Runtime>(window: &tauri::Window<R>, event: &WindowEvent) -> bool {
    let label = window.label().to_owned();
    match event {
        WindowEvent::CloseRequested { api, .. } => {
            let prevented = if label == EDITOR_LABEL {
                editor::on_close_requested(window)
            } else if is_popup_window(&label) {
                popup_close_requested(window)
            } else if label == MAIN_LABEL || is_session_window(&label) {
                guard_app_window_close(window)
            } else {
                false
            };
            if prevented {
                api.prevent_close();
            }
            prevented
        }
        WindowEvent::Destroyed => {
            on_destroyed(window.app_handle(), &label);
            false
        }
        _ => false,
    }
}

fn on_destroyed<R: Runtime>(app: &AppHandle<R>, label: &str) {
    let Some(st) = app.try_state::<WindowsState>() else {
        return;
    };
    st.replies.fail_window(label);
    st.terminal_focus.lock().remove(label);
    st.close_confirmed.lock().remove(label);
    st.close_pending.lock().remove(label);
    st.transparent.lock().remove(label);
    st.popup_configs.lock().remove(label);
    st.open_sessions.lock().remove(label);
    if label == EDITOR_LABEL {
        editor::on_destroyed(app);
    }
    if is_popup_window(label) {
        release_popup(app, label);
    }
    // Electron: `trackRendererSessionLifetime` — sessions die with the
    // window that started them.
    let owned = st.routes.lock().owned_by(label);
    for session_id in owned {
        let change = st.routes.lock().remove(&session_id);
        st.grants.lock().release_session(&session_id);
        broadcast_route(app, change);
        let handle = app.clone();
        tauri::async_runtime::spawn(async move {
            if let Some(app_state) = handle.try_state::<AppState<R>>() {
                if let Err(err) = app_state.sessions.close(&session_id).await {
                    tracing::debug!(%err, "closing a destroyed window's session failed");
                }
            }
        });
    }
    st.window_ids.lock().remove(label);
}

/// App run-loop events (wired in `lib.rs::run`): the unsaved-editor quit
/// guard (Electron: `before-quit` → `handleBeforeQuit`).
///
/// Every explicit quit (`app.exit`: menu, tray, `quitApp`) is held while the
/// main / session / editor windows are asked about unsaved work. The update
/// restart (`RESTART_EXIT_CODE`) already ran its own check, and the implicit
/// exit after the last window closed (`code: None`) has nothing left to ask.
pub fn on_run_event<R: Runtime>(app: &AppHandle<R>, event: &RunEvent) {
    let RunEvent::ExitRequested {
        code: Some(code),
        api,
        ..
    } = event
    else {
        return;
    };
    let Some(st) = app.try_state::<WindowsState>() else {
        return;
    };
    let code = *code;
    if code == tauri::RESTART_EXIT_CODE || st.quit_confirmed.load(Ordering::SeqCst) {
        st.quitting.store(true, Ordering::SeqCst);
        return;
    }
    if st.quit_busy.load(Ordering::SeqCst) {
        api.prevent_exit();
        return;
    }
    let labels = dirty_editor_windows(app);
    if labels.is_empty() {
        st.quit_confirmed.store(true, Ordering::SeqCst);
        st.quitting.store(true, Ordering::SeqCst);
        return;
    }
    api.prevent_exit();
    st.quit_busy.store(true, Ordering::SeqCst);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let checks = labels.iter().map(|label| {
            let app = app.clone();
            async move { (label.clone(), query_dirty(&app, label).await) }
        });
        let results = futures::future::join_all(checks).await;
        let st = state(&app);
        st.quit_busy.store(false, Ordering::SeqCst);
        let dirty: Vec<&(String, super::update::DirtyOutcome)> = results
            .iter()
            .filter(|(_, outcome)| outcome.blocks())
            .collect();
        if dirty.is_empty() {
            st.quit_confirmed.store(true, Ordering::SeqCst);
            st.quitting.store(true, Ordering::SeqCst);
            app.exit(code);
            return;
        }
        // The renderer shows the warning in its own window: bring every
        // dirty owner forward (it may be hidden to the tray).
        for (label, _) in &dirty {
            if let Some(window) = app.get_webview_window(label) {
                show_and_focus(&window);
            }
        }
        if dirty
            .iter()
            .any(|(_, outcome)| *outcome == super::update::DirtyOutcome::Editors)
        {
            use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
            app.dialog()
                .message(
                    "One or more editors have unsaved changes. If the app is locked, unlock it, then save or discard before quitting.",
                )
                .title("Unsaved changes")
                .kind(MessageDialogKind::Warning)
                .show(|_| {});
        }
    });
}

// ---------------------------------------------------------------------------
// Editor window commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn windows_open_editor<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    payload: Value,
) -> Value {
    editor::open(&app, &window, &payload).await
}

/// The editor page subscribed to `editorOpenTab` (Electron:
/// `netcatty:window:editorReady`).
#[tauri::command]
pub fn windows_editor_ready<R: Runtime>(app: AppHandle<R>, window: WebviewWindow<R>) {
    editor::ready(&app, window.label());
}

#[tauri::command]
pub fn windows_focus_editor<R: Runtime>(app: AppHandle<R>, editor_id: Option<String>) -> Value {
    editor::focus(&app, editor_id.as_deref())
}

#[tauri::command]
pub async fn windows_close_editor_tabs<R: Runtime>(app: AppHandle<R>, payload: Value) -> Value {
    let force = payload.get("force") == Some(&Value::Bool(true));
    editor::close_tabs(&app, sanitize::editor_ids(&payload), force).await
}

#[tauri::command]
pub async fn windows_save_editor_tab<R: Runtime>(app: AppHandle<R>, payload: Value) -> Value {
    editor::save(&app, &payload).await
}

#[tauri::command]
pub async fn windows_dock_editor_tab<R: Runtime>(app: AppHandle<R>, payload: Value) -> Value {
    editor::dock(&app, &payload).await
}

#[tauri::command]
pub fn windows_report_editor_dirty<R: Runtime>(app: AppHandle<R>, payload: Value) {
    editor::report_dirty(&app, &payload);
}

#[tauri::command]
pub fn windows_report_editor_tabs_closed<R: Runtime>(app: AppHandle<R>, payload: Value) {
    editor::report_tabs_closed(&app, &payload);
}

#[tauri::command]
pub fn windows_remap_editor_session<R: Runtime>(app: AppHandle<R>, payload: Value) {
    editor::remap_session(&app, &payload);
}

/// Renderer reply to a request event (`editorOpenTabResult`,
/// `editorCloseTabsResult`, `editorSaveResult`, `editorDockResult`,
/// `snapshot-response`, `apply-snapshot-response`). Only the queried window
/// can settle its request.
#[tauri::command]
pub fn windows_report<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    channel: String,
    payload: Value,
) -> bool {
    state(&app)
        .replies
        .resolve(window.label(), &channel, payload)
}

// ---------------------------------------------------------------------------
// Terminal popups (Electron: `terminalPopupWindow.cjs`)
// ---------------------------------------------------------------------------

fn client_rect(value: Option<&Value>) -> Option<Rect> {
    let value = value?;
    let n = |k: &str| {
        value
            .get(k)
            .and_then(Value::as_f64)
            .filter(|v| v.is_finite())
    };
    let (x, y, w, h) = (n("x")?, n("y")?, n("width")?, n("height")?);
    (w > 0.0 && h > 0.0 && w < 10000.0 && h < 10000.0).then_some(Rect::new(x, y, w, h))
}

fn popup_frame<R: Runtime>(source: &WebviewWindow<R>, avoid: Option<Rect>) -> Option<Rect> {
    let g = source_geometry(source)?;
    let avoid = avoid.map(|r| {
        Rect::new(
            g.inner.x + r.x * g.scale,
            g.inner.y + r.y * g.scale,
            r.width * g.scale,
            r.height * g.scale,
        )
    });
    Some(match avoid {
        Some(avoid) => placement::place_terminal_popup(
            &g.work_area,
            &g.inner,
            Some(&avoid),
            POPUP_WIDTH * g.scale,
            POPUP_HEIGHT * g.scale,
            POPUP_MIN_WIDTH * g.scale,
            POPUP_MIN_HEIGHT * g.scale,
        ),
        None => placement::center_on(
            &g.work_area,
            &g.outer,
            POPUP_WIDTH * g.scale,
            POPUP_HEIGHT * g.scale,
        ),
    })
}

/// `openTerminalPopup`: a terminal popup window. With `attachSessionId` the
/// popup observes an existing session (one popup per session, reused) and
/// receives an `attachAuthorization` token for the attach commands.
#[tauri::command]
pub async fn windows_open_terminal_popup<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    payload: Value,
) -> Value {
    let Some(config) = payload.as_object().cloned() else {
        return json!({ "success": false, "error": "Invalid popup payload" });
    };
    let st = state(&app);
    let attach_session = config
        .get("attachSessionId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    if let Some(session_id) = &attach_session {
        let existing = st
            .popups
            .lock()
            .iter()
            .find(|(_, p)| p.attach_session.as_deref() == Some(session_id))
            .map(|(label, p)| (label.clone(), p.popup_id.clone()));
        if let Some((label, popup_id)) = existing {
            if let Some(popup) = app.get_webview_window(&label) {
                show_and_focus(&popup);
                return json!({ "success": true, "popupId": popup_id, "reused": true });
            }
        }
    }
    let title = config
        .get("title")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .unwrap_or("Terminal")
        .to_owned();
    let popup_id = match config.get("popupId") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => uuid::Uuid::new_v4().to_string(),
    };
    if st.popups.lock().values().any(|p| p.popup_id == popup_id) {
        return json!({
            "success": false,
            "error": format!("Terminal popup ID is already active: {popup_id}"),
        });
    }
    let label = format!("{POPUP_LABEL_PREFIX}{}", st.next());
    let authorization = attach_session
        .as_ref()
        .map(|_| uuid::Uuid::new_v4().to_string());

    let mut config = config;
    config.insert("popupId".into(), json!(popup_id));
    if let Some(token) = &authorization {
        config.insert("attachAuthorization".into(), json!(token));
    }
    st.popup_configs
        .lock()
        .insert(label.clone(), Value::Object(config));
    st.popups.lock().insert(
        label.clone(),
        PopupRecord {
            popup_id: popup_id.clone(),
            attach_session: attach_session.clone(),
            authorization: authorization.clone(),
            close_requested: false,
        },
    );
    if let (Some(session_id), Some(token)) = (&attach_session, &authorization) {
        st.grants.lock().register(token, session_id, &label);
    }

    let popup = match build_app_window(
        &app,
        AppWindowKind::Popup,
        &label,
        &title,
        (POPUP_WIDTH, POPUP_HEIGHT),
        (POPUP_MIN_WIDTH, POPUP_MIN_HEIGHT),
        None,
    ) {
        Ok(popup) => popup,
        Err(err) => {
            release_popup(&app, &label);
            st.popup_configs.lock().remove(&label);
            return json!({ "success": false, "error": err.message });
        }
    };
    let avoid = client_rect(payload.get("avoidClientRect"));
    let source = if window.label() == MAIN_LABEL || is_app_content_window(window.label()) {
        Some(window)
    } else {
        app.get_webview_window(MAIN_LABEL)
    };
    if let Some(frame) = source.as_ref().and_then(|s| popup_frame(s, avoid)) {
        apply_frame(&popup, frame);
    }
    json!({ "success": true, "popupId": popup_id })
}

/// The popup page pulls its configuration (Electron pushes it after load and
/// the preload buffers it; a pull cannot race the page's listener).
#[tauri::command]
pub fn windows_terminal_popup_config<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
) -> Option<Value> {
    state(&app)
        .popup_configs
        .lock()
        .get(window.label())
        .cloned()
}

#[tauri::command]
pub fn windows_mark_attach_close_prepared<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    session_id: Option<String>,
    authorization: Option<String>,
) -> Value {
    let ok = state(&app).grants.lock().mark_close_prepared(
        authorization.as_deref().unwrap_or(""),
        session_id.as_deref().unwrap_or(""),
        window.label(),
    );
    if ok {
        json!({ "success": true })
    } else {
        json!({ "success": false, "error": "Unauthorized attach request" })
    }
}

/// Attach popups hand the session back before closing: ask the page to
/// prepare (it pushes its terminal state home and calls
/// `windows_mark_attach_close_prepared`), destroy after 2 s regardless.
fn popup_close_requested<R: Runtime>(window: &tauri::Window<R>) -> bool {
    let app = window.app_handle().clone();
    let label = window.label().to_owned();
    let st = state(&app);
    if st.quitting() {
        return false;
    }
    let (session_id, token) = {
        let mut popups = st.popups.lock();
        let Some(record) = popups.get_mut(&label) else {
            return false;
        };
        let (Some(session_id), Some(token)) =
            (record.attach_session.clone(), record.authorization.clone())
        else {
            return false;
        };
        if st.grants.lock().is_close_prepared(&token) {
            return false;
        }
        if record.close_requested {
            return true;
        }
        record.close_requested = true;
        (session_id, token)
    };
    let _ = app.emit_to(
        label.as_str(),
        events::TERMINAL_POPUP_PREPARE_CLOSE,
        json!({ "sessionId": session_id, "authorization": token }),
    );
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(ATTACH_CLOSE_PREPARE_TIMEOUT).await;
        if let Some(popup) = app.get_webview_window(&label) {
            let _ = popup.destroy();
        }
    });
    true
}

/// A popup window is gone: restore an attached session's display route to
/// the main window and drop the grant.
fn release_popup<R: Runtime>(app: &AppHandle<R>, label: &str) {
    let st = state(app);
    let Some(record) = st.popups.lock().remove(label) else {
        return;
    };
    if let Some(token) = &record.authorization {
        st.grants.lock().release(token);
    }
    let Some(session_id) = record.attach_session else {
        return;
    };
    if st.routes.lock().display_of(&session_id) != Some(label) {
        return;
    }
    if app.get_webview_window(MAIN_LABEL).is_some() && session_exists(app, &session_id) {
        let change = st.routes.lock().restore(&session_id, MAIN_LABEL);
        broadcast_route(app, change);
    } else {
        let change = st.routes.lock().remove(&session_id);
        broadcast_route(app, change);
    }
}

// ---------------------------------------------------------------------------
// Session windows (Electron: `netcatty:window:openSession`)
// ---------------------------------------------------------------------------

/// `openSessionInNewWindow`: a peer window (`#/session-window`) that opens a
/// copy of `sourceSession`. Resolves once the page took the payload.
#[tauri::command]
pub async fn windows_open_session<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    payload: Value,
) -> Value {
    if !payload.is_object() || payload.get("sourceSession").is_none_or(Value::is_null) {
        return json!({ "success": false, "error": "Invalid session payload" });
    }
    let title = payload
        .get("title")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .unwrap_or("Netcatty")
        .to_owned();
    let mut delivery = Map::new();
    delivery.insert("title".into(), json!(title));
    delivery.insert("sourceSession".into(), payload["sourceSession"].clone());
    if let Some(shell) = payload.get("localShellType").filter(|v| !v.is_null()) {
        delivery.insert("localShellType".into(), shell.clone());
    }
    let st = state(&app);
    let label = format!("{SESSION_LABEL_PREFIX}{}", st.next());
    let (tx, rx) = oneshot::channel();
    st.open_sessions.lock().insert(
        label.clone(),
        PendingOpenSession {
            payload: Value::Object(delivery),
            delivered: Some(tx),
        },
    );
    let source = Some(&window).filter(|w| is_app_content_window(w.label()));
    if let Err(err) = build_app_window(
        &app,
        AppWindowKind::Session,
        &label,
        &title,
        (SESSION_WIDTH, SESSION_HEIGHT),
        (900.0, 600.0),
        source,
    ) {
        st.open_sessions.lock().remove(&label);
        return json!({ "success": false, "error": err.message });
    }
    match tokio::time::timeout(OPEN_SESSION_DELIVERY_TIMEOUT, rx).await {
        Ok(Ok(())) => json!({ "success": true }),
        Ok(Err(_)) => {
            json!({ "success": false, "error": "Window closed before message could be delivered" })
        }
        Err(_) => {
            tracing::warn!("new session window could not receive the duplicated tab");
            json!({ "success": false, "error": "New window did not become ready in time" })
        }
    }
}

/// The session window page takes its `onOpenSessionInNewWindow` payload
/// (once; `null` afterwards).
#[tauri::command]
pub fn windows_take_open_session<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
) -> Option<Value> {
    let mut pending = state(&app).open_sessions.lock().remove(window.label())?;
    if let Some(tx) = pending.delivered.take() {
        let _ = tx.send(());
    }
    Some(pending.payload)
}

// ---------------------------------------------------------------------------
// Session output routing and attach hand-over (Electron: terminalBridge.cjs)
// ---------------------------------------------------------------------------

/// The calling window started `sessionId` (owner + display window).
#[tauri::command]
pub fn windows_track_session<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    session_id: String,
) {
    if session_id.is_empty() {
        return;
    }
    prune_routes(&app);
    let change = state(&app).routes.lock().track(&session_id, window.label());
    broadcast_route(&app, change);
}

#[derive(Serialize)]
pub struct RoutesSnapshot {
    routes: Vec<RouteChange>,
}

/// Current display window of every routed session (adapter start-up).
#[tauri::command]
pub fn windows_output_routes<R: Runtime>(app: AppHandle<R>) -> RoutesSnapshot {
    RoutesSnapshot {
        routes: state(&app).routes.lock().snapshot(),
    }
}

fn authorized<R: Runtime>(
    app: &AppHandle<R>,
    window: &WebviewWindow<R>,
    session_id: &str,
    authorization: Option<&str>,
) -> bool {
    state(app)
        .grants
        .lock()
        .validate(authorization.unwrap_or(""), session_id, window.label())
}

/// `rebindTerminalSessionOutput`: move a live session's display to the
/// calling attach popup (same backend session).
#[tauri::command]
pub fn windows_rebind_output<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    session_id: Option<String>,
    authorization: Option<String>,
) -> Value {
    let session_id = session_id.unwrap_or_default();
    if session_id.is_empty() {
        return json!({ "success": false, "error": "Missing sessionId" });
    }
    if !authorized(&app, &window, &session_id, authorization.as_deref()) {
        return json!({ "success": false, "error": "Unauthorized attach request" });
    }
    if !session_exists(&app, &session_id) {
        return json!({ "success": false, "error": "Session not found" });
    }
    let st = state(&app);
    let (previous, change) = st
        .routes
        .lock()
        .rebind(&session_id, window.label(), MAIN_LABEL);
    broadcast_route(&app, Some(change));
    let previous_id = previous.map(|label| st.window_id(&label));
    json!({
        "success": true,
        "previousWebContentsId": previous_id,
        "webContentsId": st.window_id(window.label()),
    })
}

/// `restoreTerminalSessionOutput`: hand the display back to a main window.
#[tauri::command]
pub fn windows_restore_output<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    session_id: Option<String>,
    web_contents_id: Option<u64>,
    authorization: Option<String>,
) -> Value {
    let session_id = session_id.unwrap_or_default();
    if session_id.is_empty() {
        return json!({ "success": false, "error": "Missing sessionId" });
    }
    if !authorized(&app, &window, &session_id, authorization.as_deref()) {
        return json!({ "success": false, "error": "Unauthorized attach request" });
    }
    let st = state(&app);
    // Only main windows are restore targets (Electron:
    // `findRegisteredMainWebContents`); the preferred id is honoured when it
    // names one.
    let preferred = web_contents_id.and_then(|id| st.label_of(id));
    let target = preferred
        .filter(|l| l == MAIN_LABEL)
        .or_else(|| Some(MAIN_LABEL.to_owned()))
        .filter(|l| app.get_webview_window(l).is_some());
    let Some(target) = target else {
        return json!({ "success": false, "error": "No live renderer to restore output to" });
    };
    if !session_exists(&app, &session_id) {
        return json!({ "success": true, "restored": false });
    }
    let change = {
        let mut routes = st.routes.lock();
        match routes.restore(&session_id, &target) {
            Some(change) => Some(change),
            None => routes.track(&session_id, &target),
        }
    };
    broadcast_route(&app, change);
    json!({ "success": true, "restored": true, "webContentsId": st.window_id(&target) })
}

/// `requestTerminalSessionSnapshot`: the window currently displaying the
/// session serializes its terminal for the attach popup.
#[tauri::command]
pub async fn windows_request_snapshot<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    session_id: Option<String>,
    authorization: Option<String>,
) -> Value {
    let fail = |error: &str| json!({ "success": false, "snapshot": "", "error": error });
    let session_id = session_id.unwrap_or_default();
    if session_id.is_empty() {
        return fail("Missing sessionId");
    }
    if !authorized(&app, &window, &session_id, authorization.as_deref()) {
        return fail("Unauthorized attach request");
    }
    let st = state(&app);
    let home = st
        .routes
        .lock()
        .display_of(&session_id)
        .map(str::to_owned)
        .or_else(|| session_exists(&app, &session_id).then(|| MAIN_LABEL.to_owned()));
    let Some(home) = home else {
        return fail("Home renderer not found");
    };
    if app.get_webview_window(&home).is_none() {
        return fail("Home renderer destroyed");
    }
    let mut request = Map::new();
    request.insert("sessionId".into(), json!(session_id));
    match st
        .replies
        .request(
            &app,
            &home,
            events::SNAPSHOT_REQUEST,
            events::SNAPSHOT_RESPONSE,
            request,
            SNAPSHOT_TIMEOUT,
        )
        .await
    {
        Ok(reply) => sanitize::snapshot_result(&reply),
        Err(ReplyError::Timeout) => fail("timeout"),
        Err(_) => fail("Home renderer destroyed"),
    }
}

/// `applyTerminalSessionSnapshot`: an attach popup pushes its terminal state
/// back to the home renderer before the display route is restored.
#[tauri::command]
pub async fn windows_apply_snapshot<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    payload: Value,
) -> Value {
    let fail = |error: &str| json!({ "success": false, "error": error });
    let Some((session_id, event)) = sanitize::apply_snapshot_event(&payload) else {
        return fail("Missing sessionId or snapshot");
    };
    let authorization = payload.get("authorization").and_then(Value::as_str);
    if !authorized(&app, &window, &session_id, authorization) {
        return fail("Unauthorized attach request");
    }
    let st = state(&app);
    if st.routes.lock().home_of(&session_id).is_none() {
        return fail("Home renderer not found");
    }
    // Homes are main windows (Electron: `findRegisteredMainWebContents`).
    if app.get_webview_window(MAIN_LABEL).is_none() {
        return fail("Home renderer unavailable");
    }
    match st
        .replies
        .request(
            &app,
            MAIN_LABEL,
            events::APPLY_SNAPSHOT,
            events::APPLY_SNAPSHOT_RESPONSE,
            event,
            SNAPSHOT_TIMEOUT,
        )
        .await
    {
        Ok(reply) if reply.get("success") == Some(&Value::Bool(false)) => fail(
            reply
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("Snapshot apply failed"),
        ),
        Ok(_) => json!({ "success": true }),
        Err(ReplyError::Timeout) => fail("timeout"),
        Err(_) => fail("Home renderer unavailable"),
    }
}

// ---------------------------------------------------------------------------
// Window chrome: opacity, background blur, terminal keyboard focus
// ---------------------------------------------------------------------------

const BLUR_SUPPORTED: bool = cfg!(target_os = "macos");

/// Apply the current opacity / blur to `window` (also used for the settings
/// window; the tray panel only takes the blur material).
pub(crate) fn apply_window_chrome<R: Runtime>(window: &WebviewWindow<R>) {
    let app = window.app_handle();
    let Some(st) = app.try_state::<WindowsState>() else {
        return;
    };
    let label = window.label().to_owned();
    let (alpha, vibrancy) = sanitize::window_chrome(
        BLUR_SUPPORTED,
        st.blur_requested.load(Ordering::SeqCst),
        st.opacity(),
    );
    if label == super::tray::TRAY_PANEL_LABEL {
        native::set_vibrancy(window, vibrancy);
        return;
    }
    if !(is_app_content_window(&label) || label == SETTINGS_LABEL) {
        return;
    }
    native::set_alpha(window, alpha);
    if vibrancy {
        native::set_vibrancy(window, true);
        let _ = window.set_background_color(Some(tauri::window::Color(0, 0, 0, 0)));
        st.transparent.lock().insert(label);
    } else if st.transparent.lock().remove(&label) {
        native::set_vibrancy(window, false);
        let _ = window.set_background_color(Some(restore_background(app)));
    }
}

/// Background to restore after the blur: the last pushed colour, else the
/// theme default (Electron: `THEME_COLORS`).
fn restore_background<R: Runtime>(app: &AppHandle<R>) -> tauri::window::Color {
    let (theme, background) = super::window::window_appearance(app);
    if let Some(color) = background {
        return color;
    }
    let dark = match theme {
        Some(theme) => theme == tauri::Theme::Dark,
        None => app
            .get_webview_window(MAIN_LABEL)
            .and_then(|w| w.theme().ok())
            .is_some_and(|t| t == tauri::Theme::Dark),
    };
    if dark {
        tauri::window::Color(0x0b, 0x12, 0x20, 255)
    } else {
        tauri::window::Color(255, 255, 255, 255)
    }
}

/// `true` while `window` shows the blur material: background colour pushes
/// must keep its backing transparent (`window::app_set_background_color`).
pub(crate) fn keeps_transparent_background<R: Runtime>(window: &WebviewWindow<R>) -> bool {
    window
        .app_handle()
        .try_state::<WindowsState>()
        .is_some_and(|st| st.transparent.lock().contains(window.label()))
}

fn apply_chrome_everywhere<R: Runtime>(app: &AppHandle<R>) {
    for window in app.webview_windows().values() {
        apply_window_chrome(window);
    }
}

/// `setWindowOpacity`: 0.5 ..= 1 on every app window. Resolves `true`.
#[tauri::command]
pub fn windows_set_opacity<R: Runtime>(app: AppHandle<R>, opacity: Option<f64>) -> bool {
    *state(&app).opacity.lock() = Some(sanitize::clamp_opacity(opacity));
    apply_chrome_everywhere(&app);
    true
}

/// `setWindowBackgroundBlur`: macOS vibrancy behind translucent windows.
/// Resolves whether the platform supports it (Electron: macOS only).
#[tauri::command]
pub fn windows_set_background_blur<R: Runtime>(app: AppHandle<R>, enabled: bool) -> bool {
    state(&app)
        .blur_requested
        .store(BLUR_SUPPORTED && enabled, Ordering::SeqCst);
    apply_chrome_everywhere(&app);
    BLUR_SUPPORTED
}

/// `setTerminalKeyboardFocus`: whether a terminal in the calling window has
/// keyboard focus (Electron ignores menu shortcuts meanwhile).
#[tauri::command]
pub fn windows_set_terminal_keyboard_focus<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    focused: bool,
) {
    state(&app)
        .terminal_focus
        .lock()
        .insert(window.label().to_owned(), focused);
}

/// Whether a terminal in `label` has keyboard focus.
pub fn has_terminal_keyboard_focus<R: Runtime>(app: &AppHandle<R>, label: &str) -> bool {
    app.try_state::<WindowsState>().is_some_and(|st| {
        st.terminal_focus
            .lock()
            .get(label)
            .copied()
            .unwrap_or(false)
    })
}

/// Language changed (`window::app_set_language`): relabel the app menu.
pub fn on_language_changed<R: Runtime>(app: &AppHandle<R>, language: &str) {
    #[cfg(target_os = "macos")]
    menu::install(app, language);
    #[cfg(not(target_os = "macos"))]
    let _ = (app, language);
}

/// Platform window chrome.
mod native {
    use tauri::{Runtime, WebviewWindow};

    /// Native window alpha. macOS: `NSWindow.alphaValue` (Electron
    /// `setOpacity`). Linux: no-op, like Electron. Windows: not applied —
    /// WebView2 content is not composited into `WS_EX_LAYERED` windows.
    #[cfg(target_os = "macos")]
    pub fn set_alpha<R: Runtime>(window: &WebviewWindow<R>, alpha: f64) {
        let Ok(ptr) = window.ns_window() else {
            return;
        };
        let addr = ptr as usize;
        let _ = window.run_on_main_thread(move || {
            let ns_window = addr as *mut objc2::runtime::AnyObject;
            if ns_window.is_null() {
                return;
            }
            // SAFETY: `ns_window` is the live NSWindow of this Tauri window,
            // messaged on the main thread.
            unsafe {
                let _: () = objc2::msg_send![ns_window, setAlphaValue: alpha];
            }
        });
    }

    #[cfg(not(target_os = "macos"))]
    pub fn set_alpha<R: Runtime>(_window: &WebviewWindow<R>, _alpha: f64) {}

    /// The `hud` vibrancy material behind the webview (macOS only).
    #[cfg(target_os = "macos")]
    pub fn set_vibrancy<R: Runtime>(window: &WebviewWindow<R>, enabled: bool) {
        use tauri::utils::config::WindowEffectsConfig;
        use tauri::window::{Effect, EffectState};
        if enabled {
            if let Ok(ptr) = window.ns_window() {
                let addr = ptr as usize;
                let _ = window.run_on_main_thread(move || {
                    let ns_window = addr as *mut objc2::runtime::AnyObject;
                    if ns_window.is_null() {
                        return;
                    }
                    // SAFETY: as in `set_alpha`; a non-opaque window lets the
                    // material show through the transparent backing.
                    unsafe {
                        let _: () = objc2::msg_send![ns_window, setOpaque: false];
                    }
                });
            }
            let _ = window.set_effects(WindowEffectsConfig {
                effects: vec![Effect::HudWindow],
                state: Some(EffectState::Active),
                ..Default::default()
            });
        } else {
            let _ = window.set_effects(None);
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn set_vibrancy<R: Runtime>(_window: &WebviewWindow<R>, _enabled: bool) {}
}

/// The macOS application menu (Electron: `buildAppMenu`). Cmd+W is routed
/// to the renderer of the main / settings window (`command-close`) so it
/// closes the active tab first; other windows close directly. Quit goes
/// through `app.exit` so the unsaved-editor guard runs.
#[cfg(target_os = "macos")]
mod menu {
    use super::sanitize::menu_label;
    use tauri::menu::{Menu, MenuItem, SubmenuBuilder};
    use tauri::{AppHandle, Emitter, Manager, Runtime};

    const QUIT: &str = "netcatty:menu:quit";
    const CLOSE_WINDOW: &str = "netcatty:menu:close-window";
    const RELOAD: &str = "netcatty:menu:reload";
    const DEVTOOLS: &str = "netcatty:menu:devtools";

    fn build<R: Runtime>(app: &AppHandle<R>, language: &str) -> tauri::Result<Menu<R>> {
        let quit = MenuItem::with_id(app, QUIT, "Quit Netcatty", true, Some("CmdOrCtrl+Q"))?;
        let app_menu = SubmenuBuilder::new(app, "Netcatty")
            .about(None)
            .separator()
            .hide()
            .hide_others()
            .show_all()
            .separator()
            .item(&quit)
            .build()?;
        let edit = SubmenuBuilder::new(app, menu_label(language, "edit"))
            .undo()
            .redo()
            .separator()
            .cut()
            .copy()
            .paste()
            .select_all()
            .build()?;
        let reload = MenuItem::with_id(app, RELOAD, reload_label(language), true, None::<&str>)?;
        let devtools = MenuItem::with_id(
            app,
            DEVTOOLS,
            "Toggle Developer Tools",
            cfg!(debug_assertions),
            Some("Alt+CmdOrCtrl+I"),
        )?;
        let view = SubmenuBuilder::new(app, menu_label(language, "view"))
            .item(&reload)
            .item(&devtools)
            .separator()
            .fullscreen()
            .build()?;
        let close = MenuItem::with_id(
            app,
            CLOSE_WINDOW,
            menu_label(language, "closeWindow"),
            true,
            Some("CmdOrCtrl+W"),
        )?;
        let window = SubmenuBuilder::new(app, menu_label(language, "window"))
            .minimize()
            .maximize()
            .separator()
            .item(&close)
            .bring_all_to_front()
            .build()?;
        Menu::with_items(app, &[&app_menu, &edit, &view, &window])
    }

    fn reload_label(language: &str) -> &'static str {
        match language.split('-').next().unwrap_or("") {
            "ru" => "Перезагрузить",
            "zh" if language == "zh-TW" => "重新載入",
            "zh" => "重新加载",
            _ => "Reload",
        }
    }

    pub fn install<R: Runtime>(app: &AppHandle<R>, language: &str) {
        match build(app, language) {
            Ok(menu) => {
                if let Err(err) = app.set_menu(menu) {
                    tracing::warn!(%err, "could not install the application menu");
                }
            }
            Err(err) => tracing::warn!(%err, "could not build the application menu"),
        }
    }

    fn focused_window<R: Runtime>(app: &AppHandle<R>) -> Option<tauri::WebviewWindow<R>> {
        app.webview_windows()
            .into_values()
            .find(|w| w.is_focused().unwrap_or(false))
    }

    pub fn on_event<R: Runtime>(app: &AppHandle<R>, id: &str) {
        match id {
            QUIT => app.exit(0),
            CLOSE_WINDOW => {
                let target =
                    focused_window(app).or_else(|| app.get_webview_window(super::MAIN_LABEL));
                let Some(window) = target else {
                    return;
                };
                let label = window.label();
                if label == super::MAIN_LABEL || label == super::SETTINGS_LABEL {
                    let _ = app.emit_to(label, super::events::WINDOW_COMMAND_CLOSE, ());
                } else {
                    let _ = window.close();
                }
            }
            RELOAD => {
                if let Some(window) = focused_window(app) {
                    let _ = window.reload();
                }
            }
            DEVTOOLS =>
            {
                #[cfg(debug_assertions)]
                if let Some(window) = focused_window(app) {
                    if window.is_devtools_open() {
                        window.close_devtools();
                    } else {
                        window.open_devtools();
                    }
                }
            }
            _ => {}
        }
    }
}

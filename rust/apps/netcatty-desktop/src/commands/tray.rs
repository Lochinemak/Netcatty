//! System tray, tray panel and close-to-tray (Electron:
//! `globalShortcutBridge.cjs`, `trayPanelBounds.cjs`).
//!
//! * The tray icon exists while the user wants it shown (`setShowTrayIcon`),
//!   when close-to-tray is turned on with the icon allowed, and while a hidden
//!   auto-launch cold start (`--hidden`) has not shown its window yet.
//! * Clicking the icon toggles the tray panel (a small frameless window on the
//!   renderer's `#/tray` route) on macOS; on Windows a left click opens the
//!   main window and a right click toggles the panel. Linux trays do not report
//!   clicks, so Linux gets a native menu (same items as Electron's).
//! * With close-to-tray on, closing the main window hides it instead (leaving
//!   native fullscreen first on macOS). Hooked from
//!   [`super::window::on_window_event`].
//! * Tray menu / panel actions reach the main window renderer as events
//!   (`netcatty:tray:*`, `netcatty:trayPanel:*`, see `ipc.rs`).

use super::window::MAIN_LABEL;
use super::CmdResult;
use netcatty_core::ipc::events::{
    TRAY_FOCUS_SESSION, TRAY_PANEL_CLOSE_SESSION, TRAY_PANEL_CONNECT_TO_HOST,
    TRAY_PANEL_JUMP_TO_SESSION, TRAY_PANEL_MENU_DATA, TRAY_PANEL_REFRESH,
    TRAY_PANEL_START_PORT_FORWARD, TRAY_TOGGLE_PORT_FORWARD,
};
use netcatty_core::CoreError;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, Instant};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{
    AppHandle, Manager, PhysicalPosition, PhysicalSize, RunEvent, Runtime, WebviewUrl,
    WebviewWindow, WebviewWindowBuilder, WindowEvent,
};

/// Id of the single tray icon.
pub const TRAY_ID: &str = "netcatty";
/// Label of the tray panel window (`index.html#/tray`).
pub const TRAY_PANEL_LABEL: &str = "tray-panel";
/// Argument the autostart entry launches the app with (start hidden in the tray).
pub const HIDDEN_LAUNCH_ARG: &str = "--hidden";

/// Designed tray panel size and gap to the icon (logical px), as Electron.
const TRAY_PANEL_WIDTH: f64 = 360.0;
const TRAY_PANEL_HEIGHT: f64 = 520.0;
const TRAY_PANEL_GAP: f64 = 6.0;
/// A `tray.rect()` fallback further than this from the cursor is ignored.
const ANCHOR_CURSOR_SLOP_PX: f64 = 96.0;
const PANEL_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
/// The panel is shown on `rendererReady`; this is the fallback.
const PANEL_SHOW_FALLBACK: Duration = Duration::from_secs(3);
/// macOS close-to-tray on a fullscreen window: wait for the window to leave
/// fullscreen (bounded), then let the space transition settle before hiding,
/// otherwise macOS re-shows the window at the end of the animation.
const FULLSCREEN_LEAVE_TIMEOUT: Duration = Duration::from_secs(5);
const FULLSCREEN_SETTLE: Duration = Duration::from_millis(800);
/// A tray click this soon after the panel hid on blur closes, not reopens.
const BLUR_CLICK_GRACE: Duration = Duration::from_millis(300);

// Native menu item ids (Linux tray menu).
const MENU_OPEN_MAIN: &str = "tray:open-main";
const MENU_QUIT: &str = "tray:quit";
const MENU_SESSION_PREFIX: &str = "tray:session:";
const MENU_PORT_FORWARD_PREFIX: &str = "tray:pf:";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Data the renderer syncs for the tray menu / panel. Entries are kept as the
/// renderer sent them and handed back to the panel unchanged.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrayMenuData {
    #[serde(default)]
    pub sessions: Vec<Value>,
    #[serde(default)]
    pub port_forward_rules: Vec<Value>,
    #[serde(default)]
    pub hosts: Vec<Value>,
}

/// `updateTrayMenuData` payload: absent lists are left unchanged.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrayMenuUpdate {
    #[serde(default)]
    sessions: Option<Vec<Value>>,
    #[serde(default)]
    port_forward_rules: Option<Vec<Value>>,
    #[serde(default)]
    hosts: Option<Vec<Value>>,
}

/// What a preference change means for the native tray icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrayChange {
    /// Create the icon unless it exists.
    Ensure,
    /// Remove the icon.
    Remove,
    /// Leave it as it is.
    Keep,
}

#[derive(Debug)]
struct Prefs {
    close_to_tray: bool,
    show_tray_icon: bool,
    /// A hidden auto-launch cold start keeps the icon until its window was
    /// shown once, whatever the icon preference says (no trayless zombie).
    hidden_launch_pinned: bool,
    menu_data: TrayMenuData,
    /// The tray panel's renderer reported ready (first load finished).
    panel_ready: bool,
    /// Show the panel as soon as its renderer is ready.
    panel_show_when_ready: bool,
    /// Bumped on every panel show / hide; stops the refresh loop.
    panel_generation: u64,
    /// Bumped whenever the main window is hidden or brought forward; cancels
    /// a pending fullscreen-exit hide.
    hide_generation: u64,
    /// When the panel last hid because it lost focus: the click on the tray
    /// icon that caused it must not reopen it (Windows taskbar focus).
    panel_blur_hidden_at: Option<Instant>,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            close_to_tray: false,
            show_tray_icon: true,
            hidden_launch_pinned: false,
            menu_data: TrayMenuData::default(),
            panel_ready: false,
            panel_show_when_ready: false,
            panel_generation: 0,
            hide_generation: 0,
            panel_blur_hidden_at: None,
        }
    }
}

impl Prefs {
    fn set_show_tray_icon(&mut self, enabled: bool) -> TrayChange {
        self.show_tray_icon = enabled;
        if enabled {
            TrayChange::Ensure
        } else if self.hidden_launch_pinned {
            TrayChange::Keep
        } else {
            TrayChange::Remove
        }
    }

    fn set_close_to_tray(&mut self, enabled: bool) -> TrayChange {
        self.close_to_tray = enabled;
        if enabled && self.show_tray_icon {
            TrayChange::Ensure
        } else {
            TrayChange::Keep
        }
    }

    fn pin_for_hidden_launch(&mut self) -> TrayChange {
        self.hidden_launch_pinned = true;
        TrayChange::Ensure
    }

    fn release_hidden_launch_pin(&mut self) -> TrayChange {
        if !std::mem::take(&mut self.hidden_launch_pinned) || self.show_tray_icon {
            TrayChange::Keep
        } else {
            TrayChange::Remove
        }
    }

    /// Close-to-tray also applies with the icon hidden by preference (the
    /// app keeps running in the background), as in Electron.
    fn hides_on_close(&self, tray_exists: bool) -> bool {
        self.close_to_tray && (tray_exists || !self.show_tray_icon)
    }

    fn apply_update(&mut self, update: TrayMenuUpdate) {
        if let Some(sessions) = update.sessions {
            self.menu_data.sessions = sessions;
        }
        if let Some(rules) = update.port_forward_rules {
            self.menu_data.port_forward_rules = rules;
        }
        if let Some(hosts) = update.hosts {
            self.menu_data.hosts = hosts;
        }
    }
}

/// Managed tray state (registered by [`setup`]).
#[derive(Default)]
pub struct TrayState {
    prefs: Mutex<Prefs>,
}

fn with_prefs<R: Runtime, T>(app: &AppHandle<R>, f: impl FnOnce(&mut Prefs) -> T) -> Option<T> {
    app.try_state::<TrayState>().map(|s| f(&mut s.prefs.lock()))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnabledResult {
    success: bool,
    enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnabledStatus {
    enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ActionResult {
    fn ok() -> Self {
        Self {
            success: true,
            error: None,
        }
    }

    fn failed(error: &str) -> Self {
        Self {
            success: false,
            error: Some(error.to_owned()),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FocusSessionEvent {
    session_id: String,
    label: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TogglePortForwardEvent {
    rule_id: String,
    start: bool,
}

// ---------------------------------------------------------------------------
// Setup and lifecycle hooks (wired in `lib.rs` / `window.rs`)
// ---------------------------------------------------------------------------

/// Manage [`TrayState`]; on a hidden auto-launch cold start (`--hidden`) keep
/// the main window hidden and pin the tray icon.
pub fn setup<R: Runtime>(app: &tauri::App<R>) {
    app.manage(TrayState::default());
    if std::env::args().any(|arg| arg == HIDDEN_LAUNCH_ARG) {
        let handle = app.handle();
        apply_change(handle, with_prefs(handle, Prefs::pin_for_hidden_launch));
        if let Some(main) = handle.get_webview_window(MAIN_LABEL) {
            let _ = main.hide();
        }
    }
}

/// Window lifecycle for the main window (close-to-tray) and the tray panel
/// (hide on blur / close). Returns `true` when the event is fully handled.
pub fn on_window_event<R: Runtime>(window: &tauri::Window<R>, event: &WindowEvent) -> bool {
    let app = window.app_handle();
    match (window.label(), event) {
        (MAIN_LABEL, WindowEvent::CloseRequested { api, .. }) => {
            let tray_exists = app.tray_by_id(TRAY_ID).is_some();
            if with_prefs(app, |p| p.hides_on_close(tray_exists)).unwrap_or(false) {
                api.prevent_close();
                if let Some(main) = app.get_webview_window(MAIN_LABEL) {
                    hide_main_window(app, &main);
                }
                return true;
            }
            // Really closing: the hidden panel must not keep the app alive.
            if let Some(panel) = app.get_webview_window(TRAY_PANEL_LABEL) {
                let _ = panel.destroy();
            }
            false
        }
        (TRAY_PANEL_LABEL, WindowEvent::CloseRequested { api, .. }) => {
            api.prevent_close();
            hide_tray_panel(app);
            true
        }
        (TRAY_PANEL_LABEL, WindowEvent::Focused(false)) => {
            let visible = window.is_visible().unwrap_or(false);
            hide_tray_panel(app);
            if visible {
                with_prefs(app, |p| p.panel_blur_hidden_at = Some(Instant::now()));
            }
            true
        }
        (TRAY_PANEL_LABEL, WindowEvent::Destroyed) => {
            with_prefs(app, |p| {
                p.panel_ready = false;
                p.panel_show_when_ready = false;
                p.panel_generation += 1;
            });
            false
        }
        _ => false,
    }
}

/// Called by `window_renderer_ready` before it shows a hidden window: the
/// tray panel is shown only when a show is pending, the main window not
/// while a hidden auto-launch keeps it in the tray.
pub fn renderer_ready_may_show<R: Runtime>(window: &WebviewWindow<R>) -> bool {
    let label = window.label().to_owned();
    with_prefs(window.app_handle(), |p| match label.as_str() {
        TRAY_PANEL_LABEL => {
            p.panel_ready = true;
            std::mem::take(&mut p.panel_show_when_ready)
        }
        MAIN_LABEL => !p.hidden_launch_pinned,
        _ => true,
    })
    .unwrap_or(true)
}

/// The main window is being shown: cancel a pending hide-to-tray, and a
/// hidden launch is over.
pub fn main_window_shown<R: Runtime>(app: &AppHandle<R>) {
    with_prefs(app, |p| p.hide_generation += 1);
    apply_change(app, with_prefs(app, Prefs::release_hidden_launch_pin));
}

/// App run-loop events (wired in `lib.rs::run`): clicking the Dock icon
/// re-shows a main window hidden to the tray (Electron `activate`).
pub fn on_run_event<R: Runtime>(app: &AppHandle<R>, event: RunEvent) {
    #[cfg(target_os = "macos")]
    if let RunEvent::Reopen {
        has_visible_windows: false,
        ..
    } = event
    {
        bring_main_to_foreground(app);
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (app, event);
}

// ---------------------------------------------------------------------------
// Main window show / hide (also used by the global hotkey)
// ---------------------------------------------------------------------------

/// Unminimize, show and focus the main window; cancels a pending hide.
pub(crate) fn bring_main_to_foreground<R: Runtime>(app: &AppHandle<R>) -> bool {
    main_window_shown(app);
    let Some(main) = app.get_webview_window(MAIN_LABEL) else {
        return false;
    };
    let _ = main.unminimize();
    let _ = main.show();
    main.set_focus().is_ok()
}

/// Hide the main window to the tray, leaving macOS native fullscreen first.
pub(crate) fn hide_main_window<R: Runtime>(app: &AppHandle<R>, main: &WebviewWindow<R>) {
    let generation = with_prefs(app, |p| {
        p.hide_generation += 1;
        p.hide_generation
    })
    .unwrap_or(0);
    if cfg!(target_os = "macos") && main.is_fullscreen().unwrap_or(false) {
        let _ = main.set_fullscreen(false);
        let (app, main) = (app.clone(), main.clone());
        tauri::async_runtime::spawn(async move {
            let deadline = Instant::now() + FULLSCREEN_LEAVE_TIMEOUT;
            while main.is_fullscreen().unwrap_or(false) && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            tokio::time::sleep(FULLSCREEN_SETTLE).await;
            // Brought back (hotkey, tray, Dock) in the meantime: keep it.
            if with_prefs(&app, |p| p.hide_generation) == Some(generation) {
                let _ = main.hide();
            }
        });
        return;
    }
    let _ = main.hide();
}

/// Global hotkey ("Quake mode"): show a hidden / minimized / unfocused main
/// window, hide a focused one.
pub(crate) fn toggle_main_window<R: Runtime>(app: &AppHandle<R>) {
    let Some(main) = app.get_webview_window(MAIN_LABEL) else {
        return;
    };
    let minimized = main.is_minimized().unwrap_or(false);
    let visible = main.is_visible().unwrap_or(false);
    let focused = main.is_focused().unwrap_or(false);
    if !minimized && visible && focused {
        hide_main_window(app, &main);
    } else {
        bring_main_to_foreground(app);
    }
}

// ---------------------------------------------------------------------------
// Tray icon and native menu
// ---------------------------------------------------------------------------

/// macOS: template image (the system tints it); elsewhere the coloured icon.
/// Same artwork as the Electron build (`public/`).
fn tray_image() -> Option<Image<'static>> {
    #[cfg(target_os = "macos")]
    let bytes: &[u8] = include_bytes!("../../../../../public/tray-iconTemplate@2x.png");
    #[cfg(not(target_os = "macos"))]
    let bytes: &[u8] = include_bytes!("../../../../../public/tray-icon@2x.png");
    Image::from_bytes(bytes).ok()
}

fn apply_change<R: Runtime>(app: &AppHandle<R>, change: Option<TrayChange>) {
    match change {
        Some(TrayChange::Ensure) => ensure_tray(app),
        Some(TrayChange::Remove) => {
            if app.remove_tray_by_id(TRAY_ID).is_some() {
                tracing::debug!("tray icon removed");
            }
        }
        Some(TrayChange::Keep) | None => {}
    }
}

fn ensure_tray<R: Runtime>(app: &AppHandle<R>) {
    if app.tray_by_id(TRAY_ID).is_some() {
        return;
    }
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("Netcatty")
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| handle_tray_event(tray.app_handle(), event))
        .on_menu_event(|app, event| handle_menu_action(app, event.id().as_ref()));
    if let Some(image) = tray_image() {
        builder = builder.icon(image);
    }
    #[cfg(target_os = "macos")]
    {
        builder = builder.icon_as_template(true);
    }
    // Linux trays never report clicks: the native menu is the only entry point.
    #[cfg(target_os = "linux")]
    {
        let data = with_prefs(app, |p| p.menu_data.clone()).unwrap_or_default();
        match build_native_menu(app, &data) {
            Ok(menu) => builder = builder.menu(&menu),
            Err(err) => tracing::warn!(%err, "tray menu build failed"),
        }
    }
    match builder.build(app) {
        Ok(_) => tracing::debug!("tray icon created"),
        Err(err) => tracing::warn!(%err, "tray icon creation failed"),
    }
}

/// Rebuild the Linux tray menu after the renderer synced new data.
fn refresh_native_menu<R: Runtime>(app: &AppHandle<R>) {
    #[cfg(target_os = "linux")]
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let data = with_prefs(app, |p| p.menu_data.clone()).unwrap_or_default();
        match build_native_menu(app, &data) {
            Ok(menu) => {
                let _ = tray.set_menu(Some(menu));
            }
            Err(err) => tracing::warn!(%err, "tray menu rebuild failed"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = app;
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn build_native_menu<R: Runtime>(
    app: &AppHandle<R>,
    data: &TrayMenuData,
) -> tauri::Result<Menu<R>> {
    let menu = Menu::new(app)?;
    for entry in build_menu_entries(data) {
        match entry {
            MenuEntry::Item { id, label, enabled } => {
                menu.append(&MenuItem::with_id(app, id, label, enabled, None::<&str>)?)?
            }
            MenuEntry::Separator => menu.append(&PredefinedMenuItem::separator(app)?)?,
        }
    }
    Ok(menu)
}

fn handle_tray_event<R: Runtime>(app: &AppHandle<R>, event: TrayIconEvent) {
    let TrayIconEvent::Click {
        button,
        button_state: MouseButtonState::Up,
        rect,
        ..
    } = event
    else {
        return;
    };
    let bounds = rect_bounds(&rect);
    match button {
        MouseButton::Left if cfg!(windows) => {
            bring_main_to_foreground(app);
        }
        MouseButton::Left => spawn_toggle_tray_panel(app, bounds),
        MouseButton::Right if cfg!(windows) => spawn_toggle_tray_panel(app, bounds),
        _ => {}
    }
}

/// Off the event-loop thread: creating the panel's webview from inside an
/// event handler can deadlock on Windows (WebView2).
fn spawn_toggle_tray_panel<R: Runtime>(app: &AppHandle<R>, bounds: Option<Bounds>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move { toggle_tray_panel(&app, bounds) });
}

fn handle_menu_action<R: Runtime>(app: &AppHandle<R>, id: &str) {
    match parse_menu_action(id) {
        Some(MenuAction::OpenMain) => {
            bring_main_to_foreground(app);
        }
        Some(MenuAction::FocusSession { session_id, focus }) => {
            // AI silent sessions open a terminal popup from the renderer and
            // must not force the main window forward.
            if focus {
                bring_main_to_foreground(app);
            }
            emit_focus_session(app, MAIN_LABEL, &session_id);
        }
        Some(MenuAction::TogglePortForward { rule_id, start }) => {
            bring_main_to_foreground(app);
            crate::events::emit(
                app,
                TRAY_TOGGLE_PORT_FORWARD,
                TogglePortForwardEvent { rule_id, start },
            );
        }
        Some(MenuAction::Quit) => {
            with_prefs(app, |p| p.close_to_tray = false);
            app.exit(0);
        }
        None => {}
    }
}

pub(crate) fn emit_focus_session<R: Runtime>(app: &AppHandle<R>, label: &str, session_id: &str) {
    crate::events::emit(
        app,
        TRAY_FOCUS_SESSION,
        FocusSessionEvent {
            session_id: session_id.to_owned(),
            label: label.to_owned(),
        },
    );
}

#[derive(Debug, Clone, PartialEq)]
enum MenuEntry {
    Item {
        id: String,
        label: String,
        enabled: bool,
    },
    Separator,
}

#[derive(Debug, Clone, PartialEq)]
enum MenuAction {
    OpenMain,
    Quit,
    FocusSession { session_id: String, focus: bool },
    TogglePortForward { rule_id: String, start: bool },
}

fn item(id: impl Into<String>, label: impl Into<String>, enabled: bool) -> MenuEntry {
    MenuEntry::Item {
        id: id.into(),
        label: label.into(),
        enabled,
    }
}

fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// `String(value)` for the scalar fields the labels interpolate.
fn display_field(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

/// The tray menu Electron builds (`buildTrayMenuTemplate`), as plain data.
fn build_menu_entries(data: &TrayMenuData) -> Vec<MenuEntry> {
    let mut entries = vec![
        item(MENU_OPEN_MAIN, "Open Main Window", true),
        MenuEntry::Separator,
    ];

    let sessions: Vec<&Value> = data
        .sessions
        .iter()
        .filter(|s| str_field(s, "id").is_some_and(|id| !id.is_empty()))
        .collect();
    if !sessions.is_empty() {
        entries.push(item("tray:header:sessions", "Sessions", false));
        for session in sessions {
            let id = str_field(session, "id").unwrap_or_default();
            let status = match str_field(session, "status") {
                Some("connected") => "Connected",
                Some("connecting") => "Connecting",
                _ => "Disconnected",
            };
            let name = str_field(session, "hostLabel")
                .filter(|l| !l.is_empty())
                .or_else(|| str_field(session, "label"))
                .unwrap_or_default();
            let focus = session.get("aiHidden") != Some(&Value::Bool(true));
            entries.push(item(
                format!("{MENU_SESSION_PREFIX}{}:{id}", u8::from(focus)),
                format!("  {name}  ({status})"),
                true,
            ));
        }
        entries.push(MenuEntry::Separator);
    }

    let rules: Vec<&Value> = data
        .port_forward_rules
        .iter()
        .filter(|r| str_field(r, "id").is_some_and(|id| !id.is_empty()))
        .collect();
    if !rules.is_empty() {
        entries.push(item(
            "tray:header:port-forwarding",
            "Port Forwarding",
            false,
        ));
        for rule in rules {
            let id = str_field(rule, "id").unwrap_or_default();
            let status = str_field(rule, "status").unwrap_or_default();
            let connecting = status == "connecting";
            let stoppable =
                status == "active" || connecting || rule.get("canStop") == Some(&Value::Bool(true));
            let status_text = match status {
                "active" => "Active",
                "connecting" => "Connecting",
                "error" => "Error",
                _ => "Inactive",
            };
            let kind = str_field(rule, "type").unwrap_or_default();
            let type_label = match kind {
                "local" => "L",
                "remote" => "R",
                _ => "D",
            };
            let local_port = display_field(rule, "localPort");
            let port_info = if kind == "dynamic" {
                local_port
            } else {
                format!(
                    "{local_port} → {}:{}",
                    display_field(rule, "remoteHost"),
                    display_field(rule, "remotePort")
                )
            };
            let name = str_field(rule, "label")
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .unwrap_or(port_info);
            entries.push(item(
                format!("{MENU_PORT_FORWARD_PREFIX}{}:{id}", u8::from(!stoppable)),
                format!("  [{type_label}] {name}  ({status_text})"),
                !connecting,
            ));
        }
        entries.push(MenuEntry::Separator);
    }

    entries.push(item(MENU_QUIT, "Quit", true));
    entries
}

fn parse_menu_action(id: &str) -> Option<MenuAction> {
    let flagged = |rest: &str| -> Option<(bool, String)> {
        let (flag, value) = rest.split_once(':')?;
        Some((flag == "1", value.to_owned()))
    };
    match id {
        MENU_OPEN_MAIN => Some(MenuAction::OpenMain),
        MENU_QUIT => Some(MenuAction::Quit),
        _ => {
            if let Some(rest) = id.strip_prefix(MENU_SESSION_PREFIX) {
                let (focus, session_id) = flagged(rest)?;
                Some(MenuAction::FocusSession { session_id, focus })
            } else if let Some(rest) = id.strip_prefix(MENU_PORT_FORWARD_PREFIX) {
                let (start, rule_id) = flagged(rest)?;
                Some(MenuAction::TogglePortForward { rule_id, start })
            } else {
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tray panel window
// ---------------------------------------------------------------------------

fn build_tray_panel<R: Runtime>(app: &AppHandle<R>) -> CmdResult<WebviewWindow<R>> {
    let builder = WebviewWindowBuilder::new(
        app,
        TRAY_PANEL_LABEL,
        WebviewUrl::App("index.html#/tray".into()),
    )
    .title("Netcatty")
    .inner_size(TRAY_PANEL_WIDTH, TRAY_PANEL_HEIGHT)
    .resizable(false)
    .maximizable(false)
    .minimizable(false)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .shadow(true)
    .visible(false)
    .focused(true)
    .disable_drag_drop_handler();
    // Rounded CSS corners need a see-through window; on macOS that needs the
    // private-API feature, so the panel stays a plain rectangle there.
    #[cfg(not(target_os = "macos"))]
    let builder = builder.transparent(true);
    builder
        .build()
        .map_err(|err| CoreError::internal(err.to_string()))
}

fn toggle_tray_panel<R: Runtime>(app: &AppHandle<R>, event_bounds: Option<Bounds>) {
    let (pending, just_blurred) = with_prefs(app, |p| {
        let just_blurred = p
            .panel_blur_hidden_at
            .take()
            .is_some_and(|at| at.elapsed() < BLUR_CLICK_GRACE);
        (p.panel_show_when_ready, just_blurred)
    })
    .unwrap_or((false, false));
    let visible = app
        .get_webview_window(TRAY_PANEL_LABEL)
        .is_some_and(|w| w.is_visible().unwrap_or(false));
    if just_blurred && !visible {
        // This click took the focus away and the panel already closed.
        return;
    }
    // A pending first-load show counts as open, so a second click cancels it.
    if pending || visible {
        hide_tray_panel(app);
    } else {
        show_tray_panel(app, event_bounds);
    }
}

fn show_tray_panel<R: Runtime>(app: &AppHandle<R>, event_bounds: Option<Bounds>) {
    let (panel, created) = match app.get_webview_window(TRAY_PANEL_LABEL) {
        Some(panel) => (panel, false),
        None => match build_tray_panel(app) {
            Ok(panel) => (panel, true),
            Err(err) => {
                tracing::warn!(error = %err.message, "tray panel creation failed");
                return;
            }
        },
    };
    position_tray_panel(app, &panel, event_bounds);
    let Some((generation, ready)) = with_prefs(app, |p| {
        if created {
            p.panel_ready = false;
        }
        p.panel_generation += 1;
        if !p.panel_ready {
            p.panel_show_when_ready = true;
        }
        (p.panel_generation, p.panel_ready)
    }) else {
        return;
    };
    if ready {
        let _ = panel.show();
        let _ = panel.set_focus();
    } else {
        // Shown by `window_renderer_ready`; fall back if that never comes.
        let (app, panel) = (app.clone(), panel.clone());
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(PANEL_SHOW_FALLBACK).await;
            let due = with_prefs(&app, |p| {
                let due = p.panel_generation == generation
                    && std::mem::take(&mut p.panel_show_when_ready);
                // Do not wait for a ready signal again on later opens.
                p.panel_ready |= due;
                due
            });
            if due == Some(true) {
                let _ = panel.show();
                let _ = panel.set_focus();
            }
        });
    }
    push_menu_data(app);
    spawn_refresh_loop(app.clone(), generation);
}

/// Hide the tray panel and stop its refresh ticks.
pub(crate) fn hide_tray_panel<R: Runtime>(app: &AppHandle<R>) {
    with_prefs(app, |p| {
        p.panel_show_when_ready = false;
        p.panel_generation += 1;
    });
    if let Some(panel) = app.get_webview_window(TRAY_PANEL_LABEL) {
        let _ = panel.hide();
    }
}

fn spawn_refresh_loop<R: Runtime>(app: AppHandle<R>, generation: u64) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(PANEL_REFRESH_INTERVAL).await;
            if with_prefs(&app, |p| p.panel_generation) != Some(generation) {
                break;
            }
            let visible = app
                .get_webview_window(TRAY_PANEL_LABEL)
                .is_some_and(|w| w.is_visible().unwrap_or(false));
            if visible {
                crate::events::emit(&app, TRAY_PANEL_REFRESH, ());
            }
        }
    });
}

fn push_menu_data<R: Runtime>(app: &AppHandle<R>) {
    if app.get_webview_window(TRAY_PANEL_LABEL).is_none() {
        return;
    }
    if let Some(data) = with_prefs(app, |p| p.menu_data.clone()) {
        crate::events::emit(app, TRAY_PANEL_MENU_DATA, data);
    }
}

fn position_tray_panel<R: Runtime>(
    app: &AppHandle<R>,
    panel: &WebviewWindow<R>,
    event_bounds: Option<Bounds>,
) {
    let cursor = app.cursor_position().ok().map(|p| Point { x: p.x, y: p.y });
    let tray_bounds = app
        .tray_by_id(TRAY_ID)
        .and_then(|tray| tray.rect().ok().flatten())
        .and_then(|rect| rect_bounds(&rect));
    let point = resolve_tray_display_point(event_bounds, tray_bounds, cursor);
    let monitor = app
        .monitor_from_point(point.x, point.y)
        .ok()
        .flatten()
        .or_else(|| app.primary_monitor().ok().flatten());
    let (work_area, scale) = match &monitor {
        Some(m) => {
            let area = m.work_area();
            (
                Some(Bounds {
                    x: f64::from(area.position.x),
                    y: f64::from(area.position.y),
                    width: f64::from(area.size.width),
                    height: f64::from(area.size.height),
                }),
                m.scale_factor(),
            )
        }
        None => (None, 1.0),
    };
    let anchor = resolve_tray_anchor(event_bounds, tray_bounds, cursor, work_area);
    let placed = place_tray_panel(
        Some(anchor),
        work_area,
        TRAY_PANEL_WIDTH * scale,
        TRAY_PANEL_HEIGHT * scale,
        TRAY_PANEL_GAP * scale,
    );
    let _ = panel.set_size(PhysicalSize::new(
        placed.width.round() as u32,
        placed.height.round() as u32,
    ));
    let _ = panel.set_position(PhysicalPosition::new(placed.x as i32, placed.y as i32));
}

// ---------------------------------------------------------------------------
// Tray panel placement (port of `trayPanelBounds.cjs`, physical pixels)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Bounds {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Point {
    x: f64,
    y: f64,
}

impl Bounds {
    fn is_valid(&self) -> bool {
        [self.x, self.y, self.width, self.height]
            .iter()
            .all(|v| v.is_finite())
            && self.width > 0.0
            && self.height > 0.0
    }

    fn near(&self, point: Point, slop: f64) -> bool {
        point.x >= self.x - slop
            && point.x <= self.x + self.width + slop
            && point.y >= self.y - slop
            && point.y <= self.y + self.height + slop
    }
}

fn rect_bounds(rect: &tauri::Rect) -> Option<Bounds> {
    let position = rect.position.to_physical::<f64>(1.0);
    let size = rect.size.to_physical::<f64>(1.0);
    let bounds = Bounds {
        x: position.x,
        y: position.y,
        width: size.width,
        height: size.height,
    };
    bounds.is_valid().then_some(bounds)
}

/// JavaScript `Math.round` (halves round up, also for negatives).
fn js_round(value: f64) -> f64 {
    (value + 0.5).floor()
}

fn clamp(value: f64, min: f64, max: f64) -> f64 {
    if max < min {
        min
    } else {
        value.clamp(min, max)
    }
}

/// Anchor rectangle for the panel: event bounds win; a `tray.rect()`
/// fallback is used only near the cursor; then the cursor; then the
/// bottom-right corner of the work area.
fn resolve_tray_anchor(
    event: Option<Bounds>,
    tray: Option<Bounds>,
    cursor: Option<Point>,
    work_area: Option<Bounds>,
) -> Bounds {
    if let Some(event) = event.filter(Bounds::is_valid) {
        return event;
    }
    let cursor = cursor.filter(|c| c.x.is_finite() && c.y.is_finite());
    if let Some(tray) = tray.filter(Bounds::is_valid) {
        if cursor.is_none_or(|c| tray.near(c, ANCHOR_CURSOR_SLOP_PX)) {
            return tray;
        }
    }
    if let Some(c) = cursor {
        return Bounds {
            x: c.x,
            y: c.y,
            width: 1.0,
            height: 1.0,
        };
    }
    let area = work_area.filter(Bounds::is_valid).unwrap_or(Bounds {
        x: 0.0,
        y: 0.0,
        width: 0.0,
        height: 0.0,
    });
    Bounds {
        x: area.x + area.width.max(0.0),
        y: area.y + area.height.max(0.0),
        width: 1.0,
        height: 1.0,
    }
}

/// Point that picks the monitor: event bounds, else the cursor, else the
/// tray rect.
fn resolve_tray_display_point(
    event: Option<Bounds>,
    tray: Option<Bounds>,
    cursor: Option<Point>,
) -> Point {
    if let Some(event) = event.filter(Bounds::is_valid) {
        return Point {
            x: event.x,
            y: event.y,
        };
    }
    if let Some(c) = cursor.filter(|c| c.x.is_finite() && c.y.is_finite()) {
        return c;
    }
    if let Some(tray) = tray.filter(Bounds::is_valid) {
        return Point {
            x: tray.x,
            y: tray.y,
        };
    }
    Point { x: 0.0, y: 0.0 }
}

/// Below the anchor when it fits (macOS menu bar), else above (bottom
/// taskbar), clamped to the work area.
fn place_tray_panel(
    anchor: Option<Bounds>,
    work_area: Option<Bounds>,
    width: f64,
    height: f64,
    gap: f64,
) -> Bounds {
    let area = work_area.filter(Bounds::is_valid).unwrap_or(Bounds {
        x: 0.0,
        y: 0.0,
        width: width.max(1.0),
        height: height.max(1.0),
    });
    let or_default = |v: f64, d: f64| if v == 0.0 { d } else { v };
    let panel_width = width.max(1.0).min(or_default(area.width, width));
    let panel_height = height.max(1.0).min(or_default(area.height, height));
    let anchor = anchor.filter(Bounds::is_valid).unwrap_or(Bounds {
        x: area.x,
        y: area.y,
        width: 1.0,
        height: 1.0,
    });

    let x = js_round(clamp(
        anchor.x + anchor.width / 2.0 - panel_width / 2.0,
        area.x,
        area.x + area.width - panel_width,
    ));
    let min_y = area.y;
    let max_y = area.y + area.height - panel_height;
    let below = anchor.y + anchor.height + gap;
    let above = anchor.y - panel_height - gap;
    let y = if below + panel_height <= area.y + area.height {
        below
    } else if above >= area.y {
        above
    } else {
        clamp(below, min_y, max_y)
    };
    Bounds {
        x,
        y: js_round(clamp(y, min_y, max_y)),
        width: panel_width,
        height: panel_height,
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Show / hide the tray icon (independent of close-to-tray).
#[tauri::command]
pub fn tray_set_show_icon<R: Runtime>(app: AppHandle<R>, enabled: bool) -> EnabledResult {
    apply_change(&app, with_prefs(&app, |p| p.set_show_tray_icon(enabled)));
    EnabledResult {
        success: true,
        enabled,
    }
}

#[tauri::command]
pub fn tray_is_show_icon<R: Runtime>(app: AppHandle<R>) -> EnabledStatus {
    EnabledStatus {
        enabled: with_prefs(&app, |p| p.show_tray_icon).unwrap_or(true),
    }
}

/// Hide the main window instead of closing it; creates the tray icon unless
/// it is hidden by preference.
#[tauri::command]
pub fn tray_set_close_to_tray<R: Runtime>(app: AppHandle<R>, enabled: bool) -> EnabledResult {
    if !enabled {
        // Cancel a pending fullscreen-exit hide.
        with_prefs(&app, |p| p.hide_generation += 1);
    }
    apply_change(&app, with_prefs(&app, |p| p.set_close_to_tray(enabled)));
    EnabledResult {
        success: true,
        enabled,
    }
}

#[tauri::command]
pub fn tray_is_close_to_tray<R: Runtime>(app: AppHandle<R>) -> EnabledStatus {
    EnabledStatus {
        enabled: with_prefs(&app, |p| p.close_to_tray).unwrap_or(false),
    }
}

/// Renderer → tray menu / panel data (`updateTrayMenuData`).
#[tauri::command]
pub fn tray_update_menu_data<R: Runtime>(
    app: AppHandle<R>,
    payload: Option<TrayMenuUpdate>,
) -> ActionResult {
    with_prefs(&app, |p| p.apply_update(payload.unwrap_or_default()));
    refresh_native_menu(&app);
    push_menu_data(&app);
    ActionResult::ok()
}

/// Current tray data (the panel reads it once when it subscribes, since the
/// push on show may arrive before its listener exists).
#[tauri::command]
pub fn tray_get_menu_data<R: Runtime>(app: AppHandle<R>) -> TrayMenuData {
    with_prefs(&app, |p| p.menu_data.clone()).unwrap_or_default()
}

#[tauri::command]
pub fn tray_panel_hide<R: Runtime>(app: AppHandle<R>) -> ActionResult {
    hide_tray_panel(&app);
    ActionResult::ok()
}

/// Forwarded to the main window without focusing it (AI silent sessions open
/// a terminal popup instead).
#[tauri::command]
pub fn tray_panel_jump_to_session<R: Runtime>(
    app: AppHandle<R>,
    session_id: String,
) -> ActionResult {
    crate::events::emit(&app, TRAY_PANEL_JUMP_TO_SESSION, session_id);
    ActionResult::ok()
}

#[tauri::command]
pub fn tray_panel_connect_to_host<R: Runtime>(app: AppHandle<R>, host_id: String) -> ActionResult {
    if !host_id.is_empty() {
        bring_main_to_foreground(&app);
        crate::events::emit(&app, TRAY_PANEL_CONNECT_TO_HOST, host_id);
    }
    ActionResult::ok()
}

#[tauri::command]
pub fn tray_panel_start_port_forward<R: Runtime>(
    app: AppHandle<R>,
    rule_id: String,
) -> ActionResult {
    if app.get_webview_window(MAIN_LABEL).is_none() {
        return ActionResult::failed("Main window is not ready");
    }
    crate::events::emit(&app, TRAY_PANEL_START_PORT_FORWARD, rule_id);
    ActionResult::ok()
}

#[tauri::command]
pub fn tray_panel_close_session<R: Runtime>(app: AppHandle<R>, session_id: String) -> ActionResult {
    if app.get_webview_window(MAIN_LABEL).is_none() {
        return ActionResult::failed("Main window is not available");
    }
    crate::events::emit(&app, TRAY_PANEL_CLOSE_SESSION, session_id);
    ActionResult::ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const WORK_AREA: Bounds = Bounds {
        x: 0.0,
        y: 0.0,
        width: 1920.0,
        height: 1040.0,
    };
    const TOP_TRAY: Bounds = Bounds {
        x: 900.0,
        y: 0.0,
        width: 24.0,
        height: 24.0,
    };
    const BOTTOM_TRAY: Bounds = Bounds {
        x: 1680.0,
        y: 1044.0,
        width: 24.0,
        height: 24.0,
    };
    const EMPTY: Bounds = Bounds {
        x: 0.0,
        y: 0.0,
        width: 0.0,
        height: 0.0,
    };
    const OTHER_MONITOR_CURSOR: Point = Point {
        x: 2600.0,
        y: 400.0,
    };

    fn place(anchor: Bounds) -> Bounds {
        place_tray_panel(
            Some(anchor),
            Some(WORK_AREA),
            TRAY_PANEL_WIDTH,
            TRAY_PANEL_HEIGHT,
            TRAY_PANEL_GAP,
        )
    }

    #[test]
    fn anchor_prefers_event_bounds_even_with_cursor_elsewhere() {
        let anchor = resolve_tray_anchor(
            Some(BOTTOM_TRAY),
            Some(EMPTY),
            Some(OTHER_MONITOR_CURSOR),
            Some(WORK_AREA),
        );
        assert_eq!(anchor, BOTTOM_TRAY);
        assert_eq!(
            resolve_tray_display_point(Some(BOTTOM_TRAY), None, Some(OTHER_MONITOR_CURSOR)),
            Point {
                x: 1680.0,
                y: 1044.0
            }
        );
    }

    #[test]
    fn anchor_ignores_a_y0_tray_rect_far_from_the_cursor() {
        let lied = Bounds {
            x: 1680.0,
            y: 0.0,
            width: 24.0,
            height: 24.0,
        };
        let cursor = Point {
            x: 1692.0,
            y: 1058.0,
        };
        assert_eq!(
            resolve_tray_anchor(None, Some(lied), Some(cursor), Some(WORK_AREA)),
            Bounds {
                x: 1692.0,
                y: 1058.0,
                width: 1.0,
                height: 1.0
            }
        );
        // Without a cursor the tray rect is trusted.
        assert_eq!(
            resolve_tray_anchor(None, Some(lied), None, Some(WORK_AREA)),
            lied
        );
        // Nothing usable: bottom-right corner of the work area.
        assert_eq!(
            resolve_tray_anchor(Some(EMPTY), Some(EMPTY), None, Some(WORK_AREA)),
            Bounds {
                x: 1920.0,
                y: 1040.0,
                width: 1.0,
                height: 1.0
            }
        );
    }

    #[test]
    fn panel_goes_below_a_top_tray_and_above_a_bottom_tray() {
        assert_eq!(
            place(TOP_TRAY),
            Bounds {
                x: 900.0 + 12.0 - 180.0,
                y: 30.0,
                width: 360.0,
                height: 520.0
            }
        );
        assert_eq!(
            place(BOTTOM_TRAY),
            Bounds {
                x: 1680.0 + 12.0 - 180.0,
                y: 1044.0 - 520.0 - 6.0,
                width: 360.0,
                height: 520.0
            }
        );
    }

    #[test]
    fn panel_is_clamped_to_the_work_area() {
        let placed = place(Bounds {
            x: 1900.0,
            y: 1044.0,
            width: 24.0,
            height: 24.0,
        });
        assert_eq!(placed.x, 1920.0 - 360.0);
        assert_eq!(placed.y, 1044.0 - 520.0 - 6.0);
        // A work area smaller than the panel shrinks it.
        let small = place_tray_panel(
            Some(TOP_TRAY),
            Some(Bounds {
                x: 0.0,
                y: 0.0,
                width: 300.0,
                height: 400.0,
            }),
            360.0,
            520.0,
            6.0,
        );
        assert_eq!((small.width, small.height), (300.0, 400.0));
        assert_eq!((small.x, small.y), (0.0, 0.0));
    }

    #[test]
    fn tray_icon_lifecycle_matches_electron() {
        // setCloseToTray(true) creates the tray; hiding the icon removes it
        // but close-to-tray still hides the window.
        let mut p = Prefs::default();
        assert_eq!(p.set_close_to_tray(true), TrayChange::Ensure);
        assert!(p.hides_on_close(true));
        assert_eq!(p.set_show_tray_icon(false), TrayChange::Remove);
        assert!(p.hides_on_close(false));
        // ... and does not recreate it while hidden by preference.
        assert_eq!(p.set_close_to_tray(true), TrayChange::Keep);
        assert_eq!(p.set_show_tray_icon(true), TrayChange::Ensure);
        // Close-to-tray off: a visible tray stays, the window closes.
        assert_eq!(p.set_close_to_tray(false), TrayChange::Keep);
        assert!(!p.hides_on_close(true));
    }

    #[test]
    fn hidden_launch_pin_keeps_the_tray_until_released() {
        let mut p = Prefs::default();
        assert_eq!(p.pin_for_hidden_launch(), TrayChange::Ensure);
        assert_eq!(p.set_show_tray_icon(false), TrayChange::Keep);
        assert_eq!(p.release_hidden_launch_pin(), TrayChange::Remove);
        // Releasing twice (or without a pin) is a no-op.
        assert_eq!(p.release_hidden_launch_pin(), TrayChange::Keep);

        let mut p = Prefs::default();
        p.pin_for_hidden_launch();
        assert_eq!(p.release_hidden_launch_pin(), TrayChange::Keep);
    }

    #[test]
    fn menu_data_updates_only_replace_given_lists() {
        let mut p = Prefs::default();
        p.apply_update(
            serde_json::from_value(
                json!({ "sessions": [{ "id": "s1" }], "hosts": [{ "id": "h" }] }),
            )
            .unwrap(),
        );
        p.apply_update(
            serde_json::from_value(json!({ "portForwardRules": [{ "id": "r" }] })).unwrap(),
        );
        assert_eq!(p.menu_data.sessions.len(), 1);
        assert_eq!(p.menu_data.port_forward_rules.len(), 1);
        assert_eq!(p.menu_data.hosts.len(), 1);
        assert_eq!(
            serde_json::to_value(&p.menu_data).unwrap(),
            json!({
                "sessions": [{ "id": "s1" }],
                "portForwardRules": [{ "id": "r" }],
                "hosts": [{ "id": "h" }]
            })
        );
    }

    #[test]
    fn native_menu_matches_the_electron_template() {
        let data: TrayMenuData = serde_json::from_value(json!({
            "sessions": [
                { "id": "s1", "label": "web", "hostLabel": "Web 1", "status": "connected" },
                { "id": "s2", "label": "ai", "hostLabel": "", "status": "connecting", "aiHidden": true }
            ],
            "portForwardRules": [
                { "id": "r1", "label": "", "type": "local", "localPort": 8080, "remoteHost": "db", "remotePort": 5432, "status": "inactive" },
                { "id": "r2", "label": "socks", "type": "dynamic", "localPort": 1080, "status": "connecting" },
                { "id": "r3", "label": "", "type": "remote", "localPort": 9000, "remoteHost": "x", "remotePort": 1, "status": "error", "canStop": true }
            ]
        }))
        .unwrap();
        let labels: Vec<(String, bool)> = build_menu_entries(&data)
            .into_iter()
            .map(|e| match e {
                MenuEntry::Item { label, enabled, .. } => (label, enabled),
                MenuEntry::Separator => ("---".into(), true),
            })
            .collect();
        let expected: Vec<(&str, bool)> = vec![
            ("Open Main Window", true),
            ("---", true),
            ("Sessions", false),
            ("  Web 1  (Connected)", true),
            ("  ai  (Connecting)", true),
            ("---", true),
            ("Port Forwarding", false),
            ("  [L] 8080 → db:5432  (Inactive)", true),
            ("  [D] socks  (Connecting)", false),
            ("  [R] 9000 → x:1  (Error)", true),
            ("---", true),
            ("Quit", true),
        ];
        assert_eq!(
            labels,
            expected
                .into_iter()
                .map(|(l, e)| (l.to_owned(), e))
                .collect::<Vec<_>>()
        );

        let ids: Vec<String> = build_menu_entries(&data)
            .into_iter()
            .filter_map(|e| match e {
                MenuEntry::Item { id, .. } => Some(id),
                MenuEntry::Separator => None,
            })
            .collect();
        assert_eq!(
            parse_menu_action(&ids[2]),
            Some(MenuAction::FocusSession {
                session_id: "s1".into(),
                focus: true
            })
        );
        assert_eq!(
            parse_menu_action(&ids[3]),
            Some(MenuAction::FocusSession {
                session_id: "s2".into(),
                focus: false
            })
        );
        // Inactive → start; error with canStop → explicit stop.
        assert_eq!(
            parse_menu_action(&ids[5]),
            Some(MenuAction::TogglePortForward {
                rule_id: "r1".into(),
                start: true
            })
        );
        assert_eq!(
            parse_menu_action(&ids[7]),
            Some(MenuAction::TogglePortForward {
                rule_id: "r3".into(),
                start: false
            })
        );
        assert_eq!(
            parse_menu_action(MENU_OPEN_MAIN),
            Some(MenuAction::OpenMain)
        );
        assert_eq!(parse_menu_action(MENU_QUIT), Some(MenuAction::Quit));
        assert_eq!(parse_menu_action("tray:header:sessions"), None);
    }

    #[test]
    fn empty_menu_has_open_and_quit_only() {
        let entries = build_menu_entries(&TrayMenuData::default());
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn tray_icon_artwork_decodes() {
        assert!(tray_image().is_some());
    }
}

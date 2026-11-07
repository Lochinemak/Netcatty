//! Window management (Electron: `windowManager.cjs`, `settingsWindow.cjs`):
//! the reusable settings window, the custom title-bar controls, native theme
//! and background colour, language broadcast and cross-window settings sync.
//!
//! Commands act on the window that invoked them (`tauri::WebviewWindow`
//! command argument), like Electron's `getWindowForIpcEvent`.

use super::CmdResult;
use netcatty_core::CoreError;
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tauri::window::Color;
use tauri::{
    AppHandle, Manager, Runtime, Theme, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
    WindowEvent,
};

pub const MAIN_LABEL: &str = "main";
pub const SETTINGS_LABEL: &str = "settings";

/// Same size as the Electron settings window.
const SETTINGS_WIDTH: f64 = 980.0;
const SETTINGS_HEIGHT: f64 = 720.0;
/// A hidden window is shown on `rendererReady`; this is the fallback when
/// the signal never arrives (Electron uses the same safety net).
const SHOW_FALLBACK: Duration = Duration::from_secs(3);

use netcatty_core::ipc::events::{
    LANGUAGE_CHANGED as EVENT_LANGUAGE_CHANGED, SETTINGS_CHANGED as EVENT_SETTINGS_CHANGED,
    WINDOW_FULLSCREEN_CHANGED as EVENT_FULLSCREEN_CHANGED,
};

/// Window-level preferences applied to windows created later (the settings
/// window opens after the renderer already pushed theme / background).
#[derive(Default)]
pub struct WindowState {
    theme: Mutex<Option<Theme>>,
    background: Mutex<Option<Color>>,
    language: Mutex<String>,
    fullscreen: Mutex<HashMap<String, bool>>,
}

/// Cross-window settings broadcast. `source` is the label of the sending
/// window: Tauri delivers events to every `listen()` subscriber, so the
/// renderer drops its own echoes.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SettingsChanged {
    source: String,
    payload: Value,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FullscreenChanged {
    label: String,
    fullscreen: bool,
}

fn window_state<R: Runtime>(app: &AppHandle<R>) -> tauri::State<'_, WindowState> {
    app.state::<WindowState>()
}

fn internal(err: impl std::fmt::Display) -> CoreError {
    CoreError::internal(err.to_string())
}

// ---------------------------------------------------------------------------
// Window event hook (wired in `lib.rs`)
// ---------------------------------------------------------------------------

/// Per-window lifecycle handling:
/// * the settings window is hidden instead of destroyed (reused on next open);
/// * closing the main window also destroys the hidden settings window, so the
///   app quits instead of lingering without a visible window;
/// * fullscreen transitions are reported to the window's renderer.
pub fn on_window_event<R: Runtime>(window: &tauri::Window<R>, event: &WindowEvent) {
    let label = window.label().to_owned();
    match event {
        WindowEvent::CloseRequested { api, .. } if label == SETTINGS_LABEL => {
            api.prevent_close();
            let _ = window.hide();
        }
        WindowEvent::CloseRequested { .. } if label == MAIN_LABEL => {
            // Tauri quits once the last window is gone; drop the hidden
            // settings window so it cannot keep the process alive.
            if let Some(settings) = window.app_handle().get_webview_window(SETTINGS_LABEL) {
                let _ = settings.destroy();
            }
        }
        WindowEvent::Destroyed => {
            window_state(window.app_handle())
                .fullscreen
                .lock()
                .remove(&label);
        }
        WindowEvent::Resized(_) => {
            let Ok(fullscreen) = window.is_fullscreen() else {
                return;
            };
            let app = window.app_handle();
            let previous = window_state(app)
                .fullscreen
                .lock()
                .insert(label.clone(), fullscreen);
            if previous.unwrap_or(false) != fullscreen {
                crate::events::emit(
                    app,
                    EVENT_FULLSCREEN_CHANGED,
                    FullscreenChanged { label, fullscreen },
                );
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Settings window
// ---------------------------------------------------------------------------

fn show_and_focus<R: Runtime>(window: &WebviewWindow<R>) {
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
}

/// Centre `window` (of the given logical size) on the monitor `source` is on.
fn center_on<R: Runtime>(window: &WebviewWindow<R>, source: Option<&WebviewWindow<R>>) {
    let monitor = source
        .and_then(|w| w.current_monitor().ok().flatten())
        .or_else(|| window.current_monitor().ok().flatten());
    let Some(monitor) = monitor else {
        let _ = window.center();
        return;
    };
    let scale = monitor.scale_factor();
    let area = monitor.work_area();
    let width = (SETTINGS_WIDTH * scale) as i32;
    let height = (SETTINGS_HEIGHT * scale) as i32;
    let x = area.position.x + (area.size.width as i32 - width) / 2;
    let y = area.position.y + (area.size.height as i32 - height) / 2;
    let _ = window.set_position(tauri::PhysicalPosition::new(
        x.max(area.position.x),
        y.max(area.position.y),
    ));
}

fn build_settings_window<R: Runtime>(app: &AppHandle<R>) -> CmdResult<WebviewWindow<R>> {
    let state = window_state(app);
    let builder = WebviewWindowBuilder::new(
        app,
        SETTINGS_LABEL,
        WebviewUrl::App("index.html#/settings".into()),
    )
    .title("Settings")
    .inner_size(SETTINGS_WIDTH, SETTINGS_HEIGHT)
    .min_inner_size(720.0, 520.0)
    .resizable(true)
    .visible(false)
    .disable_drag_drop_handler()
    .theme(*state.theme.lock());
    let builder = match *state.background.lock() {
        Some(color) => builder.background_color(color),
        None => builder,
    };
    // Same chrome as Electron: inset traffic lights on macOS (the page keeps
    // a spacer for them), frameless elsewhere (the page draws its own close
    // button and drag region).
    #[cfg(target_os = "macos")]
    let builder = builder
        .title_bar_style(tauri::TitleBarStyle::Overlay)
        .hidden_title(true);
    #[cfg(not(target_os = "macos"))]
    let builder = builder.decorations(false);
    builder.build().map_err(internal)
}

/// Fallback for a renderer that never reports ready.
fn schedule_show_fallback<R: Runtime>(window: WebviewWindow<R>) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(SHOW_FALLBACK).await;
        if !window.is_visible().unwrap_or(true) {
            show_and_focus(&window);
        }
    });
}

/// Open (or re-show) the settings window. Resolves `true` like Electron.
#[tauri::command]
pub async fn window_open_settings<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
) -> CmdResult<bool> {
    if let Some(existing) = app.get_webview_window(SETTINGS_LABEL) {
        center_on(&existing, Some(&window));
        show_and_focus(&existing);
        return Ok(true);
    }
    let settings = build_settings_window(&app)?;
    center_on(&settings, Some(&window));
    schedule_show_fallback(settings);
    Ok(true)
}

/// Hide the settings window (it is reused on the next open). Called from any
/// other window it still targets the settings window, like Electron.
#[tauri::command]
pub fn window_close_settings<R: Runtime>(app: AppHandle<R>, window: WebviewWindow<R>) -> bool {
    let target = app.get_webview_window(SETTINGS_LABEL).unwrap_or(window);
    target.hide().is_ok()
}

/// Renderer finished its first render: show a window created hidden.
#[tauri::command]
pub fn window_renderer_ready<R: Runtime>(window: WebviewWindow<R>) {
    if !window.is_visible().unwrap_or(true) {
        show_and_focus(&window);
    }
}

// ---------------------------------------------------------------------------
// Title-bar controls (custom window buttons on Windows / Linux)
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn window_minimize<R: Runtime>(window: WebviewWindow<R>) -> CmdResult<()> {
    window.minimize().map_err(internal)
}

/// Toggle maximize; returns the new maximized state (Electron parity).
#[tauri::command]
pub fn window_maximize<R: Runtime>(window: WebviewWindow<R>) -> CmdResult<bool> {
    if window.is_maximized().map_err(internal)? {
        window.unmaximize().map_err(internal)?;
        Ok(false)
    } else {
        window.maximize().map_err(internal)?;
        Ok(true)
    }
}

#[tauri::command]
pub fn window_close<R: Runtime>(window: WebviewWindow<R>) -> CmdResult<()> {
    window.close().map_err(internal)
}

#[tauri::command]
pub fn window_is_maximized<R: Runtime>(window: WebviewWindow<R>) -> bool {
    window.is_maximized().unwrap_or(false)
}

#[tauri::command]
pub fn window_is_fullscreen<R: Runtime>(window: WebviewWindow<R>) -> bool {
    window.is_fullscreen().unwrap_or(false)
}

#[tauri::command]
pub fn window_focus<R: Runtime>(window: WebviewWindow<R>) -> bool {
    show_and_focus(&window);
    true
}

/// Empty titles fall back to the app name (Electron parity).
#[tauri::command]
pub fn window_set_title<R: Runtime>(window: WebviewWindow<R>, title: Option<String>) -> bool {
    let title = title.unwrap_or_default();
    let title = title.trim();
    window
        .set_title(if title.is_empty() { "Netcatty" } else { title })
        .is_ok()
}

/// Show and focus the main window (tray / secondary windows).
#[tauri::command]
pub fn window_open_main<R: Runtime>(app: AppHandle<R>) -> bool {
    match app.get_webview_window(MAIN_LABEL) {
        Some(main) => {
            show_and_focus(&main);
            true
        }
        None => false,
    }
}

#[tauri::command]
pub fn app_quit<R: Runtime>(app: AppHandle<R>) {
    app.exit(0);
}

// ---------------------------------------------------------------------------
// Theme, background colour, language
// ---------------------------------------------------------------------------

/// `"light" | "dark" | "system"` → native window theme for every window.
#[tauri::command]
pub fn app_set_theme<R: Runtime>(app: AppHandle<R>, theme: String) -> bool {
    let theme = match theme.as_str() {
        "light" => Some(Theme::Light),
        "dark" => Some(Theme::Dark),
        _ => None,
    };
    *window_state(&app).theme.lock() = theme;
    for window in app.webview_windows().values() {
        let _ = window.set_theme(theme);
    }
    true
}

/// Window background behind the webview (visible while resizing / loading).
/// Accepts `#rgb`, `#rrggbb`, `#rrggbbaa` or the theme token form
/// `"H S% L%"`; returns `false` for anything else (Electron parity).
#[tauri::command]
pub fn app_set_background_color<R: Runtime>(app: AppHandle<R>, color: Option<String>) -> bool {
    let Some(color) = color.as_deref().and_then(parse_color) else {
        return false;
    };
    *window_state(&app).background.lock() = Some(color);
    for window in app.webview_windows().values() {
        let _ = window.set_background_color(Some(color));
    }
    true
}

/// Remember the UI language and tell every window (Electron:
/// `broadcastLanguageChanged`).
#[tauri::command]
pub fn app_set_language<R: Runtime>(app: AppHandle<R>, language: Option<String>) -> bool {
    let language = language
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "en".to_owned());
    *window_state(&app).language.lock() = language.clone();
    crate::events::emit(&app, EVENT_LANGUAGE_CHANGED, language);
    true
}

/// Relay a settings change to the other windows.
#[tauri::command]
pub fn app_broadcast_settings_changed<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    payload: Value,
) {
    crate::events::emit(
        &app,
        EVENT_SETTINGS_CHANGED,
        SettingsChanged {
            source: window.label().to_owned(),
            payload,
        },
    );
}

// ---------------------------------------------------------------------------
// Colour parsing
// ---------------------------------------------------------------------------

pub(crate) fn parse_color(raw: &str) -> Option<Color> {
    let raw = raw.trim();
    if let Some(hex) = raw.strip_prefix('#') {
        return parse_hex(hex);
    }
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    let h: f64 = parts[0].parse().ok()?;
    let s: f64 = parts[1].trim_end_matches('%').parse().ok()?;
    let l: f64 = parts[2].trim_end_matches('%').parse().ok()?;
    if !(h.is_finite() && s.is_finite() && l.is_finite()) {
        return None;
    }
    let (r, g, b) = hsl_to_rgb(h, s, l);
    Some(Color(r, g, b, 255))
}

fn parse_hex(hex: &str) -> Option<Color> {
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let digit = |i: usize| u8::from_str_radix(&hex[i..i + 1], 16).ok();
    let byte = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).ok();
    match hex.len() {
        3 => Some(Color(digit(0)? * 17, digit(1)? * 17, digit(2)? * 17, 255)),
        6 => Some(Color(byte(0)?, byte(2)?, byte(4)?, 255)),
        8 => Some(Color(byte(0)?, byte(2)?, byte(4)?, byte(6)?)),
        _ => None,
    }
}

/// CSS HSL → sRGB (h in degrees, s / l in percent), same rounding as
/// Electron's `hslToHex`.
fn hsl_to_rgb(h: f64, s: f64, l: f64) -> (u8, u8, u8) {
    let s = (s / 100.0).clamp(0.0, 1.0);
    let l = (l / 100.0).clamp(0.0, 1.0);
    let a = s * l.min(1.0 - l);
    let channel = |n: f64| {
        let k = (n + h / 30.0).rem_euclid(12.0);
        let value = l - a * (k - 3.0).min(9.0 - k).clamp(-1.0, 1.0);
        (value * 255.0).round().clamp(0.0, 255.0) as u8
    };
    (channel(0.0), channel(8.0), channel(4.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgb(color: Color) -> (u8, u8, u8, u8) {
        color.into()
    }

    #[test]
    fn parses_hex_forms() {
        assert_eq!(rgb(parse_color("#fff").unwrap()), (255, 255, 255, 255));
        assert_eq!(
            rgb(parse_color("#1e2a3b").unwrap()),
            (0x1e, 0x2a, 0x3b, 255)
        );
        assert_eq!(
            rgb(parse_color(" #1e2a3b80 ").unwrap()),
            (0x1e, 0x2a, 0x3b, 0x80)
        );
        assert!(parse_color("#12").is_none());
        assert!(parse_color("#zzzzzz").is_none());
    }

    #[test]
    fn parses_theme_hsl_tokens() {
        assert_eq!(rgb(parse_color("0 0% 100%").unwrap()), (255, 255, 255, 255));
        assert_eq!(rgb(parse_color("0 0% 0%").unwrap()), (0, 0, 0, 255));
        // 216 33% 96% (light theme background) = #f1f4f8, as Electron
        assert_eq!(
            rgb(parse_color("216 33% 96%").unwrap()),
            (241, 244, 248, 255)
        );
        assert_eq!(rgb(parse_color("120 100% 50%").unwrap()), (0, 255, 0, 255));
        assert!(parse_color("").is_none());
        assert!(parse_color("red").is_none());
        assert!(parse_color("1 2").is_none());
    }
}

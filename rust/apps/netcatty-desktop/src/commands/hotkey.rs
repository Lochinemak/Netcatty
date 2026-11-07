//! Global toggle hotkey, "Quake mode" (Electron: `globalShortcutBridge.cjs`
//! `registerGlobalHotkey` / `unregisterGlobalHotkey`), on
//! `tauri-plugin-global-shortcut`.
//!
//! The renderer sends its display form (`"⌘ + Space"`, `"Ctrl + `"`); it is
//! converted to an Electron-style accelerator (returned to the renderer as in
//! Electron) and from there to a plugin shortcut.

use parking_lot::Mutex;
use serde::Serialize;
use std::str::FromStr;
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_global_shortcut::{Shortcut, ShortcutState};

const DISABLED: &str = "Disabled";

/// Registered hotkey (renderer form + plugin shortcut).
#[derive(Default)]
pub struct HotkeyState {
    current: Mutex<Option<(String, Shortcut)>>,
    /// Serializes register / unregister (the commands are async and the
    /// renderer may fire two in a row, e.g. React StrictMode effects).
    op: Mutex<()>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accelerator: Option<String>,
}

impl RegisterResult {
    fn failed(error: impl Into<String>) -> Self {
        Self {
            success: false,
            enabled: None,
            error: Some(error.into()),
            accelerator: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HotkeyStatus {
    enabled: bool,
    hotkey: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessResult {
    success: bool,
}

/// Manage [`HotkeyState`] and register the global-shortcut plugin. The
/// plugin is added at runtime so a platform without a usable hotkey
/// backend only loses this feature (`registerGlobalHotkey` then reports an
/// error) instead of failing app start.
pub fn setup<R: Runtime>(app: &tauri::App<R>) {
    app.manage(HotkeyState::default());
    if let Err(err) = app
        .handle()
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
    {
        tracing::warn!(%err, "global shortcuts unavailable");
    }
}

/// Renderer hotkey string → Electron accelerator (`toElectronAccelerator`).
/// `None` for an empty / disabled hotkey.
pub(crate) fn to_accelerator(hotkey: &str) -> Option<String> {
    if hotkey.is_empty() || hotkey == DISABLED {
        return None;
    }
    let parts: Vec<String> = hotkey
        .split('+')
        .map(str::trim)
        .map(|part| {
            match part {
                "⌘" | "Cmd" | "Command" => "CommandOrControl",
                "⌃" | "Ctrl" | "Control" => "Control",
                "⌥" | "Alt" | "Option" => "Alt",
                "Shift" => "Shift",
                "Win" | "Super" | "Meta" => "Super",
                "↑" => "Up",
                "↓" => "Down",
                "←" => "Left",
                "→" => "Right",
                "↵" | "Enter" | "Return" => "Return",
                "⇥" | "Tab" => "Tab",
                "⌫" | "Backspace" => "Backspace",
                "Del" | "Delete" => "Delete",
                "Esc" | "Escape" => "Escape",
                "Space" => "Space",
                "`" | "~" => "`",
                other if is_function_key(other) => return other.to_ascii_uppercase(),
                other => other,
            }
            .to_owned()
        })
        .collect();
    Some(parts.join("+"))
}

fn is_function_key(part: &str) -> bool {
    let mut chars = part.chars();
    matches!(chars.next(), Some('F' | 'f'))
        && !part[1..].is_empty()
        && part[1..].chars().all(|c| c.is_ascii_digit())
}

/// Electron accelerator → plugin shortcut. Shifted US-layout symbols map to
/// their physical key (the renderer records `e.key`, so `Shift + !` means
/// Shift+1).
pub(crate) fn to_shortcut(accelerator: &str) -> Option<Shortcut> {
    let tokens: Vec<String> = accelerator
        .split('+')
        .map(|token| {
            match token {
                "Return" => "Enter",
                "!" => "1",
                "@" => "2",
                "#" => "3",
                "$" => "4",
                "%" => "5",
                "^" => "6",
                "&" => "7",
                "*" => "8",
                "(" => "9",
                ")" => "0",
                "_" => "-",
                "{" => "[",
                "}" => "]",
                "|" => "\\",
                ":" => ";",
                "\"" => "'",
                "<" => ",",
                ">" => ".",
                "?" => "/",
                other => other,
            }
            .to_owned()
        })
        .collect();
    Shortcut::from_str(&tokens.join("+")).ok()
}

fn unregister_current<R: Runtime>(app: &AppHandle<R>) {
    let Some(state) = app.try_state::<HotkeyState>() else {
        return;
    };
    let Some((hotkey, shortcut)) = state.current.lock().take() else {
        return;
    };
    if let Some(plugin) = app.try_state::<tauri_plugin_global_shortcut::GlobalShortcut<R>>() {
        if let Err(err) = plugin.unregister(shortcut) {
            tracing::warn!(%err, hotkey, "global hotkey unregister failed");
        }
    }
}

// Async: the plugin registers on the main thread and blocks until done,
// which would deadlock a synchronous (main-thread) command.

/// Register the toggle hotkey, replacing the previous one.
#[tauri::command]
pub async fn hotkey_register<R: Runtime>(
    app: AppHandle<R>,
    hotkey: Option<String>,
) -> RegisterResult {
    let state = app.try_state::<HotkeyState>();
    let _op = state.as_ref().map(|s| s.op.lock());
    unregister_current(&app);
    let hotkey = hotkey.unwrap_or_default();
    let Some(accelerator) = to_accelerator(&hotkey) else {
        return RegisterResult {
            success: true,
            enabled: Some(false),
            error: None,
            accelerator: None,
        };
    };
    let Some(shortcut) = to_shortcut(&accelerator) else {
        return RegisterResult::failed("Invalid hotkey format");
    };
    let Some(plugin) = app.try_state::<tauri_plugin_global_shortcut::GlobalShortcut<R>>() else {
        return RegisterResult::failed("Global shortcuts are not available on this system");
    };
    let registered = plugin.on_shortcut(shortcut, |app, _shortcut, event| {
        if event.state == ShortcutState::Pressed {
            super::tray::toggle_main_window(app);
        }
    });
    match registered {
        Ok(()) => {
            if let Some(state) = &state {
                *state.current.lock() = Some((hotkey, shortcut));
            }
            tracing::info!(accelerator, "global hotkey registered");
            RegisterResult {
                success: true,
                enabled: Some(true),
                error: None,
                accelerator: Some(accelerator),
            }
        }
        Err(err) => {
            tracing::warn!(%err, accelerator, "global hotkey registration failed");
            RegisterResult::failed("Hotkey may be in use by another application")
        }
    }
}

#[tauri::command]
pub async fn hotkey_unregister<R: Runtime>(app: AppHandle<R>) -> SuccessResult {
    let state = app.try_state::<HotkeyState>();
    let _op = state.as_ref().map(|s| s.op.lock());
    unregister_current(&app);
    SuccessResult { success: true }
}

#[tauri::command]
pub fn hotkey_status<R: Runtime>(app: AppHandle<R>) -> HotkeyStatus {
    let hotkey = app
        .try_state::<HotkeyState>()
        .and_then(|s| s.current.lock().as_ref().map(|(h, _)| h.clone()));
    HotkeyStatus {
        enabled: hotkey.is_some(),
        hotkey,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tauri_plugin_global_shortcut::{Code, Modifiers};

    #[test]
    fn converts_renderer_hotkeys_like_electron() {
        assert_eq!(
            to_accelerator("⌘ + Space").as_deref(),
            Some("CommandOrControl+Space")
        );
        assert_eq!(to_accelerator("⌃ + `").as_deref(), Some("Control+`"));
        assert_eq!(to_accelerator("Ctrl + `").as_deref(), Some("Control+`"));
        assert_eq!(
            to_accelerator("Alt + Shift + ~").as_deref(),
            Some("Alt+Shift+`")
        );
        assert_eq!(to_accelerator("Win + ↑").as_deref(), Some("Super+Up"));
        assert_eq!(to_accelerator("⌥ + ↵").as_deref(), Some("Alt+Return"));
        assert_eq!(to_accelerator("Ctrl + f12").as_deref(), Some("Control+F12"));
        assert_eq!(to_accelerator("Ctrl + K").as_deref(), Some("Control+K"));
        assert_eq!(to_accelerator("Disabled"), None);
        assert_eq!(to_accelerator(""), None);
    }

    #[test]
    fn accelerators_parse_into_plugin_shortcuts() {
        let shortcut = |s: &str| to_shortcut(&to_accelerator(s).unwrap());
        assert_eq!(
            shortcut("Ctrl + `"),
            Some(Shortcut::new(Some(Modifiers::CONTROL), Code::Backquote))
        );
        assert_eq!(
            shortcut("Alt + ↵"),
            Some(Shortcut::new(Some(Modifiers::ALT), Code::Enter))
        );
        assert_eq!(
            shortcut("Ctrl + Shift + !"),
            Some(Shortcut::new(
                Some(Modifiers::CONTROL | Modifiers::SHIFT),
                Code::Digit1
            ))
        );
        assert_eq!(
            shortcut("Win + Esc"),
            Some(Shortcut::new(Some(Modifiers::SUPER), Code::Escape))
        );
        let expected_cmd = if cfg!(target_os = "macos") {
            Modifiers::SUPER
        } else {
            Modifiers::CONTROL
        };
        assert_eq!(
            shortcut("⌘ + Space"),
            Some(Shortcut::new(Some(expected_cmd), Code::Space))
        );
        // Keys the backend cannot express are rejected.
        assert_eq!(shortcut("Ctrl + ä"), None);
        assert_eq!(shortcut("Ctrl + "), None);
    }
}

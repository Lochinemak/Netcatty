//! Native system notifications (Electron: `systemNotification.cjs`), on
//! `tauri-plugin-notification`.
//!
//! Title / body are sanitized like Electron (control characters stripped,
//! whitespace collapsed, 120 / 500 characters with an ellipsis). Clicking a
//! notification shows and focuses the window that raised it and, when it
//! carried a `sessionId`, emits `netcatty:tray:focusSession` to that window.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use tauri::{AppHandle, Manager, Runtime, WebviewWindow};
use tauri_plugin_notification::{NotificationExt, PermissionState};

const TITLE_MAX: usize = 120;
const BODY_MAX: usize = 500;
const DEFAULT_TITLE: &str = "Netcatty";
/// Click targets remembered for this many recent notifications.
const MAX_TRACKED: usize = 256;

/// Dedupe keys and click targets of shown notifications.
#[derive(Default)]
pub struct NotificationState {
    shown_keys: Mutex<HashSet<String>>,
    targets: Mutex<VecDeque<ClickTarget>>,
    next_id: Mutex<i32>,
}

struct ClickTarget {
    id: i32,
    label: String,
    session_id: String,
}

/// `showSystemNotification` payload. Fields are read leniently (non-strings
/// are ignored) as in Electron.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShowNotificationPayload {
    #[serde(default)]
    title: Value,
    #[serde(default)]
    body: Value,
    #[serde(default)]
    session_id: Value,
    #[serde(default)]
    dedupe_key: Value,
    #[serde(default)]
    when_unfocused: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ShowNotificationResult {
    shown: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl ShowNotificationResult {
    fn skipped(reason: impl Into<String>) -> Self {
        Self {
            shown: false,
            reason: Some(reason.into()),
        }
    }
}

/// Manage [`NotificationState`], register the plugin and route clicks.
pub fn setup<R: Runtime>(app: &tauri::App<R>) {
    app.manage(NotificationState::default());
    let handle = app.handle();
    if let Err(err) = handle.plugin(tauri_plugin_notification::init()) {
        tracing::warn!(%err, "system notifications unavailable");
        return;
    }
    let click_app = handle.clone();
    let _ = handle.notification().on_action(move |performed| {
        if performed.action_id() != "tap" {
            return;
        }
        if let Some(id) = performed.notification().map(|n| n.id()) {
            on_click(&click_app, id);
        }
    });
}

fn on_click<R: Runtime>(app: &AppHandle<R>, id: i32) {
    let Some(state) = app.try_state::<NotificationState>() else {
        return;
    };
    let target = {
        let mut targets = state.targets.lock();
        let index = targets.iter().position(|t| t.id == id);
        index.and_then(|i| targets.remove(i))
    };
    let Some(target) = target else {
        return;
    };
    if let Some(window) = app.get_webview_window(&target.label) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        if target.label == super::window::MAIN_LABEL {
            super::tray::main_window_shown(app);
        }
    }
    if !target.session_id.is_empty() {
        super::tray::emit_focus_session(app, &target.label, &target.session_id);
    }
}

/// Strip control characters, collapse whitespace, trim and truncate to `max`
/// characters with a trailing ellipsis (`sanitizeNotificationText`).
pub(crate) fn sanitize_notification_text(value: &Value, max: usize) -> String {
    let Some(text) = value.as_str() else {
        return String::new();
    };
    if max == 0 {
        return String::new();
    }
    let without_controls: String = text
        .chars()
        .filter(|c| !matches!(c, '\0'..='\x08' | '\x0B' | '\x0C' | '\x0E'..='\x1F' | '\x7F'))
        .collect();
    let cleaned = without_controls
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if cleaned.chars().count() <= max {
        return cleaned;
    }
    let head: String = cleaned.chars().take(max - 1).collect();
    format!("{}…", head.trim_end())
}

fn any_window_focused<R: Runtime>(app: &AppHandle<R>) -> bool {
    app.webview_windows()
        .values()
        .any(|w| w.is_focused().unwrap_or(false))
}

/// Show a native notification for the calling window.
#[tauri::command]
pub async fn notification_show<R: Runtime>(
    app: AppHandle<R>,
    window: WebviewWindow<R>,
    payload: Option<ShowNotificationPayload>,
) -> ShowNotificationResult {
    let payload = payload.unwrap_or_default();
    if payload.when_unfocused == Value::Bool(true) && any_window_focused(&app) {
        return ShowNotificationResult::skipped("focused");
    }
    let Some(state) = app.try_state::<NotificationState>() else {
        return ShowNotificationResult::skipped("unavailable");
    };
    let dedupe_key = payload.dedupe_key.as_str().unwrap_or_default().to_owned();
    if !dedupe_key.is_empty() && state.shown_keys.lock().contains(&dedupe_key) {
        return ShowNotificationResult::skipped("duplicate");
    }
    if app
        .try_state::<tauri_plugin_notification::Notification<R>>()
        .is_none()
    {
        return ShowNotificationResult::skipped("unavailable");
    }
    if !matches!(
        app.notification().permission_state(),
        Ok(PermissionState::Granted)
    ) {
        return ShowNotificationResult::skipped("unsupported");
    }

    let title = Some(sanitize_notification_text(&payload.title, TITLE_MAX))
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| DEFAULT_TITLE.to_owned());
    let body = sanitize_notification_text(&payload.body, BODY_MAX);
    let id = {
        let mut next = state.next_id.lock();
        *next = next.wrapping_add(1).max(1);
        *next
    };
    {
        let mut targets = state.targets.lock();
        if targets.len() >= MAX_TRACKED {
            targets.pop_front();
        }
        targets.push_back(ClickTarget {
            id,
            label: window.label().to_owned(),
            session_id: payload.session_id.as_str().unwrap_or_default().to_owned(),
        });
    }

    match app
        .notification()
        .builder()
        .id(id)
        .title(title)
        .body(body)
        .show()
    {
        Ok(()) => {
            if !dedupe_key.is_empty() {
                state.shown_keys.lock().insert(dedupe_key);
            }
            ShowNotificationResult {
                shown: true,
                reason: None,
            }
        }
        Err(err) => ShowNotificationResult::skipped(err.to_string()),
    }
}

/// Best-effort backend notification without a click target (file-watch
/// sync results, like Electron's `showSystemNotification` helper there).
pub fn show_simple<R: Runtime>(app: &AppHandle<R>, title: &str, body: &str) {
    if app
        .try_state::<tauri_plugin_notification::Notification<R>>()
        .is_none()
        || !matches!(
            app.notification().permission_state(),
            Ok(PermissionState::Granted)
        )
    {
        return;
    }
    let body = sanitize_notification_text(&Value::String(body.to_owned()), BODY_MAX);
    if let Err(err) = app.notification().builder().title(title).body(body).show() {
        tracing::debug!(%err, "notification failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sanitizes_like_electron() {
        assert_eq!(
            sanitize_notification_text(&json!("  a\u{0007}b\n\n c\t d  "), 120),
            "ab c d"
        );
        assert_eq!(sanitize_notification_text(&json!(42), 120), "");
        assert_eq!(sanitize_notification_text(&json!("abc"), 0), "");
        assert_eq!(sanitize_notification_text(&json!("abcdef"), 4), "abc…");
        // Trailing whitespace before the ellipsis is trimmed.
        assert_eq!(sanitize_notification_text(&json!("ab cdef"), 4), "ab…");
        assert_eq!(
            sanitize_notification_text(&json!("中文标题"), 4),
            "中文标题"
        );
    }
}

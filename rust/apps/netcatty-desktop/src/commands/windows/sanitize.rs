//! Payload validation shared by the window commands (Electron:
//! `sanitizeEditorSnapshot`, `normalizeKittyKeyboardModeState`, the snapshot
//! handlers of `terminalBridge.cjs`, `clampWindowOpacity`, `tMenu`).

use serde_json::{json, Map, Value};

/// Electron: `MAX_EDITOR_CONTENT_BYTES`.
pub const MAX_EDITOR_CONTENT_BYTES: usize = 10 * 1024 * 1024;

fn str_field<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

/// Electron's `sanitizeEditorSnapshot`: `None` when a required field is
/// missing / empty or either content exceeds 10 MiB.
pub fn editor_snapshot(payload: &Value) -> Option<Map<String, Value>> {
    if !payload.is_object() {
        return None;
    }
    let editor_id = str_field(payload, "editorId").unwrap_or("").trim();
    let session_id = str_field(payload, "sessionId").unwrap_or("");
    let sftp_tab_id = str_field(payload, "sftpTabId").unwrap_or("");
    let host_id = str_field(payload, "hostId").unwrap_or("");
    let remote_path = str_field(payload, "remotePath").unwrap_or("");
    let file_name = str_field(payload, "fileName").unwrap_or("").trim();
    if [
        editor_id,
        session_id,
        sftp_tab_id,
        host_id,
        remote_path,
        file_name,
    ]
    .iter()
    .any(|v| v.is_empty())
    {
        return None;
    }
    let content = str_field(payload, "content").unwrap_or("");
    let baseline = str_field(payload, "baselineContent").unwrap_or("");
    if content.len() > MAX_EDITOR_CONTENT_BYTES || baseline.len() > MAX_EDITOR_CONTENT_BYTES {
        return None;
    }
    let mut out = Map::new();
    out.insert("editorId".into(), json!(editor_id));
    out.insert("sessionId".into(), json!(session_id));
    out.insert("sftpTabId".into(), json!(sftp_tab_id));
    out.insert("hostId".into(), json!(host_id));
    if let Some(label) = str_field(payload, "hostLabel") {
        out.insert("hostLabel".into(), json!(label));
    }
    out.insert("remotePath".into(), json!(remote_path));
    out.insert("fileName".into(), json!(file_name));
    let language = str_field(payload, "languageId").filter(|l| !l.is_empty());
    out.insert("languageId".into(), json!(language.unwrap_or("plaintext")));
    out.insert("content".into(), json!(content));
    out.insert("baselineContent".into(), json!(baseline));
    out.insert(
        "wordWrap".into(),
        json!(payload.get("wordWrap") == Some(&Value::Bool(true))),
    );
    let view_state = payload
        .get("viewState")
        .filter(|v| v.is_object() || v.is_array())
        .cloned()
        .unwrap_or(Value::Null);
    out.insert("viewState".into(), view_state);
    Some(out)
}

/// `saveEditorWindowTab` payload: the snapshot identity fields plus the
/// content to write (Electron validates it through `sanitizeEditorSnapshot`
/// with a placeholder file name).
pub fn save_request(payload: &Value) -> Option<Map<String, Value>> {
    let mut probe = payload.as_object().cloned()?;
    let file_name = str_field(payload, "fileName")
        .filter(|n| !n.is_empty())
        .unwrap_or("file")
        .to_owned();
    probe.insert("fileName".into(), json!(file_name));
    let content = str_field(payload, "content").unwrap_or("").to_owned();
    probe.insert("baselineContent".into(), json!(content));
    let snapshot = editor_snapshot(&Value::Object(probe))?;
    let mut out = Map::new();
    for key in ["editorId", "sessionId", "sftpTabId", "hostId", "remotePath"] {
        out.insert(key.into(), snapshot[key].clone());
    }
    out.insert("content".into(), json!(content));
    Some(out)
}

/// `editorIds` filtered to non-empty strings.
pub fn editor_ids(payload: &Value) -> Vec<String> {
    payload
        .get("editorIds")
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// `reportEditorWindowTabsClosed`: `editorIds`, else a single `editorId`.
pub fn closed_editor_ids(payload: &Value) -> Vec<String> {
    if payload.get("editorIds").is_some_and(Value::is_array) {
        return editor_ids(payload);
    }
    str_field(payload, "editorId")
        .filter(|id| !id.is_empty())
        .map(|id| vec![id.to_owned()])
        .unwrap_or_default()
}

/// Electron's `normalizeKittyKeyboardModeState`.
pub fn kitty_state(value: Option<&Value>) -> Option<Value> {
    let value = value.filter(|v| v.is_object())?;
    let flags = |v: Option<&Value>| -> u64 {
        match v.and_then(Value::as_f64) {
            Some(n) if n.is_finite() => (n.floor().max(0.0) as u64) & 31,
            _ => 0,
        }
    };
    let stack = |v: Option<&Value>| -> Vec<u64> {
        match v.and_then(Value::as_array) {
            Some(items) => {
                let start = items.len().saturating_sub(32);
                items[start..].iter().map(|i| flags(Some(i))).collect()
            }
            None => Vec::new(),
        }
    };
    Some(json!({
        "mainFlags": flags(value.get("mainFlags")),
        "alternateFlags": flags(value.get("alternateFlags")),
        "mainStack": stack(value.get("mainStack")),
        "alternateStack": stack(value.get("alternateStack")),
        "alternateScreenActive": value.get("alternateScreenActive") == Some(&Value::Bool(true)),
    }))
}

fn copy_bool(from: &Value, to: &mut Map<String, Value>, key: &str) {
    if let Some(b) = from.get(key).and_then(Value::as_bool) {
        to.insert(key.into(), json!(b));
    }
}

/// `cwd` / `title`: string, explicit `null`, or absent.
fn copy_nullable_str(from: &Value, to: &mut Map<String, Value>, key: &str) {
    match from.get(key) {
        Some(Value::Null) => {
            to.insert(key.into(), Value::Null);
        }
        Some(Value::String(s)) => {
            to.insert(key.into(), json!(s));
        }
        _ => {}
    }
}

/// The renderer's snapshot reply as the popup receives it (Electron:
/// `handleTerminalSessionSnapshotResponse`).
pub fn snapshot_result(reply: &Value) -> Value {
    let mut out = Map::new();
    out.insert("success".into(), json!(true));
    out.insert(
        "snapshot".into(),
        json!(str_field(reply, "snapshot").unwrap_or("")),
    );
    copy_bool(reply, &mut out, "perCharacterInput");
    if let Some(state) = kitty_state(reply.get("kittyKeyboardModeState")) {
        out.insert("kittyKeyboardModeState".into(), state);
    }
    copy_bool(reply, &mut out, "kittyKeyboardProtocolEnabled");
    copy_bool(reply, &mut out, "passwordPromptActive");
    copy_nullable_str(reply, &mut out, "cwd");
    copy_nullable_str(reply, &mut out, "title");
    Value::Object(out)
}

/// `applyTerminalSessionSnapshot` payload → the `apply-snapshot` event for
/// the home window, or `None` when a required field is missing (Electron:
/// `Missing sessionId or snapshot`).
pub fn apply_snapshot_event(payload: &Value) -> Option<(String, Map<String, Value>)> {
    let session_id = str_field(payload, "sessionId").filter(|s| !s.is_empty())?;
    let mut out = Map::new();
    out.insert("sessionId".into(), json!(session_id));
    for key in [
        "snapshot",
        "contextSnapshot",
        "contextViewportSnapshot",
        "contextScrollbackSnapshot",
    ] {
        out.insert(key.into(), json!(str_field(payload, key)?));
    }
    out.insert(
        "alternateScreen".into(),
        json!(payload.get("alternateScreen")?.as_bool()?),
    );
    copy_bool(payload, &mut out, "perCharacterInput");
    if let Some(state) = kitty_state(payload.get("kittyKeyboardModeState")) {
        out.insert("kittyKeyboardModeState".into(), state);
    }
    copy_bool(payload, &mut out, "kittyKeyboardProtocolEnabled");
    copy_bool(payload, &mut out, "passwordPromptActive");
    copy_nullable_str(payload, &mut out, "cwd");
    copy_nullable_str(payload, &mut out, "title");
    Some((session_id.to_owned(), out))
}

/// Electron's `clampWindowOpacity`: 0.5 ..= 1, non-numbers → 1.
pub fn clamp_opacity(value: Option<f64>) -> f64 {
    match value {
        Some(v) if v.is_finite() => v.clamp(0.5, 1.0),
        _ => 1.0,
    }
}

/// Native chrome of an app window: `(alpha, vibrancy)`. Blur (macOS only)
/// keeps the native alpha at 1 and lets the renderer's translucent CSS show
/// the vibrancy material (Electron: `applyWindowOpacityToWindow`).
pub fn window_chrome(blur_supported: bool, blur_requested: bool, opacity: f64) -> (f64, bool) {
    let blur_active = blur_supported && blur_requested && opacity < 1.0;
    if blur_active {
        (1.0, true)
    } else {
        (opacity, false)
    }
}

/// Application menu labels (Electron: `MENU_LABELS` / `tMenu`).
pub fn menu_label(language: &str, key: &str) -> &'static str {
    const LABELS: &[(&str, [&str; 4])] = &[
        // edit, view, window, closeWindow
        ("en", ["Edit", "View", "Window", "Close Window"]),
        ("ru", ["Правка", "Вид", "Окно", "Закрыть окно"]),
        ("zh-CN", ["编辑", "视图", "窗口", "关闭窗口"]),
        ("zh-TW", ["編輯", "檢視", "視窗", "關閉視窗"]),
    ];
    let index = match key {
        "edit" => 0,
        "view" => 1,
        "window" => 2,
        _ => 3,
    };
    let base = language.split('-').next().unwrap_or("");
    let found = LABELS
        .iter()
        .find(|(lang, _)| *lang == language)
        .or_else(|| {
            LABELS
                .iter()
                .find(|(lang, _)| *lang == base || lang.starts_with(&format!("{base}-")))
        });
    found.unwrap_or(&LABELS[0]).1[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Value {
        json!({
            "editorId": " e1 ", "sessionId": "s", "sftpTabId": "t", "hostId": "h",
            "remotePath": "/etc/hosts", "fileName": " hosts ", "content": "a", "baselineContent": "b",
            "wordWrap": true, "viewState": { "x": 1 }, "extra": "dropped"
        })
    }

    #[test]
    fn editor_snapshot_is_sanitized() {
        let out = editor_snapshot(&snapshot()).unwrap();
        assert_eq!(out["editorId"], "e1");
        assert_eq!(out["fileName"], "hosts");
        assert_eq!(out["languageId"], "plaintext");
        assert_eq!(out["wordWrap"], true);
        assert!(!out.contains_key("extra"));
        assert!(!out.contains_key("hostLabel"));
        let mut missing = snapshot();
        missing["hostId"] = json!("");
        assert!(editor_snapshot(&missing).is_none());
        let mut huge = snapshot();
        huge["content"] = json!("x".repeat(MAX_EDITOR_CONTENT_BYTES + 1));
        assert!(editor_snapshot(&huge).is_none());
        assert!(editor_snapshot(&json!("nope")).is_none());
    }

    #[test]
    fn save_request_keeps_identity_and_content() {
        let out = save_request(&json!({
            "editorId": "e", "sessionId": "s", "sftpTabId": "t", "hostId": "h",
            "remotePath": "/a", "content": "new"
        }))
        .unwrap();
        assert_eq!(out["content"], "new");
        assert_eq!(out.len(), 6);
        assert!(save_request(&json!({ "editorId": "e" })).is_none());
    }

    #[test]
    fn closed_ids_accept_array_or_single() {
        assert_eq!(
            closed_editor_ids(&json!({ "editorIds": ["a", "", 3, "b"] })),
            ["a", "b"]
        );
        assert_eq!(closed_editor_ids(&json!({ "editorId": "x" })), ["x"]);
        assert!(closed_editor_ids(&json!({})).is_empty());
    }

    #[test]
    fn kitty_state_is_clamped() {
        let state = kitty_state(Some(&json!({
            "mainFlags": 63.7, "alternateFlags": -4, "mainStack": (0..40).collect::<Vec<_>>(),
            "alternateScreenActive": 1
        })))
        .unwrap();
        assert_eq!(state["mainFlags"], 31);
        assert_eq!(state["alternateFlags"], 0);
        assert_eq!(state["mainStack"].as_array().unwrap().len(), 32);
        assert_eq!(state["mainStack"][0], 8);
        assert_eq!(state["alternateStack"], json!([]));
        assert_eq!(state["alternateScreenActive"], false);
        assert!(kitty_state(Some(&json!(5))).is_none());
    }

    #[test]
    fn snapshot_reply_and_apply_payload() {
        let reply = snapshot_result(&json!({
            "requestId": "r", "snapshot": "abc", "cwd": null, "title": 5, "passwordPromptActive": true
        }));
        assert_eq!(reply["success"], true);
        assert_eq!(reply["snapshot"], "abc");
        assert_eq!(reply["cwd"], Value::Null);
        assert!(reply.get("title").is_none());
        assert!(reply.get("requestId").is_none());

        let full = json!({
            "sessionId": "s", "snapshot": "a", "contextSnapshot": "", "contextViewportSnapshot": "",
            "contextScrollbackSnapshot": "", "alternateScreen": false, "authorization": "secret"
        });
        let (id, event) = apply_snapshot_event(&full).unwrap();
        assert_eq!(id, "s");
        assert!(event.get("authorization").is_none());
        let mut partial = full.clone();
        partial.as_object_mut().unwrap().remove("alternateScreen");
        assert!(apply_snapshot_event(&partial).is_none());
    }

    #[test]
    fn opacity_and_blur_chrome() {
        assert_eq!(clamp_opacity(Some(0.2)), 0.5);
        assert_eq!(clamp_opacity(Some(2.0)), 1.0);
        assert_eq!(clamp_opacity(Some(f64::NAN)), 1.0);
        assert_eq!(clamp_opacity(None), 1.0);
        // macOS blur keeps native opacity at one; 100% opacity drops vibrancy.
        assert_eq!(window_chrome(true, true, 0.85), (1.0, true));
        assert_eq!(window_chrome(true, true, 1.0), (1.0, false));
        assert_eq!(window_chrome(true, false, 0.85), (0.85, false));
        // Unsupported platforms keep the plain opacity behaviour.
        assert_eq!(window_chrome(false, true, 0.7), (0.7, false));
    }

    #[test]
    fn menu_labels_fall_back_by_base_language() {
        assert_eq!(menu_label("en", "closeWindow"), "Close Window");
        assert_eq!(menu_label("zh-TW", "edit"), "編輯");
        assert_eq!(menu_label("zh", "window"), "窗口");
        assert_eq!(menu_label("ru-RU", "view"), "Вид");
        assert_eq!(menu_label("fr", "edit"), "Edit");
    }
}

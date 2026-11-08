//! Detached SFTP editor window (Electron: `windowManager/editorWindow.cjs`).
//!
//! One reusable window (`editor`, route `#/editor-window`) hosts editor tabs
//! moved out of SFTP views. Every tab remembers its *source* window: saves
//! and docks are routed back there (the SFTP connection lives in that
//! renderer), and the source learns about dirty changes and closed tabs.
//! A tab is only "owned" by the editor once its renderer accepted it; until
//! then the source keeps its copy.

use super::{replies::ReplyError, sanitize, show_and_focus, state, AppWindowKind, EDITOR_LABEL};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, Runtime, WebviewWindow};
use tokio::sync::watch;

const EDITOR_WIDTH: f64 = 1100.0;
const EDITOR_HEIGHT: f64 = 760.0;
const CLOSE_TABS_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);
const CLOSE_TABS_FORCE_TIMEOUT: Duration = Duration::from_secs(8);
const SAVE_TIMEOUT: Duration = Duration::from_secs(30);
const DOCK_TIMEOUT: Duration = Duration::from_secs(8);
const OPEN_TAB_TIMEOUT: Duration = Duration::from_secs(30);

pub mod events {
    pub const OPEN_TAB: &str = "netcatty:window:editorOpenTab";
    pub const OPEN_TAB_RESULT: &str = "netcatty:window:editorOpenTabResult";
    pub const ACTIVATE_TAB: &str = "netcatty:window:editorActivateTab";
    pub const CLOSE_TABS: &str = "netcatty:window:editorCloseTabs";
    pub const CLOSE_TABS_RESULT: &str = "netcatty:window:editorCloseTabsResult";
    pub const SAVE_REQUEST: &str = "netcatty:window:editorSaveRequest";
    pub const SAVE_RESULT: &str = "netcatty:window:editorSaveResult";
    pub const DOCK_REQUEST: &str = "netcatty:window:editorDockRequest";
    pub const DOCK_RESULT: &str = "netcatty:window:editorDockResult";
    pub const DIRTY_CHANGED: &str = "netcatty:window:editorDirtyChanged";
    pub const TABS_CLOSED: &str = "netcatty:window:editorTabsClosed";
    pub const REMAP_SESSION: &str = "netcatty:window:editorRemapSession";
}

type Loaded = Option<Result<(), String>>;

struct EditorWindow {
    loaded_tx: watch::Sender<Loaded>,
    loaded: watch::Receiver<Loaded>,
    native_close_pending: bool,
    close_confirmed: bool,
}

struct Owner {
    token: u64,
    label: String,
    accepted: bool,
    /// Resolves `Some(true)` once the editor accepted the tab.
    opening: Option<watch::Receiver<Option<bool>>>,
}

#[derive(Default)]
pub struct EditorRegistry {
    window: Option<EditorWindow>,
    sources: HashMap<String, Owner>,
    next_token: u64,
}

impl EditorRegistry {
    pub fn has_tabs_for_source(&self, label: &str) -> bool {
        self.sources.values().any(|o| o.label == label)
    }

    fn source_of(&self, editor_id: &str) -> Option<String> {
        self.sources.get(editor_id).map(|o| o.label.clone())
    }

    /// Remove `editor_ids` and group the accepted ones by source window.
    fn take_closed(&mut self, editor_ids: &[String]) -> Vec<(String, Vec<String>)> {
        let mut by_source: Vec<(String, Vec<String>)> = Vec::new();
        for id in editor_ids {
            let Some(owner) = self.sources.remove(id) else {
                continue;
            };
            if !owner.accepted {
                continue;
            }
            match by_source
                .iter_mut()
                .find(|(label, _)| *label == owner.label)
            {
                Some((_, ids)) => ids.push(id.clone()),
                None => by_source.push((owner.label, vec![id.clone()])),
            }
        }
        by_source
    }
}

fn failure(error: impl Into<String>) -> Value {
    json!({ "success": false, "error": error.into() })
}

fn editor_window<R: Runtime>(app: &AppHandle<R>) -> Option<WebviewWindow<R>> {
    let window = app.get_webview_window(EDITOR_LABEL)?;
    state(app).editor.lock().window.as_ref()?;
    Some(window)
}

/// Tell each source window which of its accepted tabs are gone.
fn notify_sources_tabs_closed<R: Runtime>(app: &AppHandle<R>, editor_ids: &[String]) {
    let grouped = state(app).editor.lock().take_closed(editor_ids);
    for (label, ids) in grouped {
        if app.get_webview_window(&label).is_some() {
            let _ = app.emit_to(
                label.as_str(),
                events::TABS_CLOSED,
                json!({ "editorIds": ids }),
            );
        }
    }
}

async fn wait_loaded<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let rx = state(app)
        .editor
        .lock()
        .window
        .as_ref()
        .map(|w| w.loaded.clone());
    let Some(mut rx) = rx else {
        return Ok(());
    };
    let outcome = match rx.wait_for(Option::is_some).await {
        Ok(value) => value.clone().unwrap_or(Ok(())),
        Err(_) => Err("Editor window is gone".to_owned()),
    };
    outcome
}

fn reply_error(err: ReplyError) -> &'static str {
    match err {
        ReplyError::Timeout => "Timed out waiting for editor window",
        ReplyError::Gone | ReplyError::SendFailed => "Target window is gone",
    }
}

async fn send_open_tab<R: Runtime>(
    app: &AppHandle<R>,
    snapshot: Map<String, Value>,
    source_label: &str,
    reused: bool,
) -> Value {
    if app.get_webview_window(source_label).is_none() {
        return failure("Source window is gone");
    }
    let editor_id = snapshot["editorId"].as_str().unwrap_or_default().to_owned();
    let (opening_tx, opening_rx) = watch::channel(None);
    let token = {
        let st = state(app);
        let mut reg = st.editor.lock();
        reg.next_token += 1;
        let token = reg.next_token;
        reg.sources.insert(
            editor_id.clone(),
            Owner {
                token,
                label: source_label.to_owned(),
                accepted: false,
                opening: Some(opening_rx),
            },
        );
        token
    };

    let result = async {
        // Every open, including reuse during a cold start, waits for the
        // editor renderer to mount its receiver.
        wait_loaded(app).await?;
        if editor_window(app).is_none() {
            return Err("Editor window is gone".to_owned());
        }
        let reply = state(app)
            .replies
            .request(
                app,
                EDITOR_LABEL,
                events::OPEN_TAB,
                events::OPEN_TAB_RESULT,
                snapshot,
                OPEN_TAB_TIMEOUT,
            )
            .await;
        let accepted = matches!(&reply, Ok(v) if v.get("ok") == Some(&Value::Bool(true)));
        let window = editor_window(app);
        match (accepted, window) {
            (true, Some(window)) => Ok(window),
            _ => Err(match reply {
                Ok(v) => v
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("Editor did not accept the file")
                    .to_owned(),
                Err(e) => reply_error(e).to_owned(),
            }),
        }
    }
    .await;

    let accepted = {
        let st = state(app);
        let mut reg = st.editor.lock();
        let is_ours = reg
            .sources
            .get(&editor_id)
            .is_some_and(|o| o.token == token);
        match (&result, is_ours) {
            (Ok(_), true) => {
                if let Some(owner) = reg.sources.get_mut(&editor_id) {
                    owner.accepted = true;
                }
                true
            }
            (Ok(_), false) => true,
            (Err(_), true) => {
                reg.sources.remove(&editor_id);
                false
            }
            (Err(_), false) => false,
        }
    };
    let _ = opening_tx.send(Some(accepted));
    match result {
        Ok(window) => {
            show_and_focus(&window);
            json!({ "success": true, "reused": reused })
        }
        Err(error) => failure(error),
    }
}

/// `openEditorWindow`: open (or reuse) the editor window and hand it the tab.
pub async fn open<R: Runtime>(
    app: &AppHandle<R>,
    source: &WebviewWindow<R>,
    payload: &Value,
) -> Value {
    let Some(snapshot) = sanitize::editor_snapshot(payload) else {
        return failure("Invalid editor payload");
    };
    if editor_window(app).is_some() {
        if state(app)
            .editor
            .lock()
            .window
            .as_ref()
            .is_some_and(|w| w.native_close_pending)
        {
            return failure("Editor window is closing");
        }
        return send_open_tab(app, snapshot, source.label(), true).await;
    }
    // A leftover window without a registry entry (should not happen) is
    // replaced so the ready handshake starts clean.
    if let Some(stale) = app.get_webview_window(EDITOR_LABEL) {
        let _ = stale.destroy();
    }

    let title = snapshot["fileName"].as_str().unwrap_or("Editor").to_owned();
    let window = match super::build_app_window(
        app,
        AppWindowKind::Editor,
        EDITOR_LABEL,
        &title,
        (EDITOR_WIDTH, EDITOR_HEIGHT),
        (640.0, 420.0),
        Some(source),
    ) {
        Ok(window) => window,
        Err(err) => return failure(err.message),
    };
    let (loaded_tx, loaded) = watch::channel(None);
    state(app).editor.lock().window = Some(EditorWindow {
        loaded_tx,
        loaded,
        native_close_pending: false,
        close_confirmed: false,
    });
    // The renderer mounts its receiver and calls `windows_editor_ready`;
    // without it the window is torn down like Electron's load failure.
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(OPEN_TAB_TIMEOUT).await;
        let timed_out = state(&handle)
            .editor
            .lock()
            .window
            .as_ref()
            .is_some_and(|w| {
                w.loaded.borrow().is_none()
                    && w.loaded_tx
                        .send(Some(Err("Timed out waiting for editor receiver".into())))
                        .is_ok()
            });
        if timed_out {
            let _ = window.destroy();
        }
    });
    send_open_tab(app, snapshot, source.label(), false).await
}

/// The editor renderer subscribed to `editorOpenTab`.
pub fn ready<R: Runtime>(app: &AppHandle<R>, label: &str) {
    if label != EDITOR_LABEL {
        return;
    }
    if let Some(window) = state(app).editor.lock().window.as_ref() {
        if window.loaded.borrow().is_none() {
            let _ = window.loaded_tx.send(Some(Ok(())));
        }
    }
}

pub fn focus<R: Runtime>(app: &AppHandle<R>, editor_id: Option<&str>) -> Value {
    let Some(window) = editor_window(app) else {
        return failure("Editor window is not open");
    };
    if let Some(id) = editor_id.filter(|id| !id.is_empty()) {
        let _ = app.emit_to(
            EDITOR_LABEL,
            events::ACTIVATE_TAB,
            json!({ "editorId": id }),
        );
    }
    show_and_focus(&window);
    json!({ "success": true })
}

fn cancelled(error: impl Into<String>) -> Value {
    json!({ "success": false, "cancelled": true, "closedIds": [], "error": error.into() })
}

/// `closeEditorWindowTabs`: run the editor's Save / Discard / Cancel flow
/// for `editor_ids` (`force` closes without prompting).
pub async fn close_tabs<R: Runtime>(
    app: &AppHandle<R>,
    editor_ids: Vec<String>,
    force: bool,
) -> Value {
    if editor_ids.is_empty() {
        return json!({ "success": true, "cancelled": false, "closedIds": [] });
    }
    // Closing an owner during a cold start must not overtake its open receipt.
    let openings: Vec<watch::Receiver<Option<bool>>> = {
        let st = state(app);
        let reg = st.editor.lock();
        editor_ids
            .iter()
            .filter_map(|id| reg.sources.get(id).and_then(|o| o.opening.clone()))
            .collect()
    };
    for mut rx in openings {
        let ok = matches!(
            rx.wait_for(Option::is_some).await.map(|v| *v),
            Ok(Some(true))
        );
        if !ok {
            return cancelled("Editor transfer did not complete");
        }
    }
    if let Err(error) = wait_loaded(app).await {
        return cancelled(error);
    }
    let Some(window) = editor_window(app) else {
        notify_sources_tabs_closed(app, &editor_ids);
        return json!({ "success": true, "cancelled": false, "closedIds": editor_ids });
    };
    if !force {
        show_and_focus(&window);
    }
    let mut request = Map::new();
    request.insert("editorIds".into(), json!(editor_ids));
    request.insert("force".into(), json!(force));
    let reply = state(app)
        .replies
        .request(
            app,
            EDITOR_LABEL,
            events::CLOSE_TABS,
            events::CLOSE_TABS_RESULT,
            request,
            if force {
                CLOSE_TABS_FORCE_TIMEOUT
            } else {
                CLOSE_TABS_PROMPT_TIMEOUT
            },
        )
        .await;
    let reply = match reply {
        Ok(reply) => reply,
        Err(err) if force => {
            tracing::debug!(?err, "forced editor close got no reply; closing anyway");
            let _ = app.emit_to(
                EDITOR_LABEL,
                events::CLOSE_TABS,
                json!({
                    "requestId": uuid::Uuid::new_v4().to_string(),
                    "editorIds": editor_ids,
                    "force": true,
                }),
            );
            notify_sources_tabs_closed(app, &editor_ids);
            return json!({ "success": true, "cancelled": false, "closedIds": editor_ids });
        }
        Err(err) => return cancelled(reply_error(err)),
    };
    let closed_ids = sanitize::closed_editor_ids(&json!({
        "editorIds": reply.get("closedIds").cloned().unwrap_or_else(|| json!([])),
    }));
    notify_sources_tabs_closed(app, &closed_ids);
    let was_cancelled = reply.get("cancelled") == Some(&Value::Bool(true));
    json!({ "success": true, "cancelled": was_cancelled, "closedIds": closed_ids })
}

/// Close the editor tabs whose source is `label` (that window is closing).
pub async fn close_tabs_for_source<R: Runtime>(app: &AppHandle<R>, label: &str) -> Value {
    let ids: Vec<String> = {
        let st = state(app);
        let reg = st.editor.lock();
        let mut ids: Vec<String> = reg
            .sources
            .iter()
            .filter(|(_, o)| o.label == label)
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    };
    close_tabs(app, ids, false).await
}

pub fn has_tabs_for_source<R: Runtime>(app: &AppHandle<R>, label: &str) -> bool {
    state(app).editor.lock().has_tabs_for_source(label)
}

fn source_window<R: Runtime>(app: &AppHandle<R>, editor_id: &str) -> Option<String> {
    let label = state(app).editor.lock().source_of(editor_id)?;
    app.get_webview_window(&label).map(|_| label)
}

/// `saveEditorWindowTab`: the source window writes the file over its SFTP
/// connection.
pub async fn save<R: Runtime>(app: &AppHandle<R>, payload: &Value) -> Value {
    let Some(request) = sanitize::save_request(payload) else {
        return json!({ "ok": false, "error": "Invalid save payload" });
    };
    let editor_id = request["editorId"].as_str().unwrap_or_default().to_owned();
    let session_id = request["sessionId"].as_str().unwrap_or_default().to_owned();
    let Some(source) = source_window(app, &editor_id) else {
        return json!({
            "ok": false,
            "error": "SFTP editor bridge not registered — cannot save (no SFTP view mounted)",
        });
    };
    let reply = state(app)
        .replies
        .request(
            app,
            &source,
            events::SAVE_REQUEST,
            events::SAVE_RESULT,
            request,
            SAVE_TIMEOUT,
        )
        .await;
    let reply = match reply {
        Ok(reply) => reply,
        Err(err) => return json!({ "ok": false, "error": reply_error(err) }),
    };
    if reply.get("ok") == Some(&Value::Bool(false)) {
        let error = reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Save failed");
        return json!({ "ok": false, "error": error });
    }
    let live = reply
        .get("liveConnectionId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty());
    if let Some(live) = live {
        if editor_window(app).is_some() {
            let _ = app.emit_to(
                EDITOR_LABEL,
                events::REMAP_SESSION,
                json!({ "fromSessionId": session_id, "toSessionId": live }),
            );
        }
    }
    let mut out = json!({ "ok": true });
    if let Some(live) = live {
        out["liveConnectionId"] = json!(live);
    }
    out
}

/// `dockEditorWindowTab`: move the tab back into its source window.
pub async fn dock<R: Runtime>(app: &AppHandle<R>, payload: &Value) -> Value {
    let Some(snapshot) = sanitize::editor_snapshot(payload) else {
        return failure("Invalid dock payload");
    };
    let editor_id = snapshot["editorId"].as_str().unwrap_or_default().to_owned();
    let Some(source) = source_window(app, &editor_id) else {
        return failure("Source window is gone");
    };
    let reply = state(app)
        .replies
        .request(
            app,
            &source,
            events::DOCK_REQUEST,
            events::DOCK_RESULT,
            snapshot,
            DOCK_TIMEOUT,
        )
        .await;
    match reply {
        Ok(reply) if reply.get("ok") != Some(&Value::Bool(false)) => {
            state(app).editor.lock().sources.remove(&editor_id);
            json!({ "success": true })
        }
        Ok(reply) => failure(
            reply
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("Failed to dock editor tab"),
        ),
        Err(err) => failure(reply_error(err)),
    }
}

pub fn report_dirty<R: Runtime>(app: &AppHandle<R>, payload: &Value) {
    let Some(editor_id) = payload
        .get("editorId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return;
    };
    if let Some(source) = source_window(app, editor_id) {
        let dirty = payload.get("dirty") == Some(&Value::Bool(true));
        let _ = app.emit_to(
            source.as_str(),
            events::DIRTY_CHANGED,
            json!({ "editorId": editor_id, "dirty": dirty }),
        );
    }
}

pub fn report_tabs_closed<R: Runtime>(app: &AppHandle<R>, payload: &Value) {
    notify_sources_tabs_closed(app, &sanitize::closed_editor_ids(payload));
}

pub fn remap_session<R: Runtime>(app: &AppHandle<R>, payload: &Value) {
    let from = payload
        .get("fromSessionId")
        .and_then(Value::as_str)
        .unwrap_or("");
    let to = payload
        .get("toSessionId")
        .and_then(Value::as_str)
        .unwrap_or("");
    if from.is_empty() || to.is_empty() || from == to || editor_window(app).is_none() {
        return;
    }
    let _ = app.emit_to(
        EDITOR_LABEL,
        events::REMAP_SESSION,
        json!({ "fromSessionId": from, "toSessionId": to }),
    );
}

/// Native close (title bar, Alt+F4, `windowClose`): the same renderer
/// Save / Discard / Cancel flow as closing the tabs. Returns `true` when the
/// close was prevented.
pub fn on_close_requested<R: Runtime>(window: &tauri::Window<R>) -> bool {
    let app = window.app_handle().clone();
    if state(&app).quitting() {
        return false;
    }
    {
        let st = state(&app);
        let mut reg = st.editor.lock();
        let Some(editor) = reg.window.as_mut() else {
            return false;
        };
        if editor.close_confirmed {
            return false;
        }
        if editor.native_close_pending {
            return true;
        }
        editor.native_close_pending = true;
    }
    tauri::async_runtime::spawn(async move {
        let ids: Vec<String> = {
            let st = state(&app);
            let reg = st.editor.lock();
            let mut ids: Vec<String> = reg.sources.keys().cloned().collect();
            ids.sort();
            ids
        };
        let result = close_tabs(&app, ids, false).await;
        let proceed = result.get("success") == Some(&Value::Bool(true))
            && result.get("cancelled") != Some(&Value::Bool(true));
        {
            let st = state(&app);
            let mut reg = st.editor.lock();
            if let Some(editor) = reg.window.as_mut() {
                editor.native_close_pending = false;
                editor.close_confirmed = proceed;
            }
        }
        if proceed {
            if let Some(window) = app.get_webview_window(EDITOR_LABEL) {
                let _ = window.destroy();
            }
        }
    });
    true
}

/// The editor window is gone: release every tab it held.
pub fn on_destroyed<R: Runtime>(app: &AppHandle<R>) {
    let leftover: Vec<String> = {
        let st = state(app);
        let mut reg = st.editor.lock();
        if let Some(editor) = reg.window.take() {
            if editor.loaded.borrow().is_none() {
                let _ = editor
                    .loaded_tx
                    .send(Some(Err("Editor window closed before it was ready".into())));
            }
        }
        reg.sources.keys().cloned().collect()
    };
    notify_sources_tabs_closed(app, &leftover);
    state(app).editor.lock().sources.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(token: u64, label: &str, accepted: bool) -> Owner {
        Owner {
            token,
            label: label.into(),
            accepted,
            opening: None,
        }
    }

    #[test]
    fn closed_tabs_notify_only_accepted_owners_grouped_by_source() {
        let mut reg = EditorRegistry::default();
        reg.sources.insert("a".into(), owner(1, "main", true));
        reg.sources.insert("b".into(), owner(2, "session-1", true));
        reg.sources.insert("c".into(), owner(3, "main", false));
        reg.sources.insert("d".into(), owner(4, "main", true));
        assert!(reg.has_tabs_for_source("session-1"));
        let mut grouped =
            reg.take_closed(&["a".into(), "b".into(), "c".into(), "d".into(), "zz".into()]);
        grouped.sort();
        assert_eq!(
            grouped,
            vec![
                ("main".to_owned(), vec!["a".to_owned(), "d".to_owned()]),
                ("session-1".to_owned(), vec!["b".to_owned()]),
            ]
        );
        assert!(reg.sources.is_empty());
        assert!(!reg.has_tabs_for_source("main"));
    }
}

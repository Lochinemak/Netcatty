//! Port of `electron/bridges/scriptBridge.test.cjs` (and the end-to-end cases
//! of `scriptRuntime.test.cjs`): scripts run against a fake session host
//! that records writes, answers screen snapshots / dialogs like the renderer
//! and feeds output into the session buffer.

use netcatty_scripts::buffer::OutputBuffer;
use netcatty_scripts::manager::{
    events, HostSessionInfo, ManagerHost, RendererSessionMeta, RunParams, ScriptManager,
    MAX_SCRIPT_RECORDING_STEPS, SCRIPT_RECORDING_LIMIT_ERROR,
};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

type WriteHook = Box<dyn Fn(&str) + Send + Sync>;

#[derive(Default)]
struct FakeState {
    writes: Vec<String>,
    closed: Vec<String>,
    sessions: HashMap<String, HostSessionInfo>,
    active_logs: HashSet<String>,
    log_paths: HashMap<u64, PathBuf>,
    next_token: u64,
    started_logs: Vec<PathBuf>,
}

struct FakeHost {
    state: Arc<Mutex<FakeState>>,
    events: mpsc::UnboundedSender<(String, Value)>,
    renderer: bool,
    on_write: Arc<Mutex<Option<WriteHook>>>,
    log_dir: PathBuf,
}

impl ManagerHost for FakeHost {
    fn write_to_session(&self, _session_id: &str, data: &str, _automated: bool, _sensitive: bool) {
        self.state.lock().writes.push(data.to_string());
        if let Some(hook) = self.on_write.lock().as_ref() {
            hook(data);
        }
    }
    fn close_session(&self, session_id: &str) {
        self.state.lock().closed.push(session_id.to_string());
    }
    fn emit(&self, event: &str, payload: Value) {
        let _ = self.events.send((event.to_string(), payload));
    }
    fn has_renderer(&self) -> bool {
        self.renderer
    }
    fn session_info(&self, session_id: &str) -> Option<HostSessionInfo> {
        self.state.lock().sessions.get(session_id).cloned()
    }
    fn start_session_log(
        &self,
        session_id: &str,
        file_path: PathBuf,
        _host_label: &str,
    ) -> Result<u64, String> {
        let mut state = self.state.lock();
        if !state.active_logs.insert(session_id.to_string()) {
            return Err("Stream already active for this session".into());
        }
        state.next_token += 1;
        let token = state.next_token;
        state.log_paths.insert(token, file_path.clone());
        state.started_logs.push(file_path);
        Ok(token)
    }
    fn stop_session_log(&self, session_id: &str, token: u64) {
        let mut state = self.state.lock();
        if state.log_paths.remove(&token).is_some() {
            state.active_logs.remove(session_id);
        }
    }
    fn default_log_dir(&self) -> PathBuf {
        self.log_dir.clone()
    }
    fn app_version(&self) -> String {
        "test".into()
    }
}

/// How the fake renderer answers dialogs.
enum DialogAnswer {
    Value(Value),
    Cancel,
    /// Leave the request pending.
    Ignore,
}

struct Harness {
    manager: ScriptManager<FakeHost>,
    state: Arc<Mutex<FakeState>>,
    on_write: Arc<Mutex<Option<WriteHook>>>,
    run_updates: Arc<Mutex<Vec<Vec<Value>>>>,
    dialogs: Arc<Mutex<Vec<Value>>>,
    inputs: Arc<Mutex<Vec<Value>>>,
}

impl Harness {
    fn new(
        renderer: bool,
        snapshot: impl Fn(&str) -> Option<Value> + Send + Sync + 'static,
        dialog: impl Fn(&Value) -> DialogAnswer + Send + Sync + 'static,
    ) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<(String, Value)>();
        let state = Arc::new(Mutex::new(FakeState::default()));
        let on_write: Arc<Mutex<Option<WriteHook>>> = Arc::new(Mutex::new(None));
        let manager = ScriptManager::new(FakeHost {
            state: state.clone(),
            events: tx,
            renderer,
            on_write: on_write.clone(),
            log_dir: std::env::temp_dir(),
        });
        let run_updates = Arc::new(Mutex::new(Vec::new()));
        let dialogs = Arc::new(Mutex::new(Vec::new()));
        let inputs = Arc::new(Mutex::new(Vec::new()));
        {
            let manager = manager.clone();
            let run_updates = run_updates.clone();
            let dialogs = dialogs.clone();
            let inputs = inputs.clone();
            tokio::spawn(async move {
                while let Some((event, payload)) = rx.recv().await {
                    match event.as_str() {
                        events::RUNS_UPDATED => {
                            run_updates
                                .lock()
                                .push(payload["runs"].as_array().cloned().unwrap_or_default());
                        }
                        events::SCREEN_SNAPSHOT_REQUEST => {
                            let request_id = payload["requestId"].as_str().unwrap().to_string();
                            let session_id = payload["sessionId"].as_str().unwrap().to_string();
                            let value = snapshot(&session_id).unwrap_or_else(
                                || json!({ "rows": 24, "cols": 80, "currentRow": 0, "lines": [] }),
                            );
                            manager.screen_snapshot_response(&request_id, Some(value));
                        }
                        events::DIALOG_REQUEST => {
                            dialogs.lock().push(payload.clone());
                            let request_id = payload["requestId"].as_str().unwrap().to_string();
                            match dialog(&payload) {
                                DialogAnswer::Value(v) => {
                                    manager.dialog_response(&request_id, Some(v), false);
                                }
                                DialogAnswer::Cancel => {
                                    manager.dialog_response(&request_id, None, true);
                                }
                                DialogAnswer::Ignore => {}
                            }
                        }
                        events::SESSION_INPUT => inputs.lock().push(payload),
                        _ => {}
                    }
                }
            });
        }
        Self {
            manager,
            state,
            on_write,
            run_updates,
            dialogs,
            inputs,
        }
    }

    fn simple() -> Self {
        Self::new(true, |_| None, |_| DialogAnswer::Value(Value::Bool(true)))
    }

    async fn run(&self, session_id: &str, script_id: &str, content: &str) -> Value {
        self.run_with(json!({
            "scriptId": script_id,
            "scriptLabel": script_id,
            "sessionId": session_id,
            "content": content,
            "permissionMode": "auto",
        }))
        .await
    }

    async fn run_with(&self, params: Value) -> Value {
        let script_id = params["scriptId"].as_str().unwrap_or("").to_string();
        let params: RunParams = serde_json::from_value(params).unwrap();
        self.manager.run(params).await.unwrap();
        self.final_run(&script_id).await
    }

    /// The run as the renderer last saw it.
    async fn final_run(&self, script_id: &str) -> Value {
        // Events are delivered asynchronously; give the fan-out a moment.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let runs = self.manager.get_runs(None);
        let run = runs
            .iter()
            .rev()
            .find(|r| r.script_id.as_deref() == Some(script_id))
            .expect("run present");
        serde_json::to_value(run).unwrap()
    }

    fn writes(&self) -> Vec<String> {
        self.state.lock().writes.clone()
    }

    fn set_write_hook(&self, hook: impl Fn(&str) + Send + Sync + 'static) {
        *self.on_write.lock() = Some(Box::new(hook));
    }

    fn buffer(&self, session_id: &str) -> OutputBuffer {
        self.manager.buffer(session_id)
    }
}

fn log_text(run: &Value) -> String {
    run["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["message"].as_str().unwrap_or("").to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

async fn wait_until<T>(mut predicate: impl FnMut() -> Option<T>) -> T {
    let started = Instant::now();
    loop {
        if let Some(value) = predicate() {
            return value;
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "condition not met"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn snapshot_lines(lines: &[&str]) -> Value {
    json!({ "rows": 24, "cols": 80, "currentRow": 0, "lines": lines })
}

#[tokio::test(flavor = "multi_thread")]
async fn run_completion_stores_actual_executed_step_count() {
    let h = Harness::simple();
    let run = h
        .run(
            "session-1",
            "script-loop",
            "for (let i = 0; i < 3; i += 1) { nct.log(`step ${i}`); }",
        )
        .await;
    assert_eq!(run["status"], "completed");
    assert_eq!(run["stepIndex"], 3);
    assert_eq!(run["progressMode"], "activity");
    assert!(run.get("totalSteps").is_none());
    assert_eq!(log_text(&run), "step 0\nstep 1\nstep 2");
    // The renderer received the final state too.
    let last = h.run_updates.lock().last().cloned().unwrap();
    assert_eq!(last[0]["status"], "completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn same_session_runs_are_serialized_through_the_session_queue() {
    let h = Harness::new(false, |_| None, |_| DialogAnswer::Ignore);
    let slow = h.run(
        "session-mutex",
        "slow",
        "await nct.sleep(40); await nct.screen.sendLine('slow-run');",
    );
    let fast = h.run(
        "session-mutex",
        "fast",
        "await nct.screen.sendLine('fast-run');",
    );
    tokio::join!(slow, fast);
    let order: Vec<String> = h
        .writes()
        .into_iter()
        .filter(|w| w.contains("-run"))
        .collect();
    assert_eq!(order, vec!["slow-run", "fast-run"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_can_cancel_its_queued_script_by_run_id() {
    let h = Harness::new(true, |_| None, |_| DialogAnswer::Ignore);
    let manager = h.manager.clone();
    let active = tokio::spawn(async move {
        manager
            .run(
                serde_json::from_value(json!({
                    "runId": "unrelated-active-run",
                    "scriptId": "manual",
                    "sessionId": "session-queued-cancel",
                    "content": "await nct.dialog.confirm('hold queue'); await nct.screen.sendLine('active-finished');",
                }))
                .unwrap(),
            )
            .await
    });
    let dialogs = h.dialogs.clone();
    let request_id = wait_until(|| {
        dialogs
            .lock()
            .first()
            .map(|d| d["requestId"].as_str().unwrap().to_string())
    })
    .await;
    let queued = h
        .manager
        .run(
            serde_json::from_value(json!({
                "runId": "queued-connect-run",
                "returnWhenQueued": true,
                "scriptId": "connect",
                "sessionId": "session-queued-cancel",
                "content": "await nct.screen.sendLine('queued-ran');",
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&queued).unwrap(),
        json!({ "runId": "queued-connect-run", "runIds": ["queued-connect-run"] })
    );
    assert!(h.manager.stop("queued-connect-run").ok);
    assert!(
        h.manager
            .dialog_response(&request_id, Some(json!(true)), false)
            .ok
    );
    active.await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;
    let writes = h.writes();
    assert!(writes.iter().any(|w| w.contains("active-finished")));
    assert!(!writes.iter().any(|w| w.contains("queued-ran")));
    // A stopped queued run never appears in the run list.
    assert!(h
        .manager
        .get_runs(None)
        .iter()
        .all(|r| r.run_id != "queued-connect-run"));
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_a_script_releases_the_session_queue_so_it_can_run_again() {
    let h = Harness::new(true, |_| None, |_| DialogAnswer::Ignore);
    let manager = h.manager.clone();
    let first = tokio::spawn(async move {
        manager
            .run(
                serde_json::from_value(json!({
                    "scriptId": "blocked",
                    "sessionId": "session-stop-queue",
                    "content": "await nct.dialog.confirm('wait'); await nct.screen.sendLine('never');",
                }))
                .unwrap(),
            )
            .await
    });
    let dialogs = h.dialogs.clone();
    wait_until(|| dialogs.lock().first().cloned()).await;
    let run_id = h.manager.get_runs(Some("session-stop-queue"))[0]
        .run_id
        .clone();
    assert!(h.manager.stop(&run_id).ok);
    first.await.unwrap().unwrap();
    let stopped = h.final_run("blocked").await;
    assert_eq!(stopped["status"], "failed");
    assert_eq!(stopped["error"], "Stopped by user");

    let again = h
        .run(
            "session-stop-queue",
            "again",
            "await nct.screen.sendLine('again-ran');",
        )
        .await;
    assert_eq!(again["status"], "completed");
    assert!(h.writes().iter().any(|w| w == "again-ran"));
    assert!(!h.writes().iter().any(|w| w == "never"));
}

#[tokio::test(flavor = "multi_thread")]
async fn completed_scripts_clear_unawaited_dialog_requests() {
    let h = Harness::new(true, |_| None, |_| DialogAnswer::Ignore);
    let run = h
        .run(
            "session-unawaited-dialog",
            "unawaited",
            "void nct.dialog.confirm('background'); nct.log('done');",
        )
        .await;
    assert_eq!(run["status"], "completed");
    let request_id = wait_until(|| {
        h.dialogs
            .lock()
            .first()
            .map(|d| d["requestId"].as_str().unwrap().to_string())
    })
    .await;
    // The pending request was settled when the run ended.
    assert!(
        !h.manager
            .dialog_response(&request_id, Some(json!(true)), false)
            .ok
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unawaited_host_requests_do_not_run_after_the_script_finishes() {
    let h = Harness::new(true, |_| None, |_| DialogAnswer::Ignore);
    let run = h
        .run(
            "session-unawaited-disconnect",
            "unawaited-disconnect",
            "void nct.dialog.confirm('background').then(() => nct.session.disconnect()); nct.log('done');",
        )
        .await;
    assert_eq!(run["status"], "completed");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(h.state.lock().closed.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_a_script_releases_its_session_log_so_the_next_run_can_start_one() {
    let h = Harness::simple();
    let sid = "session-stop-log-cleanup";
    h.state.lock().sessions.insert(
        sid.into(),
        HostSessionInfo {
            label: "box".into(),
            hostname: "example.test".into(),
            username: "u".into(),
        },
    );
    let dir = tempfile::tempdir().unwrap();
    let first_path = dir.path().join("first.log");
    let manager = h.manager.clone();
    let content = format!(
        "await nct.session.startLog({}); try {{ await nct.sleep(5000); }} finally {{ await nct.session.stopLog(); }}",
        serde_json::to_string(first_path.to_str().unwrap()).unwrap()
    );
    let sid_owned = sid.to_string();
    let first = tokio::spawn(async move {
        manager
            .run(
                serde_json::from_value(json!({
                    "scriptId": "stopped-log-run",
                    "sessionId": sid_owned,
                    "content": content,
                }))
                .unwrap(),
            )
            .await
    });
    let state = h.state.clone();
    wait_until(|| state.lock().active_logs.contains(sid).then_some(())).await;
    let run_id = h.manager.get_runs(Some(sid))[0].run_id.clone();
    assert!(h.manager.stop(&run_id).ok);
    first.await.unwrap().unwrap();
    assert!(!h.state.lock().active_logs.contains(sid));

    let second_path = dir.path().join("second.log");
    let run = h
        .run(
            sid,
            "next-log-run",
            &format!(
                "await nct.session.startLog({}); await nct.session.stopLog();",
                serde_json::to_string(second_path.to_str().unwrap()).unwrap()
            ),
        )
        .await;
    assert_eq!(run["status"], "completed");
    assert!(!h.state.lock().active_logs.contains(sid));
    assert_eq!(h.state.lock().started_logs, vec![first_path, second_path]);
}

#[tokio::test(flavor = "multi_thread")]
async fn start_log_without_path_uses_the_default_directory() {
    let h = Harness::simple();
    let run = h
        .run(
            "session-default-log",
            "default-log",
            "await nct.session.startLog(); await nct.session.stopLog();",
        )
        .await;
    assert_eq!(run["status"], "completed");
    let started = h.state.lock().started_logs.clone();
    assert_eq!(started.len(), 1);
    assert_eq!(started[0].parent().unwrap(), std::env::temp_dir().as_path());
    let name = started[0]
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        name.starts_with("netcatty-script-") && name.ends_with(".log"),
        "{name}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn renderer_session_meta_and_registry_labels_are_exposed() {
    let h = Harness::simple();
    let run = h
        .run_with(json!({
            "scriptId": "renderer-meta",
            "sessionId": "worker-session",
            "content": "nct.log([nct.session.connected, nct.session.name, nct.session.hostname, nct.session.username].join('|'));",
            "sessionMeta": { "connected": true, "name": "Prod", "hostname": "prod.example", "username": "deploy" },
        }))
        .await;
    assert_eq!(log_text(&run), "true|Prod|prod.example|deploy");

    h.state.lock().sessions.insert(
        "registry-session".into(),
        HostSessionInfo {
            label: "Main label".into(),
            hostname: "main.example".into(),
            username: "root".into(),
        },
    );
    let run = h
        .run(
            "registry-session",
            "registry-meta",
            "nct.log([nct.session.connected, nct.session.name, nct.session.hostname, nct.session.username].join('|'));",
        )
        .await;
    assert_eq!(log_text(&run), "true|Main label|main.example|root");

    let run = h
        .run(
            "unknown-session",
            "no-meta",
            "nct.log(String(nct.session.connected) + '|' + nct.session.name);",
        )
        .await;
    assert_eq!(log_text(&run), "false|");
    // Unused type import guard.
    let _ = RendererSessionMeta::default();
}

#[tokio::test(flavor = "multi_thread")]
async fn form_dialog_requests_resolve_object_responses() {
    let h = Harness::new(
        true,
        |_| Some(snapshot_lines(&["user@host:~$ "])),
        |_| DialogAnswer::Value(json!({ "env": "prod", "restart": true, "mode": "safe" })),
    );
    let run = h
        .run(
            "session-form-dialog",
            "form-dialog",
            r#"
            const values = await nct.dialog.form({
              title: 'Deploy',
              message: 'Choose options',
              fields: [
                { type: 'select', name: 'env', label: 'Environment', options: ['dev', 'prod'], defaultValue: 'dev' },
                { type: 'checkbox', name: 'restart', label: 'Restart', defaultValue: false },
                { type: 'radio', name: 'mode', label: 'Mode', options: ['safe', 'fast'], defaultValue: 'fast' },
              ],
            });
            nct.log(values.env + ':' + values.restart + ':' + values.mode);
            "#,
        )
        .await;
    let request = h.dialogs.lock()[0].clone();
    assert_eq!(request["type"], "form");
    assert_eq!(request["message"], "Choose options");
    assert_eq!(request["form"]["title"], "Deploy");
    let fields: Vec<Value> = request["form"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| json!([f["type"], f["name"], f["defaultValue"]]))
        .collect();
    assert_eq!(
        fields,
        vec![
            json!(["select", "env", "dev"]),
            json!(["checkbox", "restart", false]),
            json!(["radio", "mode", "fast"]),
        ]
    );
    assert_eq!(run["status"], "completed");
    assert!(log_text(&run).contains("prod:true:safe"));
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_form_dialogs_fail_the_script() {
    let h = Harness::new(true, |_| None, |_| DialogAnswer::Cancel);
    let run = h
        .run(
            "session-form-cancel",
            "form-cancel",
            "await nct.dialog.form({ fields: [{ type: 'checkbox', name: 'ok' }] }); nct.log('unreachable');",
        )
        .await;
    assert_eq!(run["status"], "failed");
    assert_eq!(run["error"], "Dialog cancelled");
    assert!(!log_text(&run).contains("unreachable"));
}

#[tokio::test(flavor = "multi_thread")]
async fn convenience_dialogs_return_single_values() {
    let h = Harness::new(
        true,
        |_| None,
        |request| {
            let field = &request["form"]["fields"][0];
            DialogAnswer::Value(match field["type"].as_str() {
                Some("checkbox") => json!({ "value": true }),
                Some("radio") => json!({ "value": "b" }),
                _ => json!({ "value": "y" }),
            })
        },
    );
    let run = h
        .run(
            "session-convenience",
            "convenience",
            r#"
            const s = await nct.dialog.select('Pick', ['x', 'y']);
            const r = await nct.dialog.radio('Mode', [{ value: 'a' }, { value: 'b' }], 'a');
            const c = await nct.dialog.checkbox('Sure?');
            nct.log(typeof s + ':' + s + ':' + r + ':' + c);
            "#,
        )
        .await;
    assert_eq!(log_text(&run), "string:y:b:true");
    let first = h.dialogs.lock()[0].clone();
    assert_eq!(first["message"], "Pick");
    assert_eq!(first["form"]["fields"][0]["label"], "Pick");
    assert_eq!(first["form"]["fields"][0]["defaultValue"], "x");
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_form_specs_fail_with_the_validation_message() {
    let h = Harness::simple();
    let run = h
        .run(
            "session-bad-form",
            "bad-form",
            "await nct.dialog.form({ fields: [] });",
        )
        .await;
    assert_eq!(run["status"], "failed");
    assert_eq!(run["error"], "Dialog form requires at least one field");
    assert!(h.dialogs.lock().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_renderer_dialogs_resolve_with_defaults() {
    let h = Harness::new(false, |_| None, |_| DialogAnswer::Ignore);
    let run = h
        .run(
            "session-no-renderer",
            "no-renderer",
            "const c = await nct.dialog.confirm('q'); const p = await nct.dialog.prompt('q', 'dflt'); const f = await nct.dialog.form({ fields: [{ type: 'checkbox', name: 'a' }] }); nct.log(c + ':' + p + ':' + JSON.stringify(f));",
        )
        .await;
    assert_eq!(log_text(&run), "false:dflt:{}");
}

#[tokio::test(flavor = "multi_thread")]
async fn wait_for_matches_text_already_visible_on_the_startup_screen() {
    let h = Harness::new(
        true,
        |_| {
            Some(
                json!({ "rows": 24, "cols": 80, "currentRow": 1, "lines": ["visible READY marker", "user@host:~$ "] }),
            )
        },
        |_| DialogAnswer::Value(json!("abort")),
    );
    let sid = "session-visible-startup-output";
    h.manager
        .append_session_output(sid, "scrolled-off READY marker\n");
    let run = h
        .run(
            sid,
            "visible-output",
            "const value = await nct.screen.waitFor('READY', 1000); nct.log('matched ' + value);",
        )
        .await;
    assert_eq!(run["status"], "completed");
    assert!(log_text(&run).contains("matched READY"));
}

#[tokio::test(flavor = "multi_thread")]
async fn wait_for_ignores_keywords_that_have_scrolled_off_the_visible_screen() {
    let h = Harness::new(
        true,
        |_| Some(snapshot_lines(&["user@host:~$ "])),
        |_| DialogAnswer::Value(json!("abort")),
    );
    let sid = "session-scrolled-off";
    h.manager
        .append_session_output(sid, "old deployment READY marker\nuser@host:~$ \n");
    let run = h
        .run(
            sid,
            "scrolled-off",
            "await nct.screen.waitFor('READY', 100); nct.log('unexpected');",
        )
        .await;
    assert_eq!(run["status"], "failed");
    assert_eq!(run["error"], "Script stopped by user");
    let timeout_dialog = h.dialogs.lock()[0].clone();
    assert_eq!(timeout_dialog["type"], "waitForTimeout");
    assert_eq!(timeout_dialog["pattern"], "READY");
    assert_eq!(timeout_dialog["timeoutMs"], 100);
    assert_eq!(
        timeout_dialog["message"],
        "Timed out waiting for \"READY\" after 100ms"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn buffer_fallback_seeding_keeps_connection_banners_waitable() {
    // No renderer: the snapshot is the buffer fallback (#1960).
    let h = Harness::new(false, |_| None, |_| DialogAnswer::Ignore);
    let sid = "session-buffer-fallback";
    h.manager
        .append_session_output(sid, "Welcome\nSSH资源(5) :\n  [1] host\n");
    let run = h
        .run(sid, "fallback", "const v = await nct.screen.waitForRegex('SSH资源\\\\(\\\\d+\\\\)', 500); nct.log('matched ' + v);")
        .await;
    assert_eq!(run["status"], "completed", "{run}");
    assert!(log_text(&run).contains("matched SSH资源(5)"));
}

#[tokio::test(flavor = "multi_thread")]
async fn wait_for_sees_output_that_arrives_while_startup_snapshot_sync_is_pending() {
    let sid = "session-sync-race";
    let h_slot: Arc<Mutex<Option<OutputBuffer>>> = Arc::new(Mutex::new(None));
    let slot = h_slot.clone();
    let h = Harness::new(
        true,
        move |_| {
            // Output lands while the renderer is producing its snapshot.
            if let Some(buffer) = slot.lock().as_ref() {
                buffer.append("late READY\n");
            }
            Some(snapshot_lines(&["user@host:~$ "]))
        },
        |_| DialogAnswer::Value(json!("abort")),
    );
    *h_slot.lock() = Some(h.buffer(sid));
    let run = h
        .run(
            sid,
            "sync-race",
            "const v = await nct.screen.waitForText('READY', 500); nct.log('matched ' + v);",
        )
        .await;
    assert_eq!(run["status"], "completed", "{run}");
}

#[tokio::test(flavor = "multi_thread")]
async fn wait_for_prompt_can_still_use_the_current_startup_prompt() {
    let h = Harness::new(
        true,
        |_| Some(snapshot_lines(&["Last login: today", "root@host:~# "])),
        |_| DialogAnswer::Value(json!("abort")),
    );
    let run = h
        .run(
            "session-startup-prompt",
            "startup-prompt",
            "const i = await nct.screen.waitForPrompt(500); nct.log('prompt ' + i);",
        )
        .await;
    assert_eq!(run["status"], "completed", "{run}");
    assert!(log_text(&run).contains("prompt 0"));
}

#[tokio::test(flavor = "multi_thread")]
async fn send_line_invalidates_startup_seed_before_later_waits() {
    let sid = "session-send-invalidates-seed";
    let h = Harness::new(
        true,
        |_| Some(snapshot_lines(&["root@host:~# ", "old READY"])),
        |_| DialogAnswer::Value(json!("abort")),
    );
    let manager = h.manager.clone();
    let runner = tokio::spawn(async move {
        manager
            .run(
                serde_json::from_value(json!({
                    "scriptId": "send-invalidates-seed",
                    "sessionId": sid,
                    "content": "await nct.screen.sendLine('echo hi'); const prompt = await nct.screen.waitForPrompt(1000); nct.log('prompt ' + prompt); const value = await nct.screen.waitForText('READY', 1000); nct.log('matched ' + value);",
                }))
                .unwrap(),
            )
            .await
    });
    let state = h.state.clone();
    wait_until(|| state.lock().writes.iter().any(|w| w == "\r").then_some(())).await;
    tokio::time::sleep(Duration::from_millis(40)).await;
    let mid = &h.manager.get_runs(Some(sid))[0];
    assert_eq!(serde_json::to_value(mid.status).unwrap(), "running");
    h.manager
        .append_session_output(sid, "\necho hi\nroot@host:~# \nfresh READY\n");
    runner.await.unwrap().unwrap();
    let run = h.final_run("send-invalidates-seed").await;
    assert_eq!(run["status"], "completed", "{run}");
    assert!(log_text(&run).contains("prompt 0"));
    assert!(log_text(&run).contains("matched READY"));
    // Body and Enter are separate writes; both are announced to the terminal.
    assert_eq!(h.writes(), vec!["echo hi", "\r"]);
    let inputs = h.inputs.lock().clone();
    assert_eq!(inputs[0], json!({ "sessionId": sid, "data": "echo hi" }));
}

#[tokio::test(flavor = "multi_thread")]
async fn send_line_keeps_prompts_that_arrive_between_body_and_cr_waitable() {
    let sid = "session-sendline-gap-prompt";
    let h = Harness::new(true, |_| None, |_| DialogAnswer::Value(json!("abort")));
    let buffer = h.buffer(sid);
    h.set_write_hook(move |data| {
        if data == "menu" {
            // The bastion prints its prompt before Enter arrives.
            buffer.append("menu\nSelect host: ");
        }
    });
    let run = h
        .run(sid, "gap-prompt", "await nct.screen.sendLine('menu'); const v = await nct.screen.waitForText('Select host:', 500); nct.log('matched ' + v);")
        .await;
    assert_eq!(run["status"], "completed", "{run}");
    assert!(log_text(&run).contains("matched Select host:"));
}

#[tokio::test(flavor = "multi_thread")]
async fn wait_timeout_dialog_can_skip_and_retry() {
    let answers = Arc::new(Mutex::new(vec!["retry", "skip"]));
    let h = Harness::new(
        true,
        |_| None,
        move |_| {
            let mut answers = answers.lock();
            let answer = if answers.is_empty() {
                "abort"
            } else {
                answers.remove(0)
            };
            DialogAnswer::Value(json!(answer))
        },
    );
    let run = h
        .run(
            "session-timeout-skip",
            "timeout-skip",
            "const v = await nct.screen.waitForText('never', 30); const i = await nct.screen.waitForAny(['nope'], 30).catch(e => e.message); nct.log(JSON.stringify(v) + '|' + i);",
        )
        .await;
    // First wait: retry, then skip → "". Second wait: abort → rejection.
    assert_eq!(h.dialogs.lock().len(), 3);
    assert_eq!(run["status"], "completed", "{run}");
    assert!(
        log_text(&run).contains("\"\"|Script stopped by user"),
        "{run}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn observer_mode_blocks_writes() {
    let h = Harness::simple();
    let run = h
        .run_with(json!({
            "scriptId": "observer",
            "sessionId": "session-observer",
            "content": "await nct.screen.send('ls');",
            "permissionMode": "observer",
        }))
        .await;
    assert_eq!(run["status"], "failed");
    assert_eq!(
        run["error"],
        "Observer mode: screen.send is disabled. Switch to Confirm or Auto mode."
    );
    assert!(h.writes().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn sensitive_input_is_masked_in_status_and_logs() {
    let h = Harness::simple();
    let run = h
        .run(
            "session-sensitive",
            "sensitive",
            "await nct.screen.sendLine('hunter2', { sensitive: true }); await nct.screen.send('a\\r\\n');",
        )
        .await;
    assert_eq!(run["status"], "completed");
    let logs = log_text(&run);
    assert!(!logs.contains("hunter2"));
    assert!(logs.contains("→ [sensitive]"));
    assert!(logs.contains("→ a\\r\\n"));
    assert!(h.writes().contains(&"hunter2".to_string()));
    let updates = h.run_updates.lock().clone();
    assert!(!serde_json::to_string(&updates).unwrap().contains("hunter2"));
}

#[tokio::test(flavor = "multi_thread")]
async fn regex_waits_work_over_multiline_output() {
    let sid = "session-regex-multiline";
    let h = Harness::simple();
    let buffer = h.buffer(sid);
    h.set_write_hook(move |data| {
        if data == "\r" {
            buffer.append("line one\nVersion: 2.0\nREADY\n");
        }
    });
    let run = h
        .run(
            sid,
            "regex-multiline",
            "await nct.screen.sendLine('show'); const v = await nct.screen.waitFor(/Version: (\\d+)\\.\\d+\\nREADY/, 500); nct.log(v);",
        )
        .await;
    assert_eq!(run["status"], "completed", "{run}");
    assert_eq!(
        log_text(&run).lines().last().unwrap(),
        "Version: 2.0\nREADY".lines().last().unwrap()
    );
    assert!(log_text(&run).contains("Version: 2.0"));
}

#[tokio::test(flavor = "multi_thread")]
async fn determinate_progress_is_reported_and_cleared() {
    let h = Harness::simple();
    let run_future = h.run(
        "session-progress",
        "progress",
        "nct.progress.start('Hosts', 4); nct.progress.step('a'); nct.progress.set(3, 'c'); await nct.sleep(80); nct.progress.done();",
    );
    let updates = h.run_updates.clone();
    let observer = tokio::spawn(async move {
        wait_until(|| {
            updates.lock().iter().flatten().find_map(|r| {
                (r["progressMode"] == "determinate" && r["progressCurrent"] == 3.0)
                    .then(|| r.clone())
            })
        })
        .await
    });
    let run = run_future.await;
    let mid = observer.await.unwrap();
    assert_eq!(mid["progressLabel"], "Hosts");
    assert_eq!(mid["progressTotal"], 4.0);
    assert_eq!(mid["activityLabel"], "c");
    assert_eq!(run["status"], "completed");
    assert_eq!(run["progressMode"], "activity");
    assert!(run.get("progressCurrent").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn pause_blocks_writes_until_resume() {
    let h = Harness::simple();
    let manager = h.manager.clone();
    let runner = tokio::spawn(async move {
        manager
            .run(
                serde_json::from_value(json!({
                    "scriptId": "pausable",
                    "sessionId": "session-pause",
                    "content": "await nct.sleep(100); await nct.screen.send('after-pause');",
                }))
                .unwrap(),
            )
            .await
    });
    let m = h.manager.clone();
    let run_id = wait_until(|| {
        m.get_runs(Some("session-pause"))
            .first()
            .map(|r| r.run_id.clone())
    })
    .await;
    assert!(h.manager.pause(&run_id).ok);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(h.writes().is_empty());
    assert_eq!(
        serde_json::to_value(h.manager.get_runs(Some("session-pause"))[0].status).unwrap(),
        "paused"
    );
    assert!(h.manager.resume(&run_id).ok);
    runner.await.unwrap().unwrap();
    assert_eq!(h.writes(), vec!["after-pause"]);
    assert!(!h.manager.pause("missing").ok);
    assert!(!h.manager.stop("missing").ok);
}

#[tokio::test(flavor = "multi_thread")]
async fn script_errors_and_timeouts_fail_the_run() {
    let h = Harness::simple();
    let run = h
        .run("session-throw", "throws", "throw new Error('boom');")
        .await;
    assert_eq!(run["status"], "failed");
    assert_eq!(run["error"], "boom");
    assert!(log_text(&run).ends_with("boom"));

    h.manager
        .set_engine_limits(netcatty_scripts::engine::EngineLimits {
            sync_execution_timeout_ms: 30,
            ..Default::default()
        });
    let run = h.run("session-loop", "loops", "while (true) {}").await;
    assert_eq!(run["status"], "failed");
    assert_eq!(run["error"], "Script execution timed out after 30ms");
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnect_and_clear_reach_the_session() {
    let h = Harness::simple();
    let run = h
        .run(
            "session-disconnect",
            "disconnect",
            "await nct.screen.clear(); await nct.session.disconnect();",
        )
        .await;
    assert_eq!(run["status"], "completed");
    assert_eq!(h.writes(), vec!["\x1b[2J\x1b[H"]);
    assert_eq!(h.state.lock().closed, vec!["session-disconnect"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn get_text_reads_the_renderer_snapshot() {
    let h = Harness::new(
        true,
        |_| {
            Some(json!({ "rows": 30, "cols": 100, "currentRow": 2, "lines": ["a", "b", "c", "d"] }))
        },
        |_| DialogAnswer::Ignore,
    );
    let run = h
        .run(
            "session-get-text",
            "get-text",
            "const all = await nct.screen.getText(); const part = await nct.screen.getText(1, 2); nct.log(JSON.stringify([all, part, nct.screen.rows, nct.screen.cols, nct.screen.currentRow]));",
        )
        .await;
    assert_eq!(log_text(&run), r#"["a\nb\nc\nd","b\nc",30,100,2]"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_parameter_validation_matches_electron() {
    let h = Harness::simple();
    let err = |params: Value| {
        let manager = h.manager.clone();
        async move {
            manager
                .run(serde_json::from_value(params).unwrap())
                .await
                .unwrap_err()
        }
    };
    assert_eq!(
        err(json!({ "content": "x" })).await,
        "No target session for script run"
    );
    assert_eq!(
        err(json!({ "sessionId": "s", "content": "  " })).await,
        "Script content is empty"
    );
    assert_eq!(
        err(json!({ "sessionIds": ["a", "b"], "content": "x", "runId": "r" })).await,
        "A caller-provided runId requires exactly one target session"
    );
    assert_eq!(
        err(json!({ "sessionIds": ["a", "b"], "content": "x", "returnWhenQueued": true })).await,
        "returnWhenQueued requires exactly one target session"
    );
    assert_eq!(
        err(json!({ "sessionId": "s", "content": "x", "runId": " " })).await,
        "Invalid script run id"
    );
    h.run_with(
        json!({ "scriptId": "dup", "sessionId": "s", "content": "nct.log(1)", "runId": "dup-id" }),
    )
    .await;
    assert_eq!(
        err(json!({ "sessionId": "s", "content": "x", "runId": "dup-id" })).await,
        "Script run id already exists: dup-id"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_session_runs_return_every_run_id() {
    let h = Harness::simple();
    let result = h
        .manager
        .run(
            serde_json::from_value(json!({
                "sessionIds": ["a", "b"],
                "content": "nct.log(nct.session.name)",
                "mode": "sequential",
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(result.run_ids.len(), 2);
    assert_eq!(result.run_id.as_ref(), Some(&result.run_ids[0]));
    assert_eq!(h.manager.get_runs(Some("a")).len(), 1);
    assert_eq!(h.manager.get_runs(None).len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_a_terminal_releases_its_script_output_buffer() {
    let h = Harness::simple();
    h.manager.append_session_output("closing-session", "hello");
    assert!(h.manager.has_buffer("closing-session"));
    h.manager.recording_start("closing-session").unwrap();
    h.manager.session_closed("closing-session");
    assert!(!h.manager.has_buffer("closing-session"));
    assert_eq!(h.manager.recording_stop("closing-session").steps.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn recording_generates_javascript() {
    let h = Harness::simple();
    let sid = "recording-basic";
    assert_eq!(
        h.manager.recording_start("").unwrap_err(),
        "sessionId required"
    );
    h.manager.recording_start(sid).unwrap();
    assert!(
        h.manager
            .recording_append_step(sid, Some(json!({ "type": "send", "value": "ls" })))
            .ok
    );
    assert!(
        h.manager
            .recording_append_step(sid, Some(json!({ "type": "waitForPrompt" })))
            .ok
    );
    let missing = h.manager.recording_append_step(sid, None);
    assert_eq!(missing.error.as_deref(), Some("Recording step is required"));
    let result = h.manager.recording_stop(sid);
    assert_eq!(result.steps.len(), 2);
    assert!(result.code.contains("await nct.screen.sendLine(\"ls\");"));
    assert!(result
        .code
        .contains("await nct.screen.waitForPrompt(30000);"));
    assert!(result.code.contains("// Recorded on 20"));
    assert_eq!(h.manager.recording_stop(sid).code, "");
}

#[tokio::test(flavor = "multi_thread")]
async fn recording_stops_explicitly_when_the_retained_step_limit_is_reached() {
    let h = Harness::new(false, |_| None, |_| DialogAnswer::Ignore);
    let sid = "recording-step-budget";
    h.manager.recording_start(sid).unwrap();
    let mut result = None;
    for index in 0..MAX_SCRIPT_RECORDING_STEPS {
        result = Some(
            h.manager
                .recording_append_step(sid, Some(json!({ "type": "sleep", "value": index }))),
        );
    }
    let result = result.unwrap();
    assert_eq!(result.stopped, Some(true));
    assert_eq!(result.error.as_deref(), Some(SCRIPT_RECORDING_LIMIT_ERROR));
    assert_eq!(
        result.steps.as_ref().unwrap().len(),
        MAX_SCRIPT_RECORDING_STEPS
    );
    assert!(result.code.as_ref().unwrap().contains("sleep"));
    let after = h
        .manager
        .recording_append_step(sid, Some(json!({ "type": "sleep", "value": 10_001 })));
    assert_eq!(
        serde_json::to_value(&after).unwrap(),
        json!({ "ok": false, "error": "Recording not started" })
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn recording_rejects_one_step_beyond_the_total_byte_budget_without_retaining_it() {
    let h = Harness::new(false, |_| None, |_| DialogAnswer::Ignore);
    let sid = "recording-byte-budget";
    h.manager.recording_start(sid).unwrap();
    let result = h.manager.recording_append_step(
        sid,
        Some(json!({ "type": "send", "value": "x".repeat(2 * 1024 * 1024 + 1) })),
    );
    assert_eq!(result.stopped, Some(true));
    assert_eq!(result.reason, Some("limit"));
    assert_eq!(result.error.as_deref(), Some(SCRIPT_RECORDING_LIMIT_ERROR));
    assert_eq!(result.steps.as_deref(), Some(&[][..]));
    assert_eq!(result.code.as_deref(), Some(""));
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_and_dialog_responses_for_unknown_requests_are_rejected() {
    let h = Harness::simple();
    assert!(!h.manager.dialog_response("nope", None, false).ok);
    assert!(!h.manager.screen_snapshot_response("nope", None).ok);
}

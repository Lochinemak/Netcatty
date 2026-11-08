//! Bidirectional stream-json transport used by the Claude Code and CodeBuddy
//! CLIs (`--input-format stream-json --output-format stream-json`): user
//! messages and `control_request`s go to stdin, messages and
//! `control_response`s / CLI-initiated `control_request`s come from stdout.

use crate::cli::SpawnSpec;
use crate::process::{spawn_lines, Stdin, StderrTail};
use crate::EnvMap;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Child;
use tokio::sync::{mpsc, oneshot};

pub const MAX_STREAM_JSON_LINE_BYTES: usize = 64 * 1024 * 1024;
const MAX_STDERR_CHARS: usize = 32 * 1024;

/// Answers CLI-initiated control requests (`can_use_tool`, `hook_callback`,
/// `elicitation_create`, ...). `Ok` → success response, `Err` → error response.
#[async_trait::async_trait]
pub trait ControlHandler: Send + Sync {
    async fn handle(&self, request: Value) -> Result<Value, String>;
}

/// Handler that rejects every request (`canUseTool callback is not provided.`).
pub struct RejectAll;

#[async_trait::async_trait]
impl ControlHandler for RejectAll {
    async fn handle(&self, request: Value) -> Result<Value, String> {
        match request.get("subtype").and_then(|s| s.as_str()) {
            Some("can_use_tool") => Err("canUseTool callback is not provided.".into()),
            Some("hook_callback") => Ok(json!({ "continue": true })),
            Some(other) => Err(format!("Unsupported control request subtype: {other}")),
            None => Err("Unsupported control request".into()),
        }
    }
}

/// Messages and process events surfaced to the driver.
#[derive(Debug)]
pub enum StreamEvent {
    Message(Value),
    /// A stdout line exceeded the cap; the transport is unusable.
    Overflow,
}

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<Result<Value, String>>>>>;

pub struct StreamJsonProcess {
    pub child: Child,
    pub stderr: StderrTail,
    stdin_tx: Option<mpsc::UnboundedSender<String>>,
    pending: Pending,
    next_id: AtomicU64,
}

impl StreamJsonProcess {
    /// Spawn the CLI; returns the process and the ordered message stream.
    pub fn spawn(
        spec: &SpawnSpec,
        env: &EnvMap,
        cwd: Option<&Path>,
        handler: Arc<dyn ControlHandler>,
    ) -> std::io::Result<(Self, mpsc::UnboundedReceiver<StreamEvent>)> {
        let mut spawned = spawn_lines(spec, env, cwd, Stdin::Piped, MAX_STREAM_JSON_LINE_BYTES, MAX_STDERR_CHARS)?;
        let mut stdin = spawned.child.stdin.take().ok_or_else(|| std::io::Error::other("child has no stdin"))?;
        let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(line) = stdin_rx.recv().await {
                if stdin.write_all(line.as_bytes()).await.is_err() || stdin.flush().await.is_err() {
                    break;
                }
            }
            let _ = stdin.shutdown().await;
        });
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let mut reader = spawned.stdout;
        let pending_reader = pending.clone();
        let responder = stdin_tx.clone();
        tokio::spawn(async move {
            loop {
                match reader.next_line().await {
                    Ok(Some(line)) => {
                        let Ok(message) = serde_json::from_str::<Value>(&line) else { continue };
                        match message.get("type").and_then(|t| t.as_str()) {
                            Some("control_response") => {
                                let response = &message["response"];
                                let id = response["request_id"].as_str().unwrap_or("").to_string();
                                if let Some(tx) = pending_reader.lock().remove(&id) {
                                    let result = if response["subtype"] == "success" {
                                        Ok(response.get("response").cloned().unwrap_or(Value::Null))
                                    } else {
                                        Err(response["error"].as_str().unwrap_or("control request failed").to_string())
                                    };
                                    let _ = tx.send(result);
                                }
                            }
                            Some("control_request") => {
                                let handler = handler.clone();
                                let responder = responder.clone();
                                tokio::spawn(async move {
                                    let request_id = message["request_id"].as_str().unwrap_or("").to_string();
                                    let request = message.get("request").cloned().unwrap_or(Value::Null);
                                    let response = match handler.handle(request).await {
                                        Ok(body) => json!({ "type": "control_response", "response": { "subtype": "success", "request_id": request_id, "response": body } }),
                                        Err(error) => json!({ "type": "control_response", "response": { "subtype": "error", "request_id": request_id, "error": error } }),
                                    };
                                    let _ = responder.send(format!("{response}\n"));
                                });
                            }
                            Some("control_cancel_request") | Some("keep_alive") => {}
                            _ => {
                                if events_tx.send(StreamEvent::Message(message)).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {
                        let _ = events_tx.send(StreamEvent::Overflow);
                        break;
                    }
                }
            }
            // Fail any request still waiting for an answer.
            for (_, tx) in pending_reader.lock().drain() {
                let _ = tx.send(Err("CLI process closed".into()));
            }
        });
        Ok((
            Self { child: spawned.child, stderr: spawned.stderr, stdin_tx: Some(stdin_tx), pending, next_id: AtomicU64::new(1) },
            events_rx,
        ))
    }

    /// Write one JSON line to stdin.
    pub fn send(&self, message: &Value) -> bool {
        match &self.stdin_tx {
            Some(tx) => tx.send(format!("{message}\n")).is_ok(),
            None => false,
        }
    }

    /// `{ type: "user", session_id: "", message: { role: "user", content }, parent_tool_use_id: null }`.
    pub fn send_user_message(&self, content: Value) -> bool {
        self.send(&json!({
            "type": "user",
            "session_id": "",
            "message": { "role": "user", "content": content },
            "parent_tool_use_id": null,
        }))
    }

    /// Send a control request; resolves with its response body.
    pub fn request(&self, request: Value) -> oneshot::Receiver<Result<Value, String>> {
        let id = format!("req_{}_{}", self.next_id.fetch_add(1, Ordering::Relaxed), uuid::Uuid::new_v4().simple());
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(id.clone(), tx);
        if !self.send(&json!({ "type": "control_request", "request_id": id, "request": request })) {
            if let Some(tx) = self.pending.lock().remove(&id) {
                let _ = tx.send(Err("CLI stdin is unavailable".into()));
            }
        }
        rx
    }

    /// Await a control request with a timeout.
    pub async fn request_timeout(&self, request: Value, timeout: Duration) -> Result<Value, String> {
        let rx = self.request(request);
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("CLI process closed".into()),
            Err(_) => Err("control request timed out".into()),
        }
    }

    /// Close stdin (single-turn: the CLI exits after its `result`).
    pub fn end_input(&mut self) {
        self.stdin_tx = None;
    }

    pub async fn terminate(&mut self) {
        self.end_input();
        crate::process::terminate_child(&mut self.child, crate::process::DEFAULT_ABORT_GRACE).await;
    }

    /// Wait for exit (bounded) and return the exit code.
    pub async fn wait_exit(&mut self, timeout: Duration) -> Option<i32> {
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(Ok(status)) => status.code(),
            _ => {
                self.terminate().await;
                None
            }
        }
    }
}

/// `node <file>` for JavaScript entry points, the file itself otherwise.
pub fn spec_for_cli(bin_path: &str, args: Vec<String>) -> SpawnSpec {
    let lower = bin_path.to_ascii_lowercase();
    if [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"].iter().any(|ext| lower.ends_with(ext)) {
        let mut full = vec![bin_path.to_string()];
        full.extend(args);
        return SpawnSpec { command: "node".into(), args: full, shell: false };
    }
    crate::cli::prepare_command_for_spawn(bin_path, &args, true)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn control_round_trip_and_messages() {
        // Fake CLI: answers the first control request, asks one of its own,
        // then emits a message per stdin line until EOF.
        let script = r#"
read line
id=$(printf '%s' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p')
printf '{"type":"control_response","response":{"subtype":"success","request_id":"%s","response":{"models":[1]}}}\n' "$id"
printf '{"type":"control_request","request_id":"cli-1","request":{"subtype":"can_use_tool","tool_name":"Bash"}}\n'
read answer
printf '{"type":"system","answer":%s}\n' "$answer"
printf '{"type":"keep_alive"}\n'
printf '{"type":"result","subtype":"success"}\n'
"#;
        let spec = SpawnSpec { command: "sh".into(), args: vec!["-c".into(), script.into()], shell: false };
        let env: EnvMap = [("PATH".to_string(), "/usr/bin:/bin".to_string())].into_iter().collect();
        let (mut proc_, mut events) = StreamJsonProcess::spawn(&spec, &env, None, Arc::new(RejectAll)).unwrap();
        let response = proc_.request_timeout(json!({ "subtype": "initialize" }), Duration::from_secs(5)).await.unwrap();
        assert_eq!(response["models"][0], 1);
        let StreamEvent::Message(system) = events.recv().await.unwrap() else { panic!() };
        assert_eq!(system["answer"]["response"]["subtype"], "error");
        assert_eq!(system["answer"]["response"]["request_id"], "cli-1");
        assert_eq!(system["answer"]["response"]["error"], "canUseTool callback is not provided.");
        let StreamEvent::Message(result) = events.recv().await.unwrap() else { panic!() };
        assert_eq!(result["type"], "result");
        proc_.end_input();
        assert_eq!(proc_.wait_exit(Duration::from_secs(5)).await, Some(0));
        assert!(events.recv().await.is_none());
    }

    #[test]
    fn js_entry_runs_through_node() {
        let spec = spec_for_cli("/x/cli.js", vec!["-p".into()]);
        assert_eq!(spec.command, "node");
        assert_eq!(spec.args, vec!["/x/cli.js".to_string(), "-p".to_string()]);
        assert_eq!(spec_for_cli("/x/claude", vec![]).command, "/x/claude");
    }
}

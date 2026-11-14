//! Host integration tests over a fake backend (ported cases from
//! `electron/bridges/mcpServerBridge*.test.cjs`).

use super::backend::*;
use super::*;
use netcatty_ptyexec::job::{OutputRx, PtyInput};
use netcatty_ptyexec::shell_kind::{ExecProbe, ShellKindState};
use netcatty_ptyexec::shell_utils::PromptTracker;
use parking_lot::Mutex as PMutex;
use serde_json::json;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

/// A fake PTY: every write is recorded; the wrapper is answered with the
/// start/end markers and `reply` as command output.
struct FakeTerm {
    id: String,
    protocol: String,
    writes: Arc<PMutex<Vec<String>>>,
    taps: Arc<PMutex<Vec<mpsc::UnboundedSender<String>>>>,
    reply: Arc<PMutex<Option<(String, i32)>>>,
    shell: Arc<ShellKindState>,
    displays: Arc<PMutex<Vec<(String, bool)>>>,
}

struct Writer(Arc<FakeTerm>);

#[async_trait::async_trait]
impl PtyInput for Writer {
    async fn write(&self, data: &str) -> Result<(), String> {
        self.0.writes.lock().push(data.to_string());
        let re = regex::Regex::new(r"(__NCMCP_[a-z0-9]+_[0-9a-f]+__)").unwrap();
        if let Some(m) = re.captures(data) {
            if data.contains("_P:%s") {
                let marker = m[1].to_string();
                for tx in self.0.taps.lock().iter() {
                    let _ = tx.send(format!("\n{marker}_P:bash\n{marker}_Q"));
                }
                return Ok(());
            }
            if data.contains("_cmd") || data.contains("Invoke-Expression") {
                if let Some((out, code)) = self.0.reply.lock().clone() {
                    let marker = m[1].to_string();
                    for tx in self.0.taps.lock().iter() {
                        let _ = tx.send(format!("{marker}_S\n{out}\n{marker}_E:{code}\n"));
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl TerminalSession for Arc<FakeTerm> {
    fn session_id(&self) -> &str {
        &self.id
    }
    fn protocol(&self) -> &str {
        &self.protocol
    }
    fn label(&self) -> String {
        "web".into()
    }
    fn hostname(&self) -> String {
        "web.example".into()
    }
    fn username(&self) -> String {
        "root".into()
    }
    fn host_id(&self) -> String {
        "host-1".into()
    }
    fn writer(&self) -> Option<Arc<dyn PtyInput>> {
        Some(Arc::new(Writer(self.clone())))
    }
    fn subscribe(&self) -> OutputRx {
        let (tx, rx) = mpsc::unbounded_channel();
        self.taps.lock().push(tx);
        rx
    }
    fn prompt(&self) -> PromptTracker {
        PromptTracker::default()
    }
    fn shell_kind(&self) -> Arc<ShellKindState> {
        self.shell.clone()
    }
    fn remote_ssh_version(&self) -> String {
        "OpenSSH_9.6".into()
    }
    fn single_channel(&self) -> bool {
        false
    }
    fn exec_probe(&self) -> Option<Arc<dyn ExecProbe>> {
        None
    }
    async fn channel_exec(&self, _c: &str, _t: u64, _m: usize) -> Option<Result<ChannelOutput, ChannelError>> {
        None
    }
    fn prompt_recovery_pending(&self) -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }
    fn clear_flow(&self) {}
    fn emit_display(&self, data: &str, synthetic: bool) {
        self.displays.lock().push((data.to_string(), synthetic));
    }
}

#[derive(Default)]
struct FakeBackend {
    sessions: PMutex<HashMap<String, Arc<FakeTerm>>>,
    events: PMutex<Vec<(String, Value)>>,
}

impl FakeBackend {
    fn add(&self, id: &str, protocol: &str, kind: Option<&str>) -> Arc<FakeTerm> {
        let t = Arc::new(FakeTerm {
            id: id.into(),
            protocol: protocol.into(),
            writes: Default::default(),
            taps: Default::default(),
            reply: Arc::new(PMutex::new(Some(("hello".into(), 0)))),
            shell: ShellKindState::with_shell_kind(kind.map(str::to_string)),
            displays: Default::default(),
        });
        self.sessions.lock().insert(id.into(), t.clone());
        t
    }
    fn events_named(&self, name: &str) -> Vec<Value> {
        self.events.lock().iter().filter(|(n, _)| n == name).map(|(_, v)| v.clone()).collect()
    }
}

#[async_trait::async_trait]
impl HostBackend for FakeBackend {
    fn session(&self, id: &str) -> Option<Arc<dyn TerminalSession>> {
        self.sessions.lock().get(id).map(|t| Arc::new(t.clone()) as Arc<dyn TerminalSession>)
    }
    fn session_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.sessions.lock().keys().cloned().collect();
        v.sort();
        v
    }
    async fn sftp(&self, _id: &str, op: SftpOp, cancel: tokio_util::sync::CancellationToken) -> Result<Value, String> {
        match op {
            SftpOp::Home => Ok(json!("/root")),
            SftpOp::Read { offset, max_bytes, .. } => {
                tokio::select! {
                    _ = cancel.cancelled() => Err("Cancelled".into()),
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {
                        let file = b"file-content";
                        let start = (offset as usize).min(file.len());
                        let end = max_bytes.map_or(file.len(), |m| (start + m as usize).min(file.len()));
                        Ok(super::sftp::read_chunk(file[start..end].to_vec(), offset, Some(file.len() as u64), max_bytes))
                    }
                }
            }
            SftpOp::Find { options } => Ok(json!({ "path": options.root, "pattern": options.pattern, "matches": [{ "path": "/etc/app.conf", "type": "file" }], "matchCount": 1, "truncated": false, "maxDepth": options.max_depth })),
            SftpOp::List { .. } => Ok(json!([{ "name": "a.txt", "type": "file" }])),
            _ => Ok(Value::Null),
        }
    }
    fn emit(&self, event: &str, payload: Value) {
        self.events.lock().push((event.into(), payload));
    }
    async fn list_port_forwards(&self) -> Vec<Value> {
        vec![]
    }
}

fn host_with(backend: Arc<FakeBackend>) -> Arc<McpHost> {
    McpHost::new(backend, None)
}

fn scope(host: &McpHost, chat: &str, ids: &[&str]) {
    let list: Vec<Value> = ids.iter().map(|id| json!({ "sessionId": id, "hostname": "web.example", "label": "web", "connected": true, "protocol": "ssh", "savedHostId": "host-1" })).collect();
    host.update_session_metadata(&list, Some(chat));
}

fn p(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[tokio::test]
async fn exec_runs_in_scope_and_rejects_out_of_scope() {
    let backend = Arc::new(FakeBackend::default());
    backend.add("s1", "ssh", Some("posix"));
    backend.add("s2", "ssh", Some("posix"));
    let host = host_with(backend.clone());
    host.set_permission_mode("auto");
    scope(&host, "chat", &["s1"]);
    let r = host.dispatch("netcatty/exec", p(json!({ "sessionId": "s1", "command": "echo hello", "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["stdout"], "hello");
    assert_eq!(r["exitCode"], 0);
    let displays = backend.sessions.lock()["s1"].displays.lock().clone();
    assert!(displays.iter().any(|(d, synthetic)| *synthetic && d == "echo hello\r\n"));
    assert!(displays.iter().any(|(d, synthetic)| !synthetic && d.ends_with("_I\n")));
    let r = host.dispatch("netcatty/exec", p(json!({ "sessionId": "s2", "command": "ls", "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert_eq!(r["error"], "Session \"s2\" is not in the current scope.");
    let r = host.dispatch("netcatty/exec", p(json!({ "sessionId": "s1", "command": "ls" })), Default::default()).await.unwrap();
    assert_eq!(r["error"], "chatSessionId is required for write operations.");
}

#[tokio::test]
async fn blocklist_observer_and_unsupported_local_shell() {
    let backend = Arc::new(FakeBackend::default());
    backend.add("s1", "ssh", Some("posix"));
    backend.add("l1", "local", Some("unknown"));
    let host = host_with(backend.clone());
    host.set_permission_mode("auto");
    host.set_command_blocklist(netcatty_ptyexec::safety::default_command_blocklist());
    scope(&host, "chat", &["s1", "l1"]);
    let r = host.dispatch("netcatty/exec", p(json!({ "sessionId": "s1", "command": "rm -rf /", "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert!(r["error"].as_str().unwrap().starts_with("Command blocked by safety policy. Pattern:"));
    let r = host.dispatch("netcatty/exec", p(json!({ "sessionId": "l1", "command": "ls", "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert_eq!(r["error"], exec::UNSUPPORTED_LOCAL_SHELL);
    host.set_permission_mode("observer");
    let r = host.catty_exec("s1", "ls", Some("chat")).await;
    assert_eq!(r["error"], "Execution blocked: permission mode is 'observer'");
}

#[tokio::test]
async fn catty_exec_strips_markers_and_reports_exit_code() {
    let backend = Arc::new(FakeBackend::default());
    let t = backend.add("s1", "ssh", Some("posix"));
    *t.reply.lock() = Some(("partial".into(), 3));
    let host = host_with(backend.clone());
    let r = host.catty_exec("s1", "false", Some("chat")).await;
    assert_eq!(r["ok"], false);
    assert_eq!(r["exitCode"], 3);
    assert_eq!(r["stdout"], "partial");
    assert!(r.get("error").is_none());
    assert_eq!(host.catty_exec("missing", "ls", None).await["error"], "Session not found");
}

#[tokio::test]
async fn catty_cancel_interrupts_running_command() {
    let backend = Arc::new(FakeBackend::default());
    let t = backend.add("s1", "ssh", Some("posix"));
    *t.reply.lock() = None;
    let host = host_with(backend.clone());
    let h2 = host.clone();
    let task = tokio::spawn(async move { h2.catty_exec("s1", "sleep 100", Some("chat")).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(host.session_busy_error("s1").is_some());
    host.catty_cancel("chat").await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(t.writes.lock().iter().any(|w| w == "\x03"));
    // Prompt never returns in the fake: the pre-start cancel fallback (2 s)
    // finishes the job as Cancelled and releases the session lock.
    let r = tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
    assert_eq!(r["error"], "Cancelled");
    assert!(host.session_busy_error("s1").is_none());
}

#[tokio::test]
async fn background_jobs_start_poll_and_stop() {
    let backend = Arc::new(FakeBackend::default());
    let t = backend.add("s1", "ssh", Some("posix"));
    *t.reply.lock() = None;
    let host = host_with(backend.clone());
    host.set_permission_mode("auto");
    scope(&host, "chat", &["s1"]);
    let start = host.dispatch("netcatty/jobStart", p(json!({ "sessionId": "s1", "command": "tail -f x", "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert_eq!(start["ok"], true, "{start}");
    assert_eq!(start["outputMode"], "foreground-mirrored");
    let job_id = start["jobId"].as_str().unwrap().to_string();
    let busy = host.dispatch("netcatty/exec", p(json!({ "sessionId": "s1", "command": "ls", "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert!(busy["error"].as_str().unwrap().contains("a long-running command"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let marker = {
        let re = regex::Regex::new(r"(__NCMCP_[a-z0-9]+_[0-9a-f]+__)").unwrap();
        let w = t.writes.lock();
        w.iter().find_map(|x| re.captures(x).map(|c| c[1].to_string())).unwrap()
    };
    for tx in t.taps.lock().iter() {
        let _ = tx.send(format!("{marker}_S\nline1\nline2\n"));
    }
    tokio::time::sleep(Duration::from_millis(30)).await;
    let poll = host.dispatch("netcatty/jobPoll", p(json!({ "jobId": job_id, "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert_eq!(poll["status"], "running");
    assert_eq!(poll["output"], "line1\nline2\n");
    let next = poll["nextOffset"].as_u64().unwrap();
    let foreign = host.dispatch("netcatty/jobPoll", p(json!({ "jobId": job_id, "chatSessionId": "other" })), Default::default()).await.unwrap();
    assert_eq!(foreign["error"], "Background job not found");
    for tx in t.taps.lock().iter() {
        let _ = tx.send(format!("line3\n{marker}_E:0\n"));
    }
    tokio::time::sleep(Duration::from_millis(30)).await;
    let poll = host.dispatch("netcatty/jobPoll", p(json!({ "jobId": job_id, "chatSessionId": "chat", "offset": next })), Default::default()).await.unwrap();
    assert_eq!(poll["status"], "completed", "{poll}");
    assert_eq!(poll["output"], "line3\n");
    assert!(host.session_busy_error("s1").is_none());
    let stop = host.dispatch("netcatty/jobStop", p(json!({ "jobId": job_id, "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert_eq!(stop["completed"], true);
}

#[tokio::test]
async fn confirm_mode_approval_request_resolve_and_timeout_cancel() {
    let backend = Arc::new(FakeBackend::default());
    backend.add("s1", "ssh", Some("posix"));
    let host = host_with(backend.clone());
    scope(&host, "chat", &["s1"]);
    let h2 = host.clone();
    let task = tokio::spawn(async move {
        h2.dispatch("netcatty/exec", p(json!({ "sessionId": "s1", "command": "echo hi", "chatSessionId": "chat" })), Default::default()).await
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let req = backend.events_named(approvals::APPROVAL_REQUEST_EVENT).pop().unwrap();
    assert_eq!(req["toolName"], "netcatty/exec");
    assert_eq!(req["args"], json!({ "sessionId": "s1", "command": "echo hi" }));
    assert_eq!(req["target"]["hostId"], "host-1");
    assert_eq!(req["allowSession"], false);
    let id = req["approvalId"].as_str().unwrap().to_string();
    assert!(host.cancel_approval_timeout(&id));
    assert!(!host.cancel_approval_timeout(&id));
    // A second exec on the same session waits behind the pending approval.
    let r = host.dispatch("netcatty/exec", p(json!({ "sessionId": "s1", "command": "ls", "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert!(r["error"].as_str().unwrap().contains("awaiting approval"));
    assert!(host.resolve_approval(&id, false, "once"));
    let r = task.await.unwrap().unwrap();
    assert_eq!(r["error"], "Operation denied by user.");
    let cleared = backend.events_named(approvals::APPROVAL_CLEARED_EVENT);
    assert_eq!(cleared.last().unwrap()["approvalIds"], json!([id]));
}

#[tokio::test(start_paused = true)]
async fn approval_auto_denies_after_absolute_deadline() {
    let backend = Arc::new(FakeBackend::default());
    let host = host_with(backend.clone());
    let h2 = host.clone();
    let task = tokio::spawn(async move { h2.request_approval("x", json!({}), Some("chat".into()), None, None).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    let id = backend.events_named(approvals::APPROVAL_REQUEST_EVENT)[0]["approvalId"].as_str().unwrap().to_string();
    host.cancel_approval_timeout(&id);
    tokio::time::sleep(Duration::from_millis(MCP_APPROVAL_TIMEOUT_MS + 10)).await;
    assert!(!task.await.unwrap());
    assert!(!host.resolve_approval(&id, true, "once"));
}

#[tokio::test]
async fn host_open_owned_sessions_survive_sidebar_replace_but_not_empty_replace() {
    let backend = Arc::new(FakeBackend::default());
    let host = host_with(backend.clone());
    host.set_permission_mode("auto");
    scope(&host, "chat", &["tab-1"]);
    let h2 = host.clone();
    let open = tokio::spawn(async move {
        h2.dispatch("vault/hosts/open", p(json!({ "hostId": "host-1", "chatSessionId": "chat" })), Default::default()).await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let req = backend.events_named(vault_agent::VAULT_AGENT_REQUEST_EVENT).pop().unwrap();
    assert_eq!(req["op"], "host.open");
    host.vault_agent.respond(
        req["requestId"].as_str().unwrap(),
        json!({ "ok": true, "sessionId": "opened-1", "status": "connected", "host": { "id": "host-1", "hostname": "db.example", "label": "db" } }),
    );
    let r = open.await.unwrap().unwrap();
    assert_eq!(r["scopeBound"], true, "{r}");
    scope(&host, "chat", &["tab-1"]);
    assert!(host.scoped_session_ids(Some("chat")).contains(&"opened-1".to_string()));
    host.update_session_metadata(&[], Some("chat"));
    assert!(host.scoped_session_ids(Some("chat")).is_empty());
}

#[tokio::test]
async fn get_context_lists_scoped_hosts_and_external_disabled() {
    let backend = Arc::new(FakeBackend::default());
    backend.add("s1", "ssh", Some("posix"));
    backend.add("s2", "local", Some("posix"));
    let host = host_with(backend.clone());
    scope(&host, "chat", &["s1", "ghost"]);
    host.update_session_metadata(&[json!({ "sessionId": "s1", "label": "web", "connected": true }), json!({ "sessionId": "ghost", "label": "gone", "connected": false })], Some("chat"));
    let ctx = host.dispatch("netcatty/getContext", p(json!({ "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert_eq!(ctx["hostCount"], 2);
    assert_eq!(ctx["hosts"][1]["connected"], false);
    assert_eq!(ctx["tools"]["terminal"]["execute"], "terminal_execute");
    assert!(ctx["description"].as_str().unwrap().contains("Vault → Hosts vs Vault → Notes"));
    let empty = host.dispatch("netcatty/getContext", p(json!({ "chatSessionId": "nobody" })), Default::default()).await.unwrap();
    assert_eq!(empty["description"], "No hosts are available in the current scope.");
    let err = host.dispatch("netcatty/getContext", Map::new(), Default::default()).await.unwrap_err();
    assert_eq!(err, "chatSessionId or scopedSessionIds is required.");
    let ext = host.dispatch("netcatty/getContext", p(json!({ "chatSessionId": EXTERNAL_MCP_CHAT_SESSION_ID })), Default::default()).await.unwrap();
    assert_eq!(ext["description"], "External MCP is disabled.");
}

#[tokio::test]
async fn attachments_list_read_and_limits() {
    let backend = Arc::new(FakeBackend::default());
    let host = host_with(backend);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("hosts.csv");
    std::fs::write(&file, "a,b\n1,2\n").unwrap();
    host.update_attachment_metadata(&[json!({ "filename": "hosts.csv", "mediaType": "text/csv", "filePath": file.to_string_lossy() }), json!({ "filename": "n.md", "base64Data": "IyBoaQ==" })], "chat");
    let list = host.handle_list_attachments(&p(json!({ "chatSessionId": "chat" })));
    assert_eq!(list["attachments"].as_array().unwrap().len(), 2);
    let r = host.handle_read_attachment(&p(json!({ "chatSessionId": "chat", "filename": "hosts.csv" })));
    assert_eq!(r["text"], "a,b\n1,2\n");
    let r = host.handle_read_attachment(&p(json!({ "chatSessionId": "chat", "filename": "hosts.csv", "maxBytes": 3 })));
    assert_eq!(r["error"], "Attachment exceeds the requested size limit.");
    let r = host.handle_read_attachment(&p(json!({ "chatSessionId": "chat", "filePath": "/etc/passwd" })));
    assert_eq!(r["error"], "Attachment is not registered for this chat session.");
    let r = host.handle_read_attachment(&p(json!({ "chatSessionId": "chat", "filename": "n.md" })));
    assert_eq!(r["text"], "# hi");
}

#[tokio::test]
async fn sftp_handlers_and_cancellation() {
    let backend = Arc::new(FakeBackend::default());
    backend.add("s1", "ssh", Some("posix"));
    let host = host_with(backend);
    host.set_permission_mode("auto");
    scope(&host, "chat", &["s1"]);
    let r = host.dispatch("netcatty/sftp/home", p(json!({ "sessionId": "s1", "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert_eq!(r, json!({ "ok": true, "homeDir": "/root" }));
    let h2 = host.clone();
    let read = tokio::spawn(async move {
        h2.dispatch("netcatty/sftp/read", p(json!({ "sessionId": "s1", "path": "/x", "chatSessionId": "chat" })), Default::default()).await
    });
    tokio::time::sleep(Duration::from_millis(5)).await;
    host.cancel_sftp_ops_for_chat("chat").await;
    assert_eq!(read.await.unwrap().unwrap_err(), "Cancelled");
    let err = host.dispatch("netcatty/sftp/read", p(json!({ "sessionId": "s1", "chatSessionId": "chat" })), Default::default()).await.unwrap_err();
    assert_eq!(err, "path is required");
}

#[tokio::test]
async fn sftp_read_ranges_and_find() {
    let backend = Arc::new(FakeBackend::default());
    backend.add("s1", "ssh", Some("posix"));
    let host = host_with(backend);
    scope(&host, "chat", &["s1"]);
    let read = |extra: Value| {
        let host = host.clone();
        async move {
            let mut params = p(json!({ "sessionId": "s1", "path": "/x", "chatSessionId": "chat" }));
            params.extend(p(extra));
            host.dispatch("netcatty/sftp/read", params, Default::default()).await.unwrap()
        }
    };
    // No limit: the whole file, as before, now with its extent.
    let whole = read(json!({})).await;
    assert_eq!(whole, json!({ "ok": true, "path": "/x", "content": "file-content", "offset": 0, "bytesRead": 12, "truncated": false, "totalBytes": 12 }));
    let first = read(json!({ "maxBytes": 5 })).await;
    assert_eq!((first["content"].clone(), first["truncated"].clone(), first["nextOffset"].clone()), (json!("file-"), json!(true), json!(5)));
    // The tool CLI sends numbers as floats.
    let rest = read(json!({ "offset": 5.0, "maxBytes": 100.0 })).await;
    assert_eq!((rest["content"].clone(), rest["truncated"].clone()), (json!("content"), json!(false)));
    assert!(rest.get("nextOffset").is_none());
    // A limit too small to hold one character is raised, not honoured.
    assert_eq!(read(json!({ "maxBytes": 1 })).await["bytesRead"], 4);

    let find = |params: Value| {
        let host = host.clone();
        async move { host.dispatch("netcatty/sftp/find", p(params), Default::default()).await }
    };
    let r = find(json!({ "sessionId": "s1", "path": "/etc", "pattern": "*.conf", "type": "file", "chatSessionId": "chat" })).await.unwrap();
    assert_eq!(r["ok"], true);
    assert_eq!(r["matches"][0]["path"], "/etc/app.conf");
    assert_eq!(r["maxDepth"], 5, "default depth");
    assert_eq!(find(json!({ "sessionId": "s1", "path": "/etc", "chatSessionId": "chat" })).await.unwrap_err(), "pattern is required");
    assert_eq!(find(json!({ "sessionId": "s1", "pattern": "*", "chatSessionId": "chat" })).await.unwrap_err(), "path is required");
    assert_eq!(find(json!({ "sessionId": "s1", "path": "/", "pattern": "*", "type": "socket", "chatSessionId": "chat" })).await.unwrap_err(), "type must be file, directory, or symlink");
    assert!(find(json!({ "sessionId": "s1", "path": "/", "pattern": "a/b", "chatSessionId": "chat" })).await.unwrap_err().contains("not paths"));
    // Read-only: allowed in observer mode, and scoped like every other tool.
    host.set_permission_mode("observer");
    assert_eq!(find(json!({ "sessionId": "s1", "path": "/etc", "pattern": "*", "chatSessionId": "chat" })).await.unwrap()["ok"], true);
    let r = find(json!({ "sessionId": "s9", "path": "/etc", "pattern": "*", "chatSessionId": "chat" })).await.unwrap();
    assert_eq!(r["error"], "Session \"s9\" is not in the current scope.");
}

async fn rpc(lines: &mut tokio::io::Lines<BufReader<tokio::net::tcp::OwnedReadHalf>>, w: &mut tokio::net::tcp::OwnedWriteHalf, id: u64, method: &str, params: Value) -> Value {
    let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    w.write_all(format!("{msg}\n").as_bytes()).await.unwrap();
    serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap()
}

#[tokio::test]
async fn tcp_auth_gate_status_and_discovery_self_heal() {
    let backend = Arc::new(FakeBackend::default());
    let dir = tempfile::tempdir().unwrap();
    let discovery = dir.path().join("netcatty-tool-cli").join("discovery.json");
    let host = McpHost::new(backend, Some(discovery.clone()));
    let port = host.get_or_create_host().await.unwrap();
    assert_eq!(host.get_or_create_host().await.unwrap(), port);
    let parsed: Value = serde_json::from_str(&std::fs::read_to_string(&discovery).unwrap()).unwrap();
    assert_eq!(parsed["port"], port);
    let token = parsed["token"].as_str().unwrap().to_string();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&discovery).unwrap().permissions().mode() & 0o777, 0o600);
    }

    let sock = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (r, mut w) = sock.into_split();
    let mut lines = BufReader::new(r).lines();
    let resp = rpc(&mut lines, &mut w, 1, "netcatty/getStatus", json!({})).await;
    assert_eq!(resp["error"]["code"], -32001);

    let sock = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (r, mut w) = sock.into_split();
    let mut lines = BufReader::new(r).lines();
    assert_eq!(rpc(&mut lines, &mut w, 1, "auth/verify", json!({ "token": token })).await["result"]["ok"], true);
    std::fs::remove_file(&discovery).unwrap();
    let status = rpc(&mut lines, &mut w, 2, "netcatty/getStatus", json!({})).await;
    assert_eq!(status["result"]["permissionMode"], "confirm");
    assert_eq!(status["result"]["approvalTimeoutMs"], 110_000);
    assert_eq!(status["result"]["discoveryFilePresent"], true, "self-healed before reporting");
    let unknown = rpc(&mut lines, &mut w, 3, "netcatty/nope", json!({})).await;
    assert_eq!(unknown["error"]["message"], "Unknown method: netcatty/nope");

    let ext = host.issue_external_mcp_auth_token();
    let sock = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (r, mut w) = sock.into_split();
    let mut lines = BufReader::new(r).lines();
    let resp = rpc(&mut lines, &mut w, 1, "auth/verify", json!({ "token": ext })).await;
    assert_eq!(resp["error"]["message"], "External MCP is disabled. Re-enable it in Netcatty Settings → AI.");
    host.shutdown_host(false);
    assert!(!discovery.exists());
}

fn named_scope(host: &McpHost, chat: &str, sessions: &[(&str, &str, &str)]) {
    let list: Vec<Value> = sessions
        .iter()
        .map(|(id, label, hostname)| json!({ "sessionId": id, "label": label, "hostname": hostname, "username": "root", "connected": true, "protocol": "ssh" }))
        .collect();
    host.update_session_metadata(&list, Some(chat));
}

fn wrote_command(backend: &FakeBackend, id: &str) -> bool {
    backend.sessions.lock()[id].writes.lock().iter().any(|w| w.contains("uptime"))
}

#[tokio::test]
async fn a_session_is_addressed_by_label_hostname_or_user_at_host() {
    let backend = Arc::new(FakeBackend::default());
    backend.add("s1", "ssh", Some("posix"));
    backend.add("s2", "ssh", Some("posix"));
    let host = host_with(backend.clone());
    host.set_permission_mode("auto");
    named_scope(&host, "chat", &[("s1", "web", "web.internal"), ("s2", "Database", "db.internal")]);
    let exec = |target: &'static str| {
        let host = host.clone();
        async move { host.dispatch("netcatty/exec", p(json!({ "sessionId": target, "command": "uptime", "chatSessionId": "chat" })), Default::default()).await.unwrap() }
    };
    for target in ["database", "db.internal", "root@db.internal", " Database "] {
        let r = exec(target).await;
        assert_eq!(r["ok"], true, "{target}: {r}");
    }
    assert!(wrote_command(&backend, "s2"));
    assert!(!wrote_command(&backend, "s1"), "a name must never reach another session");
    // An id still wins, and SFTP resolves the same way.
    assert_eq!(exec("s1").await["ok"], true);
    let r = host.dispatch("netcatty/sftp/home", p(json!({ "sessionId": "web", "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert_eq!(r["homeDir"], "/root");
}

#[tokio::test]
async fn an_ambiguous_or_unknown_session_name_is_rejected_with_the_candidates() {
    let backend = Arc::new(FakeBackend::default());
    backend.add("s1", "ssh", Some("posix"));
    backend.add("s2", "ssh", Some("posix"));
    backend.add("s3", "ssh", Some("posix"));
    let host = host_with(backend.clone());
    host.set_permission_mode("auto");
    // s3 shares the label but is outside this chat's scope.
    named_scope(&host, "chat", &[("s1", "web", "a.internal"), ("s2", "web", "b.internal")]);
    named_scope(&host, "other", &[("s3", "web", "c.internal")]);
    let r = host.dispatch("netcatty/exec", p(json!({ "sessionId": "web", "command": "uptime", "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert_eq!(r["ok"], false);
    assert_eq!(r["error"], "\"web\" matches 2 sessions in the current scope. Pass the sessionId of the one you mean.");
    let ids: Vec<&str> = r["sessions"].as_array().unwrap().iter().map(|s| s["sessionId"].as_str().unwrap()).collect();
    assert_eq!(ids, ["s1", "s2"]);
    assert_eq!(r["sessions"][0]["hostname"], "a.internal");
    for id in ["s1", "s2", "s3"] {
        assert!(!wrote_command(&backend, id), "{id}");
    }
    // The hostname is unique, so it resolves where the label could not.
    let r = host.dispatch("netcatty/exec", p(json!({ "sessionId": "b.internal", "command": "uptime", "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert_eq!(r["ok"], true, "{r}");
    assert!(wrote_command(&backend, "s2"));
    // A name from another scope is unknown here, and says what is available.
    let r = host.dispatch("netcatty/exec", p(json!({ "sessionId": "c.internal", "command": "uptime", "chatSessionId": "chat" })), Default::default()).await.unwrap();
    assert_eq!(r["error"], "Session \"c.internal\" is not in the current scope.");
    assert_eq!(r["sessions"].as_array().unwrap().len(), 2);
    assert!(!wrote_command(&backend, "s3"));
}

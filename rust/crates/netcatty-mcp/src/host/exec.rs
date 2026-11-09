//! Command execution on live sessions (Electron `mcpServerBridge/
//! execHandlers.cjs` and `aiBridge/cattyExecHandlers.cjs`).

use super::backend::{ChannelError, TerminalSession};
use super::jobs::{create_background_job_id, BackgroundJob, DEFAULT_BACKGROUND_JOB_POLL_INTERVAL_MS, DEFAULT_BACKGROUND_JOB_TIMEOUT_MS, MAX_BACKGROUND_JOB_OUTPUT_CHARS};
use super::McpHost;
use netcatty_capabilities::services::{run_guard, ExecGuard};
use netcatty_ptyexec::cancel::ActiveExecs;
use netcatty_ptyexec::job::{start_pty_job, JobCallbacks, JobOptions, JobResult};
use netcatty_ptyexec::raw::{exec_via_raw_pty, RawCancel};
use netcatty_ptyexec::safety::{check_blocklist_for_shell, resolve_session_blocklist_shell_kind};
use netcatty_ptyexec::shell_kind::{ensure_session_shell_kind, remote_disallows_chunked_channel_write, remote_software_requires_single_channel, DEFAULT_PROBE_TIMEOUT_MS};
use netcatty_ptyexec::shell_utils::format_synthetic_echo;
use serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Which caller runs the command.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExecFlavor {
    /// MCP / CLI `terminal_execute`: hard wall-clock timeout.
    Mcp,
    /// Catty sidebar `aiExec`: inactivity timeout only, markers stripped.
    Catty,
}

pub const UNSUPPORTED_LOCAL_SHELL: &str = "AI execution is not supported for this local shell executable. Configure the local terminal to use bash/zsh/sh, fish, PowerShell/pwsh, or cmd.exe.";

fn cancelled_result() -> Value {
    json!({ "ok": false, "cancelled": true, "stdout": "", "stderr": "", "exitCode": 130, "error": "Cancelled" })
}

fn to_value(r: JobResult) -> Value {
    serde_json::to_value(r).unwrap_or_else(|_| json!({ "ok": false, "error": "serialize failed" }))
}

fn single_channel(session: &dyn TerminalSession) -> bool {
    session.single_channel() || remote_software_requires_single_channel(&session.remote_ssh_version())
}

impl McpHost {
    fn is_network_device(&self, session: &dyn TerminalSession, chat: Option<&str>) -> bool {
        let meta = self.session_meta(session.session_id(), chat).unwrap_or_default();
        let protocol = if session.protocol().is_empty() { meta.protocol.as_str() } else { session.protocol() };
        let ssh_or_serial = protocol == "ssh" || protocol == "serial";
        (meta.device_type == "network" && ssh_or_serial) || protocol == "serial"
    }

    /// Probe the login shell once, cancellable via the chat's cancel.
    async fn ensure_shell_kind_for_exec(&self, session: &Arc<dyn TerminalSession>, chat: Option<&str>) -> Result<(), Value> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let c = cancelled.clone();
        let _guard = self.active_execs.register(
            ActiveExecs::pending_key("SK"),
            chat,
            Arc::new(move || c.store(true, Ordering::SeqCst)),
        );
        let probe = if single_channel(&**session) { None } else { session.exec_probe() };
        ensure_session_shell_kind(
            &session.shell_kind(),
            probe.as_deref(),
            &session.remote_ssh_version(),
            session.protocol() == "local",
            DEFAULT_PROBE_TIMEOUT_MS,
        )
        .await;
        if cancelled.load(Ordering::SeqCst) {
            return Err(cancelled_result());
        }
        Ok(())
    }

    fn blocklist_shell_kind(&self, session: &dyn TerminalSession) -> String {
        let kind = session.shell_kind().snapshot();
        let prompt = session.prompt().fresh_idle_prompt();
        resolve_session_blocklist_shell_kind(
            kind.shell_kind.as_deref().unwrap_or(""),
            kind.login_shell_kind.as_deref().unwrap_or(""),
            &prompt,
        )
    }

    fn job_options(&self, session: &Arc<dyn TerminalSession>, chat: Option<&str>, flavor: ExecFlavor, guard: Option<ExecGuard>, timeout_ms: u64) -> JobOptions {
        let kind = session.shell_kind().snapshot();
        let prompt = session.prompt();
        let tracked = prompt.tracked;
        let s1 = session.clone();
        let s2 = session.clone();
        let s3 = session.clone();
        let s4 = session.clone();
        let s5 = session.clone();
        JobOptions {
            timeout_ms,
            shell_kind: kind.shell_kind.clone().unwrap_or_default(),
            login_shell_hint: kind.login_shell_kind.clone().unwrap_or_default(),
            probe_live_shell: true,
            bastion_keystrokes: remote_disallows_chunked_channel_write(&session.remote_ssh_version()),
            skip_pending_input_clear: session.single_channel(),
            chat_session_id: chat.map(str::to_string),
            expected_prompt: prompt.fresh_idle_prompt(),
            typed_input: true,
            enforce_wall_timeout: flavor == ExecFlavor::Mcp,
            strip_markers: flavor == ExecFlavor::Catty,
            prompt_recovery_pending: Some(session.prompt_recovery_pending()),
            callbacks: JobCallbacks {
                on_interrupt: Some(Arc::new(move || s1.clear_flow())),
                on_probe_aborted: Some(Arc::new(move |m: &str| s2.emit_display(&format!("{m}_R\n"), false))),
                on_echo_suppression_prime: Some(Arc::new(move |m: &str| s3.emit_display(&format!("{m}_I\n"), false))),
                echo_command: Some(Arc::new(move |cmd: &str| s4.emit_display(&format_synthetic_echo(cmd), true))),
                get_ready_prompt: tracked.then(|| Arc::new(move || s5.prompt().ready_prompt()) as Arc<dyn Fn() -> String + Send + Sync>),
                before_input: guard.map(|g| Arc::new(move || g()) as Arc<dyn Fn() -> Result<(), String> + Send + Sync>),
            },
            ..Default::default()
        }
    }

    /// Execute `command` on a live session (both flavors). The caller holds
    /// the session execution lock.
    pub(crate) async fn run_on_session(
        &self,
        session: Arc<dyn TerminalSession>,
        command: &str,
        chat: Option<&str>,
        flavor: ExecFlavor,
        guard: Option<ExecGuard>,
    ) -> Value {
        if session.protocol() == "local" && session.shell_kind().shell_kind() == "unknown" {
            return json!({ "ok": false, "error": UNSUPPORTED_LOCAL_SHELL });
        }
        if let Err(e) = run_guard(guard.as_ref()) {
            return json!({ "ok": false, "error": e });
        }
        let timeout_ms = self.command_timeout_ms();
        let network_device = self.is_network_device(&*session, chat);
        let writer = session.writer();

        if network_device {
            let Some(writer) = writer else {
                return json!({ "ok": false, "error": "Network device session has no writable PTY stream for command execution" });
            };
            if session.file_transfer_active() {
                return json!({ "ok": false, "error": "Serial file transfer is already in progress" });
            }
            let rx = session.subscribe();
            let cancel = RawCancel::default();
            let c = cancel.clone();
            let _g = self.active_execs.register(format!("__NCRAW_{}", super::jobs::base36(super::now_ms())), chat, Arc::new(move || c.cancel()));
            return to_value(exec_via_raw_pty(writer, rx, command, timeout_ms, 3000, cancel).await);
        }

        if let Some(writer) = writer {
            if let Err(cancelled) = self.ensure_shell_kind_for_exec(&session, chat).await {
                return cancelled;
            }
            if let Err(e) = run_guard(guard.as_ref()) {
                return json!({ "ok": false, "error": e });
            }
            let safety = check_blocklist_for_shell(command, &self.blocklist_shell_kind(&*session), &self.command_blocklist());
            if safety.blocked {
                return json!({ "ok": false, "error": safety.error_message() });
            }
            let rx = session.subscribe();
            let opts = self.job_options(&session, chat, flavor, guard, timeout_ms);
            return match start_pty_job(writer, rx, command, opts) {
                Ok(handle) => {
                    let h = handle.clone();
                    let _g = self.active_execs.register(handle.marker.clone(), chat, Arc::new(move || h.cancel()));
                    to_value(handle.wait().await)
                }
                Err(err) => json!({ "ok": false, "stdout": "", "stderr": "", "exitCode": -1, "error": err.message, "code": err.code }),
            };
        }

        if !single_channel(&*session) {
            if let Err(cancelled) = self.ensure_shell_kind_for_exec(&session, chat).await {
                return cancelled;
            }
            if let Err(e) = run_guard(guard.as_ref()) {
                return json!({ "ok": false, "error": e });
            }
            let safety = check_blocklist_for_shell(command, &self.blocklist_shell_kind(&*session), &self.command_blocklist());
            if safety.blocked {
                return json!({ "ok": false, "error": safety.error_message() });
            }
            if let Some(result) = self.exec_via_channel(&session, command, chat, timeout_ms).await {
                return result;
            }
        }
        let msg = match flavor {
            ExecFlavor::Mcp => "Session does not support command execution",
            ExecFlavor::Catty => "No terminal stream or SSH client available for this session",
        };
        json!({ "ok": false, "error": msg })
    }

    /// SSH exec-channel fallback (`execViaChannel`), cancellable.
    async fn exec_via_channel(&self, session: &Arc<dyn TerminalSession>, command: &str, chat: Option<&str>, timeout_ms: u64) -> Option<Value> {
        let token = tokio_util::sync::CancellationToken::new();
        let t = token.clone();
        let _g = self.active_execs.register(ActiveExecs::pending_key("CH"), chat, Arc::new(move || t.cancel()));
        let timeout_sec = (timeout_ms as f64 / 1000.0).round() as u64;
        tokio::select! {
            _ = token.cancelled() => Some(json!({ "ok": false, "stdout": "", "stderr": "", "exitCode": -1, "error": "Cancelled" })),
            r = session.channel_exec(command, timeout_ms, 1024 * 1024) => {
                let r = r?;
                Some(match r {
                    Ok(out) => match out.exit_code {
                        Some(code) => json!({ "ok": code == 0, "stdout": out.stdout, "stderr": out.stderr, "exitCode": code }),
                        None => json!({ "ok": false, "stdout": out.stdout, "stderr": out.stderr, "exitCode": -1, "error": "Command terminated unexpectedly (connection lost or signal)" }),
                    },
                    Err(ChannelError::OpenTimeout) => json!({ "ok": false, "stdout": "", "stderr": "", "exitCode": -1, "error": format!("Command timed out ({timeout_sec}s) while opening SSH exec channel") }),
                    Err(ChannelError::RunTimeout) => json!({ "ok": false, "stdout": "", "stderr": "", "exitCode": -1, "error": format!("Command timed out ({timeout_sec}s)") }),
                    Err(ChannelError::OutputLimit(n)) => json!({ "ok": false, "stdout": "", "stderr": "", "exitCode": -1, "error": format!("Command output exceeded the {n} byte limit") }),
                    Err(ChannelError::Failed(e)) => json!({ "ok": false, "error": e }),
                })
            }
        }
    }

    /// MCP `netcatty/exec` on a live session (`handleExec`).
    pub async fn handle_exec(&self, params: &Map<String, Value>, guard: Option<ExecGuard>) -> Result<Value, String> {
        let session_id = params.get("sessionId").and_then(Value::as_str).unwrap_or("");
        let command = params.get("command").and_then(Value::as_str).unwrap_or("");
        if session_id.is_empty() || params.get("command").is_none_or(Value::is_null) {
            return Err("sessionId and command are required".into());
        }
        if command.trim().is_empty() {
            return Ok(json!({ "ok": false, "error": "Invalid command", "exitCode": 1 }));
        }
        let Some(session) = self.backend.session(session_id) else {
            return Ok(json!({ "ok": false, "error": "Session not found" }));
        };
        let chat = params.get("chatSessionId").and_then(Value::as_str);
        let token = match self.reserve_session_execution(session_id, "exec") {
            Ok(t) => t,
            Err(busy) => return Ok(busy),
        };
        let lock = match self.begin_chat_execution(chat, session_id, command) {
            Ok(l) => l,
            Err((active_session, active_command)) => {
                self.release_session_execution(session_id, &token);
                return Ok(json!({
                    "ok": false,
                    "code": "COMMAND_ALREADY_RUNNING",
                    "error": format!("Another Netcatty command is already running for chat session \"{}\". Wait for it to finish before starting a new exec.", chat.unwrap_or("")),
                    "activeCommand": active_command,
                    "activeSessionId": active_session,
                }));
            }
        };
        let result = self.run_on_session(session, command, chat, ExecFlavor::Mcp, guard).await;
        self.release_session_execution(session_id, &token);
        drop(lock);
        Ok(result)
    }

    /// Catty sidebar `aiExec` (`netcatty:ai:exec`).
    pub async fn catty_exec(&self, session_id: &str, command: &str, chat: Option<&str>) -> Value {
        if self.permission_mode() == "observer" {
            return json!({ "ok": false, "error": "Execution blocked: permission mode is 'observer'" });
        }
        let Some(session) = self.backend.session(session_id) else {
            return json!({ "ok": false, "error": "Session not found" });
        };
        if let Some(busy) = self.session_busy_error(session_id) {
            return busy;
        }
        let token = match self.reserve_session_execution(session_id, "exec") {
            Ok(t) => t,
            Err(busy) => return busy,
        };
        let result = self.run_on_session(session, command, chat, ExecFlavor::Catty, None).await;
        self.release_session_execution(session_id, &token);
        result
    }

    /// `aiCattyCancelExec`.
    pub async fn catty_cancel(&self, chat: &str) -> Value {
        self.cancel_pty_execs_for_session(chat);
        self.cancel_sftp_ops_for_chat(chat).await;
        json!({ "ok": true })
    }

    /// MCP `netcatty/jobStart` (`handleJobStart`).
    pub async fn handle_job_start(&self, params: &Map<String, Value>, guard: Option<ExecGuard>) -> Result<Value, String> {
        let session_id = params.get("sessionId").and_then(Value::as_str).unwrap_or("").to_string();
        let command = params.get("command").and_then(Value::as_str).unwrap_or("").to_string();
        if session_id.is_empty() || params.get("command").is_none_or(Value::is_null) {
            return Err("sessionId and command are required".into());
        }
        if command.trim().is_empty() {
            return Ok(json!({ "ok": false, "error": "Invalid command", "exitCode": 1 }));
        }
        let Some(session) = self.backend.session(&session_id) else {
            return Ok(json!({ "ok": false, "error": "Session not found" }));
        };
        let chat = params.get("chatSessionId").and_then(Value::as_str).map(str::to_string);
        if session.protocol() == "local" && session.shell_kind().shell_kind() == "unknown" {
            return Ok(json!({ "ok": false, "error": UNSUPPORTED_LOCAL_SHELL }));
        }
        if self.is_network_device(&*session, chat.as_deref()) || session.protocol() == "serial" {
            return Ok(json!({ "ok": false, "error": "Background execution currently supports shell-backed PTY sessions only." }));
        }
        let Some(writer) = session.writer() else {
            return Ok(json!({ "ok": false, "error": "Background execution requires a writable PTY-backed terminal session." }));
        };
        let token = match self.reserve_session_execution(&session_id, "job") {
            Ok(t) => t,
            Err(busy) => return Ok(busy),
        };
        let job_id = create_background_job_id();
        let timeout_ms = self.command_timeout_ms().max(DEFAULT_BACKGROUND_JOB_TIMEOUT_MS);
        let started_at = super::now_ms();
        let probe_cancel = Arc::new(AtomicBool::new(false));
        self.jobs.jobs.lock().insert(
            job_id.clone(),
            BackgroundJob {
                id: job_id.clone(),
                session_id: session_id.clone(),
                chat_session_id: chat.clone(),
                command: command.clone(),
                status: "running".into(),
                started_at,
                updated_at: started_at,
                exit_code: None,
                error: None,
                code: None,
                stdout: String::new(),
                output_base_offset: 0,
                total_output_chars: 0,
                output_truncated: false,
                handle: None,
                probe_cancel: probe_cancel.clone(),
            },
        );
        let probe = if single_channel(&*session) { None } else { session.exec_probe() };
        ensure_session_shell_kind(&session.shell_kind(), probe.as_deref(), &session.remote_ssh_version(), session.protocol() == "local", DEFAULT_PROBE_TIMEOUT_MS).await;
        let fail = |host: &McpHost, status: &str, error: String, remove: bool| {
            let mut jobs = host.jobs.jobs.lock();
            if remove {
                jobs.remove(&job_id);
            } else if let Some(j) = jobs.get_mut(&job_id) {
                j.status = status.into();
                j.error = Some(error.clone());
                j.updated_at = super::now_ms();
            }
            drop(jobs);
            host.release_session_execution(&session_id, &token);
        };
        if probe_cancel.load(Ordering::SeqCst) {
            fail(self, "cancelled", "Cancelled".into(), false);
            return Ok(json!({ "ok": false, "error": "Cancelled", "jobId": job_id, "sessionId": session_id, "status": "cancelled" }));
        }
        let safety = check_blocklist_for_shell(&command, &self.blocklist_shell_kind(&*session), &self.command_blocklist());
        if safety.blocked {
            fail(self, "failed", safety.error_message(), true);
            return Ok(json!({ "ok": false, "error": safety.error_message() }));
        }
        if let Err(e) = run_guard(guard.as_ref()) {
            fail(self, "failed", e.clone(), false);
            return Ok(json!({ "ok": false, "error": e }));
        }
        let mut opts = self.job_options(&session, chat.as_deref(), ExecFlavor::Mcp, guard, timeout_ms);
        opts.enforce_wall_timeout = false;
        opts.max_buffered_chars = MAX_BACKGROUND_JOB_OUTPUT_CHARS;
        opts.normalize_final_output = false;
        let rx = session.subscribe();
        let handle = match start_pty_job(writer, rx, &command, opts) {
            Ok(h) => h,
            Err(err) => {
                fail(self, "failed", err.message.clone(), false);
                return Ok(json!({ "ok": false, "error": err.message }));
            }
        };
        if let Some(j) = self.jobs.jobs.lock().get_mut(&job_id) {
            j.handle = Some(handle.clone());
        }
        let weak = self.me.clone();
        let (jid, sid, tok) = (job_id.clone(), session_id.clone(), token.clone());
        tokio::spawn(async move {
            let result = handle.wait().await;
            let Some(host) = weak.upgrade() else {
                return;
            };
            if let Some(job) = host.jobs.jobs.lock().get_mut(&jid) {
                job.updated_at = super::now_ms();
                job.exit_code = result.exit_code;
                job.code = result.code.clone();
                job.stdout = result.stdout.clone();
                job.output_base_offset = result.output_base_offset;
                job.total_output_chars = result.total_output_chars.max(result.output_base_offset + result.stdout.chars().count());
                job.output_truncated = result.output_truncated;
                job.handle = None;
                let err = result.error.clone();
                match err.as_deref() {
                    Some(e) if e == "Cancelled" || e.contains("forced") => {
                        job.status = "cancelled".into();
                        job.error = err;
                    }
                    Some(_) => {
                        job.status = "failed".into();
                        job.error = err;
                    }
                    None => match result.exit_code {
                        Some(code) if code != 0 => {
                            job.status = "failed".into();
                            job.error = Some(format!("Command exited with code {code}"));
                        }
                        _ => job.status = "completed".into(),
                    },
                }
            }
            host.release_session_execution(&sid, &tok);
        });
        Ok(json!({
            "ok": true,
            "jobId": job_id,
            "sessionId": session_id,
            "command": command,
            "status": "running",
            "startedAt": started_at,
            "outputMode": "foreground-mirrored",
            "recommendedPollIntervalMs": DEFAULT_BACKGROUND_JOB_POLL_INTERVAL_MS,
        }))
    }

    fn scoped_ids_param(params: &Map<String, Value>) -> Option<Vec<String>> {
        params.get("scopedSessionIds").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
    }

    /// MCP `netcatty/jobPoll`.
    pub fn handle_job_poll(&self, params: &Map<String, Value>) -> Result<Value, String> {
        let job_id = params.get("jobId").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("jobId is required")?;
        let chat = params.get("chatSessionId").and_then(Value::as_str);
        if self.scoped_job(job_id, chat).is_none() {
            return Ok(json!({ "ok": false, "error": "Background job not found" }));
        }
        let session_id = self.jobs.jobs.lock().get(job_id).map(|j| j.session_id.clone()).unwrap_or_default();
        let scoped = Self::scoped_ids_param(params);
        if let Some(err) = self.validate_session_scope(&session_id, chat, scoped.as_deref()) {
            return Ok(json!({ "ok": false, "error": err }));
        }
        let offset = params.get("offset").and_then(Value::as_f64).filter(|v| *v >= 0.0).unwrap_or(0.0) as u64;
        Ok(self.jobs.jobs.lock().get_mut(job_id).map(|j| j.serialize(offset)).unwrap_or_else(|| json!({ "ok": false, "error": "Background job not found" })))
    }

    /// MCP `netcatty/jobStop` (bypasses dynamic scope so a lock can always be released).
    pub fn handle_job_stop(&self, params: &Map<String, Value>) -> Result<Value, String> {
        let job_id = params.get("jobId").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("jobId is required")?;
        let chat = params.get("chatSessionId").and_then(Value::as_str);
        if self.scoped_job(job_id, chat).is_none() {
            return Ok(json!({ "ok": false, "error": "Background job not found" }));
        }
        let mut jobs = self.jobs.jobs.lock();
        let job = jobs.get_mut(job_id).ok_or("Background job not found")?;
        if let Some(scoped) = Self::scoped_ids_param(params) {
            if !scoped.contains(&job.session_id) {
                return Ok(json!({ "ok": false, "error": format!("Session \"{}\" is not in the current scope.", job.session_id) }));
            }
        }
        if job.status == "running" {
            job.probe_cancel.store(true, Ordering::SeqCst);
            if let Some(h) = &job.handle {
                h.cancel();
            }
            job.status = "stopping".into();
            job.error = Some("Cancellation requested".into());
            job.updated_at = super::now_ms();
        }
        Ok(job.serialize(0))
    }
}

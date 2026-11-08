//! Marker-wrapped command execution inside a live PTY (Electron
//! `startPtyJob` / `execViaPty` in `ptyExec.cjs`).
//!
//! The job is a single task that owns the session output tap and a writer:
//! it waits for shell readiness, types the (optional) live shell probe and
//! the wrapper, finds the `_S` / `_E:<code>` markers in the output, captures
//! the command's output (bounded), handles cancellation (Ctrl+C as terminal
//! data, retries, forced finish), inactivity / wall / startup deadlines and
//! the PowerShell-after-cmd "wait for the returned prompt" rule. Every
//! timer is a deadline evaluated by one `select!` loop, so there is nothing
//! to clear on finish.

use crate::helpers::{
    append_bounded_output, build_pending_input_clear_prefix, build_wrapped_command, consume_visible_text,
    find_end_marker, has_expected_prompt_suffix, new_marker, normalize_pty_output,
    resolve_effective_shell_kind, strip_job_marker_lines, tail_chars, trailing_prefix_length,
    NormalizeOptions,
};
use crate::live_probe::{build_live_shell_probe, build_live_shell_probe_cleanup, is_zsh_shell_name, parse_live_shell_probe};
use crate::shell_utils::{extract_trailing_idle_prompt, strip_ansi};
use parking_lot::Mutex;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::Instant;

pub const DEFAULT_FOREGROUND_PTY_CAPTURE_CHARS: usize = 1024 * 1024;
const END_MARKER_PROMPT_WAIT_MS: u64 = 30_000;
const CANCEL_RETRY_MS: u64 = 5000;
const CANCEL_WALL_TIMEOUT_MS: u64 = 30_000;
const BG_STARTUP_TIMEOUT_MS: u64 = 30_000;
const INPUT_PACING_MS: u64 = 30;

/// Decoded session output delivered to a job.
pub type OutputRx = mpsc::UnboundedReceiver<String>;

/// Writes terminal input for a job (the session's PTY / shell channel).
#[async_trait::async_trait]
pub trait PtyInput: Send + Sync {
    async fn write(&self, data: &str) -> Result<(), String>;
}

type Hook = Arc<dyn Fn() + Send + Sync>;
type MarkerHook = Arc<dyn Fn(&str) + Send + Sync>;

/// Renderer / session callbacks of a job.
#[derive(Clone, Default)]
pub struct JobCallbacks {
    /// Recover session flow control after Ctrl+C was sent.
    pub on_interrupt: Option<Hook>,
    /// Display reset (`<marker>_R`) when the command never started.
    pub on_probe_aborted: Option<MarkerHook>,
    /// Display suppression prime (`<marker>_I`) before the first typed byte.
    pub on_echo_suppression_prime: Option<MarkerHook>,
    /// Synthetic echo of the user's command.
    pub echo_command: Option<MarkerHook>,
    /// Current idle prompt; when set the job waits (bounded) until non-empty.
    pub get_ready_prompt: Option<Arc<dyn Fn() -> String + Send + Sync>>,
    /// Revalidates authorization right before the first PTY byte.
    pub before_input: Option<Arc<dyn Fn() -> Result<(), String> + Send + Sync>>,
}

/// Job configuration (defaults match Electron's `startPtyJob`).
#[derive(Clone)]
pub struct JobOptions {
    pub timeout_ms: u64,
    pub shell_kind: String,
    pub login_shell_hint: String,
    pub probe_live_shell: bool,
    pub bastion_keystrokes: bool,
    pub skip_pending_input_clear: bool,
    pub chat_session_id: Option<String>,
    pub expected_prompt: String,
    pub prompt_wait_timeout_ms: u64,
    pub typed_input: bool,
    /// `> 0` selects background-job mode (bounded visible buffer).
    pub max_buffered_chars: usize,
    pub normalize_final_output: bool,
    pub enforce_wall_timeout: bool,
    pub strip_markers: bool,
    /// Per-session "previous command never returned its prompt" latch.
    pub prompt_recovery_pending: Option<Arc<AtomicBool>>,
    pub callbacks: JobCallbacks,
}

impl Default for JobOptions {
    fn default() -> Self {
        Self {
            timeout_ms: 60_000,
            shell_kind: String::new(),
            login_shell_hint: String::new(),
            probe_live_shell: false,
            bastion_keystrokes: false,
            skip_pending_input_clear: false,
            chat_session_id: None,
            expected_prompt: String::new(),
            prompt_wait_timeout_ms: 30_000,
            typed_input: false,
            max_buffered_chars: 0,
            normalize_final_output: true,
            enforce_wall_timeout: false,
            strip_markers: false,
            prompt_recovery_pending: None,
            callbacks: JobCallbacks::default(),
        }
    }
}

/// Result of a PTY / channel / raw execution (`{ ok, stdout, ... }`).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JobResult {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancelled: Option<bool>,
    pub output_base_offset: usize,
    pub total_output_chars: usize,
    pub output_truncated: bool,
}

impl JobResult {
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(-1),
            error: Some(error.into()),
            code: None,
            cancelled: None,
            output_base_offset: 0,
            total_output_chars: 0,
            output_truncated: false,
        }
    }
}

/// Live view of a running job (`getSnapshot`).
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JobSnapshot {
    pub stdout: String,
    pub output_base_offset: usize,
    pub total_output_chars: usize,
    pub output_truncated: bool,
    /// `running` | `stopping` | `finished` | `cancelled`.
    pub status: String,
    pub found_start: bool,
}

/// Error raised before the job starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobStartError {
    pub code: &'static str,
    pub message: String,
}

/// Handle of a running job.
#[derive(Clone)]
pub struct PtyJobHandle {
    pub marker: String,
    cancel: Arc<Notify>,
    cancel_flag: Arc<AtomicBool>,
    snapshot: Arc<Mutex<JobSnapshot>>,
    result: watch::Receiver<Option<JobResult>>,
}

impl PtyJobHandle {
    pub fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::SeqCst);
        self.cancel.notify_one();
    }

    pub fn snapshot(&self) -> JobSnapshot {
        self.snapshot.lock().clone()
    }

    pub fn is_finished(&self) -> bool {
        self.result.borrow().is_some()
    }

    pub fn result(&self) -> Option<JobResult> {
        self.result.borrow().clone()
    }

    /// Wait for the final result.
    pub async fn wait(&self) -> JobResult {
        let mut rx = self.result.clone();
        loop {
            if let Some(result) = rx.borrow().clone() {
                return result;
            }
            if rx.changed().await.is_err() {
                return JobResult::failure("Job task ended without a result");
            }
        }
    }
}

struct PendingEnd {
    stdout: String,
    exit_code: i32,
}

struct InputState {
    chars: Vec<char>,
    offset: usize,
    batch_size: usize,
}

struct Job {
    marker: String,
    command: String,
    opts: JobOptions,
    writer: Arc<dyn PtyInput>,
    rx: OutputRx,
    cancel: Arc<Notify>,
    cancel_flag: Arc<AtomicBool>,
    snapshot: Arc<Mutex<JobSnapshot>>,
    result_tx: watch::Sender<Option<JobResult>>,

    expected_prompt: String,
    waiting_for_prompt: bool,
    readiness_failure_code: Option<&'static str>,
    waiting_for_input_guard: bool,
    resolved_shell_kind: String,
    wait_for_returned_prompt: bool,
    capture_limit_chars: usize,
    uses_live_shell_probe: bool,
    probing_shell: bool,
    delivering_input: bool,
    probe_output: String,

    output: String,
    found_start: bool,
    pre_start_output: String,
    visible_output: String,
    visible_output_offset: usize,
    visible_high_watermark: usize,
    visible_carry: String,
    visible_marker_carry: String,
    pending_start: String,
    pending_end: Option<PendingEnd>,
    cancel_requested: bool,
    finished: bool,
    final_result: Option<JobResult>,

    input: Option<InputState>,
    readiness_deadline: Option<Instant>,

    // Deadlines.
    t_output: Option<Instant>,
    t_wall: Option<Instant>,
    t_startup: Option<Instant>,
    t_prompt_fallback: Option<Instant>,
    t_end_marker_wait: Option<Instant>,
    t_cancel_retry: Option<Instant>,
    t_cancel_prestart: Option<Instant>,
    t_cancel_followup: Option<Instant>,
    t_cancel_wall: Option<Instant>,
    t_readiness: Option<Instant>,
    t_input_next: Option<Instant>,
}

/// Start a marker-wrapped command in the PTY behind `writer`, reading its
/// output from `rx`. Returns the handle; the job runs in a background task.
pub fn start_pty_job(
    writer: Arc<dyn PtyInput>,
    rx: OutputRx,
    command: &str,
    opts: JobOptions,
) -> Result<PtyJobHandle, JobStartError> {
    let marker = new_marker();
    let expected_prompt = opts.expected_prompt.clone();
    let resolved_shell_kind =
        resolve_effective_shell_kind(&opts.shell_kind, &expected_prompt, &opts.login_shell_hint);
    if let Some(flag) = &opts.prompt_recovery_pending {
        if flag.load(Ordering::SeqCst) {
            if !extract_trailing_idle_prompt(&expected_prompt).is_empty() {
                flag.store(false, Ordering::SeqCst);
            } else {
                return Err(JobStartError {
                    code: "SHELL_PROMPT_PENDING",
                    message: "Terminal is still waiting for the shell prompt after the previous command".into(),
                });
            }
        }
    }
    let wait_for_returned_prompt =
        opts.login_shell_hint == "cmd" && resolved_shell_kind == "powershell" && !expected_prompt.is_empty();
    let capture_limit_chars = if opts.max_buffered_chars > 0 {
        opts.max_buffered_chars
    } else {
        DEFAULT_FOREGROUND_PTY_CAPTURE_CHARS
    };
    let uses_live_shell_probe = opts.probe_live_shell && matches!(resolved_shell_kind.as_str(), "posix" | "fish");
    let cancel = Arc::new(Notify::new());
    let cancel_flag = Arc::new(AtomicBool::new(false));
    let snapshot = Arc::new(Mutex::new(JobSnapshot {
        status: "running".into(),
        ..Default::default()
    }));
    let (result_tx, result_rx) = watch::channel(None);
    let handle = PtyJobHandle {
        marker: marker.clone(),
        cancel: cancel.clone(),
        cancel_flag: cancel_flag.clone(),
        snapshot: snapshot.clone(),
        result: result_rx,
    };
    let waiting_for_prompt = opts.callbacks.get_ready_prompt.is_some();
    let waiting_for_input_guard = opts.callbacks.before_input.is_some();
    let job = Job {
        marker,
        command: command.to_string(),
        writer,
        rx,
        cancel,
        cancel_flag,
        snapshot,
        result_tx,
        expected_prompt,
        waiting_for_prompt,
        readiness_failure_code: None,
        waiting_for_input_guard,
        resolved_shell_kind,
        wait_for_returned_prompt,
        capture_limit_chars,
        uses_live_shell_probe,
        probing_shell: uses_live_shell_probe,
        delivering_input: false,
        probe_output: String::new(),
        output: String::new(),
        found_start: false,
        pre_start_output: String::new(),
        visible_output: String::new(),
        visible_output_offset: 0,
        visible_high_watermark: 0,
        visible_carry: String::new(),
        visible_marker_carry: String::new(),
        pending_start: String::new(),
        pending_end: None,
        cancel_requested: false,
        finished: false,
        final_result: None,
        input: None,
        readiness_deadline: None,
        t_output: None,
        t_wall: None,
        t_startup: None,
        t_prompt_fallback: None,
        t_end_marker_wait: None,
        t_cancel_retry: None,
        t_cancel_prestart: None,
        t_cancel_followup: None,
        t_cancel_wall: None,
        t_readiness: None,
        t_input_next: None,
        opts,
    };
    tokio::spawn(job.run());
    Ok(handle)
}

/// Run a command and wait for its result (`execViaPty`).
pub async fn exec_via_pty(
    writer: Arc<dyn PtyInput>,
    rx: OutputRx,
    command: &str,
    opts: JobOptions,
) -> JobResult {
    match start_pty_job(writer, rx, command, opts) {
        Ok(handle) => handle.wait().await,
        Err(err) => JobResult {
            code: Some(err.code.to_string()),
            ..JobResult::failure(err.message)
        },
    }
}

fn after(ms: u64) -> Instant {
    Instant::now() + Duration::from_millis(ms)
}

impl Job {
    fn ms(&self) -> u64 {
        self.opts.timeout_ms.max(1)
    }

    fn is_background(&self) -> bool {
        self.opts.max_buffered_chars > 0
    }

    fn update_snapshot(&self) {
        let mut snap = self.snapshot.lock();
        snap.stdout = if self.found_start { self.visible_output.clone() } else { String::new() };
        snap.output_base_offset = if self.found_start { self.visible_output_offset } else { 0 };
        snap.total_output_chars = if self.found_start {
            self.visible_output_offset + self.visible_output.chars().count()
        } else {
            0
        };
        snap.output_truncated = self.found_start && self.visible_output_offset > 0;
        snap.status = if self.finished {
            "finished".into()
        } else if self.cancel_requested {
            "stopping".into()
        } else {
            "running".into()
        };
        snap.found_start = self.found_start;
    }

    // ── timers ───────────────────────────────────────────────────────

    fn arm_output_timeout(&mut self) {
        if self.waiting_for_prompt || self.waiting_for_input_guard {
            return;
        }
        self.t_output = Some(after(self.ms()));
    }

    fn arm_wall_timeout(&mut self) {
        if !self.opts.enforce_wall_timeout || self.is_background() {
            return;
        }
        self.t_wall = Some(after(self.ms()));
    }

    fn arm_startup_timeout(&mut self) {
        let startup = if self.is_background() { BG_STARTUP_TIMEOUT_MS } else { self.ms() };
        self.t_startup = Some(after(startup));
    }

    fn schedule_prompt_fallback(&mut self) {
        self.t_prompt_fallback = None;
        if !has_expected_prompt_suffix(&self.output, &self.expected_prompt) {
            return;
        }
        let delay = if self.is_background() { 30_000 } else { 250 };
        self.t_prompt_fallback = Some(after(delay));
    }

    fn clear_cancel_oneshots(&mut self) {
        self.t_cancel_prestart = None;
        self.t_cancel_followup = None;
        self.t_cancel_wall = None;
    }

    fn earliest_deadline(&self) -> Option<Instant> {
        [
            self.t_output,
            self.t_wall,
            self.t_startup,
            self.t_prompt_fallback,
            self.t_end_marker_wait,
            self.t_cancel_retry,
            self.t_cancel_prestart,
            self.t_cancel_followup,
            self.t_cancel_wall,
            self.t_readiness,
            self.t_input_next,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    // ── interrupt / cancel ───────────────────────────────────────────

    async fn send_interrupt(&mut self) {
        let _ = self.writer.write("\x03").await;
        if let Some(cb) = self.opts.callbacks.on_interrupt.clone() {
            cb();
        }
    }

    async fn request_cancel(&mut self) {
        if self.finished || self.cancel_requested {
            return;
        }
        if self.waiting_for_prompt || self.waiting_for_input_guard {
            self.cancel_requested = true;
            self.finish(String::new(), Some(130), Some("Cancelled".into()));
            return;
        }
        if self.pending_end.is_some() {
            // The command already completed; do not interrupt the restoring prompt.
            return;
        }
        self.cancel_requested = true;
        self.t_prompt_fallback = None;
        self.t_cancel_retry = None;
        self.t_startup = None;
        if !self.found_start && self.expected_prompt.is_empty() {
            self.t_cancel_prestart = Some(after(2000));
        }
        self.send_interrupt().await;
        self.t_cancel_retry = Some(after(CANCEL_RETRY_MS));
        self.arm_output_timeout();
        self.t_cancel_followup = Some(after(150));
        self.t_cancel_wall = Some(after(CANCEL_WALL_TIMEOUT_MS));
        self.update_snapshot();
    }

    // ── output bookkeeping ───────────────────────────────────────────

    fn append_to_visible(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        let mut bounded_input = text.to_string();
        let input_chars = bounded_input.chars().count();
        if input_chars > self.capture_limit_chars {
            let skipped = input_chars - self.capture_limit_chars;
            bounded_input = tail_chars(&bounded_input, self.capture_limit_chars).to_string();
            self.visible_carry.clear();
            self.visible_output_offset += skipped;
            self.visible_high_watermark += skipped;
        }
        let (visible_text, carry) = consume_visible_text(&self.visible_carry, &bounded_input);
        self.visible_carry = carry;
        if visible_text.is_empty() {
            return;
        }
        let mut clean_visible = visible_text;
        if self.is_background() {
            clean_visible = format!("{}{}", self.visible_marker_carry, clean_visible);
            self.visible_marker_carry.clear();
            if let Some((end_idx, _)) = find_end_marker(&clean_visible, &self.marker, true) {
                clean_visible.truncate(end_idx);
            } else {
                let partial = trailing_prefix_length(&clean_visible, &format!("{}_E:", self.marker));
                if partial > 0 {
                    let cut = clean_visible.len() - partial;
                    self.visible_marker_carry = clean_visible[cut..].to_string();
                    clean_visible.truncate(cut);
                }
            }
            clean_visible = strip_job_marker_lines(&clean_visible, &self.marker);
            if clean_visible.is_empty() {
                return;
            }
        }
        self.visible_high_watermark += clean_visible.chars().count();
        let dropped = append_bounded_output(&mut self.visible_output, &clean_visible, self.capture_limit_chars);
        self.visible_output_offset += dropped;
    }

    fn append_to_output(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        let limit = self.capture_limit_chars;
        append_bounded_output(&mut self.output, text, limit);
        if self.pending_end.is_none() {
            self.append_to_visible(text);
        }
    }

    fn finish_without_returned_prompt(&mut self) {
        if self.finished {
            return;
        }
        let Some(pending) = self.pending_end.take() else {
            return;
        };
        if let Some(flag) = &self.opts.prompt_recovery_pending {
            flag.store(true, Ordering::SeqCst);
        }
        self.finish(pending.stdout, Some(pending.exit_code), None);
    }

    fn check_end(&mut self) {
        if let Some(pending) = &self.pending_end {
            if !extract_trailing_idle_prompt(&self.output).is_empty() {
                let (stdout, code) = (pending.stdout.clone(), pending.exit_code);
                self.finish(stdout, Some(code), None);
            }
            return;
        }
        let Some((end_idx, exit_code)) = find_end_marker(&self.output, &self.marker, true) else {
            return;
        };
        let stdout = self.output[..end_idx].to_string();
        if self.is_background() {
            if let Some((visible_end, _)) = find_end_marker(&self.visible_output, &self.marker, true) {
                self.visible_output.truncate(visible_end);
                self.visible_marker_carry.clear();
                self.visible_carry.clear();
            }
        }
        self.pending_end = Some(PendingEnd { stdout: stdout.clone(), exit_code });
        self.t_output = None;
        self.t_startup = None;
        self.t_cancel_retry = None;
        self.clear_cancel_oneshots();
        if !self.wait_for_returned_prompt || !extract_trailing_idle_prompt(&self.output).is_empty() {
            self.finish(stdout, Some(exit_code), None);
            return;
        }
        if self.t_end_marker_wait.is_none() {
            self.t_end_marker_wait = Some(after(END_MARKER_PROMPT_WAIT_MS));
        }
    }

    fn finish(&mut self, stdout: String, exit_code: Option<i32>, error: Option<String>) {
        if self.finished {
            return;
        }
        self.finished = true;
        if !self.found_start {
            if let Some(cb) = self.opts.callbacks.on_probe_aborted.clone() {
                cb(&self.marker);
            }
        }
        // All deadlines are irrelevant now.
        self.t_output = None;
        self.t_wall = None;
        self.t_startup = None;
        self.t_prompt_fallback = None;
        self.t_end_marker_wait = None;
        self.t_cancel_retry = None;
        self.clear_cancel_oneshots();
        self.t_readiness = None;
        self.t_input_next = None;
        self.input = None;

        if !self.visible_marker_carry.is_empty() {
            let leftover = strip_job_marker_lines(&self.visible_marker_carry, &self.marker);
            self.visible_marker_carry.clear();
            if !leftover.is_empty() {
                let dropped = append_bounded_output(&mut self.visible_output, &leftover, self.capture_limit_chars);
                self.visible_output_offset += dropped;
            }
        }

        let (cleaned, output_base_offset, total_output_chars) = if self.is_background() && self.found_start {
            let stripped = normalize_pty_output(
                &self.visible_output,
                &NormalizeOptions {
                    strip_markers: true,
                    marker_to_strip: Some(&self.marker),
                    expected_prompt: &self.expected_prompt,
                    trim_output: self.opts.normalize_final_output,
                    strip_prompt: true,
                },
            );
            let base = self.visible_output_offset;
            (stripped, base, base + self.visible_output.chars().count())
        } else {
            let visible_stdout = normalize_pty_output(
                &stdout,
                &NormalizeOptions {
                    strip_markers: self.opts.strip_markers,
                    marker_to_strip: Some(&self.marker),
                    expected_prompt: &self.expected_prompt,
                    trim_output: false,
                    strip_prompt: true,
                },
            );
            let cleaned = if self.opts.normalize_final_output {
                normalize_pty_output(
                    &stdout,
                    &NormalizeOptions {
                        strip_markers: self.opts.strip_markers,
                        marker_to_strip: Some(&self.marker),
                        expected_prompt: &self.expected_prompt,
                        trim_output: true,
                        strip_prompt: true,
                    },
                )
            } else {
                visible_stdout.clone()
            };
            let base = if self.found_start { self.visible_output_offset } else { 0 };
            (cleaned, base, base + visible_stdout.chars().count())
        };
        let final_error = match error {
            None if self.cancel_requested => Some("Cancelled".to_string()),
            other => other,
        };
        let final_exit_code = if final_error.as_deref() == Some("Cancelled") {
            Some(exit_code.unwrap_or(130))
        } else {
            exit_code
        };
        let result = match final_error {
            Some(err) => JobResult {
                ok: false,
                stdout: cleaned,
                stderr: String::new(),
                exit_code: Some(final_exit_code.unwrap_or(-1)),
                error: Some(err),
                code: self.readiness_failure_code.map(str::to_string),
                cancelled: None,
                output_base_offset,
                total_output_chars,
                output_truncated: output_base_offset > 0,
            },
            None => JobResult {
                ok: exit_code.is_none() || exit_code == Some(0),
                stdout: cleaned,
                stderr: String::new(),
                exit_code: Some(final_exit_code.unwrap_or(0)),
                error: None,
                code: None,
                cancelled: None,
                output_base_offset,
                total_output_chars,
                output_truncated: output_base_offset > 0,
            },
        };
        self.final_result = Some(result);
        self.update_snapshot();
    }

    // ── output handling ──────────────────────────────────────────────

    async fn on_data(&mut self, text: String) {
        if text.is_empty() {
            return;
        }
        if self.pending_end.is_none() && !self.delivering_input {
            self.arm_output_timeout();
        }

        if self.probing_shell {
            self.probe_output.push_str(&text);
            self.probe_output = tail_chars(&self.probe_output, 16384).to_string();
            if self.cancel_requested && has_expected_prompt_suffix(&self.probe_output, &self.expected_prompt) {
                self.finish(String::new(), Some(-1), Some("Cancelled".into()));
                return;
            }
            let Some(probe) = parse_live_shell_probe(&strip_ansi(&self.probe_output), &self.marker) else {
                return;
            };
            self.probing_shell = false;
            self.probe_output.clear();
            if let Some(kind) = probe.kind {
                self.resolved_shell_kind = kind.to_string();
            }
            if self.finished || self.cancel_requested {
                return;
            }
            let is_zsh = is_zsh_shell_name(&probe.shell_name);
            let skip_probe_cleanup = probe.kind == Some("fish") || is_zsh;
            let cleanup = if skip_probe_cleanup {
                String::new()
            } else {
                build_live_shell_probe_cleanup(&self.marker)
            };
            self.write_wrapped_command(&cleanup, is_zsh).await;
            return;
        }

        if !self.found_start {
            self.pre_start_output.push_str(&text);
            let combined = format!("{}{}", self.pending_start, text);
            self.pending_start.clear();
            let start_marker = format!("{}_S", self.marker);
            let ends_with_break = combined.ends_with('\n') || combined.ends_with('\r');
            let mut lines: Vec<&str> = combined.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
            let trailing_partial = if ends_with_break {
                lines.pop();
                String::new()
            } else {
                lines.pop().unwrap_or("").to_string()
            };
            for line in &lines {
                if strip_ansi(line).trim() == start_marker {
                    self.found_start = true;
                    break;
                }
            }
            self.pending_start = trailing_partial;
            if self.found_start {
                self.t_startup = None;
                if let Some(boundary) = self.pre_start_output.rfind(&start_marker) {
                    let after_boundary = &self.pre_start_output[boundary..];
                    let initial_output = match after_boundary.find('\n') {
                        None => String::new(),
                        Some(nl) => {
                            let start = if nl > 0 && after_boundary.as_bytes()[nl - 1] == b'\r' { nl - 1 } else { nl };
                            let rest = &after_boundary[start..];
                            rest.strip_prefix("\r\n")
                                .or_else(|| rest.strip_prefix('\n'))
                                .unwrap_or(rest)
                                .to_string()
                        }
                    };
                    self.output.clear();
                    self.visible_output.clear();
                    self.visible_output_offset = 0;
                    self.visible_carry.clear();
                    self.append_to_output(&initial_output);
                }
                self.pre_start_output.clear();
                self.schedule_prompt_fallback();
                self.check_end();
                self.update_snapshot();
                return;
            }
            if let Some((end_idx, exit_code)) = find_end_marker(&self.pre_start_output, &self.marker, false) {
                let mut stdout = self.pre_start_output[..end_idx].to_string();
                if let Some(last_start) = stdout.rfind(&start_marker) {
                    if let Some(nl) = stdout[last_start..].find('\n') {
                        stdout = stdout[last_start + nl + 1..].to_string();
                    }
                }
                self.finish(stdout, Some(exit_code), None);
                return;
            }
            if self.pre_start_output.chars().count() > self.capture_limit_chars {
                self.pre_start_output = tail_chars(&self.pre_start_output, self.capture_limit_chars).to_string();
            }
            let carry_limit = self.marker.len() + 256;
            if self.pending_start.chars().count() > carry_limit {
                self.pending_start = tail_chars(&self.pending_start, carry_limit).to_string();
            }
            if self.cancel_requested && has_expected_prompt_suffix(&self.pre_start_output, &self.expected_prompt) {
                let pre = self.pre_start_output.clone();
                self.finish(pre, Some(130), Some("Cancelled".into()));
            }
            return;
        }

        self.append_to_output(&text);
        self.check_end();
        if self.finished {
            return;
        }
        if !self.cancel_requested {
            self.schedule_prompt_fallback();
        } else if has_expected_prompt_suffix(&self.output, &self.expected_prompt) {
            let (stdout, code) = match &self.pending_end {
                Some(p) => (p.stdout.clone(), p.exit_code),
                None => (self.output.clone(), 130),
            };
            self.finish(stdout, Some(code), Some("Cancelled".into()));
            return;
        }
        self.update_snapshot();
    }

    fn on_stream_closed(&mut self) {
        if let Some(pending) = self.pending_end.take() {
            let err = if self.cancel_requested { Some("Cancelled".to_string()) } else { None };
            self.finish(pending.stdout, Some(pending.exit_code), err);
            return;
        }
        let out = if self.found_start { self.output.clone() } else { self.pre_start_output.clone() };
        let err = if self.cancel_requested { "Cancelled" } else { "Stream closed unexpectedly" };
        self.finish(out, None, Some(err.into()));
    }

    // ── input delivery ───────────────────────────────────────────────

    async fn write_input(&mut self, text: String) {
        self.t_input_next = None;
        self.t_startup = None;
        self.t_output = None;
        self.delivering_input = true;
        let chars: Vec<char> = text.chars().collect();
        let batch_size = if (self.uses_live_shell_probe || self.opts.bastion_keystrokes) && chars.len() > 1024 {
            128
        } else {
            chars.len().max(1)
        };
        self.input = Some(InputState { chars, offset: 0, batch_size });
        self.write_next().await;
    }

    async fn write_next(&mut self) {
        let Some(state) = self.input.as_mut() else {
            return;
        };
        let end = (state.offset + state.batch_size).min(state.chars.len());
        let bastion = self.opts.bastion_keystrokes;
        let mut pieces: Vec<String> = Vec::new();
        if bastion {
            for c in &state.chars[state.offset..end] {
                pieces.push(c.to_string());
            }
        } else {
            pieces.push(state.chars[state.offset..end].iter().collect());
        }
        state.offset = end;
        let remaining = state.offset < state.chars.len();
        for piece in pieces {
            if self.finished || self.cancel_requested {
                self.input = None;
                return;
            }
            if let Err(err) = self.writer.write(&piece).await {
                let pre = self.pre_start_output.clone();
                self.finish(pre, Some(-1), Some(format!("Terminal input failed: {err}")));
                self.input = None;
                return;
            }
        }
        if remaining {
            self.t_input_next = Some(after(INPUT_PACING_MS));
        } else {
            self.input = None;
            self.complete_input_delivery();
        }
    }

    fn complete_input_delivery(&mut self) {
        if !self.finished && !self.cancel_requested {
            self.delivering_input = false;
            if self.pending_end.is_none() {
                self.arm_output_timeout();
            }
            if !self.found_start {
                self.arm_startup_timeout();
            }
        }
    }

    async fn write_wrapped_command(&mut self, probe_cleanup: &str, is_zsh: bool) {
        let wrapped = build_wrapped_command(
            &self.command,
            &self.resolved_shell_kind,
            &self.marker,
            self.opts.probe_live_shell,
            is_zsh,
        );
        let prefix = if self.opts.skip_pending_input_clear {
            ""
        } else {
            build_pending_input_clear_prefix(&self.resolved_shell_kind)
        };
        self.write_input(format!("{prefix}{probe_cleanup}{wrapped}")).await;
    }

    fn echo_pending_command(&self) {
        if !self.opts.typed_input {
            return;
        }
        if let Some(cb) = &self.opts.callbacks.echo_command {
            cb(&self.command);
        }
    }

    async fn begin_input_delivery(&mut self) {
        if self.finished || self.cancel_requested {
            return;
        }
        if self.waiting_for_input_guard {
            let guard = self.opts.callbacks.before_input.clone();
            if let Some(guard) = guard {
                if let Err(message) = guard() {
                    self.readiness_failure_code = Some("EXECUTION_NOT_AUTHORIZED");
                    let msg = if message.is_empty() {
                        "Execution authorization failed; no command was sent".to_string()
                    } else {
                        message
                    };
                    self.finish(String::new(), Some(-1), Some(msg));
                    return;
                }
            }
            if let Some(get_prompt) = self.opts.callbacks.get_ready_prompt.clone() {
                if get_prompt().is_empty() {
                    self.readiness_failure_code = Some("SHELL_NOT_READY");
                    self.finish(
                        String::new(),
                        Some(-1),
                        Some("Shell prompt changed while checking authorization; no command was sent".into()),
                    );
                    return;
                }
            }
            self.waiting_for_input_guard = false;
        }
        self.deliver_authorized_input().await;
    }

    async fn deliver_authorized_input(&mut self) {
        if self.finished || self.cancel_requested {
            return;
        }
        self.echo_pending_command();
        if let Some(cb) = self.opts.callbacks.on_echo_suppression_prime.clone() {
            cb(&self.marker);
        }
        if self.probing_shell {
            let prefix = if self.opts.skip_pending_input_clear {
                ""
            } else {
                build_pending_input_clear_prefix(&self.resolved_shell_kind)
            };
            let probe = build_live_shell_probe(&self.marker);
            self.write_input(format!("{prefix}{probe}")).await;
        } else {
            self.write_wrapped_command("", false).await;
        }
    }

    async fn check_ready(&mut self) {
        if self.finished || self.cancel_requested {
            return;
        }
        let Some(get_prompt) = self.opts.callbacks.get_ready_prompt.clone() else {
            return;
        };
        let prompt = get_prompt();
        if !prompt.is_empty() {
            self.waiting_for_prompt = false;
            self.t_readiness = None;
            self.expected_prompt = prompt;
            self.resolved_shell_kind = resolve_effective_shell_kind(
                &self.opts.shell_kind,
                &self.expected_prompt,
                &self.opts.login_shell_hint,
            );
            self.uses_live_shell_probe =
                self.opts.probe_live_shell && matches!(self.resolved_shell_kind.as_str(), "posix" | "fish");
            self.probing_shell = self.uses_live_shell_probe;
            self.wait_for_returned_prompt =
                self.opts.login_shell_hint == "cmd" && self.resolved_shell_kind == "powershell";
            self.begin_input_delivery().await;
            return;
        }
        let deadline = self.readiness_deadline.unwrap_or_else(Instant::now);
        if Instant::now() >= deadline {
            self.readiness_failure_code = Some("SHELL_NOT_READY");
            self.finish(
                String::new(),
                Some(-1),
                Some("Shell prompt is not ready (startup, busy program, pending input, or unrecognized prompt); no command was sent".into()),
            );
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        self.t_readiness = Some(Instant::now() + remaining.min(Duration::from_millis(50)));
    }

    // ── main loop ────────────────────────────────────────────────────

    async fn run(mut self) {
        self.arm_output_timeout();
        self.arm_wall_timeout();
        if self.waiting_for_prompt {
            let budget = self.opts.prompt_wait_timeout_ms.clamp(1, 30_000);
            self.readiness_deadline = Some(after(budget));
            self.check_ready().await;
        } else {
            self.begin_input_delivery().await;
        }
        if self.cancel_flag.load(Ordering::SeqCst) {
            self.request_cancel().await;
        }

        while !self.finished {
            let deadline = self.earliest_deadline();
            tokio::select! {
                biased;
                _ = self.cancel.notified() => {
                    self.request_cancel().await;
                }
                chunk = self.rx.recv() => {
                    match chunk {
                        Some(text) => self.on_data(text).await,
                        None => self.on_stream_closed(),
                    }
                }
                _ = async {
                    match deadline {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    self.fire_timers().await;
                }
            }
        }
        let result = self.final_result.take().unwrap_or_else(|| JobResult::failure("Job ended without a result"));
        let _ = self.result_tx.send(Some(result));
    }

    async fn fire_timers(&mut self) {
        let now = Instant::now();
        let due = |t: &mut Option<Instant>| -> bool {
            match t {
                Some(at) if *at <= now => {
                    *t = None;
                    true
                }
                _ => false,
            }
        };

        if due(&mut self.t_input_next) && !self.finished {
            self.write_next().await;
        }
        if due(&mut self.t_readiness) && !self.finished {
            self.check_ready().await;
        }
        if due(&mut self.t_output) && !self.finished {
            self.send_interrupt().await;
            if self.cancel_requested {
                self.arm_output_timeout();
            } else {
                let timeout_sec = (self.ms() as f64 / 1000.0).round() as u64;
                let out = if self.found_start { self.output.clone() } else { self.pre_start_output.clone() };
                self.finish(out, Some(-1), Some(format!("Command timed out after {timeout_sec}s without output")));
            }
        }
        if due(&mut self.t_wall) && !self.finished {
            if self.waiting_for_prompt || self.waiting_for_input_guard {
                self.readiness_failure_code = Some(if self.waiting_for_prompt {
                    "SHELL_NOT_READY"
                } else {
                    "EXECUTION_NOT_AUTHORIZED"
                });
                let msg = if self.waiting_for_prompt {
                    "Shell prompt is not ready; no command was sent"
                } else {
                    "Execution authorization timed out; no command was sent"
                };
                self.finish(String::new(), Some(-1), Some(msg.into()));
            } else if self.pending_end.is_some() {
                self.finish_without_returned_prompt();
            } else {
                self.send_interrupt().await;
                let timeout_sec = (self.ms() as f64 / 1000.0).round() as u64;
                let out = if self.found_start { self.output.clone() } else { self.pre_start_output.clone() };
                self.finish(out, Some(-1), Some(format!("Command timed out ({timeout_sec}s)")));
            }
        }
        if due(&mut self.t_startup) && !self.finished && !self.found_start {
            self.send_interrupt().await;
            let label = if self.is_background() { "Background job startup" } else { "Command startup" };
            let pre = self.pre_start_output.clone();
            self.finish(pre, Some(-1), Some(format!("{label} timed out — start marker never arrived")));
        }
        if due(&mut self.t_prompt_fallback) && !self.finished
            && has_expected_prompt_suffix(&self.output, &self.expected_prompt) {
                let out = self.output.clone();
                self.finish(out, None, None);
            }
        if due(&mut self.t_end_marker_wait) && !self.finished {
            self.finish_without_returned_prompt();
        }
        if due(&mut self.t_cancel_retry) && !self.finished && self.cancel_requested {
            self.send_interrupt().await;
            self.t_cancel_retry = Some(after(CANCEL_RETRY_MS));
        }
        if due(&mut self.t_cancel_prestart) && !self.finished && !self.found_start {
            let pre = self.pre_start_output.clone();
            self.finish(pre, Some(130), Some("Cancelled".into()));
        }
        if due(&mut self.t_cancel_followup) && !self.finished {
            self.send_interrupt().await;
        }
        if due(&mut self.t_cancel_wall) && !self.finished {
            let out = if self.found_start { self.output.clone() } else { self.pre_start_output.clone() };
            self.finish(out, Some(130), Some("Cancelled (forced — process may still be running)".into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Records writes; a test drives output through the channel sender.
    struct FakePty {
        writes: Arc<StdMutex<Vec<String>>>,
        tx: mpsc::UnboundedSender<String>,
        /// Optional: run posix wrappers through `sh` and feed back stdout.
        shell_backed: bool,
    }

    #[async_trait::async_trait]
    impl PtyInput for FakePty {
        async fn write(&self, data: &str) -> Result<(), String> {
            self.writes.lock().unwrap().push(data.to_string());
            if self.shell_backed && data != "\x03" {
                let script = data.strip_prefix("\x0b\x15").unwrap_or(data).to_string();
                let tx = self.tx.clone();
                tokio::task::spawn_blocking(move || {
                    let out = std::process::Command::new("sh").arg("-c").arg(&script).output();
                    if let Ok(out) = out {
                        let _ = tx.send(String::from_utf8_lossy(&out.stdout).into_owned());
                    }
                });
            }
            Ok(())
        }
    }

    type Harness = (Arc<FakePty>, OutputRx, Arc<StdMutex<Vec<String>>>, mpsc::UnboundedSender<String>);

    fn harness(shell_backed: bool) -> Harness {
        let (tx, rx) = mpsc::unbounded_channel();
        let writes = Arc::new(StdMutex::new(Vec::new()));
        // Only a shell-backed fake feeds output itself; otherwise it must not
        // hold a sender, so tests can close the stream by dropping `tx`.
        let pty_tx = if shell_backed { tx.clone() } else { mpsc::unbounded_channel().0 };
        let pty = Arc::new(FakePty { writes: writes.clone(), tx: pty_tx, shell_backed });
        (pty, rx, writes, tx)
    }

    fn marker_of(writes: &Arc<StdMutex<Vec<String>>>) -> String {
        let re = regex::Regex::new(r"(__NCMCP_[a-z0-9]+_[0-9a-f]+__)").unwrap();
        for w in writes.lock().unwrap().iter() {
            if let Some(m) = re.captures(w) {
                return m[1].to_string();
            }
        }
        panic!("no marker written yet")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exec_completes_when_output_has_no_trailing_newline() {
        let (pty, rx, _w, _tx) = harness(true);
        let result = exec_via_pty(
            pty,
            rx,
            "printf 'abc'",
            JobOptions { shell_kind: "posix".into(), timeout_ms: 5000, ..Default::default() },
        )
        .await;
        assert!(result.ok, "{result:?}");
        assert_eq!(result.stdout, "abc");
        assert_eq!(result.exit_code, Some(0));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exec_reports_non_zero_exit_and_isolates_exit_from_the_shell() {
        let (pty, rx, _w, _tx) = harness(true);
        let result = exec_via_pty(
            pty,
            rx,
            "echo hi; exit 7",
            JobOptions { shell_kind: "posix".into(), timeout_ms: 5000, ..Default::default() },
        )
        .await;
        assert!(!result.ok);
        assert_eq!(result.exit_code, Some(7));
        assert_eq!(result.stdout, "hi");
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn start_marker_and_end_marker_split_across_chunks() {
        let (pty, rx, writes, tx) = harness(false);
        let handle = start_pty_job(
            pty,
            rx,
            "echo x",
            JobOptions { shell_kind: "posix".into(), timeout_ms: 5000, ..Default::default() },
        )
        .unwrap();
        tokio::task::yield_now().await;
        let m = marker_of(&writes);
        tx.send(m[..10].to_string()).unwrap();
        tx.send(format!("{}_S\nh", &m[10..])).unwrap();
        let end = format!("{m}_E:0\n");
        tx.send(format!("éllo\n{}", &end[..5])).unwrap();
        tx.send(end[5..].to_string()).unwrap();
        let result = handle.wait().await;
        assert!(result.ok);
        assert_eq!(result.stdout, "héllo");
        assert_eq!(handle.snapshot().status, "finished");
    }

    #[tokio::test]
    async fn cancellation_sends_ctrl_c_as_terminal_data_and_returns_bounded_tail() {
        let (pty, rx, writes, tx) = harness(false);
        let handle = start_pty_job(
            pty,
            rx,
            "sleep 100",
            JobOptions {
                shell_kind: "posix".into(),
                timeout_ms: 5000,
                expected_prompt: "alice@host:~$ ".into(),
                ..Default::default()
            },
        )
        .unwrap();
        tokio::task::yield_now().await;
        let m = marker_of(&writes);
        tx.send(format!("{m}_S\n{}", "y".repeat(2 * 1024 * 1024))).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        handle.cancel();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(writes.lock().unwrap().iter().any(|w| w == "\x03"));
        assert_eq!(handle.snapshot().status, "stopping");
        tx.send("^C\nalice@host:~$ ".into()).unwrap();
        let result = handle.wait().await;
        assert_eq!(result.error.as_deref(), Some("Cancelled"));
        assert_eq!(result.exit_code, Some(130));
        assert!(result.stdout.chars().count() <= DEFAULT_FOREGROUND_PTY_CAPTURE_CHARS);
        assert!(result.output_truncated);
    }

    #[tokio::test]
    async fn startup_timeout_fires_when_start_marker_never_arrives() {
        // A chatty PTY keeps the inactivity timer alive; the bounded startup
        // deadline must still end the job.
        let (pty, rx, _writes, tx) = harness(false);
        let handle = start_pty_job(
            pty,
            rx,
            "echo",
            JobOptions { shell_kind: "posix".into(), timeout_ms: 200, ..Default::default() },
        )
        .unwrap();
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(60)).await;
            let _ = tx.send("noise\n".into());
        }
        let result = handle.wait().await;
        assert!(!result.ok);
        assert!(result.error.unwrap().contains("start marker never arrived"));
    }

    #[tokio::test]
    async fn inactivity_timeout_after_start() {
        let (pty, rx, writes, tx) = harness(false);
        let handle = start_pty_job(
            pty,
            rx,
            "cat",
            JobOptions { shell_kind: "posix".into(), timeout_ms: 150, ..Default::default() },
        )
        .unwrap();
        tokio::task::yield_now().await;
        let m = marker_of(&writes);
        tx.send(format!("{m}_S\npartial")).unwrap();
        let result = handle.wait().await;
        assert_eq!(result.error.as_deref(), Some("Command timed out after 0s without output"));
        assert_eq!(result.stdout, "partial");
    }

    #[tokio::test]
    async fn stream_close_finishes_with_error() {
        let (pty, rx, writes, tx) = harness(false);
        let handle = start_pty_job(
            pty,
            rx,
            "ls",
            JobOptions { shell_kind: "posix".into(), timeout_ms: 5000, ..Default::default() },
        )
        .unwrap();
        tokio::task::yield_now().await;
        let m = marker_of(&writes);
        tx.send(format!("{m}_S\nsome\n")).unwrap();
        drop(tx);
        let result = handle.wait().await;
        assert_eq!(result.error.as_deref(), Some("Stream closed unexpectedly"));
    }

    #[tokio::test]
    async fn consecutive_powershell_jobs_wait_for_returned_prompt_after_split_end_marker() {
        for probe in ["PROBE_1", "PROBE_2"] {
            let (pty, rx, writes, tx) = harness(false);
            let handle = start_pty_job(
                pty,
                rx,
                &format!("Write-Output '{probe}'"),
                JobOptions {
                    login_shell_hint: "cmd".into(),
                    timeout_ms: 5000,
                    expected_prompt: "PS C:\\Users\\alice>".into(),
                    ..Default::default()
                },
            )
            .unwrap();
            tokio::task::yield_now().await;
            let write = writes.lock().unwrap().last().cloned().unwrap();
            assert!(write.contains("$__NCMCP_"));
            assert!(!write.to_lowercase().contains("cmd /d /s /c"));
            let m = marker_of(&writes);
            tx.send(format!("{m}_S\r\n{probe}\r\n{m}_E:0\r\n")).unwrap();
            tokio::time::sleep(Duration::from_millis(80)).await;
            assert!(!handle.is_finished());
            tx.send("PS C:\\Users\\alice>".into()).unwrap();
            let result = handle.wait().await;
            assert!(result.ok);
            assert_eq!(result.stdout, probe);
        }
    }

    #[tokio::test]
    async fn non_target_shells_finish_at_end_marker_without_prompt() {
        let (pty, rx, writes, tx) = harness(false);
        let handle = start_pty_job(
            pty,
            rx,
            "printf done",
            JobOptions {
                shell_kind: "posix".into(),
                timeout_ms: 5000,
                expected_prompt: "alice@host:~$".into(),
                ..Default::default()
            },
        )
        .unwrap();
        tokio::task::yield_now().await;
        let m = marker_of(&writes);
        tx.send(format!("{m}_S\ndone{m}_E:0\n")).unwrap();
        let result = handle.wait().await;
        assert!(result.ok);
        assert_eq!(result.stdout, "done");
    }

    #[tokio::test]
    async fn live_probe_runs_before_wrapper_and_selects_fish() {
        let (pty, rx, writes, tx) = harness(false);
        let handle = start_pty_job(
            pty,
            rx,
            "echo hi",
            JobOptions { probe_live_shell: true, timeout_ms: 5000, ..Default::default() },
        )
        .unwrap();
        tokio::task::yield_now().await;
        let m = marker_of(&writes);
        assert!(writes.lock().unwrap()[0].contains(" true "));
        tx.send(format!("\n{m}_P:fish\n{m}_Q")).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let last = writes.lock().unwrap().last().cloned().unwrap();
        assert!(last.contains("functions -e __ncmcp_int"), "{last}");
        tx.send(format!("{m}_S\nhi\n{m}_E:0\n")).unwrap();
        let result = handle.wait().await;
        assert_eq!(result.stdout, "hi");
    }

    #[tokio::test]
    async fn cancelled_live_probe_resets_display_once_without_injecting_a_command() {
        let (pty, rx, writes, tx) = harness(false);
        let resets = Arc::new(StdMutex::new(Vec::new()));
        let r = resets.clone();
        let handle = start_pty_job(
            pty,
            rx,
            "echo hi",
            JobOptions {
                probe_live_shell: true,
                timeout_ms: 5000,
                expected_prompt: "alice@host:~$ ".into(),
                callbacks: JobCallbacks {
                    on_probe_aborted: Some(Arc::new(move |m: &str| r.lock().unwrap().push(m.to_string()))),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        tokio::task::yield_now().await;
        handle.cancel();
        tokio::time::sleep(Duration::from_millis(20)).await;
        tx.send("alice@host:~$ ".into()).unwrap();
        let result = handle.wait().await;
        assert_eq!(result.error.as_deref(), Some("Cancelled"));
        assert_eq!(resets.lock().unwrap().len(), 1);
        let w = writes.lock().unwrap();
        assert!(!w.iter().any(|x| x.contains("_cmd=")));
    }

    #[tokio::test]
    async fn bastion_keystrokes_type_one_code_point_per_write() {
        let (pty, rx, writes, _tx) = harness(false);
        let _handle = start_pty_job(
            pty,
            rx,
            "echo é",
            JobOptions {
                shell_kind: "posix".into(),
                bastion_keystrokes: true,
                skip_pending_input_clear: true,
                timeout_ms: 5000,
                ..Default::default()
            },
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let w = writes.lock().unwrap();
        assert!(w.len() > 10);
        assert!(w.iter().all(|x| x.chars().count() == 1));
        assert!(w.iter().any(|x| x == "é"));
    }

    #[tokio::test]
    async fn readiness_waits_for_prompt_and_fails_closed() {
        let (pty, rx, writes, _tx) = harness(false);
        let result = exec_via_pty(
            pty,
            rx,
            "ls",
            JobOptions {
                shell_kind: "posix".into(),
                timeout_ms: 5000,
                prompt_wait_timeout_ms: 120,
                callbacks: JobCallbacks {
                    get_ready_prompt: Some(Arc::new(String::new)),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        assert_eq!(result.code.as_deref(), Some("SHELL_NOT_READY"));
        assert!(writes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn before_input_guard_blocks_typing() {
        let (pty, rx, writes, _tx) = harness(false);
        let result = exec_via_pty(
            pty,
            rx,
            "ls",
            JobOptions {
                shell_kind: "posix".into(),
                timeout_ms: 5000,
                callbacks: JobCallbacks {
                    before_input: Some(Arc::new(|| Err("privacy changed".into()))),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        assert_eq!(result.code.as_deref(), Some("EXECUTION_NOT_AUTHORIZED"));
        assert_eq!(result.error.as_deref(), Some("privacy changed"));
        assert!(writes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn echo_suppression_prime_precedes_first_write_and_cancel_resets() {
        let (pty, rx, writes, tx) = harness(false);
        let order = Arc::new(StdMutex::new(Vec::new()));
        let o = order.clone();
        let o2 = order.clone();
        let handle = start_pty_job(
            pty,
            rx,
            "ls",
            JobOptions {
                shell_kind: "posix".into(),
                timeout_ms: 5000,
                typed_input: true,
                callbacks: JobCallbacks {
                    on_echo_suppression_prime: Some(Arc::new(move |_| o.lock().unwrap().push("prime"))),
                    echo_command: Some(Arc::new(move |_| o2.lock().unwrap().push("echo"))),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(*order.lock().unwrap(), vec!["echo", "prime"]);
        assert!(!writes.lock().unwrap().is_empty());
        drop(tx);
        let _ = handle.wait().await;
    }

    #[tokio::test]
    async fn background_jobs_strip_markers_and_keep_monotonic_offsets() {
        let (pty, rx, writes, tx) = harness(false);
        let handle = start_pty_job(
            pty,
            rx,
            "seq 3",
            JobOptions {
                shell_kind: "posix".into(),
                timeout_ms: 5000,
                max_buffered_chars: 120,
                normalize_final_output: false,
                ..Default::default()
            },
        )
        .unwrap();
        tokio::task::yield_now().await;
        let m = marker_of(&writes);
        tx.send(format!("{m}_S\n{}", "x\n".repeat(100))).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let snap = handle.snapshot();
        assert!(snap.found_start);
        assert_eq!(snap.total_output_chars, 200);
        assert_eq!(snap.stdout.chars().count(), 120);
        assert_eq!(snap.output_base_offset, 80);
        assert!(snap.output_truncated);
        tx.send(format!("{m}_E:0\n")).unwrap();
        let result = handle.wait().await;
        assert!(!result.stdout.contains("__NCMCP_"));
        assert_eq!(result.total_output_chars, 200);
        assert!(result.ok);
    }

    #[tokio::test]
    async fn prompt_recovery_pending_rejects_new_jobs_without_idle_prompt() {
        let (pty, rx, _w, _tx) = harness(false);
        let flag = Arc::new(AtomicBool::new(true));
        let err = start_pty_job(
            pty,
            rx,
            "ls",
            JobOptions { prompt_recovery_pending: Some(flag.clone()), ..Default::default() },
        )
        .err()
        .unwrap();
        assert_eq!(err.code, "SHELL_PROMPT_PENDING");
        let (pty, rx, _w, _tx) = harness(false);
        assert!(start_pty_job(
            pty,
            rx,
            "ls",
            JobOptions {
                prompt_recovery_pending: Some(flag.clone()),
                expected_prompt: "PS C:\\>".into(),
                ..Default::default()
            },
        )
        .is_ok());
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn result_serialises_like_electron() {
        let r = JobResult {
            ok: true,
            stdout: "x".into(),
            stderr: String::new(),
            exit_code: Some(0),
            error: None,
            code: None,
            cancelled: None,
            output_base_offset: 0,
            total_output_chars: 1,
            output_truncated: false,
        };
        let v = serde_json::to_value(r).unwrap();
        assert_eq!(v["exitCode"], 0);
        assert_eq!(v["outputTruncated"], false);
        assert!(v.get("error").is_none());
    }
}

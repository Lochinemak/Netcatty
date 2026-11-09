//! Per-session execution lock, background jobs and in-flight SFTP
//! operations (Electron `mcpServerBridge/backgroundJobs.cjs`).

use super::McpHost;
use netcatty_ptyexec::job::PtyJobHandle;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub const DEFAULT_BACKGROUND_JOB_TIMEOUT_MS: u64 = 60 * 60 * 1000;
pub const DEFAULT_BACKGROUND_JOB_POLL_INTERVAL_MS: u64 = 30 * 1000;
pub const BACKGROUND_JOB_RETENTION_MS: u64 = 10 * 60 * 1000;
pub const MAX_BACKGROUND_JOB_OUTPUT_CHARS: usize = 256 * 1024;
pub const SESSION_CLOSE_CLEANUP_TIMEOUT_MS: u64 = 5000;

#[derive(Clone)]
pub struct BackgroundJob {
    pub id: String,
    pub session_id: String,
    pub chat_session_id: Option<String>,
    pub command: String,
    /// `running` | `stopping` | `completed` | `failed` | `cancelled`.
    pub status: String,
    pub started_at: u64,
    pub updated_at: u64,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub code: Option<String>,
    pub stdout: String,
    pub output_base_offset: usize,
    pub total_output_chars: usize,
    pub output_truncated: bool,
    pub handle: Option<PtyJobHandle>,
    /// Set while the shell-kind probe runs (cancel before the PTY job starts).
    pub probe_cancel: Arc<AtomicBool>,
}

struct Execution {
    kind: &'static str,
    token: String,
}

struct SftpOpEntry {
    chat_session_id: String,
    session_id: String,
    cancel: CancellationToken,
}

#[derive(Default)]
pub struct Jobs {
    pub(crate) jobs: Mutex<HashMap<String, BackgroundJob>>,
    executions: Mutex<HashMap<String, Execution>>,
    sftp_ops: Mutex<HashMap<u64, SftpOpEntry>>,
    sftp_seq: AtomicU64,
    closing: Mutex<HashMap<String, u32>>,
    pending_writes: Mutex<HashMap<String, String>>,
}

/// Unregisters an SFTP op on drop.
pub struct SftpOpGuard {
    host: std::sync::Weak<McpHost>,
    id: u64,
    pub token: CancellationToken,
}

impl Drop for SftpOpGuard {
    fn drop(&mut self) {
        if let Some(h) = self.host.upgrade() {
            h.jobs.sftp_ops.lock().remove(&self.id);
        }
    }
}

/// Releases a pending write-approval slot on drop.
pub struct PendingWriteGuard {
    host: std::sync::Weak<McpHost>,
    session_id: String,
}

impl Drop for PendingWriteGuard {
    fn drop(&mut self) {
        if let Some(h) = self.host.upgrade() {
            h.jobs.pending_writes.lock().remove(&self.session_id);
        }
    }
}

impl Jobs {
    pub fn is_session_busy(&self, session_id: &str) -> bool {
        self.executions.lock().contains_key(session_id)
    }

    pub fn is_closing(&self, session_id: &str) -> bool {
        self.closing.lock().contains_key(session_id)
    }
}

/// Collapse `\r` progress redraws to the latest frame.
pub fn collapse_carriage_returns(text: &str) -> String {
    if !text.contains('\r') {
        return text.to_string();
    }
    let mut result = String::new();
    let mut cr_pending = false;
    for ch in text.chars() {
        if ch == '\r' {
            cr_pending = true;
            continue;
        }
        if ch == '\n' {
            cr_pending = false;
            result.push(ch);
            continue;
        }
        if cr_pending {
            match result.rfind('\n') {
                Some(i) => result.truncate(i + 1),
                None => result.clear(),
            }
            cr_pending = false;
        }
        result.push(ch);
    }
    result
}

pub fn create_background_job_id() -> String {
    let b: [u8; 6] = rand::random();
    format!("job_{}_{}", base36(super::now_ms()), hex::encode(b))
}

pub(crate) fn base36(mut n: u64) -> String {
    let digits = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if n == 0 {
        return "0".into();
    }
    let mut out = Vec::new();
    while n > 0 {
        out.push(digits[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    String::from_utf8(out).unwrap()
}

impl BackgroundJob {
    fn refresh_from_handle(&mut self) {
        if self.status != "running" && self.status != "stopping" {
            return;
        }
        if let Some(h) = &self.handle {
            let s = h.snapshot();
            self.output_base_offset = s.output_base_offset;
            self.total_output_chars = s.total_output_chars.max(s.output_base_offset + s.stdout.chars().count());
            self.stdout = s.stdout;
            self.output_truncated = s.output_truncated;
        }
    }

    /// Poll / stop payload (`serializeBackgroundJob`).
    pub fn serialize(&mut self, offset: u64) -> Value {
        self.refresh_from_handle();
        let stdout_chars = self.stdout.chars().count();
        let total = self.total_output_chars.max(self.output_base_offset + stdout_chars);
        let offset = offset as usize;
        let relative = if offset <= self.output_base_offset { 0 } else { (offset - self.output_base_offset).min(stdout_chars) };
        let slice: String = self.stdout.chars().skip(relative).collect();
        let mut out = json!({
            "ok": true,
            "jobId": self.id,
            "sessionId": self.session_id,
            "command": self.command,
            "status": self.status,
            "completed": self.status != "running" && self.status != "stopping",
            "exitCode": self.exit_code,
            "error": self.error,
            "startedAt": self.started_at,
            "updatedAt": self.updated_at,
            "output": collapse_carriage_returns(&slice),
            "nextOffset": total,
            "totalOutputChars": total,
            "outputBaseOffset": self.output_base_offset,
            "outputTruncated": self.output_truncated,
            "recommendedPollIntervalMs": DEFAULT_BACKGROUND_JOB_POLL_INTERVAL_MS,
        });
        if let Some(code) = &self.code {
            out["code"] = json!(code);
        }
        out
    }
}

impl McpHost {
    pub fn session_busy_error(&self, session_id: &str) -> Option<Value> {
        let executions = self.jobs.executions.lock();
        let active = executions.get(session_id)?;
        let what = if active.kind == "job" { "a long-running command" } else { "another command" };
        Some(json!({
            "ok": false,
            "error": format!("Session already has {what} in progress. Wait for it to finish or stop it before starting another command."),
        }))
    }

    /// Per-session execution lock; `Err` is the busy result.
    pub fn reserve_session_execution(&self, session_id: &str, kind: &'static str) -> Result<String, Value> {
        if let Some(busy) = self.session_busy_error(session_id) {
            return Err(busy);
        }
        let b: [u8; 6] = rand::random();
        let token = format!("{kind}_{}_{}", base36(super::now_ms()), hex::encode(b));
        self.jobs.executions.lock().insert(session_id.to_string(), Execution { kind, token: token.clone() });
        Ok(token)
    }

    pub fn release_session_execution(&self, session_id: &str, token: &str) {
        let mut executions = self.jobs.executions.lock();
        if executions.get(session_id).is_some_and(|e| token.is_empty() || e.token == token) {
            executions.remove(session_id);
        }
    }

    pub(crate) fn try_reserve_pending_write(&self, session_id: &str, method: &str) -> Option<PendingWriteGuard> {
        let mut pending = self.jobs.pending_writes.lock();
        if pending.contains_key(session_id) {
            return None;
        }
        pending.insert(session_id.to_string(), method.to_string());
        Some(PendingWriteGuard { host: self.me.clone(), session_id: session_id.to_string() })
    }

    pub(crate) fn register_sftp_op(&self, chat: &str, session_id: &str) -> SftpOpGuard {
        let token = CancellationToken::new();
        if self.jobs.is_closing(session_id) {
            token.cancel();
        }
        let id = self.jobs.sftp_seq.fetch_add(1, Ordering::SeqCst) + 1;
        if !chat.is_empty() {
            self.jobs.sftp_ops.lock().insert(
                id,
                SftpOpEntry { chat_session_id: chat.to_string(), session_id: session_id.to_string(), cancel: token.clone() },
            );
        }
        SftpOpGuard { host: self.me.clone(), id, token }
    }

    pub async fn cancel_sftp_ops_for_chat(&self, chat: &str) {
        if chat.is_empty() {
            return;
        }
        let mut ops = self.jobs.sftp_ops.lock();
        let ids: Vec<u64> = ops.iter().filter(|(_, e)| e.chat_session_id == chat).map(|(k, _)| *k).collect();
        for id in ids {
            if let Some(e) = ops.remove(&id) {
                e.cancel.cancel();
            }
        }
    }

    pub fn cancel_sftp_ops_for_terminal(&self, session_id: &str) {
        let mut ops = self.jobs.sftp_ops.lock();
        let ids: Vec<u64> = ops.iter().filter(|(_, e)| e.session_id == session_id).map(|(k, _)| *k).collect();
        for id in ids {
            if let Some(e) = ops.remove(&id) {
                e.cancel.cancel();
            }
        }
    }

    pub fn cancel_all_sftp_ops(&self) {
        for (_, e) in self.jobs.sftp_ops.lock().drain() {
            e.cancel.cancel();
        }
    }

    pub fn active_sftp_op_count(&self) -> usize {
        self.jobs.sftp_ops.lock().len()
    }

    pub fn begin_terminal_session_close(&self, session_id: &str) {
        *self.jobs.closing.lock().entry(session_id.to_string()).or_insert(0) += 1;
    }

    pub fn end_terminal_session_close(&self, session_id: &str) {
        let mut closing = self.jobs.closing.lock();
        match closing.get(session_id).copied() {
            Some(n) if n > 1 => {
                closing.insert(session_id.to_string(), n - 1);
            }
            _ => {
                closing.remove(session_id);
            }
        }
    }

    pub fn cancel_background_jobs_for_chat(&self, chat: &str) {
        let now = super::now_ms();
        for job in self.jobs.jobs.lock().values_mut() {
            if job.chat_session_id.as_deref() != Some(chat) || job.status != "running" {
                continue;
            }
            job.probe_cancel.store(true, Ordering::SeqCst);
            if let Some(h) = &job.handle {
                h.cancel();
            }
            job.status = "stopping".into();
            job.error = Some("Cancellation requested".into());
            job.updated_at = now;
        }
    }

    pub fn cancel_background_jobs_for_terminal(&self, session_id: &str) {
        let now = super::now_ms();
        for job in self.jobs.jobs.lock().values_mut() {
            if job.session_id != session_id || (job.status != "running" && job.status != "stopping") {
                continue;
            }
            job.probe_cancel.store(true, Ordering::SeqCst);
            if let Some(h) = &job.handle {
                h.cancel();
            }
            job.status = "stopping".into();
            job.error = Some("Cancellation requested".into());
            job.updated_at = now;
        }
    }

    /// Wait (bounded) for the jobs of a closed terminal, then drop them.
    pub async fn settle_background_jobs_for_terminal(&self, session_id: &str) {
        let (ids, handles): (Vec<String>, Vec<PtyJobHandle>) = {
            let jobs = self.jobs.jobs.lock();
            let matching: Vec<&BackgroundJob> = jobs.values().filter(|j| j.session_id == session_id).collect();
            (matching.iter().map(|j| j.id.clone()).collect(), matching.iter().filter_map(|j| j.handle.clone()).collect())
        };
        let wait = futures_join_all(handles);
        let _ = tokio::time::timeout(Duration::from_millis(SESSION_CLOSE_CLEANUP_TIMEOUT_MS), wait).await;
        let mut jobs = self.jobs.jobs.lock();
        for id in ids {
            jobs.remove(&id);
        }
        drop(jobs);
        self.jobs.executions.lock().remove(session_id);
    }

    pub fn prune_completed_background_jobs(&self) {
        let now = super::now_ms();
        self.jobs.jobs.lock().retain(|_, j| {
            j.status == "running" || j.status == "stopping" || j.updated_at == 0 || now.saturating_sub(j.updated_at) <= BACKGROUND_JOB_RETENTION_MS
        });
    }

    pub(crate) fn scoped_job(&self, job_id: &str, chat: Option<&str>) -> Option<()> {
        let jobs = self.jobs.jobs.lock();
        let job = jobs.get(job_id)?;
        if let Some(owner) = &job.chat_session_id {
            if chat != Some(owner.as_str()) {
                return None;
            }
        }
        Some(())
    }
}

async fn futures_join_all(handles: Vec<PtyJobHandle>) {
    for h in handles {
        let _ = h.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_progress_redraws() {
        assert_eq!(collapse_carriage_returns("10%\r50%\r100%\ndone"), "100%\ndone");
        assert_eq!(collapse_carriage_returns("a\rb\r"), "b");
        assert_eq!(collapse_carriage_returns("plain"), "plain");
        assert!(create_background_job_id().starts_with("job_"));
    }
}

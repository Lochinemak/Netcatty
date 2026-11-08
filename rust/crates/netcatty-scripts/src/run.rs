//! Script run records (`serializeRun` in `electron/bridges/scriptBridge.cjs`)
//! and the status patches the runtime applies to them.

use serde::{Deserialize, Serialize};

/// `ScriptRunStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunStatus {
    Running,
    Paused,
    Completed,
    Failed,
}

/// `ScriptProgressMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProgressMode {
    #[default]
    Activity,
    Determinate,
}

/// `ScriptRunLogEntry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunLogEntry {
    pub at: i64,
    pub message: String,
}

/// Mutable state of one run (the `run` object of `runScriptOnSession`).
#[derive(Debug, Clone)]
pub struct ScriptRun {
    pub run_id: String,
    pub script_id: Option<String>,
    pub script_label: Option<String>,
    pub session_id: String,
    pub status: RunStatus,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub current_step: Option<String>,
    pub step_index: u64,
    pub total_steps: Option<u64>,
    pub progress_mode: ProgressMode,
    pub activity_label: Option<String>,
    pub progress_label: Option<String>,
    pub progress_current: Option<f64>,
    pub progress_total: Option<f64>,
    pub waiting_for: Option<String>,
    pub logs: Vec<RunLogEntry>,
    pub error: Option<String>,
    pub paused: bool,
    pub aborted: bool,
}

impl ScriptRun {
    pub fn new(
        run_id: &str,
        script_id: Option<String>,
        script_label: Option<String>,
        session_id: &str,
        started_at: i64,
    ) -> Self {
        Self {
            run_id: run_id.to_string(),
            script_id,
            script_label,
            session_id: session_id.to_string(),
            status: RunStatus::Running,
            started_at,
            ended_at: None,
            current_step: None,
            step_index: 0,
            total_steps: None,
            progress_mode: ProgressMode::Activity,
            activity_label: None,
            progress_label: None,
            progress_current: None,
            progress_total: None,
            waiting_for: None,
            logs: Vec::new(),
            error: None,
            paused: false,
            aborted: false,
        }
    }

    /// `run.aborted || run.endedAt`.
    pub fn is_finished(&self) -> bool {
        self.aborted || self.ended_at.is_some()
    }

    /// Reset the progress fields when a run ends.
    pub fn clear_progress(&mut self) {
        self.progress_mode = ProgressMode::Activity;
        self.progress_label = None;
        self.progress_current = None;
        self.progress_total = None;
    }

    /// `serializeRun`.
    pub fn serialize(&self, now: i64) -> SerializedRun {
        let elapsed_ms = match self.ended_at {
            Some(ended) => ended - self.started_at,
            None => (now - self.started_at).max(0),
        };
        let skip = self.logs.len().saturating_sub(200);
        SerializedRun {
            run_id: self.run_id.clone(),
            script_id: self.script_id.clone(),
            script_label: self.script_label.clone(),
            session_id: self.session_id.clone(),
            status: self.status,
            started_at: self.started_at,
            ended_at: self.ended_at,
            current_step: self.current_step.clone(),
            step_index: self.step_index,
            total_steps: self.total_steps,
            progress_mode: self.progress_mode,
            activity_label: self.activity_label.clone(),
            progress_label: self.progress_label.clone(),
            progress_current: self.progress_current,
            progress_total: self.progress_total,
            elapsed_ms,
            waiting_for: self.waiting_for.clone(),
            logs: self.logs[skip..].to_vec(),
            error: self.error.clone(),
        }
    }

    /// `Object.assign(run, patch)` for the runtime's status patches.
    pub fn apply(&mut self, patch: &StatusPatch) {
        if let Some(status) = patch.status {
            self.status = status;
        }
        if let Some(mode) = patch.progress_mode {
            self.progress_mode = mode;
        }
        if let Some(label) = &patch.progress_label {
            self.progress_label = label.clone();
        }
        if let Some(current) = &patch.progress_current {
            self.progress_current = *current;
        }
        if let Some(total) = &patch.progress_total {
            self.progress_total = *total;
        }
        if let Some(step_index) = patch.step_index {
            self.step_index = step_index;
        }
        if let Some(label) = &patch.activity_label {
            self.activity_label = label.clone();
        }
        if let Some(step) = &patch.current_step {
            self.current_step = step.clone();
        }
        if let Some(waiting) = &patch.waiting_for {
            self.waiting_for = waiting.clone();
        }
    }
}

/// `ScriptRun` as the renderer receives it (camelCase, `logs` capped at
/// the newest 200 entries).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SerializedRun {
    pub run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_label: Option<String>,
    pub session_id: String,
    pub status: RunStatus,
    pub started_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_step: Option<String>,
    pub step_index: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_steps: Option<u64>,
    pub progress_mode: ProgressMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_current: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_total: Option<f64>,
    pub elapsed_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiting_for: Option<String>,
    pub logs: Vec<RunLogEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A status patch (`onStatusChange(runId, patch)`). Outer `None` = key
/// absent (keep), `Some(None)` = key set to `undefined` (clear).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StatusPatch {
    pub status: Option<RunStatus>,
    pub progress_mode: Option<ProgressMode>,
    pub progress_label: Option<Option<String>>,
    pub progress_current: Option<Option<f64>>,
    pub progress_total: Option<Option<f64>>,
    pub step_index: Option<u64>,
    pub activity_label: Option<Option<String>>,
    pub current_step: Option<Option<String>>,
    pub waiting_for: Option<Option<String>>,
}

impl StatusPatch {
    pub fn status(status: RunStatus) -> Self {
        Self {
            status: Some(status),
            ..Default::default()
        }
    }

    pub fn waiting(status: RunStatus, waiting_for: Option<String>) -> Self {
        Self {
            status: Some(status),
            waiting_for: Some(waiting_for),
            ..Default::default()
        }
    }
}

/// Milliseconds since the Unix epoch (`Date.now()`).
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_with_elapsed_and_capped_logs() {
        let mut run = ScriptRun::new("r1", Some("s".into()), None, "sess", 1_000);
        for i in 0..250 {
            run.logs.push(RunLogEntry {
                at: i,
                message: format!("log-{i}"),
            });
        }
        let serialized = run.serialize(1_500);
        assert_eq!(serialized.elapsed_ms, 500);
        assert_eq!(serialized.logs.len(), 200);
        assert_eq!(serialized.logs[0].message, "log-50");
        let json = serde_json::to_value(&serialized).unwrap();
        assert_eq!(json["runId"], "r1");
        assert_eq!(json["progressMode"], "activity");
        assert_eq!(json["status"], "running");
        assert!(json.get("endedAt").is_none());
        run.ended_at = Some(1_200);
        assert_eq!(run.serialize(9_999).elapsed_ms, 200);
    }

    #[test]
    fn patches_distinguish_keep_from_clear() {
        let mut run = ScriptRun::new("r1", None, None, "sess", 0);
        run.waiting_for = Some("x".into());
        run.apply(&StatusPatch::status(RunStatus::Paused));
        assert_eq!(run.waiting_for.as_deref(), Some("x"));
        run.apply(&StatusPatch::waiting(RunStatus::Running, None));
        assert_eq!(run.waiting_for, None);
        assert_eq!(run.status, RunStatus::Running);
    }
}

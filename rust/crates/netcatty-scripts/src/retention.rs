//! Run history retention (`electron/scripts/scriptRunRetention.cjs`).

use crate::run::{RunLogEntry, ScriptRun};
use std::collections::HashMap;

pub const MAX_RETAINED_COMPLETED_RUNS: usize = 200;
pub const MAX_RETAINED_LOGS_PER_RUN: usize = 200;

/// Append a log entry, keeping only the newest `limit` entries.
pub fn append_retained_run_log(run: &mut ScriptRun, entry: RunLogEntry, limit: usize) {
    run.logs.push(entry);
    let overflow = run.logs.len().saturating_sub(limit);
    if overflow > 0 {
        run.logs.drain(..overflow);
    }
}

/// Drop the oldest completed runs beyond `limit`; active runs are never
/// removed. Returns how many were removed.
pub fn prune_completed_runs(runs: &mut HashMap<String, ScriptRun>, limit: usize) -> usize {
    let mut completed: Vec<(i64, i64, String)> = runs
        .values()
        .filter_map(|run| {
            run.ended_at
                .map(|ended| (ended, run.started_at, run.run_id.clone()))
        })
        .collect();
    completed.sort();
    let overflow = completed.len().saturating_sub(limit);
    for (_, _, run_id) in completed.iter().take(overflow) {
        runs.remove(run_id);
    }
    overflow
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_history_is_bounded_without_removing_active_runs() {
        let mut runs = HashMap::new();
        for index in 0..(MAX_RETAINED_COMPLETED_RUNS + 25) as i64 {
            let id = format!("completed-{index}");
            let mut run = ScriptRun::new(&id, None, None, "s", index);
            run.ended_at = Some(index + 1);
            runs.insert(id, run);
        }
        runs.insert("active".into(), ScriptRun::new("active", None, None, "s", 0));
        assert_eq!(prune_completed_runs(&mut runs, MAX_RETAINED_COMPLETED_RUNS), 25);
        assert_eq!(runs.len(), MAX_RETAINED_COMPLETED_RUNS + 1);
        assert!(runs.contains_key("active"));
        assert!(!runs.contains_key("completed-0"));
        assert!(runs.contains_key(&format!("completed-{}", MAX_RETAINED_COMPLETED_RUNS + 24)));
    }

    #[test]
    fn logs_keep_only_the_newest_bounded_tail() {
        let mut run = ScriptRun::new("r", None, None, "s", 0);
        for index in 0..(MAX_RETAINED_LOGS_PER_RUN + 30) {
            append_retained_run_log(
                &mut run,
                RunLogEntry {
                    at: 0,
                    message: format!("log-{index}"),
                },
                MAX_RETAINED_LOGS_PER_RUN,
            );
        }
        assert_eq!(run.logs.len(), MAX_RETAINED_LOGS_PER_RUN);
        assert_eq!(run.logs[0].message, "log-30");
        assert_eq!(
            run.logs.last().unwrap().message,
            format!("log-{}", MAX_RETAINED_LOGS_PER_RUN + 29)
        );
    }
}

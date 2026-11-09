//! Global transfer admission queue (Electron `transferBridge.cjs`:
//! `runAdmittedTransfer`, `pumpAdmittedTransfers`, `prioritizeQueuedTransfer`,
//! `pauseQueuedTransfer`, `cancelQueuedTransfer`,
//! `setGlobalTransferConcurrency`).
//!
//! Every renderer-started transfer is queued with its *resource keys*
//! (`host:<hostId>` or `session:<sftpId>` for each remote endpoint, `local`
//! when both ends are local). A job is admitted when every one of its keys
//! has fewer than `limit` running transfers; jobs are scanned in queue order
//! so a blocked job never holds back a later job for another host. The
//! admitted job receives a [`Slot`]; dropping the slot frees its keys and
//! admits the next runnable jobs.

use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::oneshot;

/// Default per-resource limit (Electron `admittedTransferLimit = 2`).
pub const DEFAULT_LIMIT: usize = 2;
/// Accepted range of `setGlobalTransferConcurrency`.
pub const MIN_LIMIT: usize = 1;
pub const MAX_LIMIT: usize = 16;

/// Electron `getAdmissionResourceKeys`.
pub fn resource_keys(
    source_host_id: Option<&str>,
    source_sftp_id: Option<&str>,
    target_host_id: Option<&str>,
    target_sftp_id: Option<&str>,
) -> Vec<String> {
    let key = |host: Option<&str>, sftp: Option<&str>| -> Option<String> {
        match (
            host.filter(|h| !h.is_empty()),
            sftp.filter(|s| !s.is_empty()),
        ) {
            (Some(host), _) => Some(format!("host:{host}")),
            (None, Some(sftp)) => Some(format!("session:{sftp}")),
            (None, None) => None,
        }
    };
    let mut keys: Vec<String> = Vec::new();
    for k in [
        key(source_host_id, source_sftp_id),
        key(target_host_id, target_sftp_id),
    ]
    .into_iter()
    .flatten()
    {
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    if keys.is_empty() {
        keys.push("local".to_string());
    }
    keys
}

/// Normalize a requested limit: integers in `1..=16`, otherwise `None`.
pub fn normalize_limit(value: f64) -> Option<usize> {
    if value.is_finite()
        && value.fract() == 0.0
        && (MIN_LIMIT as f64..=MAX_LIMIT as f64).contains(&value)
    {
        Some(value as usize)
    } else {
        None
    }
}

/// What a queued job is told.
#[derive(Debug)]
pub enum Admission {
    /// Run now; hold the slot until the transfer ends.
    Run(Slot),
    /// Cancelled while still queued.
    Cancelled,
    /// Paused while still queued (the renderer resumes by starting it again).
    Paused,
}

struct Job {
    transfer_id: String,
    keys: Vec<String>,
    tx: oneshot::Sender<Admission>,
}

struct Inner {
    limit: usize,
    active: HashMap<String, usize>,
    queue: VecDeque<Job>,
}

impl Inner {
    fn can_admit(&self, keys: &[String]) -> bool {
        keys.iter()
            .all(|k| self.active.get(k).copied().unwrap_or(0) < self.limit)
    }

    fn adjust(&mut self, keys: &[String], up: bool) {
        for key in keys {
            let next = self.active.get(key).copied().unwrap_or(0);
            let next = if up { next + 1 } else { next.saturating_sub(1) };
            if next == 0 {
                self.active.remove(key);
            } else {
                self.active.insert(key.clone(), next);
            }
        }
    }

    fn position(&self, transfer_id: &str) -> Option<usize> {
        self.queue.iter().position(|j| j.transfer_id == transfer_id)
    }
}

/// Shared admission queue. Cheap to clone.
#[derive(Clone)]
pub struct AdmissionQueue {
    inner: Arc<Mutex<Inner>>,
}

impl Default for AdmissionQueue {
    fn default() -> Self {
        Self::new(DEFAULT_LIMIT)
    }
}

impl std::fmt::Debug for AdmissionQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("AdmissionQueue")
            .field("limit", &inner.limit)
            .field("queued", &inner.queue.len())
            .finish()
    }
}

/// Waiting end of a queued job.
pub struct Ticket {
    rx: oneshot::Receiver<Admission>,
}

impl Ticket {
    /// Wait until the job is admitted, cancelled or paused.
    pub async fn wait(self) -> Admission {
        self.rx.await.unwrap_or(Admission::Cancelled)
    }
}

/// A running transfer's claim on its resource keys.
pub struct Slot {
    queue: Arc<Mutex<Inner>>,
    keys: Vec<String>,
    armed: bool,
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot").field("keys", &self.keys).finish()
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut inner = self.queue.lock();
        inner.adjust(&self.keys, false);
        pump(&self.queue, &mut inner);
    }
}

/// Admit every runnable job (never drops an armed slot while locked).
fn pump(queue: &Arc<Mutex<Inner>>, inner: &mut Inner) {
    loop {
        let Some(index) = (0..inner.queue.len()).find(|&i| inner.can_admit(&inner.queue[i].keys))
        else {
            return;
        };
        let Some(job) = inner.queue.remove(index) else {
            return;
        };
        inner.adjust(&job.keys, true);
        let slot = Slot {
            queue: queue.clone(),
            keys: job.keys.clone(),
            armed: true,
        };
        if let Err(Admission::Run(mut slot)) = job.tx.send(Admission::Run(slot)) {
            // The waiter went away: give the keys back without re-locking.
            slot.armed = false;
            inner.adjust(&job.keys, false);
        }
    }
}

impl AdmissionQueue {
    pub fn new(limit: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                limit: limit.clamp(MIN_LIMIT, MAX_LIMIT),
                active: HashMap::new(),
                queue: VecDeque::new(),
            })),
        }
    }

    /// Queue a job (at the back) and admit whatever can run.
    pub fn enqueue(&self, transfer_id: &str, keys: Vec<String>) -> Ticket {
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.lock();
        inner.queue.push_back(Job {
            transfer_id: transfer_id.to_string(),
            keys,
            tx,
        });
        pump(&self.inner, &mut inner);
        Ticket { rx }
    }

    /// Current per-resource limit.
    pub fn limit(&self) -> usize {
        self.inner.lock().limit
    }

    /// Set the limit when `value` is an integer in `1..=16`; returns the
    /// effective limit. A raised limit admits waiting jobs at once.
    pub fn set_limit(&self, value: f64) -> usize {
        let mut inner = self.inner.lock();
        if let Some(limit) = normalize_limit(value) {
            inner.limit = limit;
            pump(&self.inner, &mut inner);
        }
        inner.limit
    }

    /// Move a queued job to the front. `false` when it is not queued.
    pub fn prioritize(&self, transfer_id: &str) -> bool {
        let mut inner = self.inner.lock();
        let Some(index) = inner.position(transfer_id) else {
            return false;
        };
        if let Some(job) = inner.queue.remove(index) {
            inner.queue.push_front(job);
        }
        true
    }

    pub fn is_queued(&self, transfer_id: &str) -> bool {
        self.inner.lock().position(transfer_id).is_some()
    }

    fn take(&self, transfer_id: &str) -> Option<Job> {
        let mut inner = self.inner.lock();
        let index = inner.position(transfer_id)?;
        inner.queue.remove(index)
    }

    /// Cancel a queued job. `false` when it is not queued.
    pub fn cancel_queued(&self, transfer_id: &str) -> bool {
        match self.take(transfer_id) {
            Some(job) => {
                let _ = job.tx.send(Admission::Cancelled);
                true
            }
            None => false,
        }
    }

    /// Pause a queued job. `false` when it is not queued.
    pub fn pause_queued(&self, transfer_id: &str) -> bool {
        match self.take(transfer_id) {
            Some(job) => {
                let _ = job.tx.send(Admission::Paused);
                true
            }
            None => false,
        }
    }

    /// Ids still waiting, in admission order.
    pub fn queued_ids(&self) -> Vec<String> {
        self.inner
            .lock()
            .queue
            .iter()
            .map(|j| j.transfer_id.clone())
            .collect()
    }

    /// Running transfers holding `key`.
    pub fn active_for(&self, key: &str) -> usize {
        self.inner.lock().active.get(key).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(k: &str) -> Vec<String> {
        vec![k.to_string()]
    }

    fn admitted(ticket: &mut Ticket) -> Option<Admission> {
        ticket.rx.try_recv().ok()
    }

    #[test]
    fn resource_keys_prefer_host_then_session_then_local() {
        assert_eq!(
            resource_keys(Some("h1"), Some("s1"), None, Some("s2")),
            vec!["host:h1", "session:s2"]
        );
        assert_eq!(
            resource_keys(None, None, Some("h"), Some("s")),
            vec!["host:h"]
        );
        assert_eq!(
            resource_keys(Some("h"), None, Some("h"), None),
            vec!["host:h"]
        );
        assert_eq!(resource_keys(Some(""), None, None, None), vec!["local"]);
    }

    #[test]
    fn limit_accepts_integers_in_range_only() {
        let q = AdmissionQueue::default();
        assert_eq!(q.limit(), 2);
        assert_eq!(q.set_limit(4.0), 4);
        assert_eq!(q.set_limit(0.0), 4);
        assert_eq!(q.set_limit(17.0), 4);
        assert_eq!(q.set_limit(2.5), 4);
        assert_eq!(q.set_limit(f64::NAN), 4);
        assert_eq!(q.set_limit(16.0), 16);
    }

    #[test]
    fn jobs_beyond_the_limit_wait_and_run_when_a_slot_frees() {
        let q = AdmissionQueue::new(1);
        let mut a = q.enqueue("a", keys("host:x"));
        let mut b = q.enqueue("b", keys("host:x"));
        let slot_a = match admitted(&mut a) {
            Some(Admission::Run(slot)) => slot,
            other => panic!("a not admitted: {other:?}"),
        };
        assert!(admitted(&mut b).is_none());
        assert_eq!(q.queued_ids(), vec!["b"]);
        drop(slot_a);
        assert!(matches!(admitted(&mut b), Some(Admission::Run(_))));
        assert!(q.queued_ids().is_empty());
    }

    #[test]
    fn other_hosts_are_not_blocked_by_a_busy_host() {
        let q = AdmissionQueue::new(1);
        let mut a = q.enqueue("a", keys("host:x"));
        let mut b = q.enqueue("b", keys("host:x"));
        let mut c = q.enqueue("c", keys("host:y"));
        let _slot = admitted(&mut a);
        assert!(admitted(&mut b).is_none());
        assert!(matches!(admitted(&mut c), Some(Admission::Run(_))));
    }

    #[test]
    fn prioritize_moves_a_queued_job_to_the_front() {
        let q = AdmissionQueue::new(1);
        let mut a = q.enqueue("a", keys("local"));
        let mut b = q.enqueue("b", keys("local"));
        let mut c = q.enqueue("c", keys("local"));
        assert!(q.prioritize("c"));
        assert!(!q.prioritize("a"), "running jobs are not queued");
        assert!(!q.prioritize("missing"));
        let slot = match admitted(&mut a) {
            Some(Admission::Run(slot)) => slot,
            _ => panic!(),
        };
        drop(slot);
        let c_slot = admitted(&mut c);
        assert!(matches!(c_slot, Some(Admission::Run(_))));
        assert!(admitted(&mut b).is_none());
    }

    #[test]
    fn queued_jobs_can_be_cancelled_or_paused() {
        let q = AdmissionQueue::new(1);
        let mut a = q.enqueue("a", keys("local"));
        let mut b = q.enqueue("b", keys("local"));
        let mut c = q.enqueue("c", keys("local"));
        assert!(q.cancel_queued("b"));
        assert!(q.pause_queued("c"));
        assert!(!q.cancel_queued("b"));
        assert!(matches!(admitted(&mut b), Some(Admission::Cancelled)));
        assert!(matches!(admitted(&mut c), Some(Admission::Paused)));
        assert!(matches!(admitted(&mut a), Some(Admission::Run(_))));
    }

    #[test]
    fn raising_the_limit_admits_waiting_jobs() {
        let q = AdmissionQueue::new(1);
        let mut a = q.enqueue("a", keys("local"));
        let mut b = q.enqueue("b", keys("local"));
        let _slot = admitted(&mut a);
        assert!(admitted(&mut b).is_none());
        q.set_limit(2.0);
        let b_slot = admitted(&mut b);
        assert!(matches!(b_slot, Some(Admission::Run(_))));
        assert_eq!(q.active_for("local"), 2);
    }

    #[test]
    fn an_abandoned_ticket_does_not_leak_its_slot() {
        let q = AdmissionQueue::new(1);
        let mut a = q.enqueue("a", keys("local"));
        let b = q.enqueue("b", keys("local"));
        let mut c = q.enqueue("c", keys("local"));
        drop(b);
        let slot = match admitted(&mut a) {
            Some(Admission::Run(slot)) => slot,
            _ => panic!(),
        };
        drop(slot);
        let c_slot = admitted(&mut c);
        assert!(matches!(c_slot, Some(Admission::Run(_))));
        assert_eq!(q.active_for("local"), 1);
    }

    #[tokio::test]
    async fn ticket_wait_resolves() {
        let q = AdmissionQueue::new(1);
        let a = q.enqueue("a", keys("local"));
        assert!(matches!(a.wait().await, Admission::Run(_)));
        assert_eq!(q.active_for("local"), 0, "slot dropped with the admission");
    }
}

//! Idle close of agent-opened sessions (Electron
//! `mcpServerBridge/sessionIdleManager.cjs`).

use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::time::Instant;

pub const DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES: u64 = 480;
pub const MIN_SESSION_IDLE_TIMEOUT_MINUTES: u64 = 1;
pub const MAX_SESSION_IDLE_TIMEOUT_MINUTES: u64 = 24 * 60;

pub fn normalize_session_idle_timeout_minutes(value: Option<f64>) -> u64 {
    match value {
        Some(v) if v.is_finite() => (v.round() as i64).clamp(MIN_SESSION_IDLE_TIMEOUT_MINUTES as i64, MAX_SESSION_IDLE_TIMEOUT_MINUTES as i64) as u64,
        _ => DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES,
    }
}

/// Callback when a tracked session went idle: `(chat, session, version)`.
pub type OnIdle = Arc<dyn Fn(String, String, u64) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

struct Entry {
    chat_session_id: String,
    last_activity_at: Instant,
    activity_version: u64,
    active_count: u32,
    checking: bool,
    closing: bool,
    timer: Option<tokio::task::JoinHandle<()>>,
}

pub struct SessionIdleManager {
    entries: Mutex<HashMap<String, Entry>>,
    timeout_minutes: Mutex<u64>,
    on_idle: Mutex<Option<OnIdle>>,
    me: Mutex<Weak<SessionIdleManager>>,
}

impl SessionIdleManager {
    pub fn new(timeout_minutes: Option<f64>) -> Arc<Self> {
        let m = Arc::new(Self {
            entries: Default::default(),
            timeout_minutes: Mutex::new(normalize_session_idle_timeout_minutes(timeout_minutes)),
            on_idle: Default::default(),
            me: Default::default(),
        });
        *m.me.lock() = Arc::downgrade(&m);
        m
    }

    pub fn set_on_idle(&self, cb: OnIdle) {
        *self.on_idle.lock() = Some(cb);
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(*self.timeout_minutes.lock() * 60)
    }

    fn schedule(&self, session_id: &str, entries: &mut HashMap<String, Entry>) {
        let Some(entry) = entries.get_mut(session_id) else {
            return;
        };
        if let Some(t) = entry.timer.take() {
            t.abort();
        }
        if entry.active_count > 0 || entry.checking || entry.closing {
            return;
        }
        let me = self.me.lock().clone();
        let id = session_id.to_string();
        let expires_at = entry.last_activity_at + self.timeout();
        entry.timer = Some(tokio::spawn(async move {
            tokio::time::sleep_until(expires_at).await;
            if let Some(m) = me.upgrade() {
                m.fire(&id);
            }
        }));
    }

    fn fire(&self, session_id: &str) {
        let mut entries = self.entries.lock();
        let timeout = self.timeout();
        let Some(entry) = entries.get_mut(session_id) else {
            return;
        };
        entry.timer = None;
        if entry.active_count > 0 || entry.checking || entry.closing {
            return;
        }
        if Instant::now() < entry.last_activity_at + timeout {
            self.schedule(session_id, &mut entries);
            return;
        }
        entry.checking = true;
        let version = entry.activity_version;
        let chat = entry.chat_session_id.clone();
        drop(entries);
        if let Some(cb) = self.on_idle.lock().clone() {
            let id = session_id.to_string();
            tokio::spawn(cb(chat, id, version));
        }
    }

    pub fn track(&self, chat: &str, session_id: &str) -> bool {
        if chat.is_empty() || session_id.is_empty() {
            return false;
        }
        let mut entries = self.entries.lock();
        if let Some(old) = entries.remove(session_id) {
            if let Some(t) = old.timer {
                t.abort();
            }
        }
        entries.insert(
            session_id.to_string(),
            Entry {
                chat_session_id: chat.to_string(),
                last_activity_at: Instant::now(),
                activity_version: 0,
                active_count: 0,
                checking: false,
                closing: false,
                timer: None,
            },
        );
        self.schedule(session_id, &mut entries);
        true
    }

    pub fn touch(&self, session_id: &str) -> bool {
        let mut entries = self.entries.lock();
        let Some(e) = entries.get_mut(session_id) else {
            return false;
        };
        if e.closing {
            return false;
        }
        e.checking = false;
        e.activity_version += 1;
        e.last_activity_at = Instant::now();
        if e.timer.is_none() {
            self.schedule(session_id, &mut entries);
        }
        true
    }

    pub fn begin_activity(&self, session_id: &str) -> bool {
        let mut entries = self.entries.lock();
        let Some(e) = entries.get_mut(session_id) else {
            return false;
        };
        if e.closing {
            return false;
        }
        e.checking = false;
        e.activity_version += 1;
        e.active_count += 1;
        e.last_activity_at = Instant::now();
        if let Some(t) = e.timer.take() {
            t.abort();
        }
        true
    }

    pub fn end_activity(&self, session_id: &str) -> bool {
        let mut entries = self.entries.lock();
        let Some(e) = entries.get_mut(session_id) else {
            return false;
        };
        if e.closing {
            return false;
        }
        e.activity_version += 1;
        e.active_count = e.active_count.saturating_sub(1);
        e.last_activity_at = Instant::now();
        self.schedule(session_id, &mut entries);
        true
    }

    pub fn begin_close(&self, session_id: &str) -> bool {
        let mut entries = self.entries.lock();
        let Some(e) = entries.get_mut(session_id) else {
            return false;
        };
        if e.closing {
            return false;
        }
        e.checking = false;
        e.closing = true;
        if let Some(t) = e.timer.take() {
            t.abort();
        }
        true
    }

    pub fn is_idle_check_current(&self, session_id: &str, version: u64) -> bool {
        self.entries
            .lock()
            .get(session_id)
            .is_some_and(|e| e.checking && !e.closing && e.active_count == 0 && e.activity_version == version)
    }

    pub fn begin_idle_close(&self, session_id: &str, version: u64) -> bool {
        self.is_idle_check_current(session_id, version) && self.begin_close(session_id)
    }

    pub fn resume(&self, session_id: &str) -> bool {
        let mut entries = self.entries.lock();
        let Some(e) = entries.get_mut(session_id) else {
            return false;
        };
        e.closing = false;
        e.checking = false;
        e.activity_version += 1;
        e.active_count = 0;
        e.last_activity_at = Instant::now();
        self.schedule(session_id, &mut entries);
        true
    }

    pub fn forget_session(&self, session_id: &str) -> bool {
        match self.entries.lock().remove(session_id) {
            Some(e) => {
                if let Some(t) = e.timer {
                    t.abort();
                }
                true
            }
            None => false,
        }
    }

    pub fn set_timeout_minutes(&self, minutes: Option<f64>) -> u64 {
        let m = normalize_session_idle_timeout_minutes(minutes);
        *self.timeout_minutes.lock() = m;
        let mut entries = self.entries.lock();
        let ids: Vec<String> = entries.keys().cloned().collect();
        for id in ids {
            self.schedule(&id, &mut entries);
        }
        m
    }

    pub fn timeout_minutes(&self) -> u64 {
        *self.timeout_minutes.lock()
    }

    pub fn is_tracked(&self, session_id: &str) -> bool {
        self.entries.lock().contains_key(session_id)
    }

    pub fn is_closing(&self, session_id: &str) -> bool {
        self.entries.lock().get(session_id).is_some_and(|e| e.closing)
    }

    pub fn clear_all(&self) {
        for (_, e) in self.entries.lock().drain() {
            if let Some(t) = e.timer {
                t.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn manager() -> (Arc<SessionIdleManager>, Arc<Mutex<Vec<String>>>) {
        let m = SessionIdleManager::new(Some(1.0));
        let closed = Arc::new(Mutex::new(Vec::new()));
        let c = closed.clone();
        let weak = Arc::downgrade(&m);
        m.set_on_idle(Arc::new(move |_chat, id, version| {
            let c = c.clone();
            let weak = weak.clone();
            Box::pin(async move {
                if let Some(m) = weak.upgrade() {
                    if m.begin_idle_close(&id, version) {
                        c.lock().push(id);
                    }
                }
            })
        }));
        (m, closed)
    }

    #[tokio::test(start_paused = true)]
    async fn idle_sessions_close_independently_and_activity_renews() {
        let (m, closed) = manager();
        m.track("chat", "a");
        m.track("chat", "b");
        tokio::time::sleep(Duration::from_secs(30)).await;
        m.touch("b");
        tokio::time::sleep(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
        assert_eq!(*closed.lock(), vec!["a".to_string()]);
        tokio::time::sleep(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
        assert_eq!(closed.lock().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn in_flight_operation_cannot_time_out() {
        let (m, closed) = manager();
        m.track("chat", "a");
        m.begin_activity("a");
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert!(closed.lock().is_empty());
        m.end_activity("a");
        tokio::time::sleep(Duration::from_secs(59)).await;
        assert!(closed.lock().is_empty());
        tokio::time::sleep(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert_eq!(closed.lock().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn activity_during_idle_check_invalidates_it() {
        let m = SessionIdleManager::new(Some(1.0));
        let versions = Arc::new(Mutex::new(Vec::new()));
        let v = versions.clone();
        m.set_on_idle(Arc::new(move |_c, _id, version| {
            v.lock().push(version);
            Box::pin(async {})
        }));
        m.track("chat", "a");
        tokio::time::sleep(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        let version = versions.lock()[0];
        m.begin_activity("a");
        m.end_activity("a");
        assert!(!m.begin_idle_close("a", version));
        assert!(!m.is_closing("a"));
        let count = AtomicUsize::new(0);
        count.fetch_add(1, Ordering::SeqCst);
        assert!(m.resume("a"));
        assert!(m.forget_session("a"));
        assert_eq!(normalize_session_idle_timeout_minutes(Some(0.0)), 1);
        assert_eq!(normalize_session_idle_timeout_minutes(None), 480);
    }
}

//! Registry of in-flight executions keyed by marker, for chat-scoped
//! cancellation (Electron `activePtyExecs`).

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

type CancelFn = Arc<dyn Fn() + Send + Sync>;

struct Entry {
    chat_session_id: Option<String>,
    cancel: CancelFn,
}

#[derive(Default)]
pub struct ActiveExecs {
    entries: Mutex<HashMap<String, Entry>>,
}

/// Removes its entry when dropped (the execution settled).
pub struct ExecGuard {
    registry: Arc<ActiveExecs>,
    key: String,
}

impl Drop for ExecGuard {
    fn drop(&mut self) {
        self.registry.entries.lock().remove(&self.key);
    }
}

impl ActiveExecs {
    /// Register `cancel` under `key` for `chat_session_id`.
    pub fn register(self: &Arc<Self>, key: impl Into<String>, chat_session_id: Option<&str>, cancel: CancelFn) -> ExecGuard {
        let key = key.into();
        self.entries.lock().insert(
            key.clone(),
            Entry {
                chat_session_id: chat_session_id.map(str::to_string),
                cancel,
            },
        );
        ExecGuard {
            registry: self.clone(),
            key,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }

    /// Cancel every execution of a chat session.
    pub fn cancel_for_chat(&self, chat_session_id: &str) {
        if chat_session_id.is_empty() {
            return;
        }
        let cancels: Vec<CancelFn> = {
            let mut entries = self.entries.lock();
            let keys: Vec<String> = entries
                .iter()
                .filter(|(_, e)| e.chat_session_id.as_deref() == Some(chat_session_id))
                .map(|(k, _)| k.clone())
                .collect();
            keys.into_iter().filter_map(|k| entries.remove(&k)).map(|e| e.cancel).collect()
        };
        for cancel in cancels {
            cancel();
        }
    }

    pub fn cancel_all(&self) {
        let cancels: Vec<CancelFn> = self.entries.lock().drain().map(|(_, e)| e.cancel).collect();
        for cancel in cancels {
            cancel();
        }
    }

    /// A fresh pending key (`__NCMCP_<kind>_PENDING_<time>_<hex>__`).
    pub fn pending_key(kind: &str) -> String {
        let bytes: [u8; 8] = rand::random();
        format!("__NCMCP_{kind}_PENDING_{}_{}__", crate::helpers::base36_now(), hex::encode(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn cancels_only_matching_chat_and_guard_removes_entry() {
        let registry = Arc::new(ActiveExecs::default());
        let hits = Arc::new(AtomicUsize::new(0));
        let h1 = hits.clone();
        let h2 = hits.clone();
        let g1 = registry.register("a", Some("chat-1"), Arc::new(move || { h1.fetch_add(1, Ordering::SeqCst); }));
        let _g2 = registry.register("b", Some("chat-2"), Arc::new(move || { h2.fetch_add(10, Ordering::SeqCst); }));
        assert_eq!(registry.len(), 2);
        registry.cancel_for_chat("chat-1");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(registry.len(), 1);
        drop(g1);
        registry.cancel_all();
        assert_eq!(hits.load(Ordering::SeqCst), 11);
        assert!(registry.is_empty());
        assert!(ActiveExecs::pending_key("CH").starts_with("__NCMCP_CH_PENDING_"));
    }
}

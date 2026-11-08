//! Runtime lock state (Electron `createAppLockRuntimeBridge`).
//!
//! Every patch bumps `version`, which the controller uses as a "lock epoch":
//! a password check or OS prompt that started under one epoch must not
//! unlock a newer lock (idle → background re-lock while a dialog is open).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeState {
    pub initialized: bool,
    pub locked: bool,
    pub reason: Option<String>,
    pub version: u64,
    pub last_locked_at: Option<i64>,
    pub last_unlocked_at: Option<i64>,
    pub last_activity_at: Option<i64>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            initialized: false,
            locked: false,
            reason: None,
            version: 0,
            last_locked_at: None,
            last_unlocked_at: None,
            last_activity_at: None,
        }
    }
}

fn normalize_reason(reason: Option<&str>) -> Option<String> {
    reason
        .filter(|r| !r.trim().is_empty())
        .map(str::to_string)
}

/// Pure state machine; the controller owns timers and broadcasting.
#[derive(Debug, Default)]
pub struct Runtime {
    state: RuntimeState,
}

impl Runtime {
    pub fn state(&self) -> RuntimeState {
        self.state.clone()
    }

    fn patch(&mut self, f: impl FnOnce(&mut RuntimeState)) -> RuntimeState {
        f(&mut self.state);
        self.state.version += 1;
        self.state.clone()
    }

    /// Startup initialisation: locked with reason `startup` unless told otherwise.
    pub fn initialize(&mut self, locked: bool, reason: Option<&str>, now: i64) -> RuntimeState {
        self.patch(|s| {
            s.initialized = true;
            s.locked = locked;
            s.reason = if locked {
                normalize_reason(reason).or_else(|| Some("startup".into()))
            } else {
                None
            };
            s.last_locked_at = locked.then_some(now);
            s.last_unlocked_at = None;
            s.last_activity_at = Some(now);
        })
    }

    /// Lock with `reason` (default `manual`). Re-locking with the same reason
    /// is a no-op (no version bump, no broadcast); a different reason bumps
    /// the epoch.
    pub fn lock(&mut self, reason: Option<&str>, now: i64) -> (RuntimeState, bool) {
        let next_reason = normalize_reason(reason).unwrap_or_else(|| "manual".into());
        if self.state.initialized && self.state.locked && self.state.reason.as_deref() == Some(&next_reason) {
            return (self.state(), false);
        }
        let state = self.patch(|s| {
            s.initialized = true;
            s.locked = true;
            s.reason = Some(next_reason);
            s.last_locked_at = Some(now);
        });
        (state, true)
    }

    pub fn unlock(&mut self, now: i64) -> (RuntimeState, bool) {
        if self.state.initialized && !self.state.locked && self.state.reason.is_none() {
            return (self.state(), false);
        }
        let state = self.patch(|s| {
            s.initialized = true;
            s.locked = false;
            s.reason = None;
            s.last_unlocked_at = Some(now);
            s.last_activity_at = Some(now);
        });
        (state, true)
    }

    /// Activity while unlocked moves the idle deadline (no broadcast).
    pub fn record_activity(&mut self, timestamp: i64) -> (RuntimeState, bool) {
        if !self.state.initialized || self.state.locked || self.state.last_activity_at == Some(timestamp) {
            return (self.state(), false);
        }
        let state = self.patch(|s| s.last_activity_at = Some(timestamp));
        (state, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_locked_on_startup() {
        let mut rt = Runtime::default();
        let s = rt.initialize(true, None, 10);
        assert!(s.initialized && s.locked);
        assert_eq!(s.reason.as_deref(), Some("startup"));
        assert_eq!(s.last_locked_at, Some(10));
        assert_eq!(s.last_activity_at, Some(10));
        assert_eq!(s.version, 1);
    }

    #[test]
    fn initialize_unlocked() {
        let mut rt = Runtime::default();
        let s = rt.initialize(false, Some("startup"), 10);
        assert!(s.initialized && !s.locked);
        assert_eq!(s.reason, None);
        assert_eq!(s.last_locked_at, None);
    }

    #[test]
    fn lock_same_reason_is_noop_but_new_reason_bumps_version() {
        let mut rt = Runtime::default();
        rt.initialize(false, None, 0);
        let (a, changed) = rt.lock(Some("idle"), 1);
        assert!(changed);
        let (b, changed) = rt.lock(Some("idle"), 2);
        assert!(!changed);
        assert_eq!(a.version, b.version);
        let (c, changed) = rt.lock(Some("background"), 3);
        assert!(changed);
        assert_eq!(c.version, a.version + 1);
        assert_eq!(c.reason.as_deref(), Some("background"));
        let (d, _) = rt.lock(Some("  "), 4);
        assert_eq!(d.reason.as_deref(), Some("manual"));
    }

    #[test]
    fn unlock_resets_reason_and_activity() {
        let mut rt = Runtime::default();
        rt.initialize(true, None, 0);
        let (s, changed) = rt.unlock(50);
        assert!(changed && !s.locked);
        assert_eq!(s.reason, None);
        assert_eq!(s.last_unlocked_at, Some(50));
        assert_eq!(s.last_activity_at, Some(50));
        let (_, changed) = rt.unlock(60);
        assert!(!changed);
    }

    #[test]
    fn activity_ignored_while_locked() {
        let mut rt = Runtime::default();
        rt.initialize(true, None, 0);
        let (_, changed) = rt.record_activity(5);
        assert!(!changed);
        rt.unlock(10);
        let (s, changed) = rt.record_activity(20);
        assert!(changed);
        assert_eq!(s.last_activity_at, Some(20));
        let (_, changed) = rt.record_activity(20);
        assert!(!changed);
    }
}

//! App lock controller (Electron `createAppLockController`).
//!
//! Owns the settings store, the runtime state and the idle timer, serialises
//! settings read-modify-write mutations, verifies passwords off the async
//! runtime, shares one in-flight password / OS-prompt attempt between
//! concurrent callers, and reports every transition through
//! [`AppLockEvents`] (the desktop app broadcasts them to all windows).

use crate::runtime::{Runtime, RuntimeState};
use crate::settings::{
    can_lock, create_password_verifier, normalize_timeout_minutes, should_lock_on_background_hide,
    verify_password, AppLockSettings, PasswordVerifier,
};
use crate::store::SettingsStore;
use crate::system_auth::{SystemAuth, SystemAuthStatus};
use futures::future::{BoxFuture, FutureExt, Shared};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::Notify;

/// Receives broadcasts (`netcatty:appLock:runtimeStateChanged`,
/// `netcatty:appLock:settingsChanged`).
pub trait AppLockEvents: Send + Sync + 'static {
    fn runtime_state_changed(&self, state: &RuntimeState);
    fn settings_changed(&self, public_settings: &AppLockSettings);
}

/// `{ ok, error? }` results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OkResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl OkResult {
    pub fn ok() -> Self {
        Self { ok: true, error: None }
    }
    pub fn err(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
        }
    }
}

/// Settings mutation result: the public settings or `{ ok: false, error }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum MutationResult {
    Settings(AppLockSettings),
    Failed(OkResult),
}

impl MutationResult {
    fn fail(error: &str) -> Self {
        Self::Failed(OkResult::err(error))
    }
}

/// `getAppLockSystemUnlockStatus` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemUnlockStatus {
    pub supported: bool,
    pub available: bool,
    pub enabled: bool,
    pub platform: String,
    pub label: Option<String>,
    pub reason: Option<String>,
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
pub type FailureDelay = Arc<dyn Fn(u64) -> BoxFuture<'static, ()> + Send + Sync>;

pub struct ControllerOptions {
    pub store: SettingsStore,
    pub system_auth: Arc<dyn SystemAuth>,
    pub events: Arc<dyn AppLockEvents>,
    /// Wall clock in ms (injected by tests).
    pub clock: Clock,
    /// Backoff after a wrong password (injected by tests).
    pub failure_delay: FailureDelay,
    /// Runtime that hosts the idle timer task.
    pub runtime: tokio::runtime::Handle,
    /// PBKDF2 rounds for new verifiers (tests use the minimum).
    pub new_verifier_iterations: Option<u32>,
}

pub fn wall_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    })
}

pub fn tokio_failure_delay() -> FailureDelay {
    Arc::new(|ms| tokio::time::sleep(Duration::from_millis(ms)).boxed())
}

type SharedResult<T> = Shared<BoxFuture<'static, T>>;

pub struct AppLockController {
    store: SettingsStore,
    runtime: Mutex<Runtime>,
    system_auth: Arc<dyn SystemAuth>,
    events: Arc<dyn AppLockEvents>,
    clock: Clock,
    failure_delay: FailureDelay,
    new_verifier_iterations: Option<u32>,
    mutation: tokio::sync::Mutex<()>,
    password_in_flight: Mutex<Option<SharedResult<OkResult>>>,
    system_in_flight: Mutex<Option<SharedResult<OkResult>>>,
    failure_count: AtomicU32,
    /// `Some(timeoutMinutes)` while the idle timer is armed.
    idle_timeout: Mutex<Option<u32>>,
    idle_notify: Arc<Notify>,
}

impl AppLockController {
    pub fn new(options: ControllerOptions) -> Arc<Self> {
        let this = Arc::new(Self {
            store: options.store,
            runtime: Mutex::new(Runtime::default()),
            system_auth: options.system_auth,
            events: options.events,
            clock: options.clock,
            failure_delay: options.failure_delay,
            new_verifier_iterations: options.new_verifier_iterations,
            mutation: tokio::sync::Mutex::new(()),
            password_in_flight: Mutex::new(None),
            system_in_flight: Mutex::new(None),
            failure_count: AtomicU32::new(0),
            idle_timeout: Mutex::new(None),
            idle_notify: Arc::new(Notify::new()),
        });
        options
            .runtime
            .spawn(idle_loop(Arc::downgrade(&this), this.idle_notify.clone()));
        this
    }

    /// Load the settings file and initialise the runtime: locked with reason
    /// `startup` when the lock is enabled. Returns the initial state.
    pub fn initialize(&self) -> RuntimeState {
        let settings = match self.store.load() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("failed to load app lock settings, defaulting to disabled: {e}");
                self.store.snapshot()
            }
        };
        let locked = can_lock(&settings);
        let state = self
            .runtime
            .lock()
            .initialize(locked, locked.then_some("startup"), self.now());
        self.sync_idle_timer();
        state
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    pub fn settings(&self) -> AppLockSettings {
        self.store.snapshot()
    }

    pub fn public_settings(&self) -> AppLockSettings {
        self.settings().public()
    }

    pub fn runtime_state(&self) -> RuntimeState {
        self.runtime.lock().state()
    }

    pub fn is_locked(&self) -> bool {
        self.runtime.lock().state().locked
    }

    fn broadcast_runtime(&self, state: &RuntimeState) {
        self.events.runtime_state_changed(state);
    }

    fn sync_idle_timer(&self) {
        let settings = self.settings();
        *self.idle_timeout.lock() = can_lock(&settings).then_some(settings.timeout_minutes);
        self.idle_notify.notify_one();
    }

    /// Absolute idle deadline (ms) while armed and unlocked.
    fn idle_deadline(&self) -> Option<i64> {
        let timeout = (*self.idle_timeout.lock())?;
        if timeout == 0 {
            return None;
        }
        let state = self.runtime.lock().state();
        if !state.initialized || state.locked {
            return None;
        }
        Some(state.last_activity_at? + i64::from(timeout) * 60_000)
    }

    /// Fired by the idle task at the deadline.
    fn on_idle_deadline(&self) {
        let Some(deadline) = self.idle_deadline() else {
            return;
        };
        if self.now() < deadline {
            return; // activity moved the deadline; the loop re-arms
        }
        if !can_lock(&self.settings()) {
            *self.idle_timeout.lock() = None;
            return;
        }
        let (state, changed) = self.runtime.lock().lock(Some("idle"), self.now());
        if changed {
            self.broadcast_runtime(&state);
        }
    }

    // -- settings mutations -------------------------------------------------

    async fn save_settings(&self, next: AppLockSettings) -> MutationResult {
        match self.store.save(&next) {
            Ok(_) => {
                self.sync_idle_timer();
                let public = self.public_settings();
                self.events.settings_changed(&public);
                MutationResult::Settings(public)
            }
            Err(e) => {
                tracing::warn!("failed to save app lock settings: {e}");
                MutationResult::fail("failed")
            }
        }
    }

    pub async fn request_enable(&self) -> MutationResult {
        let _guard = self.mutation.lock().await;
        let current = self.settings();
        if current.password_verifier.is_none() {
            return MutationResult::Settings(current.public());
        }
        self.save_settings(AppLockSettings {
            enabled: true,
            ..current
        })
        .await
    }

    async fn verify_current(&self, current: &AppLockSettings, password: &str) -> Result<(), MutationResult> {
        let Some(verifier) = current.password_verifier.clone() else {
            return Ok(());
        };
        if password.is_empty() {
            return Err(MutationResult::fail("empty-current"));
        }
        if verify_off_thread(password.to_string(), verifier).await {
            Ok(())
        } else {
            Err(MutationResult::fail("incorrect"))
        }
    }

    fn cleared(current: AppLockSettings) -> AppLockSettings {
        AppLockSettings {
            enabled: false,
            password_verifier: None,
            system_unlock_enabled: false,
            system_unlock_auto_prompt_enabled: false,
            ..current
        }
    }

    fn unlock_and_broadcast(&self) {
        let (state, _) = self.runtime.lock().unlock(self.now());
        self.sync_idle_timer();
        self.broadcast_runtime(&state);
    }

    /// Disable the lock (verifier removed). Requires the current password.
    pub async fn request_disable(&self, current_password: &str) -> MutationResult {
        let saved = {
            let _guard = self.mutation.lock().await;
            let current = self.settings();
            if let Err(fail) = self.verify_current(&current, current_password).await {
                return fail;
            }
            self.save_settings(Self::cleared(current)).await
        };
        self.unlock_and_broadcast();
        saved
    }

    /// "Forgot password" style reset: same as disable (Electron keeps both).
    pub async fn request_reset(&self, current_password: &str) -> MutationResult {
        self.request_disable(current_password).await
    }

    pub async fn request_password_change(&self, input: &Value) -> MutationResult {
        let next_password = input.get("nextPassword").and_then(Value::as_str).unwrap_or("").to_string();
        let current_password = input
            .get("currentPassword")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let had_verifier_at_request = self.settings().password_verifier.is_some();
        if next_password.is_empty() {
            return MutationResult::fail("empty-next");
        }
        let (saved, enabling_from_none) = {
            let _guard = self.mutation.lock().await;
            let current = self.settings();
            // A queued disable / reset removed the verifier: never turn a
            // password change into a first-time enable.
            if had_verifier_at_request && current.password_verifier.is_none() {
                return MutationResult::fail("incorrect");
            }
            if let Err(fail) = self.verify_current(&current, &current_password).await {
                return fail;
            }
            let enabling_from_none = current.password_verifier.is_none();
            let iterations = self.new_verifier_iterations;
            let verifier = tokio::task::spawn_blocking(move || match iterations {
                Some(n) => crate::settings::create_password_verifier_with(&next_password, n),
                None => create_password_verifier(&next_password),
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r);
            let verifier = match verifier {
                Ok(v) => v,
                Err(_) => return MutationResult::fail("empty-next"),
            };
            let enabled = current.enabled || enabling_from_none;
            let saved = self
                .save_settings(AppLockSettings {
                    enabled,
                    password_verifier: Some(verifier),
                    ..current
                })
                .await;
            (saved, enabling_from_none)
        };
        if enabling_from_none {
            // While disabled the renderer never reported activity; record it
            // now so arming the idle timer does not lock immediately.
            let now = self.now();
            self.runtime.lock().record_activity(now);
            self.sync_idle_timer();
        }
        saved
    }

    pub async fn set_timeout_minutes(&self, timeout: &Value) -> MutationResult {
        let _guard = self.mutation.lock().await;
        let current = self.settings();
        self.save_settings(AppLockSettings {
            timeout_minutes: normalize_timeout_minutes(timeout),
            ..current
        })
        .await
    }

    async fn system_status_only(&self) -> SystemAuthStatus {
        self.system_auth.status().await
    }

    pub async fn system_unlock_status(&self) -> SystemUnlockStatus {
        let status = self.system_status_only().await;
        let settings = self.settings();
        let can = can_lock(&settings);
        SystemUnlockStatus {
            supported: status.supported,
            available: status.available && can,
            enabled: settings.system_unlock_enabled && can,
            platform: status.platform,
            label: status.label,
            reason: status.reason,
        }
    }

    pub async fn set_system_unlock_enabled(&self, input: &Value) -> MutationResult {
        let enabled = input.get("enabled") == Some(&Value::Bool(true));
        let auto_prompt = input.get("autoPromptEnabled") == Some(&Value::Bool(true));
        let current_password = input
            .get("currentPassword")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let current = self.settings();
        if !can_lock(&current) {
            return MutationResult::fail("unavailable");
        }
        if !enabled {
            if self.is_locked() && current_password.is_empty() {
                return MutationResult::fail("locked");
            }
            if !current_password.is_empty() {
                if let Err(fail) = self.verify_current(&current, &current_password).await {
                    return fail;
                }
            }
            let _guard = self.mutation.lock().await;
            let latest = self.settings();
            return self
                .save_settings(AppLockSettings {
                    system_unlock_enabled: false,
                    system_unlock_auto_prompt_enabled: false,
                    ..latest
                })
                .await;
        }
        if current.system_unlock_enabled {
            let _guard = self.mutation.lock().await;
            let latest = self.settings();
            return self
                .save_settings(AppLockSettings {
                    system_unlock_auto_prompt_enabled: auto_prompt,
                    ..latest
                })
                .await;
        }
        let status = self.system_status_only().await;
        if !status.supported {
            return MutationResult::fail("unsupported");
        }
        if !status.available {
            return MutationResult::fail("unavailable");
        }
        let result = self.system_auth.request_unlock().await;
        if !result.ok {
            return MutationResult::fail(result.error.as_deref().unwrap_or("failed"));
        }
        let _guard = self.mutation.lock().await;
        let latest = self.settings();
        self.save_settings(AppLockSettings {
            system_unlock_enabled: true,
            system_unlock_auto_prompt_enabled: auto_prompt,
            ..latest
        })
        .await
    }

    // -- runtime transitions ------------------------------------------------

    /// `setAppLockRuntimeLocked(reason)`: no-op when the lock is off;
    /// `background` honours "Never lock automatically".
    pub fn set_locked(&self, reason: Option<&str>) -> RuntimeState {
        let settings = self.settings();
        if !can_lock(&settings) {
            return self.runtime_state();
        }
        if reason == Some("background") && !should_lock_on_background_hide(&settings) {
            return self.runtime_state();
        }
        let (state, changed) = self.runtime.lock().lock(reason, self.now());
        self.sync_idle_timer();
        if changed {
            self.broadcast_runtime(&state);
        }
        state
    }

    pub fn report_activity(&self) -> RuntimeState {
        let now = self.now();
        let (state, _) = self.runtime.lock().record_activity(now);
        self.idle_notify.notify_one();
        state
    }

    async fn reject_password_attempt(&self) -> OkResult {
        let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
        let delay = 250u64 * (1 << (count - 1).min(3));
        (self.failure_delay)(delay).await;
        OkResult::err("incorrect")
    }

    async fn unlock_attempt(
        &self,
        password: String,
        lock_at_attempt: RuntimeState,
        verifier_at_attempt: Option<PasswordVerifier>,
    ) -> OkResult {
        let current = self.settings();
        if !can_lock(&current) {
            self.failure_count.store(0, Ordering::SeqCst);
            self.unlock_and_broadcast();
            return OkResult::ok();
        }
        if password.is_empty() {
            return OkResult::err("empty");
        }
        let Some(verifier) = verifier_at_attempt.filter(|v| Some(v) == current.password_verifier.as_ref()) else {
            return self.reject_password_attempt().await;
        };
        if !lock_at_attempt.locked {
            return self.reject_password_attempt().await;
        }
        let verified = verify_off_thread(password, verifier.clone()).await;
        let latest = self.settings();
        let lock_after = self.runtime_state();
        let stale = latest.password_verifier.as_ref() != Some(&verifier)
            || !lock_after.locked
            || lock_after.version != lock_at_attempt.version;
        if !verified || stale {
            return self.reject_password_attempt().await;
        }
        self.failure_count.store(0, Ordering::SeqCst);
        self.unlock_and_broadcast();
        OkResult::ok()
    }

    /// `requestAppLockUnlock(password)`. Calls while unlocked fail fast;
    /// concurrent calls share the one in-flight attempt.
    pub async fn request_unlock(self: &Arc<Self>, password: String) -> OkResult {
        let current = self.settings();
        let lock_state = self.runtime_state();
        if !can_lock(&current) {
            return self
                .unlock_attempt(password, lock_state, current.password_verifier)
                .await;
        }
        if !lock_state.locked {
            return OkResult::err("incorrect");
        }
        let shared = {
            let mut slot = self.password_in_flight.lock();
            if let Some(existing) = slot.clone() {
                existing
            } else {
                let this = self.clone();
                let fut = async move {
                    let result = this
                        .unlock_attempt(password, lock_state, current.password_verifier)
                        .await;
                    *this.password_in_flight.lock() = None;
                    result
                }
                .boxed()
                .shared();
                *slot = Some(fut.clone());
                fut
            }
        };
        shared.await
    }

    async fn system_unlock_attempt(&self) -> OkResult {
        let current = self.settings();
        if !can_lock(&current) {
            return OkResult::err("unavailable");
        }
        if !current.system_unlock_enabled {
            return OkResult::err("disabled");
        }
        let lock_at_prompt = self.runtime_state();
        if !lock_at_prompt.locked {
            return OkResult::err("not-locked");
        }
        let status = self.system_status_only().await;
        if !status.supported {
            return OkResult::err("unsupported");
        }
        if !status.available {
            return OkResult::err("unavailable");
        }
        let result = self.system_auth.request_unlock().await;
        if !result.ok {
            return OkResult::err(result.error.unwrap_or_else(|| "failed".into()));
        }
        let latest = self.settings();
        if !can_lock(&latest) || !latest.system_unlock_enabled {
            return OkResult::err("disabled");
        }
        let lock_after = self.runtime_state();
        if !lock_after.locked || lock_after.version != lock_at_prompt.version {
            return OkResult::err("not-locked");
        }
        self.unlock_and_broadcast();
        OkResult::ok()
    }

    /// `requestAppLockSystemUnlock()`: one OS prompt shared across windows.
    pub async fn request_system_unlock(self: &Arc<Self>) -> OkResult {
        let shared = {
            let mut slot = self.system_in_flight.lock();
            if let Some(existing) = slot.clone() {
                existing
            } else {
                let this = self.clone();
                let fut = async move {
                    let result = this.system_unlock_attempt().await;
                    *this.system_in_flight.lock() = None;
                    result
                }
                .boxed()
                .shared();
                *slot = Some(fut.clone());
                fut
            }
        };
        shared.await
    }
}

async fn verify_off_thread(password: String, verifier: PasswordVerifier) -> bool {
    tokio::task::spawn_blocking(move || verify_password(&password, &verifier))
        .await
        .unwrap_or(false)
}

async fn idle_loop(controller: Weak<AppLockController>, notify: Arc<Notify>) {
    loop {
        let notified = notify.notified();
        let wait = {
            let Some(this) = controller.upgrade() else {
                return;
            };
            this.idle_deadline()
                .map(|deadline| Duration::from_millis((deadline - this.now()).max(0) as u64))
        };
        match wait {
            None => notified.await,
            Some(wait) => {
                tokio::select! {
                    _ = notified => {}
                    _ = tokio::time::sleep(wait) => {
                        let Some(this) = controller.upgrade() else { return };
                        this.on_idle_deadline();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_auth::SystemAuthUnlock;
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;

    #[derive(Default)]
    struct Recorder {
        runtime: Mutex<Vec<RuntimeState>>,
        settings: Mutex<Vec<AppLockSettings>>,
    }

    impl AppLockEvents for Recorder {
        fn runtime_state_changed(&self, state: &RuntimeState) {
            self.runtime.lock().push(state.clone());
        }
        fn settings_changed(&self, s: &AppLockSettings) {
            self.settings.lock().push(s.clone());
        }
    }

    struct FakeAuth {
        status: Mutex<SystemAuthStatus>,
        result: Mutex<SystemAuthUnlock>,
        prompts: AtomicUsize,
        gate: Mutex<Option<Arc<Notify>>>,
    }

    impl FakeAuth {
        fn available() -> Self {
            Self {
                status: Mutex::new(crate::system_auth::normalize_status(true, true, None, "darwin")),
                result: Mutex::new(SystemAuthUnlock::ok()),
                prompts: AtomicUsize::new(0),
                gate: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl SystemAuth for FakeAuth {
        async fn status(&self) -> SystemAuthStatus {
            self.status.lock().clone()
        }
        async fn request_unlock(&self) -> SystemAuthUnlock {
            self.prompts.fetch_add(1, Ordering::SeqCst);
            let gate = self.gate.lock().clone();
            if let Some(gate) = gate {
                gate.notified().await;
            }
            self.result.lock().clone()
        }
    }

    struct Harness {
        controller: Arc<AppLockController>,
        events: Arc<Recorder>,
        auth: Arc<FakeAuth>,
        delays: Arc<Mutex<Vec<u64>>>,
        _dir: tempfile::TempDir,
    }

    fn harness_with(settings: Option<Value>, clock: Clock) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-lock-settings.json");
        if let Some(settings) = settings {
            std::fs::write(&path, settings.to_string()).unwrap();
        }
        let events = Arc::new(Recorder::default());
        let auth = Arc::new(FakeAuth::available());
        let delays = Arc::new(Mutex::new(Vec::new()));
        let recorded = delays.clone();
        let controller = AppLockController::new(ControllerOptions {
            store: SettingsStore::new(path),
            system_auth: auth.clone(),
            events: events.clone(),
            clock,
            failure_delay: Arc::new(move |ms| {
                recorded.lock().push(ms);
                async {}.boxed()
            }),
            runtime: tokio::runtime::Handle::current(),
            new_verifier_iterations: Some(crate::settings::MIN_ITERATIONS),
        });
        controller.initialize();
        Harness {
            controller,
            events,
            auth,
            delays,
            _dir: dir,
        }
    }

    fn harness(settings: Option<Value>) -> Harness {
        harness_with(settings, wall_clock())
    }

    async fn enabled_harness(password: &str) -> Harness {
        let h = harness(None);
        let r = h
            .controller
            .request_password_change(&json!({ "nextPassword": password }))
            .await;
        assert!(matches!(r, MutationResult::Settings(ref s) if s.enabled));
        h
    }

    #[tokio::test]
    async fn starts_unlocked_when_disabled_and_locked_when_enabled() {
        let h = harness(None);
        let s = h.controller.runtime_state();
        assert!(s.initialized && !s.locked);

        let verifier = crate::settings::create_password_verifier_with("pw", 100_000).unwrap();
        let h = harness(Some(json!({ "enabled": true, "passwordVerifier": verifier })));
        let s = h.controller.runtime_state();
        assert!(s.locked);
        assert_eq!(s.reason.as_deref(), Some("startup"));
    }

    #[tokio::test]
    async fn password_change_enables_and_public_settings_are_redacted() {
        let h = enabled_harness("secret").await;
        let public = h.controller.public_settings();
        assert!(public.enabled);
        let pv = public.password_verifier.unwrap();
        assert_eq!(pv.hash, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        assert_ne!(h.controller.settings().password_verifier.unwrap().hash, pv.hash);
        assert_eq!(h.events.settings.lock().len(), 1);
        // Enabling does not lock the running session.
        assert!(!h.controller.is_locked());
    }

    #[tokio::test]
    async fn password_change_requires_current_password() {
        let h = enabled_harness("one").await;
        let r = h
            .controller
            .request_password_change(&json!({ "nextPassword": "two" }))
            .await;
        assert_eq!(r, MutationResult::fail("empty-current"));
        let r = h
            .controller
            .request_password_change(&json!({ "nextPassword": "two", "currentPassword": "bad" }))
            .await;
        assert_eq!(r, MutationResult::fail("incorrect"));
        let r = h
            .controller
            .request_password_change(&json!({ "currentPassword": "one" }))
            .await;
        assert_eq!(r, MutationResult::fail("empty-next"));
        let r = h
            .controller
            .request_password_change(&json!({ "nextPassword": "two", "currentPassword": "one" }))
            .await;
        assert!(matches!(r, MutationResult::Settings(_)));
    }

    #[tokio::test]
    async fn lock_and_unlock_with_password() {
        let h = enabled_harness("pw").await;
        let locked = h.controller.set_locked(Some("manual"));
        assert!(locked.locked);
        assert_eq!(h.events.runtime.lock().last().unwrap().reason.as_deref(), Some("manual"));

        assert_eq!(h.controller.request_unlock(String::new()).await, OkResult::err("empty"));
        assert_eq!(h.controller.request_unlock("nope".into()).await, OkResult::err("incorrect"));
        assert_eq!(h.controller.request_unlock("nope".into()).await, OkResult::err("incorrect"));
        assert_eq!(*h.delays.lock(), vec![250, 500]);
        assert!(h.controller.is_locked());

        assert_eq!(h.controller.request_unlock("pw".into()).await, OkResult::ok());
        assert!(!h.controller.is_locked());
        assert!(!h.events.runtime.lock().last().unwrap().locked);
        // Unlock attempts while unlocked fail fast without backoff.
        assert_eq!(h.controller.request_unlock("pw".into()).await, OkResult::err("incorrect"));
        assert_eq!(h.delays.lock().len(), 2);
    }

    #[tokio::test]
    async fn backoff_caps_at_two_seconds() {
        let h = enabled_harness("pw").await;
        h.controller.set_locked(None);
        for _ in 0..6 {
            h.controller.request_unlock("x".into()).await;
        }
        assert_eq!(*h.delays.lock(), vec![250, 500, 1000, 2000, 2000, 2000]);
        h.controller.request_unlock("pw".into()).await;
        h.controller.set_locked(None);
        h.controller.request_unlock("x".into()).await;
        assert_eq!(*h.delays.lock().last().unwrap(), 250);
    }

    #[tokio::test]
    async fn set_locked_is_noop_when_disabled() {
        let h = harness(None);
        let s = h.controller.set_locked(Some("manual"));
        assert!(!s.locked);
        assert!(h.events.runtime.lock().is_empty());
        // Unlock with the lock disabled always succeeds.
        assert_eq!(h.controller.request_unlock(String::new()).await, OkResult::ok());
    }

    #[tokio::test]
    async fn background_lock_respects_never_timeout() {
        let h = enabled_harness("pw").await;
        h.controller.set_timeout_minutes(&json!(0)).await;
        assert!(!h.controller.set_locked(Some("background")).locked);
        h.controller.set_timeout_minutes(&json!("5")).await;
        assert_eq!(h.controller.settings().timeout_minutes, 5);
        assert!(h.controller.set_locked(Some("background")).locked);
    }

    #[tokio::test]
    async fn disable_and_reset_need_password_and_unlock() {
        let h = enabled_harness("pw").await;
        h.controller.set_locked(Some("manual"));
        assert_eq!(h.controller.request_disable("").await, MutationResult::fail("empty-current"));
        assert_eq!(h.controller.request_disable("bad").await, MutationResult::fail("incorrect"));
        let r = h.controller.request_disable("pw").await;
        assert!(matches!(r, MutationResult::Settings(ref s) if !s.enabled && s.password_verifier.is_none()));
        assert!(!h.controller.is_locked());

        let h = enabled_harness("pw").await;
        let r = h.controller.request_reset("pw").await;
        assert!(matches!(r, MutationResult::Settings(ref s) if !s.enabled));
    }

    #[tokio::test]
    async fn enable_needs_verifier() {
        let h = harness(None);
        let r = h.controller.request_enable().await;
        assert!(matches!(r, MutationResult::Settings(ref s) if !s.enabled));
    }

    #[tokio::test]
    async fn system_unlock_flow() {
        let h = enabled_harness("pw").await;
        assert_eq!(
            h.controller.request_system_unlock().await,
            OkResult::err("disabled")
        );
        let r = h
            .controller
            .set_system_unlock_enabled(&json!({ "enabled": true, "autoPromptEnabled": true }))
            .await;
        assert!(matches!(r, MutationResult::Settings(ref s) if s.system_unlock_enabled && s.system_unlock_auto_prompt_enabled));
        assert_eq!(h.auth.prompts.load(Ordering::SeqCst), 1);

        assert_eq!(h.controller.request_system_unlock().await, OkResult::err("not-locked"));
        h.controller.set_locked(Some("idle"));
        assert_eq!(h.controller.request_system_unlock().await, OkResult::ok());
        assert!(!h.controller.is_locked());

        h.controller.set_locked(Some("idle"));
        *h.auth.result.lock() = SystemAuthUnlock::err("cancelled");
        assert_eq!(h.controller.request_system_unlock().await, OkResult::err("cancelled"));
        assert!(h.controller.is_locked());

        let status = h.controller.system_unlock_status().await;
        assert!(status.supported && status.available && status.enabled);
        assert_eq!(status.label.as_deref(), Some("Touch ID"));

        // Disabling while locked requires the password.
        let r = h.controller.set_system_unlock_enabled(&json!({ "enabled": false })).await;
        assert_eq!(r, MutationResult::fail("locked"));
        let r = h
            .controller
            .set_system_unlock_enabled(&json!({ "enabled": false, "currentPassword": "pw" }))
            .await;
        assert!(matches!(r, MutationResult::Settings(ref s) if !s.system_unlock_enabled));
    }

    #[tokio::test]
    async fn system_unlock_unavailable_and_unsupported() {
        let h = enabled_harness("pw").await;
        *h.auth.status.lock() = crate::system_auth::normalize_status(true, false, None, "darwin");
        let r = h.controller.set_system_unlock_enabled(&json!({ "enabled": true })).await;
        assert_eq!(r, MutationResult::fail("unavailable"));
        *h.auth.status.lock() = SystemAuthStatus::unsupported();
        let r = h.controller.set_system_unlock_enabled(&json!({ "enabled": true })).await;
        assert_eq!(r, MutationResult::fail("unsupported"));
        let h = harness(None);
        let r = h.controller.set_system_unlock_enabled(&json!({ "enabled": true })).await;
        assert_eq!(r, MutationResult::fail("unavailable"));
    }

    #[tokio::test]
    async fn stale_system_prompt_does_not_unlock_newer_lock() {
        let h = enabled_harness("pw").await;
        h.controller
            .set_system_unlock_enabled(&json!({ "enabled": true }))
            .await;
        h.controller.set_locked(Some("idle"));
        let gate = Arc::new(Notify::new());
        *h.auth.gate.lock() = Some(gate.clone());
        let controller = h.controller.clone();
        let first = tokio::spawn(async move { controller.request_system_unlock().await });
        let controller = h.controller.clone();
        let second = tokio::spawn(async move { controller.request_system_unlock().await });
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Re-lock with a new reason while the prompt is open.
        h.controller.set_locked(Some("background"));
        gate.notify_waiters();
        assert_eq!(first.await.unwrap(), OkResult::err("not-locked"));
        assert_eq!(second.await.unwrap(), OkResult::err("not-locked"));
        // The two callers shared a single OS prompt.
        assert_eq!(h.auth.prompts.load(Ordering::SeqCst), 2);
        assert!(h.controller.is_locked());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timer_locks_after_timeout_and_activity_defers_it() {
        let start = tokio::time::Instant::now();
        let clock: Clock = Arc::new(move || 1_000_000 + start.elapsed().as_millis() as i64);
        let h = harness_with(None, clock);
        h.controller
            .request_password_change(&json!({ "nextPassword": "pw" }))
            .await;
        h.controller.set_timeout_minutes(&json!(1)).await;
        tokio::time::sleep(Duration::from_secs(40)).await;
        h.controller.report_activity();
        tokio::time::sleep(Duration::from_secs(40)).await;
        assert!(!h.controller.is_locked(), "activity moved the deadline");
        tokio::time::sleep(Duration::from_secs(25)).await;
        let s = h.controller.runtime_state();
        assert!(s.locked);
        assert_eq!(s.reason.as_deref(), Some("idle"));
        assert_eq!(h.events.runtime.lock().last().unwrap().reason.as_deref(), Some("idle"));

        // "Never" disables the idle lock.
        h.controller.request_unlock("pw".into()).await;
        h.controller.set_timeout_minutes(&json!(0)).await;
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert!(!h.controller.is_locked());
    }

    #[tokio::test]
    async fn concurrent_password_unlocks_share_one_attempt() {
        let h = enabled_harness("pw").await;
        h.controller.set_locked(None);
        let a = h.controller.clone();
        let b = h.controller.clone();
        let (ra, rb) = tokio::join!(a.request_unlock("bad".into()), b.request_unlock("pw".into()));
        // Both callers received the first attempt's outcome.
        assert_eq!(ra, rb);
        assert_eq!(h.delays.lock().len(), usize::from(!ra.ok));
    }
}

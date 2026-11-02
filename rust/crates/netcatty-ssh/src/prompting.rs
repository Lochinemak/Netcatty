//! Interactive-aware timeouts.
//!
//! Handshake and authentication are bounded by `auth_ready_timeout`, but a
//! user staring at a host-key or passphrase dialog must not be cut off by
//! it. [`PromptingCallbacks`] wraps the caller's [`SshCallbacks`] and marks
//! every interactive wait in a shared [`PromptState`]; [`with_interactive_timeout`]
//! pauses its deadline while a prompt is active and restarts it afterwards.

use crate::error::{SshError, SshResult};
use crate::known_hosts::{HostKeyDecision, HostKeyInfo};
use crate::SshCallbacks;
use async_trait::async_trait;
use netcatty_core::ipc::KeyboardInteractivePrompt;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// Shared "a prompt is on screen" flag.
#[derive(Default)]
pub struct PromptState {
    active: AtomicUsize,
    changed: Notify,
}

impl PromptState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst) > 0
    }

    fn enter(&self) {
        self.active.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    fn exit(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    /// Resolve once no prompt is active.
    pub async fn wait_idle(&self) {
        loop {
            let notified = self.changed.notified();
            if !self.is_active() {
                return;
            }
            notified.await;
        }
    }
}

struct Guard<'a>(&'a PromptState);

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.exit();
    }
}

/// [`SshCallbacks`] decorator that records interactive waits.
pub struct PromptingCallbacks {
    inner: Arc<dyn SshCallbacks>,
    state: Arc<PromptState>,
}

impl PromptingCallbacks {
    pub fn new(inner: Arc<dyn SshCallbacks>, state: Arc<PromptState>) -> Arc<Self> {
        Arc::new(Self { inner, state })
    }

    pub fn state(&self) -> Arc<PromptState> {
        self.state.clone()
    }
}

#[async_trait]
impl SshCallbacks for PromptingCallbacks {
    async fn verify_host_key(&self, info: HostKeyInfo) -> HostKeyDecision {
        self.state.enter();
        let _g = Guard(&self.state);
        self.inner.verify_host_key(info).await
    }

    async fn keyboard_interactive(
        &self,
        name: String,
        instructions: String,
        prompts: Vec<KeyboardInteractivePrompt>,
    ) -> Option<Vec<String>> {
        self.state.enter();
        let _g = Guard(&self.state);
        self.inner
            .keyboard_interactive(name, instructions, prompts)
            .await
    }

    async fn request_passphrase(&self, key_name: String, invalid: bool) -> Option<String> {
        self.state.enter();
        let _g = Guard(&self.state);
        self.inner.request_passphrase(key_name, invalid).await
    }

    async fn progress(&self, message: String) {
        self.inner.progress(message).await
    }
}

/// Run `fut` with a deadline of `limit` that is suspended while a prompt is
/// active in `state` and restarted (from zero) once the prompt is answered.
pub async fn with_interactive_timeout<F, T>(
    state: &PromptState,
    limit: Duration,
    what: &str,
    fut: F,
) -> SshResult<T>
where
    F: Future<Output = T>,
{
    tokio::pin!(fut);
    loop {
        let sleep = tokio::time::sleep(limit);
        tokio::pin!(sleep);
        tokio::select! {
            out = &mut fut => return Ok(out),
            _ = &mut sleep => {
                if state.is_active() {
                    // Wait for the human, then arm a fresh deadline.
                    tokio::select! {
                        out = &mut fut => return Ok(out),
                        _ = state.wait_idle() => continue,
                    }
                }
                return Err(SshError::Timeout(format!("{what} timed out after {}s", limit.as_secs_f64())));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UnattendedCallbacks;

    struct SlowCallbacks;

    #[async_trait]
    impl SshCallbacks for SlowCallbacks {
        async fn verify_host_key(&self, _info: HostKeyInfo) -> HostKeyDecision {
            tokio::time::sleep(Duration::from_millis(120)).await;
            HostKeyDecision::Accept { remember: true }
        }
        async fn keyboard_interactive(
            &self,
            _n: String,
            _i: String,
            _p: Vec<KeyboardInteractivePrompt>,
        ) -> Option<Vec<String>> {
            None
        }
        async fn request_passphrase(&self, _k: String, _i: bool) -> Option<String> {
            None
        }
    }

    fn info() -> HostKeyInfo {
        HostKeyInfo {
            hostname: "h".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            fingerprint: "x".into(),
            public_key: "y".into(),
            known_host_id: None,
            known_fingerprint: None,
        }
    }

    #[tokio::test]
    async fn times_out_without_prompt() {
        let state = PromptState::new();
        let r = with_interactive_timeout(&state, Duration::from_millis(30), "op", async {
            tokio::time::sleep(Duration::from_secs(5)).await;
        })
        .await;
        assert!(matches!(r, Err(SshError::Timeout(_))));
    }

    #[tokio::test]
    async fn deadline_pauses_while_prompting() {
        let state = PromptState::new();
        let cb = PromptingCallbacks::new(Arc::new(SlowCallbacks), state.clone());
        // Prompt takes 120ms, limit is 50ms: must still succeed because the
        // deadline is suspended during the prompt and restarted after it.
        let r = with_interactive_timeout(&state, Duration::from_millis(50), "op", async move {
            let d = cb.verify_host_key(info()).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            d
        })
        .await
        .unwrap();
        assert_eq!(r, HostKeyDecision::Accept { remember: true });
        assert!(!state.is_active());
    }

    #[tokio::test]
    async fn wrapper_delegates_and_clears_state() {
        let state = PromptState::new();
        let cb = PromptingCallbacks::new(Arc::new(UnattendedCallbacks), state.clone());
        assert_eq!(
            cb.verify_host_key(info()).await,
            HostKeyDecision::Accept { remember: false }
        );
        assert!(cb.request_passphrase("k".into(), false).await.is_none());
        assert!(cb
            .keyboard_interactive("n".into(), "i".into(), vec![])
            .await
            .is_none());
        assert!(!state.is_active());
    }
}

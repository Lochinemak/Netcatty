//! The FIDO service: one askpass server, one shared agent, one prompt
//! broker and the signing serialisation for the whole app.

use crate::agent::{AgentLease, AgentManager, IdentityHold, StartOptions};
use crate::askpass::{askpass_env, AskpassContext, AskpassServer, SigningAttempt};
use crate::keygen::{SkKeygenOptions, SkKeygenResult};
use crate::prompt::{PromptBroker, PromptKind, PromptOptions, PromptOutcome, PromptSink};
use crate::sk::{self, IdentityContext, StagedKey};
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

pub type TempBase = Box<dyn Fn() -> PathBuf + Send + Sync>;

pub const AGENT_UNAVAILABLE: &str =
    "FIDO2 SSH agent is unavailable. Install OpenSSH with libfido2 (macOS: brew install openssh libfido2) and try again.";

/// What to load into the agent.
#[derive(Debug, Clone, Default)]
pub struct PrepareRequest {
    /// Inline (vault) key handle.
    pub private_key: Option<String>,
    pub certificate: Option<String>,
    /// Public key line hint (vault `publicKey`).
    pub public_key: Option<String>,
    pub identity_file_paths: Vec<String>,
    pub identity: IdentityContext,
}

/// A prepared agent: the socket to sign through, the identities to use and
/// the holds that keep them loaded. Dropping it releases everything.
pub struct PreparedAgent {
    holds: Vec<IdentityHold>,
    lease: AgentLease,
    pub lease_id: String,
    /// Base64 wire blobs of the prepared identities (bare keys and certs).
    pub public_blobs: Vec<String>,
    service: Weak<FidoService>,
}

impl std::fmt::Debug for PreparedAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedAgent")
            .field("socket", &self.lease.socket())
            .field("lease_id", &self.lease_id)
            .finish()
    }
}

impl PreparedAgent {
    pub fn socket(&self) -> &str {
        self.lease.socket()
    }
}

impl Drop for PreparedAgent {
    fn drop(&mut self) {
        self.holds.clear();
        if let Some(service) = self.service.upgrade() {
            service.broker.cancel_lease(&self.lease_id, "lease-released", false);
        }
    }
}

/// Serialised hardware signature; dropping it ends the attempt (touch
/// hints tied to it close).
pub struct SigningGuard {
    _lock: tokio::sync::OwnedMutexGuard<()>,
    pub attempt: Arc<SigningAttempt>,
    ctx: Arc<AskpassContext>,
}

impl Drop for SigningGuard {
    fn drop(&mut self) {
        self.attempt.done.abort();
        let mut current = self.ctx.current_signing.lock();
        if current.as_ref().is_some_and(|c| Arc::ptr_eq(c, &self.attempt)) {
            *current = None;
        }
    }
}

/// Answer of the recovery dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    Retry,
    PasswordFallback,
    Cancel,
}

/// `failureReason` of `fidoSignFlow.cjs` (without an `ssh-sk-helper`
/// observer only `timeout` / `failed` can be told apart here).
pub fn failure_reason(timed_out: bool, helper_error: Option<u32>, pin_submitted: bool) -> &'static str {
    if timed_out {
        return "timeout";
    }
    match helper_error {
        Some(60) => "device-unavailable",
        Some(43) if pin_submitted => "pin-failed",
        _ => "failed",
    }
}

pub struct FidoService {
    pub broker: Arc<PromptBroker>,
    ctx: Arc<AskpassContext>,
    askpass: Mutex<Option<AskpassServer>>,
    agents: Arc<AgentManager>,
    temp_base: TempBase,
    helper_exe: PathBuf,
    signing: Arc<tokio::sync::Mutex<()>>,
    self_ref: Weak<FidoService>,
}

fn new_lease_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

impl FidoService {
    pub fn new(sink: Arc<dyn PromptSink>, temp_base: TempBase, helper_exe: PathBuf) -> Arc<Self> {
        let broker = PromptBroker::new(sink);
        Arc::new_cyclic(|self_ref| Self {
            ctx: Arc::new(AskpassContext {
                broker: broker.clone(),
                current_signing: Mutex::new(None),
                windows: cfg!(windows),
            }),
            broker,
            askpass: Mutex::new(None),
            agents: AgentManager::new(),
            temp_base,
            helper_exe,
            signing: Arc::new(tokio::sync::Mutex::new(())),
            self_ref: self_ref.clone(),
        })
    }

    fn askpass_socket(&self) -> Result<String, String> {
        let mut slot = self.askpass.lock();
        if let Some(server) = slot.as_ref() {
            return Ok(server.socket_path.clone());
        }
        let server = AskpassServer::start(self.ctx.clone(), &(self.temp_base)())
            .map_err(|e| format!("FIDO askpass bridge unavailable: {e}"))?;
        let path = server.socket_path.clone();
        *slot = Some(server);
        Ok(path)
    }

    /// Askpass environment for an OpenSSH child (`lease` binds its prompts
    /// to one caller).
    pub fn askpass_env(&self, lease: Option<&str>) -> Result<Vec<(String, String)>, String> {
        let socket = self.askpass_socket()?;
        Ok(askpass_env(&self.helper_exe, &socket, lease))
    }

    /// Socket of the shared agent while one runs (Mosh / ET `IdentityAgent`).
    pub fn active_agent_socket(&self) -> Option<String> {
        self.agents.active_socket()
    }

    /// Start (or join) the shared agent and load the request's sk
    /// identities into it.
    pub async fn prepare(&self, request: PrepareRequest) -> Result<PreparedAgent, String> {
        let temp_base = (self.temp_base)();
        let agent_env = self.askpass_env(None)?;
        let lease = self
            .agents
            .acquire(StartOptions {
                temp_base: &temp_base,
                env: agent_env,
            })
            .await
            .map_err(|e| {
                tracing::info!("FIDO agent start failed: {e}");
                AGENT_UNAVAILABLE.to_string()
            })?;
        let lease_id = new_lease_id();
        let env = self.askpass_env(Some(&lease_id))?;

        let mut candidates: Vec<(String, Option<Arc<StagedKey>>)> = Vec::new();
        let certificate = request.certificate.as_deref().filter(|c| !c.trim().is_empty());
        if let Some(private_key) = request.private_key.as_deref().filter(|k| sk::looks_like_sk_material(k)) {
            let staged = sk::stage_private_key(&temp_base, private_key, request.public_key.as_deref(), certificate)
                .map_err(|e| format!("Could not stage the security key handle: {e}"))?;
            candidates.push((staged.key_path.to_string_lossy().into_owned(), Some(Arc::new(staged))));
        }
        for raw in &request.identity_file_paths {
            let path = sk::resolve_identity_path(raw, &request.identity);
            if path.is_empty() || path.ends_with(".pub") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else { continue };
            let pub_text = std::fs::read_to_string(format!("{path}.pub")).unwrap_or_default();
            if !sk::looks_like_sk_material(&text) && !sk::looks_like_sk_material(&pub_text) {
                continue;
            }
            if let (Some(cert), true) = (certificate, sk::looks_like_sk_material(&text)) {
                // Vault certificate for a path-backed handle: stage a copy
                // next to `-cert.pub`; never touch the user's files.
                let staged = sk::stage_private_key(&temp_base, &text, Some(&pub_text).filter(|p| !p.trim().is_empty()).map(|s| s.as_str()), Some(cert))
                    .map_err(|e| format!("Could not stage the security key handle: {e}"))?;
                candidates.push((staged.key_path.to_string_lossy().into_owned(), Some(Arc::new(staged))));
            } else {
                candidates.push((path, None));
            }
        }
        if candidates.is_empty() {
            return Err("No security key identity to load".into());
        }

        let mut holds = Vec::new();
        let mut public_blobs = Vec::new();
        let mut last_error = None;
        for (path, staged) in candidates {
            let public_blob = staged
                .as_ref()
                .and_then(|s| s.public_line.as_deref().and_then(sk::public_key_blob))
                .or_else(|| std::fs::read_to_string(format!("{path}.pub")).ok().and_then(|t| sk::public_key_blob(&t)))
                .or_else(|| {
                    std::fs::read_to_string(&path)
                        .ok()
                        .and_then(|t| sk::sk_public_key(&t))
                        .and_then(|k| k.to_openssh().ok())
                        .and_then(|l| sk::public_key_blob(&l))
                });
            let cert_blob = std::fs::read_to_string(format!("{path}-cert.pub"))
                .ok()
                .and_then(|t| sk::public_key_blob(&t));
            match self
                .agents
                .load_identity(&lease, &path, public_blob.clone(), cert_blob.clone(), staged, &env)
                .await
            {
                Ok(mut h) => {
                    holds.append(&mut h);
                    public_blobs.extend(public_blob);
                    public_blobs.extend(cert_blob);
                }
                Err(e) => {
                    tracing::info!("could not load security key identity into the agent: {e}");
                    last_error = Some(e);
                }
            }
        }
        if public_blobs.is_empty() {
            self.broker.cancel_lease(&lease_id, "lease-released", false);
            return Err(format!(
                "Could not load the security key into the SSH agent: {}",
                last_error.unwrap_or_else(|| "unknown error".into())
            ));
        }
        Ok(PreparedAgent {
            holds,
            lease,
            lease_id,
            public_blobs,
            service: self.self_ref.clone(),
        })
    }

    /// Serialise one hardware signature and attribute agent prompts to it.
    pub async fn begin_signing(&self, lease_id: &str, key_name: &str) -> SigningGuard {
        let lock = self.signing.clone().lock_owned().await;
        let attempt = SigningAttempt::new(lease_id, key_name);
        *self.ctx.current_signing.lock() = Some(attempt.clone());
        SigningGuard {
            _lock: lock,
            attempt,
            ctx: self.ctx.clone(),
        }
    }

    /// Was the last attempt's PIN prompt cancelled by the user?
    pub fn attempt_cancelled(guard: &SigningGuard) -> bool {
        guard.attempt.cancelled.load(Ordering::SeqCst)
    }

    /// Recovery dialog after a failed hardware signature.
    pub async fn recovery(&self, key_name: &str, reason: &str, allow_password_fallback: bool, lease_id: &str) -> Recovery {
        let outcome = self
            .broker
            .request(
                PromptOptions {
                    kind: Some(PromptKind::Recovery),
                    reason: Some(reason.to_string()),
                    key_name: key_name.to_string(),
                    allow_password_fallback,
                    lease_id: lease_id.to_string(),
                    ..Default::default()
                },
                None,
            )
            .await;
        match outcome {
            PromptOutcome::Answered(r) if r == "retry" => Recovery::Retry,
            PromptOutcome::Answered(r) if r == "fallback" && allow_password_fallback => Recovery::PasswordFallback,
            _ => Recovery::Cancel,
        }
    }

    /// `generateKeyPair` for `ED25519-SK` / `ECDSA-SK`.
    pub async fn generate_key(&self, options: &SkKeygenOptions) -> SkKeygenResult {
        let lease_id = new_lease_id();
        let env = match self.askpass_env(Some(&lease_id)) {
            Ok(env) => env,
            Err(e) => {
                tracing::info!("FIDO askpass unavailable for keygen: {e}");
                Vec::new()
            }
        };
        let ssh_keygen = crate::agent::resolve_openssh_binary("ssh-keygen");
        let result = crate::keygen::generate(options, &(self.temp_base)(), &ssh_keygen, &env).await;
        self.broker.cancel_lease(&lease_id, "lease-released", false);
        result
    }

    /// Stop the agent and the askpass server (app exit).
    pub fn shutdown(&self) {
        self.agents.shutdown();
        self.askpass.lock().take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NullSink;
    impl PromptSink for NullSink {
        fn emit(&self, _event: &str, _payload: serde_json::Value) {}
    }

    #[test]
    fn failure_reasons() {
        assert_eq!(failure_reason(true, Some(60), true), "timeout");
        assert_eq!(failure_reason(false, Some(60), false), "device-unavailable");
        assert_eq!(failure_reason(false, Some(43), true), "pin-failed");
        assert_eq!(failure_reason(false, Some(43), false), "failed");
        assert_eq!(failure_reason(false, None, true), "failed");
    }

    #[tokio::test]
    async fn signing_is_serialised_and_clears_context() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().to_path_buf();
        let service = FidoService::new(Arc::new(NullSink), Box::new(move || path.clone()), PathBuf::from("/x"));
        let guard = service.begin_signing("a", "key").await;
        assert!(service.ctx.current_signing.lock().is_some());
        let s2 = service.clone();
        let second = tokio::spawn(async move { s2.begin_signing("b", "key2").await.attempt.lease_id.clone() });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!second.is_finished());
        let done = guard.attempt.done.clone();
        drop(guard);
        assert!(done.is_aborted());
        assert_eq!(second.await.unwrap(), "b");
        assert!(service.ctx.current_signing.lock().is_none());
    }

    #[tokio::test]
    async fn recovery_maps_answers() {
        #[derive(Default)]
        struct Capture(Mutex<Vec<serde_json::Value>>);
        impl PromptSink for Capture {
            fn emit(&self, _event: &str, payload: serde_json::Value) {
                self.0.lock().push(payload);
            }
        }
        let sink = Arc::new(Capture::default());
        let base = tempfile::tempdir().unwrap();
        let path = base.path().to_path_buf();
        let service = FidoService::new(sink.clone(), Box::new(move || path.clone()), PathBuf::from("/x"));
        for (answer, fallback, expected) in [
            ("retry", false, Recovery::Retry),
            ("fallback", true, Recovery::PasswordFallback),
            ("fallback", false, Recovery::Cancel),
        ] {
            let s = service.clone();
            let task = tokio::spawn(async move { s.recovery("YubiKey", "failed", fallback, "l").await });
            let id = loop {
                if let Some(p) = sink.0.lock().pop() {
                    break p["requestId"].as_str().unwrap().to_string();
                }
                tokio::task::yield_now().await;
            };
            service.broker.respond(&id, Some(answer.into()), false).unwrap();
            assert_eq!(task.await.unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn prepare_rejects_requests_without_sk_material() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().to_path_buf();
        let service = FidoService::new(Arc::new(NullSink), Box::new(move || path.clone()), PathBuf::from("/x"));
        let err = service
            .prepare(PrepareRequest {
                private_key: Some("ssh-ed25519 AAAA".into()),
                ..Default::default()
            })
            .await
            .unwrap_err();
        // Either the agent could not start here or there was nothing to load.
        assert!(err == AGENT_UNAVAILABLE || err.contains("No security key identity"), "{err}");
        service.shutdown();
    }
}

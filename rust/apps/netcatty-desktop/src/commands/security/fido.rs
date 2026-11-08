//! FIDO2 security keys (Electron `fidoPromptHandler.cjs`, `fidoAgentManager.cjs`,
//! `fidoAskpass.cjs`, `fidoSignFlow.cjs`, `fidoSshKeygen.cjs`); logic in
//! `netcatty-fido`.
//!
//! * `fido_prompt_respond`: the renderer's answer to
//!   `netcatty:fido-prompt-request`.
//! * `fido_generate_key_pair`: `generateKeyPair` for `ED25519-SK` /
//!   `ECDSA-SK` (the adapter routes those types here).
//! * [`SessionFido`]: per-connection state used by the SSH prompt callbacks
//!   (prepared agent, serialised signature, recovery dialog).
//! * [`prepare_external`]: Mosh / ET bootstrap `ssh` signs through the same
//!   owned agent.

use crate::commands::CmdResult;
use netcatty_fido::{FidoService, PrepareRequest, PreparedAgent, PromptSink, Recovery, SigningGuard, SkKeygenOptions, SkKeygenResult};
use netcatty_ssh::{SecurityKeyAgent, SecurityKeyRecovery, SecurityKeyRequest};
use parking_lot::Mutex;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, Runtime};

pub struct FidoState {
    pub service: Arc<FidoService>,
}

struct EventSink<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> PromptSink for EventSink<R> {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        if let Err(e) = self.app.emit(event, payload) {
            tracing::debug!(event, %e, "fido prompt emit failed");
        }
    }
}

pub fn setup<R: Runtime>(app: &tauri::App<R>) {
    let handle = app.handle().clone();
    let temp_handle = handle.clone();
    let helper_exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("netcatty"));
    let service = FidoService::new(
        Arc::new(EventSink { app: handle }),
        Box::new(move || crate::commands::tempdir::current(&temp_handle)),
        helper_exe,
    );
    app.manage(FidoState { service });
}

pub fn shutdown<R: Runtime>(app: &AppHandle<R>) {
    if let Some(state) = app.try_state::<FidoState>() {
        state.service.shutdown();
    }
}

fn service<R: Runtime>(app: &AppHandle<R>) -> Option<Arc<FidoService>> {
    app.try_state::<FidoState>().map(|s| s.service.clone())
}

#[derive(Debug, Serialize)]
pub struct RespondResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// `respondFidoPrompt(requestId, response, cancelled)`.
#[tauri::command]
pub fn fido_prompt_respond<R: Runtime>(
    app: AppHandle<R>,
    request_id: String,
    response: Option<String>,
    cancelled: Option<bool>,
) -> RespondResult {
    let Some(service) = service(&app) else {
        return RespondResult {
            success: false,
            error: Some("Request not found".into()),
        };
    };
    match service
        .broker
        .respond(&request_id, response, cancelled.unwrap_or(false))
    {
        Ok(()) => RespondResult {
            success: true,
            error: None,
        },
        Err(e) => RespondResult {
            success: false,
            error: Some(e.into()),
        },
    }
}

/// `generateKeyPair({ type: "ED25519-SK" | "ECDSA-SK", comment, resident,
/// verifyRequired })` through `ssh-keygen` with the askpass bridge.
#[tauri::command]
pub async fn fido_generate_key_pair<R: Runtime>(
    app: AppHandle<R>,
    payload: SkKeygenOptions,
) -> CmdResult<SkKeygenResult> {
    if !netcatty_fido::is_sk_key_type(&payload.key_type) {
        return Err(netcatty_core::CoreError::invalid(format!(
            "unsupported security-key type {}",
            payload.key_type
        )));
    }
    let service = service(&app).ok_or_else(|| netcatty_core::CoreError::internal("FIDO is not initialised"))?;
    Ok(service.generate_key(&payload).await)
}

// ---------------------------------------------------------------------------
// SSH sessions (used by `prompts::SessionCallbacks`)
// ---------------------------------------------------------------------------

/// Per-connection security-key state. Lives in the connection's callbacks,
/// so the prepared agent identity is released when the connection ends.
#[derive(Default)]
pub struct SessionFido {
    prepared: Mutex<Vec<PreparedAgent>>,
    signing: Mutex<Option<SigningGuard>>,
}

impl SessionFido {
    fn lease_id(&self) -> String {
        self.prepared
            .lock()
            .last()
            .map(|p| p.lease_id.clone())
            .unwrap_or_default()
    }

    pub async fn prepare<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        request: SecurityKeyRequest,
    ) -> Result<Option<SecurityKeyAgent>, String> {
        let Some(service) = service(app) else {
            return Ok(None);
        };
        let prepared = service
            .prepare(PrepareRequest {
                private_key: Some(request.private_key),
                certificate: request.certificate,
                ..Default::default()
            })
            .await?;
        let agent = SecurityKeyAgent {
            socket: prepared.socket().to_string(),
            public_blobs: prepared.public_blobs.clone(),
        };
        self.prepared.lock().push(prepared);
        Ok(Some(agent))
    }

    pub async fn sign_begin<R: Runtime>(&self, app: &AppHandle<R>, key_label: String) {
        let Some(service) = service(app) else { return };
        let guard = service.begin_signing(&self.lease_id(), &key_label).await;
        *self.signing.lock() = Some(guard);
    }

    pub fn sign_end(&self) -> bool {
        self.signing
            .lock()
            .take()
            .map(|guard| FidoService::attempt_cancelled(&guard))
            .unwrap_or(false)
    }

    pub async fn recovery<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        key_label: String,
        allow_password_fallback: bool,
    ) -> SecurityKeyRecovery {
        let Some(service) = service(app) else {
            return SecurityKeyRecovery::Cancel;
        };
        let reason = netcatty_fido::failure_reason(false, None, false);
        match service
            .recovery(&key_label, reason, allow_password_fallback, &self.lease_id())
            .await
        {
            Recovery::Retry => SecurityKeyRecovery::Retry,
            Recovery::PasswordFallback => SecurityKeyRecovery::PasswordFallback,
            Recovery::Cancel => SecurityKeyRecovery::Cancel,
        }
    }
}

// ---------------------------------------------------------------------------
// Mosh / EternalTerminal
// ---------------------------------------------------------------------------

fn needs_fido(auth: &netcatty_mosh::auth::ExternalSshAuth) -> bool {
    if auth.auth_method.as_deref() == Some("password") {
        return false;
    }
    let ctx = identity_context(auth);
    auth.private_key.as_deref().is_some_and(netcatty_fido::looks_like_sk_material)
        || auth.agent_public_keys.iter().any(|k| netcatty_fido::looks_like_sk_material(k))
        || netcatty_fido::sk::identity_files_look_like_sk(&auth.identity_file_paths, &ctx)
}

fn identity_context(auth: &netcatty_mosh::auth::ExternalSshAuth) -> netcatty_fido::IdentityContext {
    netcatty_fido::IdentityContext {
        hostname: auth.hostname.clone(),
        port: auth.port,
        username: auth.username.clone().unwrap_or_default(),
        ..Default::default()
    }
}

/// Mosh / ET with an sk key: load it into the owned agent and point the
/// bootstrap `ssh` at that agent (`IdentityAgent`). The agent is held until
/// `session_id` has come and gone from the session registry.
pub async fn prepare_external<R: Runtime>(
    app: &AppHandle<R>,
    auth: &mut netcatty_mosh::auth::ExternalSshAuth,
    session_id: &str,
) -> CmdResult<()> {
    if !needs_fido(auth) {
        return Ok(());
    }
    let service = service(app).ok_or_else(|| netcatty_core::CoreError::internal("FIDO is not initialised"))?;
    let prepared = service
        .prepare(PrepareRequest {
            private_key: auth.private_key.clone(),
            certificate: auth.certificate.clone(),
            public_key: auth
                .agent_public_keys
                .iter()
                .find(|k| netcatty_fido::looks_like_sk_material(k))
                .cloned(),
            identity_file_paths: auth.identity_file_paths.clone(),
            identity: identity_context(auth),
        })
        .await
        .map_err(netcatty_core::CoreError::auth)?;
    auth.use_ssh_agent = Some(true);
    auth.agent_socket = Some(prepared.socket().to_string());
    hold_until_session_ends(app.clone(), session_id.to_string(), prepared);
    Ok(())
}

fn hold_until_session_ends<R: Runtime>(app: AppHandle<R>, session_id: String, prepared: PreparedAgent) {
    tauri::async_runtime::spawn(async move {
        let registered = |app: &AppHandle<R>| {
            app.try_state::<crate::state::AppState<R>>()
                .map(|s| s.sessions.contains(&session_id))
                .unwrap_or(false)
        };
        // The session is registered once the PTY runs; give it a minute.
        let mut seen = false;
        for _ in 0..120 {
            if registered(&app) {
                seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        if seen {
            while registered(&app) {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
        drop(prepared);
    });
}

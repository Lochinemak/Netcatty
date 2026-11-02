//! Shared "get me an authenticated connection" logic for sessions, SFTP,
//! exec and port forwarding: reuse a live session transport when the
//! renderer asks for it (`sourceSessionId` / same endpoint), otherwise dial
//! with prompt callbacks bound to the requesting session id.

use crate::events;
use crate::state::AppState;
use netcatty_core::ipc::{events as ev, AuthFailedEvent, SshSessionOptions};
use netcatty_core::{CoreError, CoreResult};
use netcatty_ssh::{ConnectOptions, SshCallbacks, SshConnection, SshError};
use std::sync::Arc;
use tauri::Runtime;

pub struct Acquired {
    pub connection: Arc<SshConnection>,
    /// `true` when the connection belongs to an existing session (do not
    /// disconnect it when this consumer is done).
    pub reused: bool,
}

/// Reject empty hostname / username before dialing.
pub fn validate(payload: &SshSessionOptions) -> CoreResult<()> {
    if payload.hostname.trim().is_empty() {
        return Err(CoreError::invalid("hostname is required"));
    }
    if payload.username.trim().is_empty() {
        return Err(CoreError::invalid("username is required"));
    }
    Ok(())
}

/// Does `conn` go to the same `user@host:port` as `payload`?
pub fn endpoint_matches(conn: &SshConnection, payload: &SshSessionOptions) -> bool {
    let t = &conn.options.target;
    t.port == payload.port()
        && t.hostname.eq_ignore_ascii_case(payload.hostname.trim())
        && t.username == payload.username
}

/// Resolve the transport for `payload`.
///
/// * `reuseTransport !== false` and `singleChannelSsh !== true` allow reuse.
/// * `sourceSessionId` names a live SSH session with the same endpoint →
///   reuse it. A mismatch (or dead source) falls back to a fresh dial unless
///   `requireExactSourceSession` is set, which fails instead.
/// * `allow_endpoint_reuse` additionally reuses any live session with the
///   same endpoint (SFTP browsers and tunnels do this; terminals do not).
/// * Otherwise dial with prompt callbacks bound to `prompt_session_id`. An
///   authentication failure emits `netcatty:auth:failed` before returning.
pub async fn acquire<R: Runtime>(
    state: &AppState<R>,
    payload: &SshSessionOptions,
    prompt_session_id: &str,
    allow_endpoint_reuse: bool,
) -> CoreResult<Acquired> {
    validate(payload)?;
    let reuse_allowed =
        payload.reuse_transport != Some(false) && payload.single_channel_ssh != Some(true);
    if reuse_allowed {
        if let Some(source) = payload
            .source_session_id
            .as_deref()
            .filter(|s| !s.is_empty())
        {
            match state.sessions.connection_of(source) {
                Some(conn) if endpoint_matches(&conn, payload) => {
                    return Ok(Acquired {
                        connection: conn,
                        reused: true,
                    });
                }
                Some(_) if payload.require_exact_source_session == Some(true) => {
                    return Err(CoreError::invalid(format!(
                        "source session {source} is connected to a different endpoint"
                    )));
                }
                None if payload.require_exact_source_session == Some(true) => {
                    return Err(CoreError::not_found(format!(
                        "source session {source} is not connected"
                    )));
                }
                _ => {}
            }
        }
        if allow_endpoint_reuse {
            if let Some(conn) = state.sessions.find_connection(
                payload.hostname.trim(),
                payload.port(),
                &payload.username,
            ) {
                return Ok(Acquired {
                    connection: conn,
                    reused: true,
                });
            }
        }
    }
    let callbacks = callbacks_for(state, payload, prompt_session_id);
    let connection = dial(state, payload, prompt_session_id, callbacks).await?;
    Ok(Acquired {
        connection: Arc::new(connection),
        reused: false,
    })
}

/// Prompt callbacks bound to `session_id` for this payload.
pub fn callbacks_for<R: Runtime>(
    state: &AppState<R>,
    payload: &SshSessionOptions,
    session_id: &str,
) -> Arc<dyn SshCallbacks> {
    state.prompts.callbacks_for(
        session_id.to_string(),
        payload.hostname.trim().to_string(),
        payload.host_id.clone(),
        payload.password.clone(),
        payload.totp.as_ref().map(|t| t.uri.clone()),
    )
}

/// Dial a fresh connection; emits `netcatty:auth:failed` on `AuthFailed`.
pub async fn dial<R: Runtime>(
    state: &AppState<R>,
    payload: &SshSessionOptions,
    session_id: &str,
    callbacks: Arc<dyn SshCallbacks>,
) -> CoreResult<SshConnection> {
    let mut options = ConnectOptions::from(payload);
    options.target.hostname = options.target.hostname.trim().to_string();
    options.session_id = Some(session_id.to_string());
    match netcatty_ssh::connect(options, callbacks).await {
        Ok(conn) => Ok(conn),
        Err(err) => {
            if let SshError::AuthFailed(message) = &err {
                events::emit(
                    &state.app,
                    ev::AUTH_FAILED,
                    AuthFailedEvent {
                        session_id: session_id.to_string(),
                        error: message.clone(),
                        hostname: payload.hostname.trim().to_string(),
                    },
                );
            }
            Err(err.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_blank_fields() {
        let mut p = SshSessionOptions {
            hostname: " ".into(),
            username: "u".into(),
            ..Default::default()
        };
        assert!(validate(&p).is_err());
        p.hostname = "h".into();
        p.username = "".into();
        assert!(validate(&p).is_err());
        p.username = "u".into();
        assert!(validate(&p).is_ok());
    }
}

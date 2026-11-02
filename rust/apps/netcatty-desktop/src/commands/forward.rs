//! Port forwarding commands.

use super::session::SuccessResult;
use super::CmdResult;
use crate::connect;
use crate::events;
use crate::state::{AppState, Ctx};
use netcatty_core::ipc::{
    events as ev, PortForwardOptions, PortForwardSnapshot, PortForwardStartResult,
    PortForwardTunnelInfo,
};
use netcatty_core::models::PortForwardingStatus;
use netcatty_forward::{TunnelEvent, TunnelSpec};
use serde::Serialize;
use tauri::{AppHandle, Runtime};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatusResult {
    pub status: PortForwardingStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Forward registry events to the renderer for the lifetime of the app.
pub fn spawn_tunnel_event_forwarder<R: Runtime>(
    app: AppHandle<R>,
    mut rx: broadcast::Receiver<TunnelEvent>,
) {
    tauri::async_runtime::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(TunnelEvent::Status(event)) => {
                    events::emit(&app, ev::PORT_FORWARD_STATUS, event)
                }
                Ok(TunnelEvent::Runtime(event)) => {
                    events::emit(&app, ev::PORT_FORWARD_RUNTIME, event)
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "tunnel event forwarder lagged");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

pub fn spec_from(payload: &PortForwardOptions) -> TunnelSpec {
    TunnelSpec {
        tunnel_id: payload.tunnel_id.clone(),
        rule_id: payload.rule_id.clone().filter(|r| !r.trim().is_empty()),
        forward_type: payload.forward_type,
        bind_address: payload.bind_address().to_string(),
        local_port: payload.local_port,
        remote_host: payload.remote_host.clone(),
        remote_port: payload.remote_port,
        host_id: payload.ssh.host_id.clone(),
        hostname: payload.ssh.hostname.trim().to_string(),
    }
}

/// Register the tunnel as connecting, dial SSH (reusing a live session
/// connection for the same endpoint when `reuseTransport != false` and
/// `singleChannelSsh != true`), then activate. Status transitions are
/// published as events; this resolves once the tunnel is active or failed.
#[tauri::command]
pub async fn portforward_start<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: PortForwardOptions,
) -> CmdResult<PortForwardStartResult> {
    if payload.tunnel_id.trim().is_empty() {
        return Err(netcatty_core::CoreError::invalid("tunnelId is required"));
    }
    connect::validate(&payload.ssh)?;
    let spec = spec_from(&payload);
    let tunnel_id = spec.tunnel_id.clone();

    if !state.tunnels.begin(spec.clone()) {
        // A live tunnel for the same rule already exists: attach to it.
        let existing = spec
            .rule_id
            .as_deref()
            .and_then(|rule| state.tunnels.find_by_rule(rule));
        return Ok(match existing {
            Some(info) => PortForwardStartResult {
                tunnel_id: info.tunnel_id,
                success: true,
                reused: Some(true),
                status: Some(info.status),
                error: info.error,
            },
            None => {
                let (status, error) = state
                    .tunnels
                    .status(&tunnel_id)
                    .unwrap_or((PortForwardingStatus::Unknown, None));
                PortForwardStartResult {
                    tunnel_id,
                    success: true,
                    reused: Some(true),
                    status: Some(status),
                    error,
                }
            }
        });
    }

    let acquired = match connect::acquire(&state, &payload.ssh, &tunnel_id, true).await {
        Ok(acquired) => acquired,
        Err(err) => {
            state.tunnels.fail(&tunnel_id, err.message.clone());
            return Ok(PortForwardStartResult {
                tunnel_id,
                success: false,
                reused: None,
                status: Some(PortForwardingStatus::Error),
                error: Some(err.message),
            });
        }
    };
    if !acquired.reused {
        state
            .tunnel_connections
            .insert(tunnel_id.clone(), acquired.connection.clone());
    }

    match state
        .tunnels
        .activate(&tunnel_id, acquired.connection.clone())
        .await
    {
        Ok(()) => Ok(PortForwardStartResult {
            tunnel_id,
            success: true,
            reused: Some(false),
            status: Some(PortForwardingStatus::Active),
            error: None,
        }),
        Err(err) => {
            let message = err.to_string();
            state.tunnels.fail(&tunnel_id, message.clone());
            if let Some((_, conn)) = state.tunnel_connections.remove(&tunnel_id) {
                drop(acquired);
                state.release_connection(conn).await;
            }
            Ok(PortForwardStartResult {
                tunnel_id,
                success: false,
                reused: None,
                status: Some(PortForwardingStatus::Error),
                error: Some(message),
            })
        }
    }
}

/// Release the private connection of a stopped tunnel, if any.
async fn release_tunnel_connection<R: Runtime>(state: &AppState<R>, tunnel_id: &str) {
    state
        .prompts
        .cancel_session_with_reason(tunnel_id, "tunnel-stopped");
    if let Some((_, conn)) = state.tunnel_connections.remove(tunnel_id) {
        state.release_connection(conn).await;
    }
}

#[tauri::command]
pub async fn portforward_stop<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    tunnel_id: String,
) -> CmdResult<SuccessResult> {
    let result = state.tunnels.stop(&tunnel_id).await;
    release_tunnel_connection(&state, &tunnel_id).await;
    Ok(match result {
        Ok(()) => SuccessResult::ok(),
        Err(netcatty_forward::ForwardError::NotFound(_)) => SuccessResult::ok(),
        Err(err) => SuccessResult::fail(err.to_string()),
    })
}

#[tauri::command]
pub async fn portforward_stop_by_rule<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    rule_id: String,
) -> CmdResult<SuccessResult> {
    let tunnel_id = state
        .tunnels
        .find_by_rule(&rule_id)
        .map(|info| info.tunnel_id);
    let result = state.tunnels.stop_by_rule(&rule_id).await;
    if let Some(id) = tunnel_id {
        release_tunnel_connection(&state, &id).await;
    }
    Ok(match result {
        Ok(_) => SuccessResult::ok(),
        Err(netcatty_forward::ForwardError::NotFound(_)) => SuccessResult::ok(),
        Err(err) => SuccessResult::fail(err.to_string()),
    })
}

#[tauri::command]
pub async fn portforward_stop_all<R: tauri::Runtime>(
    state: Ctx<'_, R>,
) -> CmdResult<SuccessResult> {
    state.tunnels.stop_all().await;
    let ids: Vec<String> = state
        .tunnel_connections
        .iter()
        .map(|e| e.key().clone())
        .collect();
    for id in ids {
        release_tunnel_connection(&state, &id).await;
    }
    Ok(SuccessResult::ok())
}

#[tauri::command]
pub fn portforward_status<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    tunnel_id: String,
) -> CmdResult<TunnelStatusResult> {
    Ok(match state.tunnels.status(&tunnel_id) {
        Some((status, error)) => TunnelStatusResult { status, error },
        None => TunnelStatusResult {
            status: PortForwardingStatus::Unknown,
            error: None,
        },
    })
}

#[tauri::command]
pub fn portforward_list<R: tauri::Runtime>(state: Ctx<'_, R>) -> Vec<PortForwardTunnelInfo> {
    state.tunnels.list()
}

#[tauri::command]
pub fn portforward_snapshot<R: tauri::Runtime>(state: Ctx<'_, R>) -> PortForwardSnapshot {
    state.tunnels.snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;
    use netcatty_core::models::PortForwardingType;

    #[test]
    fn spec_from_payload() {
        let payload: PortForwardOptions = serde_json::from_str(
            r#"{"tunnelId":"t1","ruleId":"r1","type":"local","localPort":8080,"remoteHost":"db","remotePort":5432,
                "hostname":" bastion ","username":"ops","hostId":"h1"}"#,
        )
        .unwrap();
        let spec = spec_from(&payload);
        assert_eq!(spec.tunnel_id, "t1");
        assert_eq!(spec.rule_id.as_deref(), Some("r1"));
        assert_eq!(spec.forward_type, PortForwardingType::Local);
        assert_eq!(spec.bind_address, "127.0.0.1");
        assert_eq!(spec.remote_port, Some(5432));
        assert_eq!(spec.hostname, "bastion");
        assert_eq!(spec.host_id.as_deref(), Some("h1"));
    }
}

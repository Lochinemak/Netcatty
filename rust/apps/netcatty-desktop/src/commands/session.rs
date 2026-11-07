//! Terminal session commands (SSH shell, local PTY) and SSH exec.

use super::CmdResult;
use crate::connect;
use crate::sessions::{line_delay_ms, split_line_writes, SessionBackend, SessionEntry};
use crate::state::Ctx;
use crate::stream::{InputMeta, SessionInput};
use base64::Engine;
use netcatty_core::ipc::{
    DiscoveredShell, ExecCommandOptions, ExecResult, LocalSessionOptions, PathValidation,
    ResizePayload, SshSessionOptions, StartSessionResult, WriteToSessionPayload,
};
use netcatty_core::{CoreError, CoreResult};
use netcatty_pty::{LocalPtyOptions, PtySession};
use netcatty_ssh::shell::ShellOptions;
use netcatty_ssh::{SshCallbacks, UnattendedCallbacks};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SuccessResult {
    pub fn ok() -> Self {
        Self {
            success: true,
            error: None,
        }
    }
    pub fn fail(error: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PwdResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PwdResult {
    fn ok(cwd: String) -> Self {
        Self {
            success: true,
            cwd: Some(cwd),
            error: None,
        }
    }
    fn fail(error: impl Into<String>) -> Self {
        Self {
            success: false,
            cwd: None,
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteInfoResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Honor the renderer's `sessionId`, else generate one.
fn session_id_or_new(requested: Option<&String>) -> String {
    requested
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(netcatty_core::new_id)
}

/// `software` portion of an SSH identification string.
pub fn software_from_banner(banner: &str) -> String {
    let b = banner.trim();
    let b = b
        .strip_prefix("SSH-2.0-")
        .or_else(|| b.strip_prefix("SSH-1.99-"))
        .unwrap_or(b);
    b.split_whitespace().next().unwrap_or(b).to_string()
}

/// Start an interactive SSH shell. Resolves with the session id once the
/// shell channel is open; connection progress / prompts arrive as events.
#[tauri::command]
pub async fn session_start_ssh<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: SshSessionOptions,
) -> CmdResult<StartSessionResult> {
    connect::validate(&payload)?;
    let session_id = session_id_or_new(payload.session_id.as_ref());
    if state.sessions.contains(&session_id) {
        return Err(CoreError::invalid(format!(
            "session {session_id} already exists"
        )));
    }

    let acquired = connect::acquire(&state, &payload, &session_id, false).await?;
    let connection = acquired.connection;

    let shell_options = ShellOptions {
        cols: payload.cols(),
        rows: payload.rows(),
        term: "xterm-256color".to_string(),
        env: payload.env.clone().unwrap_or_default(),
        agent_forwarding: payload.agent_forwarding.unwrap_or(false),
        x11_forwarding: payload.x11_forwarding.unwrap_or(false),
        x11_display: payload.x11_display.clone(),
    };
    let shell = match connection.open_shell(shell_options).await {
        Ok(shell) => shell,
        Err(err) => {
            if !acquired.reused {
                let _ = connection.disconnect().await;
            }
            return Err(err.into());
        }
    };

    let label = payload
        .host_label
        .clone()
        .filter(|l| !l.trim().is_empty())
        .unwrap_or_else(|| format!("{}@{}", payload.username, payload.hostname.trim()));
    let charset = payload
        .charset
        .clone()
        .filter(|c| !c.trim().is_empty())
        .unwrap_or_else(|| crate::decoder::DEFAULT_CHARSET.to_string());

    // System manager: sudo password / single-channel flag of this session.
    state.system.remember_session(&session_id, &payload);
    state.sessions.insert(SessionEntry {
        session_id: session_id.clone(),
        host_id: payload.host_id.clone(),
        label,
        protocol: "ssh",
        backend: SessionBackend::Ssh {
            connection: connection.clone(),
            shell,
        },
        charset,
        connection: Some(connection),
        created_at: netcatty_core::ids::now_ms(),
    });

    // Startup command: same 300 ms grace the Electron bridge uses so the
    // remote shell has printed its prompt before input arrives.
    if let Some(command) = payload
        .startup_command
        .clone()
        .filter(|c| !c.trim().is_empty())
    {
        let registry = state.sessions.clone();
        let id = session_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            if let Err(err) = registry.write_text(&id, &format!("{command}\n")).await {
                tracing::debug!(session_id = %id, %err, "startup command write failed");
            }
        });
    }

    Ok(StartSessionResult { session_id })
}

/// Connect + authenticate + disconnect, reporting errors like a real start.
/// Cancellable with `session_cancel_test_connection`.
#[tauri::command]
pub async fn session_test_connection<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: SshSessionOptions,
) -> CmdResult<StartSessionResult> {
    connect::validate(&payload)?;
    let session_id = session_id_or_new(payload.session_id.as_ref());
    if state.test_connections.contains_key(&session_id) {
        return Err(CoreError::invalid(format!(
            "test connection {session_id} already running"
        )));
    }

    let callbacks = connect::callbacks_for(&state, &payload, &session_id);
    let mut options = netcatty_ssh::ConnectOptions::from(&payload);
    options.target.hostname = options.target.hostname.trim().to_string();
    options.session_id = Some(session_id.clone());
    let task = tokio::spawn(async move {
        let conn = netcatty_ssh::connect(options, callbacks).await?;
        let _ = conn.disconnect().await;
        Ok::<(), netcatty_ssh::SshError>(())
    });
    state
        .test_connections
        .insert(session_id.clone(), task.abort_handle());

    let outcome = task.await;
    state.test_connections.remove(&session_id);
    match outcome {
        Ok(Ok(())) => Ok(StartSessionResult { session_id }),
        Ok(Err(err)) => {
            if let netcatty_ssh::SshError::AuthFailed(message) = &err {
                crate::events::emit(
                    &state.app,
                    netcatty_core::ipc::events::AUTH_FAILED,
                    netcatty_core::ipc::AuthFailedEvent {
                        session_id: session_id.clone(),
                        error: message.clone(),
                        hostname: payload.hostname.trim().to_string(),
                    },
                );
            }
            Err(err.into())
        }
        Err(join) if join.is_cancelled() => Err(CoreError::cancelled("test connection cancelled")),
        Err(join) => Err(CoreError::internal(format!(
            "test connection task failed: {join}"
        ))),
    }
}

#[tauri::command]
pub async fn session_cancel_test_connection<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
) -> CmdResult<SuccessResult> {
    state
        .prompts
        .cancel_session_with_reason(&session_id, "cancelled");
    match state.test_connections.remove(&session_id) {
        Some((_, handle)) => {
            handle.abort();
            Ok(SuccessResult::ok())
        }
        None => Ok(SuccessResult::fail("no pending test connection")),
    }
}

#[tauri::command]
pub async fn session_start_local<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: LocalSessionOptions,
) -> CmdResult<StartSessionResult> {
    let session_id = session_id_or_new(payload.session_id.as_ref());
    if state.sessions.contains(&session_id) {
        return Err(CoreError::invalid(format!(
            "session {session_id} already exists"
        )));
    }
    let options = LocalPtyOptions {
        shell: payload.shell.clone().filter(|s| !s.trim().is_empty()),
        shell_args: payload.shell_args.clone().unwrap_or_default(),
        cwd: payload.cwd.clone().filter(|s| !s.trim().is_empty()),
        env: payload.env.clone().unwrap_or_default(),
        cols: payload.cols.unwrap_or(80),
        rows: payload.rows.unwrap_or(24),
        term: None,
        ..Default::default()
    };
    let pty = PtySession::spawn(options).await?;
    let label = pty.shell.clone();
    state.sessions.insert(SessionEntry {
        session_id: session_id.clone(),
        host_id: None,
        label,
        protocol: "local",
        backend: SessionBackend::Local { pty },
        charset: crate::decoder::DEFAULT_CHARSET.to_string(),
        connection: None,
        created_at: netcatty_core::ids::now_ms(),
    });
    Ok(StartSessionResult { session_id })
}

/// Write to a session. `binary` payloads are base64; text is encoded with
/// the session charset. `lineDelayMs` paces multi-line automated input
/// line by line (the command returns immediately; writes continue in the
/// background).
#[tauri::command]
pub async fn session_write<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: WriteToSessionPayload,
) -> CmdResult<()> {
    // Flags stream transports (telnet / serial) need: user input cancels
    // auto-login, serial Backspace expansion.
    let meta = InputMeta {
        automated: payload.automated,
        serial_erase_char: payload.serial_erase_char.clone(),
    };
    match plan_write(&payload)? {
        WritePlan::Binary(bytes) => {
            state
                .sessions
                .write_input(
                    &payload.session_id,
                    SessionInput::Bytes(bytes::Bytes::from(bytes)),
                    &meta,
                )
                .await
        }
        WritePlan::Text(text) => {
            state
                .sessions
                .write_input(&payload.session_id, SessionInput::Text(text), &meta)
                .await
        }
        WritePlan::Paced { chunks, delay_ms } => {
            if !state.sessions.contains(&payload.session_id) {
                return Err(CoreError::not_found(format!(
                    "session {} not found",
                    payload.session_id
                )));
            }
            let registry = state.sessions.clone();
            let session_id = payload.session_id.clone();
            tokio::spawn(async move {
                for (index, chunk) in chunks.iter().enumerate() {
                    if index > 0 {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                    if registry
                        .write_input(&session_id, SessionInput::Text(chunk.clone()), &meta)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            Ok(())
        }
    }
}

#[tauri::command]
pub async fn session_resize<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: ResizePayload,
) -> CmdResult<()> {
    state
        .sessions
        .resize(&payload.session_id, payload.cols, payload.rows)
        .await
}

/// Send an interrupt (Ctrl-C) to the session's foreground process.
#[tauri::command]
pub async fn session_interrupt<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
) -> CmdResult<()> {
    state
        .sessions
        .write(&session_id, bytes::Bytes::from_static(b"\x03"))
        .await
}

/// Renderer back-pressure hint: pauses the output pump (output is buffered,
/// bounded) until resumed.
#[tauri::command]
pub async fn session_set_flow_paused<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
    paused: bool,
) -> CmdResult<()> {
    state.sessions.set_flow_paused(&session_id, paused)
}

#[tauri::command]
pub async fn session_ack_flow<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
    bytes: u64,
) -> CmdResult<()> {
    let _ = (state, session_id, bytes);
    Ok(())
}

#[tauri::command]
pub async fn session_close<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
) -> CmdResult<()> {
    state.prompts.cancel_session(&session_id);
    state.sessions.close(&session_id).await
}

/// One-shot remote command on the connection of `sessionId` when alive,
/// else on a fresh connection (unattended unless
/// `enableKeyboardInteractive`), which is closed afterwards.
#[tauri::command]
pub async fn session_exec<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    payload: ExecCommandOptions,
) -> CmdResult<ExecResult> {
    if payload.command.trim().is_empty() {
        return Err(CoreError::invalid("command is required"));
    }
    let existing = payload
        .ssh
        .session_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|id| state.sessions.connection_of(id));

    let (connection, owned) = match existing {
        Some(conn) => (conn, false),
        None => {
            connect::validate(&payload.ssh)?;
            let prompt_session_id = session_id_or_new(payload.ssh.session_id.as_ref());
            let callbacks: Arc<dyn SshCallbacks> =
                if payload.enable_keyboard_interactive == Some(true) {
                    connect::callbacks_for(&state, &payload.ssh, &prompt_session_id)
                } else {
                    Arc::new(UnattendedCallbacks)
                };
            let conn = connect::dial(&state, &payload.ssh, &prompt_session_id, callbacks).await?;
            (Arc::new(conn), true)
        }
    };

    let timeout = payload
        .timeout
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis);
    let result = connection.exec(&payload.command, timeout).await;
    if owned {
        let _ = connection.disconnect().await;
    }
    let output = result?;
    Ok(ExecResult {
        stdout: output.stdout_lossy(),
        stderr: output.stderr_lossy(),
        code: output.exit_code,
    })
}

/// Working directory of the session's foreground process.
///
/// Local sessions ask the PTY (`PtySession::current_dir`). SSH sessions have
/// no portable way to read the interactive shell's cwd from a sibling exec
/// channel, so — like the Electron bridge with `allowHomeFallback` — the
/// login home directory is reported; `success: false` when even that is
/// unavailable. See the "Known gaps" note in `rust/docs/ipc-contract.md`.
#[tauri::command]
pub async fn session_pwd<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
) -> CmdResult<PwdResult> {
    let Some(entry) = state.sessions.get(&session_id) else {
        return Ok(PwdResult::fail("Session not found or not connected"));
    };
    let connection = {
        let guard = entry.lock().await;
        match &guard.backend {
            SessionBackend::Local { pty } => {
                return Ok(match pty.current_dir().await {
                    Some(cwd) if !cwd.is_empty() => PwdResult::ok(cwd),
                    _ => PwdResult::fail("Current directory is unavailable for this shell"),
                });
            }
            SessionBackend::Ssh { connection, .. } => connection.clone(),
            SessionBackend::Stream { .. } => {
                return Ok(PwdResult::fail(
                    "Current directory is unavailable for this session",
                ))
            }
            SessionBackend::Closed => {
                return Ok(PwdResult::fail("Session not found or not connected"))
            }
        }
    };
    Ok(remote_home_dir(&connection).await)
}

async fn remote_home_dir(connection: &netcatty_ssh::SshConnection) -> PwdResult {
    match connection
        .exec("sh -c 'printf %s \"$HOME\"'", Some(Duration::from_secs(5)))
        .await
    {
        Ok(output) => {
            let home = output.stdout_lossy().trim().to_string();
            if home.is_empty() || matches!(output.exit_code, Some(code) if code != 0) {
                PwdResult::fail("Current directory could not be determined")
            } else {
                PwdResult::ok(home)
            }
        }
        Err(err) => PwdResult::fail(err.to_string()),
    }
}

#[tauri::command]
pub async fn session_remote_info<R: tauri::Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
) -> CmdResult<RemoteInfoResult> {
    let Some(connection) = state.sessions.connection_of(&session_id) else {
        return Ok(RemoteInfoResult {
            success: false,
            server_banner: None,
            software: None,
            error: Some("Session not found or not connected".to_string()),
        });
    };
    let banner = connection.server_banner.clone();
    Ok(RemoteInfoResult {
        success: true,
        software: banner.as_deref().map(software_from_banner),
        server_banner: banner,
        error: None,
    })
}

#[tauri::command]
pub fn local_get_default_shell() -> String {
    netcatty_pty::default_shell()
}

#[tauri::command]
pub fn local_discover_shells() -> Vec<DiscoveredShell> {
    netcatty_pty::discover_shells()
}

#[tauri::command]
pub async fn local_validate_path(path: String, kind: Option<String>) -> PathValidation {
    let _ = kind;
    netcatty_localfs::validate_path(&path).await
}

/// Decide how a `session_write` payload is delivered: base64-decoded bytes
/// when `binary`, one text write, or paced per-line writes when
/// `lineDelayMs` is set and the data spans several lines.
pub(crate) fn plan_write(payload: &WriteToSessionPayload) -> CoreResult<WritePlan> {
    if payload.binary {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload.data.as_bytes())
            .map_err(|err| CoreError::invalid(format!("invalid base64 payload: {err}")))?;
        return Ok(WritePlan::Binary(bytes));
    }
    let delay = line_delay_ms(payload.line_delay_ms);
    if delay > 0 {
        let chunks = split_line_writes(&payload.data);
        if chunks.len() > 1 {
            return Ok(WritePlan::Paced {
                chunks,
                delay_ms: delay,
            });
        }
    }
    Ok(WritePlan::Text(payload.data.clone()))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WritePlan {
    Binary(Vec<u8>),
    Text(String),
    Paced { chunks: Vec<String>, delay_ms: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(data: &str) -> WriteToSessionPayload {
        WriteToSessionPayload {
            session_id: "s".into(),
            data: data.into(),
            ..Default::default()
        }
    }

    #[test]
    fn binary_writes_are_base64_decoded() {
        let mut p = payload("AAEC/w==");
        p.binary = true;
        assert_eq!(
            plan_write(&p).unwrap(),
            WritePlan::Binary(vec![0, 1, 2, 255])
        );
        p.data = "not base64!".into();
        assert!(plan_write(&p).is_err());
    }

    #[test]
    fn multi_line_automated_writes_are_paced() {
        let mut p = payload("cd /tmp\nls -la\n");
        p.automated = true;
        p.line_delay_ms = Some(50);
        assert_eq!(
            plan_write(&p).unwrap(),
            WritePlan::Paced {
                chunks: vec!["cd /tmp\r".into(), "ls -la\r".into()],
                delay_ms: 50
            }
        );
        // A single line is written directly even with a delay.
        p.data = "ls\n".into();
        assert_eq!(plan_write(&p).unwrap(), WritePlan::Text("ls\n".into()));
        // No delay → one write regardless of line count.
        p.data = "a\nb\n".into();
        p.line_delay_ms = None;
        assert_eq!(plan_write(&p).unwrap(), WritePlan::Text("a\nb\n".into()));
    }

    #[test]
    fn banner_software_extraction() {
        assert_eq!(
            software_from_banner("SSH-2.0-OpenSSH_9.6 Ubuntu-3"),
            "OpenSSH_9.6"
        );
        assert_eq!(software_from_banner("OpenSSH_8.9p1"), "OpenSSH_8.9p1");
        assert_eq!(software_from_banner("SSH-1.99-Cisco-1.25"), "Cisco-1.25");
    }

    #[test]
    fn session_ids_are_honored_or_generated() {
        assert_eq!(session_id_or_new(Some(&"abc".to_string())), "abc");
        assert_eq!(session_id_or_new(Some(&"  ".to_string())).len(), 36);
        assert_eq!(session_id_or_new(None).len(), 36);
    }
}

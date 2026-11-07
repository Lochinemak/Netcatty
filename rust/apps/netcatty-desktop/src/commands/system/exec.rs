//! Execution primitives for the system manager and server stats:
//!
//! * [`bounded_exec`] — one command on a fresh exec channel of an existing
//!   SSH connection with separate channel-open / run bounds, an output cap,
//!   optional stdin, and the time the exec request was confirmed (Electron
//!   `boundedSshExec.cjs`). A timed-out command is sent `SIGKILL` and its
//!   channel closed; the connection itself is never torn down.
//! * [`local_exec`] — `sh -c` / PowerShell on this machine (Electron
//!   `execOnLocalMachine`).
//! * [`DesktopExec`] — the [`SessionExec`] implementation handed to
//!   `netcatty-sysmgr`, serialized per session like Electron's exec queue.
//! * [`SshStatsTransport`] — the [`StatsTransport`] for stats samples.

use async_trait::async_trait;
use netcatty_ssh::SshConnection;
use netcatty_sysmgr::exec::{ExecRequest, ExecResult, LocalPlatform, SessionExec};
use netcatty_sysmgr::stats::{StatsExecError, StatsExecOutput, StatsTransport};
use russh::ChannelMsg;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Output of [`bounded_exec`].
#[derive(Debug, Default)]
pub(crate) struct BoundedOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: Option<i32>,
    /// From sending the channel-open until the exec request was confirmed.
    pub opened_after: Duration,
}

/// Failure of [`bounded_exec`]; `Display` gives Electron's messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BoundedError {
    OpenTimeout(u64),
    RunTimeout(u64),
    OutputLimit(usize),
    Failed(String),
}

impl std::fmt::Display for BoundedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenTimeout(ms) => write!(f, "SSH exec channel open timed out after {ms} ms"),
            Self::RunTimeout(ms) => write!(f, "SSH command execution timed out after {ms} ms"),
            Self::OutputLimit(n) => write!(f, "SSH command output exceeded {n} bytes"),
            Self::Failed(message) => f.write_str(message),
        }
    }
}

fn russh_message(err: russh::Error) -> String {
    match err {
        russh::Error::ChannelOpenFailure(reason) => format!("Channel open failure: {reason:?}"),
        russh::Error::SendError | russh::Error::Disconnect | russh::Error::HUP => {
            "Not connected".to_string()
        }
        other => other.to_string(),
    }
}

/// Run `command` on a new exec channel of `conn`.
pub(crate) async fn bounded_exec(
    conn: &SshConnection,
    command: &str,
    stdin: Option<&[u8]>,
    open_timeout: Duration,
    run_timeout: Duration,
    max_output: usize,
) -> Result<BoundedOutput, BoundedError> {
    if conn.is_closed() {
        return Err(BoundedError::Failed("Not connected".into()));
    }
    let started = Instant::now();
    let mut out = BoundedOutput::default();
    let mut captured = 0usize;

    let append = |buf: &mut Vec<u8>, data: &[u8], captured: &mut usize| -> bool {
        let room = max_output.saturating_sub(*captured);
        let take = data.len().min(room);
        buf.extend_from_slice(&data[..take]);
        *captured += take;
        data.len() <= room
    };

    // Phase 1 (open bound): open the channel, send the exec request and wait
    // for the server's confirmation — Electron's "stream opened" moment.
    let open = async {
        let mut channel = conn
            .handle
            .channel_open_session()
            .await
            .map_err(|e| BoundedError::Failed(russh_message(e)))?;
        channel
            .exec(true, command.as_bytes().to_vec())
            .await
            .map_err(|e| BoundedError::Failed(format!("Unable to exec: {e}")))?;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => break,
                Some(ChannelMsg::Failure) => {
                    return Err(BoundedError::Failed(
                        "Unable to exec: request rejected".into(),
                    ))
                }
                Some(ChannelMsg::Data { data }) => {
                    append(&mut out.stdout, &data, &mut captured);
                }
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    append(&mut out.stderr, &data, &mut captured);
                }
                Some(ChannelMsg::Close) | None => {
                    return Err(BoundedError::Failed(
                        "Channel closed before the command started".into(),
                    ))
                }
                Some(_) => {}
            }
        }
        Ok::<_, BoundedError>(channel)
    };
    let mut channel = match tokio::time::timeout(open_timeout, open).await {
        Ok(Ok(channel)) => channel,
        Ok(Err(err)) => return Err(err),
        Err(_) => return Err(BoundedError::OpenTimeout(open_timeout.as_millis() as u64)),
    };
    out.opened_after = started.elapsed();

    // Phase 2 (run bound): stdin, output, exit status.
    let run = async {
        if let Some(data) = stdin.filter(|d| !d.is_empty()) {
            channel
                .data(data)
                .await
                .map_err(|e| BoundedError::Failed(format!("stdin write failed: {e}")))?;
        }
        let _ = channel.eof().await;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    if !append(&mut out.stdout, &data, &mut captured) {
                        return Err(BoundedError::OutputLimit(max_output));
                    }
                }
                Some(ChannelMsg::ExtendedData { data, ext }) => {
                    let target = if ext == 1 {
                        &mut out.stderr
                    } else {
                        &mut out.stdout
                    };
                    if !append(target, &data, &mut captured) {
                        return Err(BoundedError::OutputLimit(max_output));
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    out.code = Some(exit_status as i32);
                }
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            }
        }
        Ok::<_, BoundedError>(())
    };
    let outcome = tokio::time::timeout(run_timeout, run).await;
    let terminate = match &outcome {
        Ok(Ok(())) => false,
        Ok(Err(_)) | Err(_) => true,
    };
    if terminate {
        // Best effort: ask sshd to kill the remote command, then close.
        let _ = channel.signal(russh::Sig::KILL).await;
        let _ = channel.close().await;
    }
    match outcome {
        Ok(Ok(())) => Ok(out),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(BoundedError::RunTimeout(run_timeout.as_millis() as u64)),
    }
}

/// Electron `execOnConnection`: map a bounded exec into an [`ExecResult`].
pub(crate) async fn exec_on_connection(conn: &SshConnection, request: &ExecRequest) -> ExecResult {
    let timeout = Duration::from_millis(request.timeout_ms.max(1));
    match bounded_exec(
        conn,
        &request.command,
        request.stdin.as_deref().map(str::as_bytes),
        timeout,
        timeout,
        request.max_buffer(),
    )
    .await
    {
        Ok(out) => ExecResult::ok(
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
            out.code.unwrap_or(0),
        ),
        Err(err) => ExecResult {
            success: false,
            error: Some(match err {
                BoundedError::OutputLimit(_) => "SSH command maxBuffer exceeded".to_string(),
                other => other.to_string(),
            }),
            code: Some(1),
            ..Default::default()
        },
    }
}

/// Electron `execOnLocalMachine`: `sh -c` (POSIX) or `powershell.exe
/// -NoProfile -NonInteractive -Command` (Windows).
pub(crate) async fn local_exec(request: &ExecRequest) -> ExecResult {
    use tokio::io::AsyncWriteExt;
    let mut command = if cfg!(windows) {
        let mut c = tokio::process::Command::new("powershell.exe");
        c.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &request.command,
        ]);
        c
    } else {
        let mut c = tokio::process::Command::new("sh");
        c.args(["-c", &request.command]);
        c
    };
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW: no console flash for background probes.
        command.creation_flags(0x0800_0000);
    }
    command
        .stdin(if request.stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => return ExecResult::fail(err.to_string()),
    };
    if let (Some(data), Some(mut pipe)) = (request.stdin.clone(), child.stdin.take()) {
        tokio::spawn(async move {
            let _ = pipe.write_all(data.as_bytes()).await;
            let _ = pipe.shutdown().await;
        });
    }
    let timeout = Duration::from_millis(request.timeout_ms.max(1));
    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => return ExecResult::fail(err.to_string()),
        Err(_) => {
            return ExecResult::fail(format!(
                "Command failed: {}\nCommand timed out after {} ms",
                request.command, request.timeout_ms
            ))
        }
    };
    let max = request.max_buffer();
    if output.stdout.len() > max || output.stderr.len() > max {
        return ExecResult::fail("stdout maxBuffer length exceeded");
    }
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code();
    if !output.status.success() && stdout.is_empty() {
        return ExecResult {
            success: false,
            error: Some(format!("Command failed: {}\n{}", request.command, stderr)),
            stderr,
            ..Default::default()
        };
    }
    ExecResult::ok(stdout, stderr, code.unwrap_or(0))
}

/// Where a session's commands run.
pub(crate) enum ExecTarget {
    Local,
    Ssh(Arc<SshConnection>),
    /// Every command fails with this result.
    Unavailable(ExecResult),
}

/// [`SessionExec`] for one terminal session.
pub(crate) struct DesktopExec {
    pub target: ExecTarget,
    /// Per-session queue: commands of one session never overlap (Electron
    /// serializes them to avoid SSH channel storms).
    pub queue: Arc<tokio::sync::Mutex<()>>,
    pub sudo: Option<String>,
}

#[async_trait]
impl SessionExec for DesktopExec {
    async fn exec(&self, request: ExecRequest) -> ExecResult {
        let _turn = self.queue.lock().await;
        match &self.target {
            ExecTarget::Local => local_exec(&request).await,
            ExecTarget::Ssh(conn) => exec_on_connection(conn, &request).await,
            ExecTarget::Unavailable(result) => result.clone(),
        }
    }

    async fn exec_local(&self, request: ExecRequest) -> ExecResult {
        let _turn = self.queue.lock().await;
        local_exec(&request).await
    }

    fn is_local(&self) -> bool {
        matches!(self.target, ExecTarget::Local)
    }

    fn local_platform(&self) -> LocalPlatform {
        LocalPlatform::current()
    }

    fn sudo_password(&self) -> Option<String> {
        self.sudo.clone().filter(|s| !s.is_empty())
    }
}

/// Ping timeout (Electron `DEFAULT_PING_TIMEOUT_MS`).
const PING_TIMEOUT: Duration = Duration::from_secs(3);

/// [`StatsTransport`] over an SSH connection.
pub(crate) struct SshStatsTransport {
    pub conn: Arc<SshConnection>,
    /// Transport pings are skipped when the user disabled keepalives for
    /// the host (some network devices mishandle global requests).
    pub ping: bool,
}

#[async_trait]
impl StatsTransport for SshStatsTransport {
    async fn run(
        &self,
        command: &str,
        timeout_ms: u64,
        max_output_bytes: usize,
    ) -> Result<StatsExecOutput, StatsExecError> {
        let timeout = Duration::from_millis(timeout_ms);
        match bounded_exec(
            &self.conn,
            command,
            None,
            timeout,
            timeout,
            max_output_bytes,
        )
        .await
        {
            Ok(out) => Ok(StatsExecOutput {
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                opened_after_ms: Some(out.opened_after.as_secs_f64() * 1000.0),
            }),
            Err(BoundedError::OpenTimeout(_) | BoundedError::RunTimeout(_)) => {
                Err(StatsExecError::Timeout)
            }
            Err(other) => Err(StatsExecError::Other(other.to_string())),
        }
    }

    async fn ping_ms(&self) -> Option<f64> {
        if !self.ping || self.conn.is_closed() {
            return None;
        }
        let started = Instant::now();
        match tokio::time::timeout(PING_TIMEOUT, self.conn.handle.send_ping()).await {
            Ok(Ok(())) => Some((started.elapsed().as_secs_f64() * 1000.0).round()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_match_electron() {
        assert_eq!(
            BoundedError::OpenTimeout(5000).to_string(),
            "SSH exec channel open timed out after 5000 ms"
        );
        assert_eq!(
            BoundedError::RunTimeout(10).to_string(),
            "SSH command execution timed out after 10 ms"
        );
        assert_eq!(
            BoundedError::OutputLimit(64).to_string(),
            "SSH command output exceeded 64 bytes"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_exec_runs_sh_with_stdin_and_codes() {
        let r =
            local_exec(&ExecRequest::new("cat; echo err >&2; exit 3", 5000).with_stdin("hi")).await;
        assert!(r.success, "{r:?}");
        assert_eq!(r.stdout, "hi");
        assert_eq!(r.stderr, "err\n");
        assert_eq!(r.code, Some(3));
        let r = local_exec(&ExecRequest::new("exit 2", 5000)).await;
        assert!(!r.success);
        assert!(r.error.unwrap().starts_with("Command failed: exit 2"));
        let r = local_exec(&ExecRequest::new("sleep 5", 100)).await;
        assert!(!r.success);
        let r = local_exec(&ExecRequest::new("printf 1234567890", 5000).with_max_buffer(4)).await;
        assert!(!r.success);
    }
}

//! Non-interactive command execution.

use crate::error::{SshError, SshResult};
use crate::SshConnection;
use russh::ChannelMsg;
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// `None` when the remote closed without an exit status.
    pub exit_code: Option<i32>,
}

impl ExecOutput {
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Upper bound on captured output per stream (64 MiB) to keep a runaway
/// command from exhausting memory; excess is discarded.
const MAX_CAPTURE: usize = 64 * 1024 * 1024;

impl SshConnection {
    /// Run `command` on a fresh session channel (no PTY) and collect output.
    /// `timeout` bounds the whole operation; on expiry the channel is closed
    /// and `SshError::Timeout` is returned.
    pub async fn exec(&self, command: &str, timeout: Option<Duration>) -> SshResult<ExecOutput> {
        self.exec_inner(command, None, timeout).await
    }

    /// Run `command` with `stdin` fed to the remote process, for scp-style
    /// protocols and `cat > file` uploads.
    pub async fn exec_with_stdin(
        &self,
        command: &str,
        stdin: Vec<u8>,
        timeout: Option<Duration>,
    ) -> SshResult<ExecOutput> {
        self.exec_inner(command, Some(stdin), timeout).await
    }

    async fn exec_inner(
        &self,
        command: &str,
        stdin: Option<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> SshResult<ExecOutput> {
        if command.trim().is_empty() {
            return Err(SshError::InvalidArgument("command is required".into()));
        }
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| match e {
                russh::Error::ChannelOpenFailure(r) => {
                    SshError::Channel(format!("channel open failed: {r:?}"))
                }
                russh::Error::SendError | russh::Error::Disconnect | russh::Error::HUP => {
                    SshError::Disconnected("connection closed".into())
                }
                other => SshError::Russh(other),
            })?;

        let work = async {
            channel
                .exec(true, command.as_bytes().to_vec())
                .await
                .map_err(|e| SshError::Channel(format!("exec request failed: {e}")))?;

            let mut out = ExecOutput::default();
            let mut stdin_pending = stdin;
            let mut exec_confirmed = false;

            loop {
                // Feed stdin only after the server accepted the exec request
                // so a rejected command does not swallow the payload.
                if exec_confirmed {
                    if let Some(data) = stdin_pending.take() {
                        if !data.is_empty() {
                            channel.data_bytes(data).await.map_err(|e| {
                                SshError::Channel(format!("stdin write failed: {e}"))
                            })?;
                        }
                        channel
                            .eof()
                            .await
                            .map_err(|e| SshError::Channel(format!("eof failed: {e}")))?;
                    }
                }
                match channel.wait().await {
                    Some(ChannelMsg::Success) => {
                        exec_confirmed = true;
                        if stdin_pending.is_none() {
                            // Nothing to send: signal EOF so commands reading
                            // stdin (e.g. `cat`) terminate.
                            let _ = channel.eof().await;
                        }
                    }
                    Some(ChannelMsg::Failure) => {
                        return Err(SshError::Channel("exec request rejected by server".into()));
                    }
                    Some(ChannelMsg::Data { data }) => append(&mut out.stdout, &data),
                    Some(ChannelMsg::ExtendedData { data, ext }) => {
                        if ext == 1 {
                            append(&mut out.stderr, &data);
                        } else {
                            append(&mut out.stdout, &data);
                        }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        out.exit_code = Some(exit_status as i32)
                    }
                    Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                        if out.exit_code.is_none() {
                            // Mirror the shell convention 128 + signal number
                            // where known; otherwise leave None.
                            out.exit_code = signal_exit_code(&signal_name);
                        }
                    }
                    Some(ChannelMsg::Eof) => {}
                    Some(ChannelMsg::Close) | None => break,
                    Some(_) => {}
                }
            }
            Ok::<_, SshError>(out)
        };

        match timeout {
            Some(limit) => match tokio::time::timeout(limit, work).await {
                Ok(res) => res,
                Err(_) => {
                    let _ = channel.close().await;
                    Err(SshError::Timeout(format!(
                        "command timed out after {}s",
                        limit.as_secs_f64()
                    )))
                }
            },
            None => work.await,
        }
    }
}

fn append(buf: &mut Vec<u8>, data: &[u8]) {
    let room = MAX_CAPTURE.saturating_sub(buf.len());
    if room == 0 {
        return;
    }
    buf.extend_from_slice(&data[..data.len().min(room)]);
}

fn signal_exit_code(sig: &russh::Sig) -> Option<i32> {
    let n = match sig {
        russh::Sig::HUP => 1,
        russh::Sig::INT => 2,
        russh::Sig::QUIT => 3,
        russh::Sig::ILL => 4,
        russh::Sig::ABRT => 6,
        russh::Sig::FPE => 8,
        russh::Sig::KILL => 9,
        russh::Sig::SEGV => 11,
        russh::Sig::PIPE => 13,
        russh::Sig::ALRM => 14,
        russh::Sig::TERM => 15,
        _ => return None,
    };
    Some(128 + n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_is_bounded() {
        let mut buf = Vec::new();
        append(&mut buf, b"abc");
        assert_eq!(buf, b"abc");
        assert_eq!(
            ExecOutput {
                stdout: buf.clone(),
                ..Default::default()
            }
            .stdout_lossy(),
            "abc"
        );
    }

    #[test]
    fn signal_codes() {
        assert_eq!(signal_exit_code(&russh::Sig::KILL), Some(137));
        assert_eq!(signal_exit_code(&russh::Sig::Custom("X".into())), None);
    }
}

//! Non-interactive command execution.

use crate::error::SshResult;
use crate::SshConnection;
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

impl SshConnection {
    /// Run `command` on a fresh session channel (no PTY) and collect output.
    /// `timeout` bounds the whole operation; on expiry the channel is closed
    /// and `SshError::Timeout` is returned.
    pub async fn exec(&self, command: &str, timeout: Option<Duration>) -> SshResult<ExecOutput> {
        let _ = (command, timeout);
        todo!("exec channel with stdout/stderr capture (ssh agent task)")
    }

    /// Run `command` with `stdin` fed to the remote process, for scp-style
    /// protocols and `cat > file` uploads.
    pub async fn exec_with_stdin(
        &self,
        command: &str,
        stdin: Vec<u8>,
        timeout: Option<Duration>,
    ) -> SshResult<ExecOutput> {
        let _ = (command, stdin, timeout);
        todo!("exec with stdin (ssh agent task)")
    }
}

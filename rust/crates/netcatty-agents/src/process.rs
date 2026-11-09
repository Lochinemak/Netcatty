//! Child-process plumbing shared by the drivers: spawning in an own process
//! group, bounded line readers, capped stderr capture and
//! SIGTERM → SIGKILL termination of the whole tree.

use crate::cli::{command_for_spec, SpawnSpec};
use crate::EnvMap;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdout, Command};

pub const DEFAULT_ABORT_GRACE: Duration = Duration::from_millis(1_500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stdin {
    Null,
    Piped,
}

/// Build a tokio command for a [`SpawnSpec`] with the agent env, cwd and
/// piped stdio. On POSIX the child leads its own process group so the npm /
/// installer shims' real servers can be signalled too.
pub fn build_command(spec: &SpawnSpec, env: &EnvMap, cwd: Option<&Path>, stdin: Stdin) -> Command {
    let mut cmd = command_for_spec(spec);
    cmd.env_clear().envs(env.iter());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.stdin(match stdin {
        Stdin::Null => std::process::Stdio::null(),
        Stdin::Piped => std::process::Stdio::piped(),
    })
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .kill_on_drop(true);
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    cmd
}

/// Send `signal` to the child's process group (POSIX) or `taskkill /T` (Windows).
pub fn signal_process_tree(pid: Option<u32>, kill: bool) {
    let Some(pid) = pid else { return };
    #[cfg(unix)]
    {
        let sig = if kill { libc::SIGKILL } else { libc::SIGTERM };
        // SAFETY: plain syscall on a pid we spawned.
        let rc = unsafe { libc::kill(-(pid as i32), sig) };
        if rc != 0 {
            unsafe {
                libc::kill(pid as i32, sig);
            }
        }
    }
    #[cfg(windows)]
    {
        let _ = kill;
        let _ = std::process::Command::new("taskkill")
            .args(["/pid", &pid.to_string(), "/T", "/F"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// SIGTERM now, SIGKILL after `grace` unless the child exited.
pub async fn terminate_child(child: &mut Child, grace: Duration) {
    let pid = child.id();
    signal_process_tree(pid, false);
    if tokio::time::timeout(grace, child.wait()).await.is_err() {
        signal_process_tree(pid, true);
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LineError {
    #[error("message exceeded {0} bytes")]
    TooLong(usize),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Newline-delimited reader with a per-line byte cap. Lines are trimmed and
/// empty lines skipped (`createLineBuffer`).
pub struct LineReader {
    inner: BufReader<ChildStdout>,
    max_line_bytes: usize,
    buf: Vec<u8>,
}

impl LineReader {
    pub fn new(stdout: ChildStdout, max_line_bytes: usize) -> Self {
        Self { inner: BufReader::with_capacity(64 * 1024, stdout), max_line_bytes, buf: Vec::new() }
    }

    /// Next non-empty line, `None` at EOF.
    pub async fn next_line(&mut self) -> Result<Option<String>, LineError> {
        loop {
            self.buf.clear();
            let n = self.inner.read_until(b'\n', &mut self.buf).await?;
            if n == 0 {
                return Ok(None);
            }
            if self.buf.len() > self.max_line_bytes {
                return Err(LineError::TooLong(self.max_line_bytes));
            }
            let line = String::from_utf8_lossy(&self.buf).trim().to_string();
            if !line.is_empty() {
                return Ok(Some(line));
            }
        }
    }
}

/// Capped stderr collector (keeps the first `max_chars`).
pub struct StderrTail {
    text: std::sync::Arc<parking_lot::Mutex<String>>,
}

impl StderrTail {
    /// Spawn a task draining `stderr` into a capped buffer.
    pub fn spawn(stderr: Option<ChildStderr>, max_chars: usize) -> Self {
        let text = std::sync::Arc::new(parking_lot::Mutex::new(String::new()));
        if let Some(mut stderr) = stderr {
            let sink = text.clone();
            tokio::spawn(async move {
                let mut chunk = [0u8; 4096];
                loop {
                    match stderr.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut guard = sink.lock();
                            let remaining = max_chars.saturating_sub(guard.len());
                            if remaining > 0 {
                                let piece = String::from_utf8_lossy(&chunk[..n]);
                                let take: String = piece.chars().take(remaining).collect();
                                guard.push_str(&take);
                            }
                        }
                    }
                }
            });
        }
        Self { text }
    }

    pub fn text(&self) -> String {
        self.text.lock().clone()
    }
}

/// Spawn a child, returning the stdout reader and stderr tail.
pub struct Spawned {
    pub child: Child,
    pub stdout: LineReader,
    pub stderr: StderrTail,
}

pub fn spawn_lines(
    spec: &SpawnSpec,
    env: &EnvMap,
    cwd: Option<&Path>,
    stdin: Stdin,
    max_line_bytes: usize,
    max_stderr_chars: usize,
) -> std::io::Result<Spawned> {
    let mut cmd = build_command(spec, env, cwd, stdin);
    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| std::io::Error::other("child has no stdout"))?;
    let stderr = StderrTail::spawn(child.stderr.take(), max_stderr_chars);
    Ok(Spawned { child, stdout: LineReader::new(stdout, max_line_bytes), stderr })
}

/// Free TCP port on `host` (never the given reserved default).
pub async fn available_port(host: &str, reserved: u16) -> std::io::Result<u16> {
    loop {
        let listener = tokio::net::TcpListener::bind((host, 0)).await?;
        let port = listener.local_addr()?.port();
        drop(listener);
        if port != reserved {
            return Ok(port);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(script: &str) -> SpawnSpec {
        SpawnSpec { command: "sh".into(), args: vec!["-c".into(), script.into()], shell: false }
    }

    fn env() -> EnvMap {
        [("PATH".to_string(), "/usr/bin:/bin".to_string())].into_iter().collect()
    }

    #[tokio::test]
    async fn line_reader_skips_blank_and_caps() {
        let mut spawned = spawn_lines(&sh("printf 'a\\n\\n  b  \\n'; printf 'cccccccccc\\n' 1>&2; printf 'x%.0s' $(seq 1 50); echo"), &env(), None, Stdin::Null, 20, 4).unwrap();
        assert_eq!(spawned.stdout.next_line().await.unwrap().as_deref(), Some("a"));
        assert_eq!(spawned.stdout.next_line().await.unwrap().as_deref(), Some("b"));
        assert!(matches!(spawned.stdout.next_line().await, Err(LineError::TooLong(20))));
        let _ = spawned.child.wait().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(spawned.stderr.text(), "cccc");
    }

    #[tokio::test]
    async fn terminate_kills_process_group() {
        let mut spawned = spawn_lines(&sh("sleep 30 & echo started; wait"), &env(), None, Stdin::Null, 1024, 1024).unwrap();
        assert_eq!(spawned.stdout.next_line().await.unwrap().as_deref(), Some("started"));
        let started = std::time::Instant::now();
        terminate_child(&mut spawned.child, Duration::from_millis(300)).await;
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(spawned.child.try_wait().unwrap().is_some());
    }

    #[tokio::test]
    async fn available_port_avoids_reserved() {
        let port = available_port("127.0.0.1", 4096).await.unwrap();
        assert_ne!(port, 4096);
        assert!(port > 0);
    }
}

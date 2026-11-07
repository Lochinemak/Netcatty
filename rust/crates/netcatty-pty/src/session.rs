//! A local shell running in a pseudo-terminal.

use crate::discovery::{default_shell, default_shell_args};
use crate::error::{PtyError, PtyResult};
use bytes::Bytes;
use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
#[cfg(unix)]
use tokio::sync::oneshot;

const DEFAULT_TERM: &str = "xterm-256color";
const DEFAULT_UTF8_LOCALE: &str = "en_US.UTF-8";
const DEFAULT_COLS: u16 = 80;
const DEFAULT_ROWS: u16 = 24;
/// Reader chunk size.
const READ_CHUNK: usize = 64 * 1024;
/// Bound of the output channel (chunks, not bytes).
const EVENT_CHANNEL_CAPACITY: usize = 1024;
const WRITE_CHANNEL_CAPACITY: usize = 256;
/// Grace period between SIGHUP and SIGKILL.
#[allow(dead_code)]
const KILL_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Default)]
pub struct LocalPtyOptions {
    /// Shell executable; `None` → [`crate::default_shell`].
    pub shell: Option<String>,
    pub shell_args: Vec<String>,
    /// Working directory; `None` → home directory.
    pub cwd: Option<String>,
    pub env: HashMap<String, String>,
    pub cols: u16,
    pub rows: u16,
    /// `TERM` (defaults to `xterm-256color`).
    pub term: Option<String>,
    /// Inherited environment variables to drop (external clients such as
    /// the Mosh bootstrap `ssh` must not forward the local locale).
    pub env_remove: Vec<String>,
    /// Do not force a UTF-8 locale when none is set (see
    /// `apply_locale_defaults`).
    pub skip_locale_defaults: bool,
}

#[derive(Debug)]
pub enum PtyEvent {
    Data(Bytes),
    /// The child exited. `None` when the status is unknown.
    Exit {
        exit_code: Option<i32>,
        signal: Option<String>,
    },
}

/// A running local terminal. Output arrives on `events`; input goes through
/// [`PtySession::write`]. The reader runs on a blocking thread (portable-pty
/// is synchronous) and forwards into the tokio channel.
pub struct PtySession {
    pub events: mpsc::Receiver<PtyEvent>,
    pub(crate) write_tx: mpsc::Sender<Bytes>,
    pub(crate) control_tx: mpsc::UnboundedSender<PtyControl>,
    pub pid: Option<u32>,
    pub shell: String,
}

impl std::fmt::Debug for PtySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtySession")
            .field("pid", &self.pid)
            .field("shell", &self.shell)
            .finish_non_exhaustive()
    }
}

pub(crate) enum PtyControl {
    Resize {
        cols: u16,
        rows: u16,
    },
    Kill,
    /// Unix only: pid of the pty's foreground process group leader.
    #[cfg(unix)]
    ForegroundPid(oneshot::Sender<Option<i32>>),
}

impl PtySession {
    pub async fn spawn(options: LocalPtyOptions) -> PtyResult<PtySession> {
        let shell = resolve_shell(options.shell.as_deref());
        let args = if options.shell_args.is_empty() {
            default_shell_args(&shell)
        } else {
            options.shell_args.clone()
        };
        let cwd = resolve_cwd(options.cwd.as_deref());
        let size = PtySize {
            rows: if options.rows == 0 {
                DEFAULT_ROWS
            } else {
                options.rows
            },
            cols: if options.cols == 0 {
                DEFAULT_COLS
            } else {
                options.cols
            },
            pixel_width: 0,
            pixel_height: 0,
        };

        let mut cmd = CommandBuilder::new(&shell);
        cmd.args(&args);
        if let Some(cwd) = &cwd {
            cmd.cwd(cwd);
        }
        for key in &options.env_remove {
            cmd.env_remove(key);
        }
        for (key, value) in &options.env {
            if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
                tracing::warn!(key = %key, "ignoring invalid environment variable for local terminal");
                continue;
            }
            cmd.env(key, value);
        }
        let term = options
            .term
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .unwrap_or(DEFAULT_TERM);
        cmd.env("TERM", term);
        cmd.env("COLORTERM", "truecolor");
        if cfg!(unix) && !options.skip_locale_defaults {
            apply_locale_defaults(&mut cmd);
        }

        tracing::debug!(shell = %shell, args = ?args, cwd = ?cwd, "spawning local terminal");

        // openpty + fork/exec are synchronous; keep them off the async threads.
        let spawn_shell = shell.clone();
        let (master, child) = tokio::task::spawn_blocking(move || -> PtyResult<_> {
            let pty_system = native_pty_system();
            let pair = pty_system
                .openpty(size)
                .map_err(|err| PtyError::Open(err.to_string()))?;
            let child = pair
                .slave
                .spawn_command(cmd)
                .map_err(|err| PtyError::Spawn {
                    shell: spawn_shell,
                    reason: err.to_string(),
                })?;
            // The child owns its copy of the slave; ours must go so the master
            // sees EOF when the child exits.
            drop(pair.slave);
            Ok((pair.master, child))
        })
        .await
        .map_err(|err| PtyError::Open(format!("pty spawn task failed: {err}")))??;

        let pid = child.process_id();
        let mut killer = child.clone_killer();
        let exited = Arc::new(AtomicBool::new(false));

        let reader = master
            .try_clone_reader()
            .map_err(|err| PtyError::Open(err.to_string()))?;
        let writer = master
            .take_writer()
            .map_err(|err| PtyError::Open(err.to_string()))?;

        let (events_tx, events_rx) = mpsc::channel::<PtyEvent>(EVENT_CHANNEL_CAPACITY);
        let (write_tx, write_rx) = mpsc::channel::<Bytes>(WRITE_CHANNEL_CAPACITY);
        let (control_tx, control_rx) = mpsc::unbounded_channel::<PtyControl>();

        spawn_reader_thread(reader, child, events_tx, Arc::clone(&exited))?;
        spawn_writer_thread(writer, write_rx)?;

        let control_exited = Arc::clone(&exited);
        tokio::spawn(async move {
            control_loop(master, control_rx, &mut killer, pid, control_exited).await;
        });

        Ok(PtySession {
            events: events_rx,
            write_tx,
            control_tx,
            pid,
            shell,
        })
    }

    pub async fn write(&self, data: Bytes) -> PtyResult<()> {
        self.write_tx
            .send(data)
            .await
            .map_err(|_| crate::PtyError::Closed)
    }

    pub fn resize(&self, cols: u16, rows: u16) -> PtyResult<()> {
        if cols == 0 || rows == 0 {
            return Err(PtyError::InvalidArgument(format!(
                "invalid terminal size {cols}x{rows}"
            )));
        }
        self.control_tx
            .send(PtyControl::Resize { cols, rows })
            .map_err(|_| crate::PtyError::Closed)
    }

    /// Terminate the child process (SIGHUP then SIGKILL on Unix).
    pub fn kill(&self) {
        let _ = self.control_tx.send(PtyControl::Kill);
    }

    /// Current working directory of the foreground process, when the
    /// platform supports discovering it (macOS `lsof`/`proc_pidinfo`, Linux
    /// `/proc/<pid>/cwd`). `None` on Windows.
    pub async fn current_dir(&self) -> Option<String> {
        #[cfg(unix)]
        {
            let foreground = {
                let (tx, rx) = oneshot::channel();
                if self.control_tx.send(PtyControl::ForegroundPid(tx)).is_ok() {
                    rx.await
                        .ok()
                        .flatten()
                        .filter(|pid| *pid > 0)
                        .map(|pid| pid as u32)
                } else {
                    None
                }
            };
            if let Some(pid) = foreground {
                if let Some(cwd) = crate::cwd::process_cwd(pid).await {
                    return Some(cwd);
                }
            }
            let shell_pid = self.pid?;
            if Some(shell_pid) == foreground {
                return None;
            }
            crate::cwd::process_cwd(shell_pid).await
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Spawn helpers
// ---------------------------------------------------------------------------

fn expand_home(path: &str) -> PathBuf {
    if path == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from(path));
    }
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn resolve_shell(requested: Option<&str>) -> String {
    let requested = requested.map(str::trim).filter(|s| !s.is_empty());
    let Some(requested) = requested else {
        return default_shell();
    };
    let expanded = expand_home(requested);
    let has_separator = requested.contains('/') || requested.contains('\\');
    if has_separator || requested.starts_with('.') {
        // Absolute or relative path: resolve relative ones against the cwd so
        // the child does not depend on PATH lookup semantics.
        let resolved = if expanded.is_absolute() {
            expanded
        } else {
            std::env::current_dir()
                .map(|d| d.join(&expanded))
                .unwrap_or(expanded)
        };
        resolved.to_string_lossy().into_owned()
    } else {
        // Bare program name: let the OS search PATH.
        requested.to_string()
    }
}

fn resolve_cwd(requested: Option<&str>) -> Option<PathBuf> {
    let home = dirs::home_dir();
    let requested = requested.map(str::trim).filter(|s| !s.is_empty());
    if let Some(requested) = requested {
        let candidate = expand_home(requested);
        let candidate = if candidate.is_absolute() {
            candidate
        } else {
            std::env::current_dir()
                .map(|d| d.join(&candidate))
                .unwrap_or(candidate)
        };
        if candidate.is_dir() {
            return Some(candidate);
        }
        tracing::warn!(cwd = %requested, "requested cwd is not a directory; using the home directory");
    }
    home.filter(|h| h.is_dir())
}

fn env_str(cmd: &CommandBuilder, key: &str) -> Option<String> {
    cmd.get_env(key).map(|v| v.to_string_lossy().into_owned())
}

fn is_utf8_locale(value: &Option<String>) -> bool {
    value
        .as_deref()
        .map(|v| {
            let lower = v.to_ascii_lowercase();
            lower.contains("utf-8") || lower.contains("utf8")
        })
        .unwrap_or(false)
}

fn is_empty_locale(value: &Option<String>) -> bool {
    match value.as_deref().map(str::trim) {
        None | Some("") | Some("C") | Some("POSIX") => true,
        Some(_) => false,
    }
}

/// Mirror `applyLocaleDefaults` from `terminalBridge.cjs`: when no locale
/// variable names a UTF-8 locale and none names any real locale, force a
/// UTF-8 one so box drawing and non-ASCII paths render.
fn apply_locale_defaults(cmd: &mut CommandBuilder) {
    let lc_all = env_str(cmd, "LC_ALL");
    let lc_ctype = env_str(cmd, "LC_CTYPE");
    let lang = env_str(cmd, "LANG");
    if is_utf8_locale(&lc_all) || is_utf8_locale(&lc_ctype) || is_utf8_locale(&lang) {
        return;
    }
    if !is_empty_locale(&lc_all) || !is_empty_locale(&lc_ctype) || !is_empty_locale(&lang) {
        return;
    }
    cmd.env("LANG", DEFAULT_UTF8_LOCALE);
    cmd.env("LC_CTYPE", DEFAULT_UTF8_LOCALE);
    cmd.env("LC_ALL", DEFAULT_UTF8_LOCALE);
}

// ---------------------------------------------------------------------------
// Threads and tasks
// ---------------------------------------------------------------------------

fn spawn_reader_thread(
    mut reader: Box<dyn Read + Send>,
    mut child: Box<dyn portable_pty::Child + Send + Sync>,
    events_tx: mpsc::Sender<PtyEvent>,
    exited: Arc<AtomicBool>,
) -> PtyResult<()> {
    std::thread::Builder::new()
        .name("netcatty-pty-reader".into())
        .spawn(move || {
            let mut buf = vec![0u8; READ_CHUNK];
            let mut receiver_alive = true;
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if receiver_alive {
                            let chunk = Bytes::copy_from_slice(&buf[..n]);
                            if events_tx.blocking_send(PtyEvent::Data(chunk)).is_err() {
                                // Nobody is listening any more; keep draining
                                // so the child is not blocked on a full pty.
                                receiver_alive = false;
                            }
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    // EIO on Unix once every slave handle is closed: normal EOF.
                    Err(_) => break,
                }
            }
            drop(reader);

            let event = match child.wait() {
                Ok(status) => exit_event(&status),
                Err(err) => {
                    tracing::warn!(error = %err, "waiting for local shell failed");
                    PtyEvent::Exit {
                        exit_code: None,
                        signal: None,
                    }
                }
            };
            exited.store(true, Ordering::SeqCst);
            if receiver_alive {
                let _ = events_tx.blocking_send(event);
            }
        })
        .map(|_| ())
        .map_err(|err| PtyError::Open(format!("failed to start pty reader thread: {err}")))
}

fn exit_event(status: &portable_pty::ExitStatus) -> PtyEvent {
    match status.signal() {
        Some(signal) => PtyEvent::Exit {
            exit_code: None,
            signal: Some(signal.to_string()),
        },
        None => PtyEvent::Exit {
            exit_code: Some(status.exit_code() as i32),
            signal: None,
        },
    }
}

fn spawn_writer_thread(
    mut writer: Box<dyn Write + Send>,
    mut write_rx: mpsc::Receiver<Bytes>,
) -> PtyResult<()> {
    std::thread::Builder::new()
        .name("netcatty-pty-writer".into())
        .spawn(move || {
            while let Some(bytes) = write_rx.blocking_recv() {
                if let Err(err) = writer.write_all(&bytes).and_then(|_| writer.flush()) {
                    tracing::debug!(error = %err, "pty write failed; stopping writer");
                    break;
                }
            }
            // Dropping the writer sends EOF to the slave side.
        })
        .map(|_| ())
        .map_err(|err| PtyError::Open(format!("failed to start pty writer thread: {err}")))
}

async fn control_loop(
    master: Box<dyn MasterPty + Send>,
    mut control_rx: mpsc::UnboundedReceiver<PtyControl>,
    killer: &mut Box<dyn ChildKiller + Send + Sync>,
    pid: Option<u32>,
    exited: Arc<AtomicBool>,
) {
    while let Some(msg) = control_rx.recv().await {
        match msg {
            PtyControl::Resize { cols, rows } => {
                if let Err(err) = master.resize(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                }) {
                    tracing::debug!(error = %err, "pty resize failed");
                }
            }
            PtyControl::Kill => terminate(killer, pid, &exited),
            #[cfg(unix)]
            PtyControl::ForegroundPid(reply) => {
                let _ = reply.send(master.process_group_leader());
            }
        }
    }
    // The session handle is gone: do not leave an orphaned shell behind.
    if !exited.load(Ordering::SeqCst) {
        terminate(killer, pid, &exited);
    }
    drop(master);
}

/// Ask the child to terminate: SIGHUP (what closing a terminal does), then
/// SIGKILL after a grace period on Unix; `TerminateProcess` on Windows.
fn terminate(
    killer: &mut Box<dyn ChildKiller + Send + Sync>,
    pid: Option<u32>,
    exited: &Arc<AtomicBool>,
) {
    if exited.load(Ordering::SeqCst) {
        return;
    }
    if let Err(err) = killer.kill() {
        tracing::debug!(error = %err, "pty kill failed");
    }
    #[cfg(unix)]
    {
        let Some(pid) = pid else { return };
        let exited = Arc::clone(exited);
        tokio::spawn(async move {
            tokio::time::sleep(KILL_GRACE).await;
            if exited.load(Ordering::SeqCst) {
                return;
            }
            // SAFETY: plain syscall; the pid belongs to a child we spawned and
            // have not yet reaped (the reader thread reaps it only after it
            // exits), so it cannot have been recycled.
            let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            if rc == 0 {
                tracing::debug!(pid, "local shell did not exit after SIGHUP; sent SIGKILL");
            }
        });
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::Instant;

    async fn run_until_exit(
        session: &mut PtySession,
        timeout: Duration,
    ) -> (Vec<u8>, Option<(Option<i32>, Option<String>)>) {
        let deadline = Instant::now() + timeout;
        let mut output = Vec::new();
        let mut exit = None;
        while exit.is_none() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, session.events.recv()).await {
                Ok(Some(PtyEvent::Data(bytes))) => output.extend_from_slice(&bytes),
                Ok(Some(PtyEvent::Exit { exit_code, signal })) => exit = Some((exit_code, signal)),
                Ok(None) => break,
                Err(_) => break,
            }
        }
        (output, exit)
    }

    fn sh(args: &[&str]) -> LocalPtyOptions {
        LocalPtyOptions {
            shell: Some("/bin/sh".to_string()),
            shell_args: args.iter().map(|a| a.to_string()).collect(),
            cols: 80,
            rows: 24,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn spawn_echo_and_exit_code() {
        let mut session = PtySession::spawn(sh(&["-c", "echo hello; exit 3"]))
            .await
            .unwrap();
        assert_eq!(session.shell, "/bin/sh");
        assert!(session.pid.is_some());
        let (output, exit) = run_until_exit(&mut session, Duration::from_secs(10)).await;
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("hello"), "output was {text:?}");
        assert_eq!(exit, Some((Some(3), None)));
        // Exactly one Exit: the channel closes afterwards.
        assert!(session.events.recv().await.is_none());
    }

    #[tokio::test]
    async fn env_and_term_are_applied() {
        let mut options = sh(&[
            "-c",
            "printf '%s|%s|%s|%s\\n' \"$TERM\" \"$FOO\" \"$COLORTERM\" \"$LANG\"",
        ]);
        options.env.insert("FOO".into(), "bar baz".into());
        options.env.insert("LANG".into(), "C".into());
        options.env.insert("LC_ALL".into(), "".into());
        options.env.insert("LC_CTYPE".into(), "".into());
        options.term = Some("xterm".into());
        let mut session = PtySession::spawn(options).await.unwrap();
        let (output, exit) = run_until_exit(&mut session, Duration::from_secs(10)).await;
        let text = String::from_utf8_lossy(&output);
        assert!(
            text.contains("xterm|bar baz|truecolor|en_US.UTF-8"),
            "output was {text:?}"
        );
        assert_eq!(exit, Some((Some(0), None)));
    }

    #[tokio::test]
    async fn write_reaches_the_shell() {
        let mut session = PtySession::spawn(sh(&["-c", "cat"])).await.unwrap();
        session.write(Bytes::from_static(b"ping\n")).await.unwrap();
        session.write(Bytes::from_static(&[0x04])).await.unwrap(); // Ctrl-D → EOF
        let (output, exit) = run_until_exit(&mut session, Duration::from_secs(10)).await;
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("ping"), "output was {text:?}");
        assert_eq!(exit, Some((Some(0), None)));
    }

    #[tokio::test]
    async fn resize_and_kill() {
        let mut session = PtySession::spawn(sh(&["-c", "sleep 0.5; stty size; sleep 30"]))
            .await
            .unwrap();
        session.resize(100, 40).unwrap();
        assert!(session.resize(0, 40).is_err());
        tokio::time::sleep(Duration::from_millis(900)).await;
        session.resize(120, 50).unwrap();
        session.kill();
        let (output, exit) = run_until_exit(&mut session, Duration::from_secs(10)).await;
        let text = String::from_utf8_lossy(&output);
        assert!(
            text.contains("40 100"),
            "resized size should be reported: {text:?}"
        );
        let (code, signal) = exit.expect("exit event after kill");
        assert!(
            signal.is_some() || code.is_some(),
            "exit status should be known"
        );
    }

    #[tokio::test]
    async fn cwd_fallback_and_current_dir() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().canonicalize().unwrap();
        let mut options = sh(&["-c", "pwd; sleep 30"]);
        options.cwd = Some(dir.path().to_string_lossy().into_owned());
        let mut session = PtySession::spawn(options).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let cwd = session.current_dir().await.expect("cwd discovered");
        assert_eq!(Path::new(&cwd).canonicalize().unwrap(), canonical);
        session.kill();
        let (output, exit) = run_until_exit(&mut session, Duration::from_secs(10)).await;
        assert!(String::from_utf8_lossy(&output)
            .contains(canonical.file_name().unwrap().to_str().unwrap()));
        assert!(exit.is_some());

        // A bogus cwd falls back to the home directory instead of failing.
        let mut options = sh(&["-c", "pwd"]);
        options.cwd = Some("/definitely/not/a/dir".into());
        let mut session = PtySession::spawn(options).await.unwrap();
        let (output, exit) = run_until_exit(&mut session, Duration::from_secs(10)).await;
        let home = dirs::home_dir().unwrap();
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains(home.to_str().unwrap()), "output was {text:?}");
        assert_eq!(exit, Some((Some(0), None)));
    }

    #[tokio::test]
    async fn missing_shell_fails_to_spawn() {
        let options = LocalPtyOptions {
            shell: Some("/definitely/missing/shell".into()),
            ..Default::default()
        };
        let err = PtySession::spawn(options).await.unwrap_err();
        assert!(
            matches!(err, PtyError::Spawn { .. } | PtyError::Open(_)),
            "{err}"
        );
    }

    #[tokio::test]
    async fn dropping_the_session_terminates_the_shell() {
        let session = PtySession::spawn(sh(&["-c", "sleep 30"])).await.unwrap();
        let pid = session.pid.unwrap();
        drop(session);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            // SAFETY: signal 0 only checks for existence.
            let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
            if !alive {
                break;
            }
            // A zombie still answers kill(0); check its state via ps.
            let state = std::process::Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            if state.is_empty() || state.starts_with('Z') {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "shell {pid} still alive after drop (state {state})"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[test]
    fn locale_defaults() {
        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.env_clear();
        apply_locale_defaults(&mut cmd);
        assert_eq!(env_str(&cmd, "LANG").as_deref(), Some(DEFAULT_UTF8_LOCALE));
        assert_eq!(
            env_str(&cmd, "LC_ALL").as_deref(),
            Some(DEFAULT_UTF8_LOCALE)
        );

        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.env_clear();
        cmd.env("LANG", "de_DE.ISO8859-1");
        apply_locale_defaults(&mut cmd);
        assert_eq!(env_str(&cmd, "LANG").as_deref(), Some("de_DE.ISO8859-1"));
        assert_eq!(env_str(&cmd, "LC_ALL"), None);

        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.env_clear();
        cmd.env("LC_CTYPE", "UTF-8");
        apply_locale_defaults(&mut cmd);
        assert_eq!(env_str(&cmd, "LANG"), None);
    }

    #[test]
    fn shell_and_cwd_resolution() {
        assert_eq!(resolve_shell(None), default_shell());
        assert_eq!(resolve_shell(Some("  ")), default_shell());
        assert_eq!(resolve_shell(Some("/bin/sh")), "/bin/sh");
        assert_eq!(resolve_shell(Some("zsh")), "zsh");
        let home = dirs::home_dir().unwrap();
        assert_eq!(
            resolve_shell(Some("~/bin/fish")),
            home.join("bin/fish").to_string_lossy()
        );
        assert_eq!(resolve_cwd(Some("~")), Some(home.clone()));
        assert_eq!(resolve_cwd(Some("/nope/nope")), Some(home.clone()));
        assert_eq!(resolve_cwd(None), Some(home));
        assert_eq!(resolve_cwd(Some("/")), Some(PathBuf::from("/")));
    }
}

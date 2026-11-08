//! Raw command execution for network devices / serial consoles (Electron
//! `execViaRawPty`): the command is sent as-is followed by CR; completion is
//! an idle timeout after the first output; exit codes do not exist.

use crate::job::{JobResult, OutputRx, PtyInput};
use crate::shell_utils::strip_ansi;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::Instant;

const MAX_OUTPUT_CHARS: usize = 512 * 1024;
const ECHO_PHASE_CHUNKS: usize = 2;

/// Cancellation handle for a raw exec.
#[derive(Clone, Default)]
pub struct RawCancel(Arc<Notify>, Arc<std::sync::atomic::AtomicBool>);

impl RawCancel {
    pub fn cancel(&self) {
        self.1.store(true, std::sync::atomic::Ordering::SeqCst);
        self.0.notify_one();
    }
}

fn finish_raw(output: &str, command: &str, error: Option<String>) -> JobResult {
    let mut cleaned = strip_ansi(output).replace('\r', "");
    let mut lines: Vec<&str> = cleaned.split('\n').collect();
    if lines.len() > 1 {
        let first_line = lines[0].trim();
        let cmd_trimmed = command.trim();
        if !cmd_trimmed.is_empty() && (first_line == cmd_trimmed || first_line.ends_with(cmd_trimmed)) {
            lines.remove(0);
        }
    }
    cleaned = lines.join("\n").trim().to_string();
    JobResult {
        ok: error.is_none(),
        stdout: cleaned,
        stderr: String::new(),
        exit_code: None,
        error,
        code: None,
        cancelled: None,
        output_base_offset: 0,
        total_output_chars: 0,
        output_truncated: false,
    }
}

/// Send `command` + CR and collect output until `idle_ms` of silence
/// (doubled during the first two chunks), `timeout_ms` overall, or cancel.
pub async fn exec_via_raw_pty(
    writer: Arc<dyn PtyInput>,
    mut rx: OutputRx,
    command: &str,
    timeout_ms: u64,
    idle_ms: u64,
    cancel: RawCancel,
) -> JobResult {
    if cancel.1.load(std::sync::atomic::Ordering::SeqCst) {
        return finish_raw("", command, Some("Cancelled".into()));
    }
    let idle_ms = if idle_ms == 0 { 3000 } else { idle_ms };
    let mut output = String::new();
    let mut chunk_count = 0usize;
    let overall = Instant::now() + Duration::from_millis(timeout_ms.max(1));
    let mut idle: Option<Instant> = None;
    if let Err(err) = writer.write(&format!("{command}\r")).await {
        return finish_raw("", command, Some(format!("Serial port error: {err}")));
    }
    loop {
        let next = match idle {
            Some(at) => at.min(overall),
            None => overall,
        };
        tokio::select! {
            biased;
            _ = cancel.0.notified() => {
                let _ = writer.write("\x03").await;
                return finish_raw(&output, command, Some("Cancelled".into()));
            }
            chunk = rx.recv() => {
                match chunk {
                    Some(text) => {
                        chunk_count += 1;
                        if output.chars().count() < MAX_OUTPUT_CHARS {
                            output.push_str(&text);
                            let effective = if chunk_count <= ECHO_PHASE_CHUNKS { idle_ms * 2 } else { idle_ms };
                            idle = Some(Instant::now() + Duration::from_millis(effective));
                        }
                    }
                    None => return finish_raw(&output, command, Some("Serial port closed unexpectedly".into())),
                }
            }
            _ = tokio::time::sleep_until(next) => {
                if Instant::now() >= overall {
                    let _ = writer.write("\x03").await;
                    let timeout_sec = (timeout_ms as f64 / 1000.0).round() as u64;
                    return finish_raw(&output, command, Some(format!("Command timed out ({timeout_sec}s)")));
                }
                if idle.is_some_and(|at| Instant::now() >= at) {
                    return finish_raw(&output, command, None);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    struct Pty(Arc<Mutex<Vec<String>>>);
    #[async_trait::async_trait]
    impl PtyInput for Pty {
        async fn write(&self, data: &str) -> Result<(), String> {
            self.0.lock().unwrap().push(data.to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn raw_exec_strips_echo_and_finishes_on_idle() {
        let (tx, rx) = mpsc::unbounded_channel();
        let writes = Arc::new(Mutex::new(Vec::new()));
        let pty = Arc::new(Pty(writes.clone()));
        let task = tokio::spawn(exec_via_raw_pty(pty, rx, "show version", 5000, 30, RawCancel::default()));
        tx.send("Router#show version\r\n".into()).unwrap();
        tx.send("Cisco IOS 15.2\r\nRouter#".into()).unwrap();
        let result = task.await.unwrap();
        assert!(result.ok);
        assert_eq!(result.exit_code, None);
        assert_eq!(result.stdout, "Cisco IOS 15.2\nRouter#");
        assert_eq!(writes.lock().unwrap()[0], "show version\r");
        assert!(!writes.lock().unwrap().iter().any(|w| w.starts_with("\x0b\x15")));
    }

    #[tokio::test]
    async fn raw_exec_cancel_and_timeout() {
        let (_tx, rx) = mpsc::unbounded_channel();
        let pty = Arc::new(Pty(Default::default()));
        let cancel = RawCancel::default();
        let c = cancel.clone();
        let task = tokio::spawn(exec_via_raw_pty(pty, rx, "x", 5000, 3000, cancel));
        tokio::time::sleep(Duration::from_millis(10)).await;
        c.cancel();
        assert_eq!(task.await.unwrap().error.as_deref(), Some("Cancelled"));
        let (_tx, rx) = mpsc::unbounded_channel();
        let pty = Arc::new(Pty(Default::default()));
        let result = exec_via_raw_pty(pty, rx, "x", 50, 3000, RawCancel::default()).await;
        assert_eq!(result.error.as_deref(), Some("Command timed out (0s)"));
    }
}

//! Netcatty-owned `ssh-agent` for FIDO2 sk-* keys (Electron
//! `fidoAgentManager.cjs` + the FIDO parts of `systemSshAgent.cjs`).
//!
//! Agents started at login usually lack `SSH_ASKPASS`, so their
//! `ssh-sk-helper` cannot ask for a PIN or show "touch your key". Netcatty
//! runs its own agent (`ssh-agent -D -a <socket>`) as a child with the
//! askpass environment, `ssh-add`s the selected key handle into it and
//! signs through it. One agent is shared by every session (reference
//! counted) and stopped when the last user releases it. On Windows the
//! Win32-OpenSSH service pipe is the fallback when no prompt-capable
//! user-mode agent can be started (Windows shows its own WebAuthn UI).

use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::process::{Child, Command};

pub const WIN_SYSTEM_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";
const SSH_ADD_TIMEOUT: Duration = Duration::from_secs(170);

fn first_existing(candidates: &[PathBuf]) -> Option<String> {
    candidates
        .iter()
        .find(|p| p.exists())
        .map(|p| p.to_string_lossy().into_owned())
}

fn windows_git_candidates(binary: &str) -> Vec<PathBuf> {
    let var = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let program_files = var("ProgramFiles", r"C:\Program Files");
    let program_files_x86 = var("ProgramFiles(x86)", r"C:\Program Files (x86)");
    let local = var("LOCALAPPDATA", "");
    let profile = var("USERPROFILE", "");
    let exe = format!("{binary}.exe");
    vec![
        Path::new(&program_files).join("Git").join("usr").join("bin").join(&exe),
        Path::new(&program_files_x86).join("Git").join("usr").join("bin").join(&exe),
        Path::new(&local).join("Programs").join("Git").join("usr").join("bin").join(&exe),
        Path::new(&profile).join("scoop").join("apps").join("git").join("current").join("usr").join("bin").join(&exe),
    ]
}

/// `ssh-agent` / `ssh-add` / `ssh-keygen` resolution: the
/// `NETCATTY_SSH_<TOOL>_PATH` override, Homebrew OpenSSH on macOS (the
/// system build lacks the FIDO provider), Git's OpenSSH on Windows, else PATH.
pub fn resolve_openssh_binary(tool: &str) -> String {
    let env_name = format!("NETCATTY_SSH_{}_PATH", tool.trim_start_matches("ssh-").to_uppercase());
    if let Ok(path) = std::env::var(&env_name) {
        if !path.trim().is_empty() {
            return path.trim().to_string();
        }
    }
    if cfg!(target_os = "macos") {
        let candidates: Vec<PathBuf> = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]
            .iter()
            .map(|d| Path::new(d).join(tool))
            .collect();
        if let Some(found) = first_existing(&candidates) {
            return found;
        }
    }
    if cfg!(windows) {
        if let Some(found) = first_existing(&windows_git_candidates(tool)) {
            return found;
        }
    }
    tool.to_string()
}

/// `ssh-add` next to a given `ssh-agent` (same OpenSSH build).
pub fn companion_binary(agent_path: &str, tool: &str) -> Option<String> {
    let path = Path::new(agent_path);
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    if name.trim_end_matches(".exe") != "ssh-agent" {
        return None;
    }
    let file = path.file_name()?.to_string_lossy().replace("ssh-agent", tool).replace("SSH-AGENT", tool);
    let candidate = path.with_file_name(file);
    candidate.exists().then(|| candidate.to_string_lossy().into_owned())
}

/// `SSH_AUTH_SOCK=...; SSH_AGENT_PID=...;` from `ssh-agent -s`.
pub fn parse_agent_stdout(stdout: &str) -> (Option<String>, Option<u32>) {
    let sock = stdout.split("SSH_AUTH_SOCK=").nth(1).and_then(|rest| {
        let value = rest.split([';', '\r', '\n']).next()?.trim();
        let value = value.trim_matches(|c| c == '\'' || c == '"');
        (!value.is_empty()).then(|| value.to_string())
    });
    let pid = stdout
        .split("SSH_AGENT_PID=")
        .nth(1)
        .and_then(|rest| rest.chars().take_while(char::is_ascii_digit).collect::<String>().parse().ok());
    (sock, pid)
}

/// One running (or borrowed) agent.
struct AgentProcess {
    socket: String,
    ssh_add: String,
    owned: bool,
    child: Mutex<Option<Child>>,
    dir: Option<PathBuf>,
}

impl AgentProcess {
    fn stop(&self) {
        if let Some(mut child) = self.child.lock().take() {
            let _ = child.start_kill();
        }
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Slot {
    agent: Arc<AgentProcess>,
    refs: usize,
    generation: u64,
}

/// Identity holds per `(socket, public blob)`: the last release removes the
/// identity from the shared agent (`ssh-add -d [-k]`).
#[derive(Default)]
struct IdentityRefs {
    entries: HashMap<(String, String), IdentityEntry>,
}

struct IdentityEntry {
    refs: usize,
    path: String,
    plain: bool,
    /// Keeps the staged handle on disk until the identity is removed.
    _staged: Option<Arc<crate::sk::StagedKey>>,
}

pub struct AgentManager {
    slot: Mutex<Option<Slot>>,
    generation: Mutex<u64>,
    start_lock: tokio::sync::Mutex<()>,
    identities: Mutex<IdentityRefs>,
    /// Serialises identity add / remove per socket.
    identity_lock: tokio::sync::Mutex<()>,
}

impl Default for AgentManager {
    fn default() -> Self {
        Self {
            slot: Mutex::new(None),
            generation: Mutex::new(0),
            start_lock: tokio::sync::Mutex::new(()),
            identities: Mutex::new(IdentityRefs::default()),
            identity_lock: tokio::sync::Mutex::new(()),
        }
    }
}

/// A caller's hold on the shared agent; dropping it releases the hold.
pub struct AgentLease {
    manager: Weak<AgentManager>,
    agent: Arc<AgentProcess>,
    generation: u64,
}

impl std::fmt::Debug for AgentLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentLease")
            .field("socket", &self.agent.socket)
            .field("owned", &self.agent.owned)
            .finish()
    }
}

impl AgentLease {
    pub fn socket(&self) -> &str {
        &self.agent.socket
    }
    pub fn ssh_add(&self) -> &str {
        &self.agent.ssh_add
    }
    pub fn owned(&self) -> bool {
        self.agent.owned
    }
}

impl Drop for AgentLease {
    fn drop(&mut self) {
        if let Some(manager) = self.manager.upgrade() {
            manager.release(self.generation);
        }
    }
}

/// Options for starting the agent.
pub struct StartOptions<'a> {
    pub temp_base: &'a Path,
    /// Askpass environment without a caller lease.
    pub env: Vec<(String, String)>,
}

impl AgentManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn release(&self, generation: u64) {
        let mut slot = self.slot.lock();
        let Some(current) = slot.as_mut() else { return };
        if current.generation != generation {
            return;
        }
        current.refs = current.refs.saturating_sub(1);
        if current.refs == 0 {
            if let Some(old) = slot.take() {
                old.agent.stop();
            }
        }
    }

    /// Live socket of the shared agent (Mosh / ET `IdentityAgent`).
    pub fn active_socket(&self) -> Option<String> {
        self.slot.lock().as_ref().map(|s| s.agent.socket.clone())
    }

    /// Stop the agent regardless of holders (app exit).
    pub fn shutdown(&self) {
        if let Some(slot) = self.slot.lock().take() {
            slot.agent.stop();
        }
        self.identities.lock().entries.clear();
    }

    fn lease_from_slot(self: &Arc<Self>) -> Option<AgentLease> {
        let mut slot = self.slot.lock();
        let current = slot.as_mut()?;
        let alive = match current.agent.child.lock().as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => true, // borrowed system pipe
        };
        if !alive {
            if let Some(old) = slot.take() {
                old.agent.stop();
            }
            return None;
        }
        current.refs += 1;
        Some(AgentLease {
            manager: Arc::downgrade(self),
            agent: current.agent.clone(),
            generation: current.generation,
        })
    }

    /// Acquire the shared agent, starting it when needed.
    pub async fn acquire(self: &Arc<Self>, options: StartOptions<'_>) -> Result<AgentLease, String> {
        if let Some(lease) = self.lease_from_slot() {
            return Ok(lease);
        }
        let _start = self.start_lock.lock().await;
        if let Some(lease) = self.lease_from_slot() {
            return Ok(lease);
        }
        let agent = start_agent(&options).await?;
        let generation = {
            let mut g = self.generation.lock();
            *g += 1;
            *g
        };
        let agent = Arc::new(agent);
        *self.slot.lock() = Some(Slot {
            agent: agent.clone(),
            refs: 1,
            generation,
        });
        Ok(AgentLease {
            manager: Arc::downgrade(self),
            agent,
            generation,
        })
    }

    /// Public blobs currently advertised by the agent (`ssh-add -L`).
    pub async fn loaded_blobs(&self, lease: &AgentLease) -> Vec<String> {
        let output = Command::new(lease.ssh_add())
            .arg("-L")
            .env("SSH_AUTH_SOCK", lease.socket())
            .env("SSH_ASKPASS_REQUIRE", "never")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output();
        match tokio::time::timeout(Duration::from_secs(10), output).await {
            Ok(Ok(out)) => String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(crate::sk::public_key_blob)
                .collect(),
            _ => Vec::new(),
        }
    }

    /// `ssh-add <args>` against the lease's agent with `env` (askpass).
    pub async fn ssh_add(&self, lease: &AgentLease, args: &[&str], env: &[(String, String)]) -> Result<(), String> {
        let mut cmd = Command::new(lease.ssh_add());
        cmd.args(args)
            .env("SSH_AUTH_SOCK", lease.socket())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        for (k, v) in env {
            cmd.env(k, v);
        }
        #[cfg(windows)]
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        let output = tokio::time::timeout(SSH_ADD_TIMEOUT, cmd.output())
            .await
            .map_err(|_| "ssh-add timed out".to_string())?
            .map_err(|e| format!("cannot run ssh-add: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(if stderr.is_empty() {
                format!("ssh-add exited with {}", output.status)
            } else {
                stderr
            })
        }
    }

    /// Make sure `staged` (or an identity file) is loaded in the agent and
    /// hold it until the returned [`IdentityHold`] is dropped. Identities
    /// that were already in the agent before Netcatty touched them are
    /// never adopted (removing them later would surprise the user).
    pub async fn load_identity(
        self: &Arc<Self>,
        lease: &AgentLease,
        identity_path: &str,
        public_blob: Option<String>,
        certificate_blob: Option<String>,
        staged: Option<Arc<crate::sk::StagedKey>>,
        askpass_env: &[(String, String)],
    ) -> Result<Vec<IdentityHold>, String> {
        let _guard = self.identity_lock.lock().await;
        let loaded = self.loaded_blobs(lease).await;
        let socket = lease.socket().to_string();
        let mut holds = Vec::new();
        let bare_present = public_blob.as_ref().is_some_and(|b| loaded.contains(b));
        let cert_missing = certificate_blob.as_ref().is_some_and(|b| !loaded.contains(b));
        let owned_by_us = |blob: &Option<String>| {
            blob.as_ref()
                .is_some_and(|b| self.identities.lock().entries.contains_key(&(socket.clone(), b.clone())))
        };
        if bare_present && !cert_missing {
            // Join existing Netcatty holds only.
            if owned_by_us(&public_blob) {
                holds.push(self.retain(&socket, public_blob.clone().unwrap(), identity_path, true, staged.clone()));
            }
            if owned_by_us(&certificate_blob) {
                let cert_path = format!("{identity_path}-cert.pub");
                holds.push(self.retain(&socket, certificate_blob.clone().unwrap(), &cert_path, false, staged.clone()));
            }
            return Ok(holds);
        }
        self.ssh_add(lease, &[identity_path], askpass_env).await?;
        let key = public_blob.clone().unwrap_or_else(|| identity_path.to_string());
        if !bare_present || owned_by_us(&public_blob) {
            holds.push(self.retain(&socket, key, identity_path, true, staged.clone()));
        }
        if let Some(cert) = certificate_blob {
            let cert_path = format!("{identity_path}-cert.pub");
            holds.push(self.retain(&socket, cert, &cert_path, false, staged));
        }
        Ok(holds)
    }

    fn retain(
        self: &Arc<Self>,
        socket: &str,
        blob: String,
        path: &str,
        plain: bool,
        staged: Option<Arc<crate::sk::StagedKey>>,
    ) -> IdentityHold {
        let key = (socket.to_string(), blob);
        let mut refs = self.identities.lock();
        let entry = refs.entries.entry(key.clone()).or_insert_with(|| IdentityEntry {
            refs: 0,
            path: path.to_string(),
            plain,
            _staged: staged,
        });
        entry.refs += 1;
        IdentityHold {
            manager: Arc::downgrade(self),
            key,
        }
    }

    fn release_identity(self: &Arc<Self>, key: &(String, String)) {
        let removed = {
            let mut refs = self.identities.lock();
            let Some(entry) = refs.entries.get_mut(key) else { return };
            entry.refs = entry.refs.saturating_sub(1);
            if entry.refs > 0 {
                return;
            }
            refs.entries.remove(key)
        };
        let Some(entry) = removed else { return };
        let still_running = self.active_socket().as_deref() == Some(key.0.as_str());
        if !still_running {
            return; // agent already gone; staged files drop with `entry`
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        let this = self.clone();
        let socket = key.0.clone();
        runtime.spawn(async move {
            let _guard = this.identity_lock.lock().await;
            let ssh_add = this
                .slot
                .lock()
                .as_ref()
                .map(|s| s.agent.ssh_add.clone())
                .unwrap_or_else(|| resolve_openssh_binary("ssh-add"));
            let mut cmd = Command::new(ssh_add);
            if entry.plain {
                cmd.args(["-d", "-k", &entry.path]);
            } else {
                cmd.args(["-d", &entry.path]);
            }
            cmd.env("SSH_AUTH_SOCK", &socket)
                .env("SSH_ASKPASS_REQUIRE", "never")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true);
            let _ = tokio::time::timeout(Duration::from_secs(5), cmd.status()).await;
            drop(entry); // staged handle removed after ssh-add -d
        });
    }
}

/// Hold on one identity in the shared agent.
pub struct IdentityHold {
    manager: Weak<AgentManager>,
    key: (String, String),
}

impl Drop for IdentityHold {
    fn drop(&mut self) {
        if let Some(manager) = self.manager.upgrade() {
            manager.release_identity(&self.key);
        }
    }
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

async fn start_agent(options: &StartOptions<'_>) -> Result<AgentProcess, String> {
    let ssh_agent = resolve_openssh_binary("ssh-agent");
    let ssh_add = companion_binary(&ssh_agent, "ssh-add").unwrap_or_else(|| resolve_openssh_binary("ssh-add"));

    #[cfg(unix)]
    {
        // Short directory name: sockaddr_un paths are limited (~104 bytes).
        let dir = options.temp_base.join(format!("fa-{}", short_id()));
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir).map_err(|e| format!("cannot create agent directory: {e}"))?;
        let socket = dir.join("agent.sock");
        let mut cmd = Command::new(&ssh_agent);
        cmd.arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        // The agent must not inherit a caller-bound lease.
        cmd.env_remove(crate::askpass::LEASE_ENV);
        for (k, v) in &options.env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().map_err(|e| start_error(&e.to_string()))?;
        for _ in 0..100 {
            if socket.exists() {
                return Ok(AgentProcess {
                    socket: socket.to_string_lossy().into_owned(),
                    ssh_add,
                    owned: true,
                    child: Mutex::new(Some(child)),
                    dir: Some(dir),
                });
            }
            if let Ok(Some(status)) = child.try_wait() {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(start_error(&format!("ssh-agent exited with {status}")));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = child.start_kill();
        let _ = std::fs::remove_dir_all(&dir);
        Err(start_error("ssh-agent did not create its socket"))
    }

    #[cfg(windows)]
    {
        let _ = options.temp_base;
        let pipe = format!(r"\\.\pipe\netcatty-fido-agent-{}", short_id());
        let mut cmd = Command::new(&ssh_agent);
        cmd.arg("-D")
            .arg("-a")
            .arg(&pipe)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .creation_flags(0x0800_0000);
        cmd.env_remove(crate::askpass::LEASE_ENV);
        for (k, v) in &options.env {
            cmd.env(k, v);
        }
        if let Ok(mut child) = cmd.spawn() {
            for _ in 0..60 {
                if tokio::net::windows::named_pipe::ClientOptions::new().open(&pipe).is_ok() {
                    return Ok(AgentProcess {
                        socket: pipe,
                        ssh_add,
                        owned: true,
                        child: Mutex::new(Some(child)),
                        dir: None,
                    });
                }
                if let Ok(Some(_)) = child.try_wait() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let _ = child.start_kill();
        }
        // Win32-OpenSSH service pipe (not owned: never killed). Windows
        // handles PIN / touch with its own WebAuthn dialog there.
        let system_add = std::env::var("SystemRoot")
            .map(|root| Path::new(&root).join("System32").join("OpenSSH").join("ssh-add.exe"))
            .ok()
            .filter(|p| p.exists())
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "ssh-add".to_string());
        Ok(AgentProcess {
            socket: WIN_SYSTEM_AGENT_PIPE.to_string(),
            ssh_add: system_add,
            owned: false,
            child: Mutex::new(None),
            dir: None,
        })
    }
}

#[cfg(unix)]
fn start_error(detail: &str) -> String {
    format!(
        "Could not start a FIDO-capable ssh-agent ({detail}). Install OpenSSH with libfido2 (macOS: brew install openssh libfido2)."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_agent_stdout() {
        let out = "SSH_AUTH_SOCK=/tmp/ssh-x/agent.1; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=4242; export SSH_AGENT_PID;\necho Agent pid 4242;\n";
        assert_eq!(parse_agent_stdout(out), (Some("/tmp/ssh-x/agent.1".into()), Some(4242)));
        assert_eq!(parse_agent_stdout("SSH_AUTH_SOCK='/a b/s'; export"), (Some("/a b/s".into()), None));
        assert_eq!(parse_agent_stdout("nothing"), (None, None));
    }

    #[test]
    fn companion_binary_requires_ssh_agent_name() {
        let dir = tempfile::tempdir().unwrap();
        let agent = dir.path().join("ssh-agent");
        std::fs::write(&agent, "").unwrap();
        assert_eq!(companion_binary(&agent.to_string_lossy(), "ssh-add"), None);
        std::fs::write(dir.path().join("ssh-add"), "").unwrap();
        assert_eq!(
            companion_binary(&agent.to_string_lossy(), "ssh-add"),
            Some(dir.path().join("ssh-add").to_string_lossy().into_owned())
        );
        assert_eq!(companion_binary("/usr/bin/ssh", "ssh-add"), None);
    }

    #[test]
    fn env_override_wins() {
        std::env::set_var("NETCATTY_SSH_KEYGEN_PATH", "/custom/ssh-keygen");
        assert_eq!(resolve_openssh_binary("ssh-keygen"), "/custom/ssh-keygen");
        std::env::remove_var("NETCATTY_SSH_KEYGEN_PATH");
    }

    /// Real OpenSSH agent: start, share, release, restart.
    #[cfg(unix)]
    #[tokio::test]
    async fn owned_agent_is_shared_and_stopped_with_last_lease() {
        if std::process::Command::new(resolve_openssh_binary("ssh-agent")).arg("-h").output().is_err() {
            return; // no OpenSSH on this machine
        }
        let base = tempfile::tempdir().unwrap();
        let manager = AgentManager::new();
        let a = manager
            .acquire(StartOptions { temp_base: base.path(), env: Vec::new() })
            .await
            .expect("agent starts");
        assert!(a.owned());
        let socket = a.socket().to_string();
        assert!(Path::new(&socket).exists());
        let b = manager
            .acquire(StartOptions { temp_base: base.path(), env: Vec::new() })
            .await
            .unwrap();
        assert_eq!(b.socket(), socket);
        assert!(manager.loaded_blobs(&a).await.is_empty());
        drop(a);
        assert_eq!(manager.active_socket().as_deref(), Some(socket.as_str()));
        drop(b);
        assert_eq!(manager.active_socket(), None);
        assert!(!Path::new(&socket).exists() || !Path::new(&socket).parent().unwrap().exists());
    }
}

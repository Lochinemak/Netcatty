//! Shell-kind classification and the one-time remote login-shell probe
//! (Electron `lib/localShell.cjs` + `sessionShellKind.cjs`).

use serde::Deserialize;
use std::sync::{Arc, LazyLock};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalShellRules {
    powershell_shells: Vec<String>,
    cmd_shells: Vec<String>,
    fish_shells: Vec<String>,
    posix_shells: Vec<String>,
    wsl_shells: Vec<String>,
    discovered_posix_shell_id_prefixes: Vec<String>,
    discovered_posix_shell_ids: Vec<String>,
}

static RULES: LazyLock<LocalShellRules> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../../lib/localShellRules.json"))
        .expect("lib/localShellRules.json is valid")
});

/// Kinds `build_wrapped_command` trusts without probing.
pub const CONFIRMED_SHELL_KINDS: [&str; 5] = ["posix", "fish", "powershell", "cmd", "raw"];
pub const DEFAULT_PROBE_TIMEOUT_MS: u64 = 3000;
pub const PROBE_OUTPUT_MARKER: &str = "__NETCATTY_SHELL_KIND__:";
pub const WINDOWS_NO_DEFAULT_SHELL_MARKER: &str = "__NETCATTY_NO_DEFAULT_SHELL__";

pub fn is_confirmed_shell_kind(kind: &str) -> bool {
    CONFIRMED_SHELL_KINDS.contains(&kind)
}

fn executable_base_name(path: &str) -> String {
    let normalized = path.trim();
    if normalized.is_empty() {
        return String::new();
    }
    normalized
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_lowercase()
}

fn resolve_disambiguated_unix_shell_id_base(shell_name: &str) -> &str {
    if shell_name.is_empty() || shell_name.contains(['/', '\\']) || !shell_name.contains('-') {
        return shell_name;
    }
    shell_name.rsplit('-').next().unwrap_or(shell_name)
}

fn classify_shell_base_name(name: &str) -> Option<&'static str> {
    let r = &*RULES;
    let has = |v: &Vec<String>| v.iter().any(|s| s == name);
    if has(&r.powershell_shells) {
        return Some("powershell");
    }
    if has(&r.cmd_shells) {
        return Some("cmd");
    }
    if has(&r.fish_shells) {
        return Some("fish");
    }
    if has(&r.posix_shells) || has(&r.wsl_shells) {
        return Some("posix");
    }
    if r.discovered_posix_shell_id_prefixes.iter().any(|p| name.starts_with(p.as_str()))
        || has(&r.discovered_posix_shell_ids)
    {
        return Some("posix");
    }
    None
}

/// `posix` / `powershell` / `cmd` / `fish` / `unknown` for a shell path;
/// an empty path yields the platform default.
pub fn classify_local_shell_type(shell_path: &str, platform: &str) -> &'static str {
    let name = executable_base_name(shell_path);
    if let Some(kind) = classify_shell_base_name(&name) {
        return kind;
    }
    let slug = resolve_disambiguated_unix_shell_id_base(&name);
    if slug != name {
        if let Some(kind) = classify_shell_base_name(slug) {
            return kind;
        }
    }
    if name.is_empty() {
        let p = platform.to_lowercase();
        let windows = !p.contains("mac") && !p.contains("darwin") && p.contains("win");
        return if windows { "powershell" } else { "posix" };
    }
    "unknown"
}

/// Classify a remote shell path; `None` when unclassifiable or empty.
pub fn classify_shell_kind_from_remote_path(shell_path: &str) -> Option<&'static str> {
    let trimmed = shell_path.trim();
    if trimmed.is_empty() {
        return None;
    }
    match classify_local_shell_type(trimmed, "linux") {
        "unknown" => None,
        kind => Some(kind),
    }
}

/// Win32-OpenSSH identification string?
pub fn is_windows_openssh_remote(remote_ssh_version: &str) -> bool {
    remote_ssh_version.to_lowercase().contains("openssh_for_windows")
}

/// Paced-write bastions (BHostSSH, TERM-SSHD): no exec-channel probe,
/// one keystroke per write.
pub fn remote_disallows_chunked_channel_write(remote_ssh_version: &str) -> bool {
    let v = remote_ssh_version.to_lowercase();
    v.contains("bhostssh") || v.contains("term-sshd")
}

/// Banners that drop the interactive shell when a second channel opens.
pub fn remote_software_requires_single_channel(remote_ssh_version: &str) -> bool {
    let v = remote_ssh_version.to_lowercase();
    remote_disallows_chunked_channel_write(&v) || v.contains("cloudbility")
}

fn quote_shell_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Silent Unix probe: prints the login shell path behind the marker.
pub fn build_remote_login_shell_probe_command() -> String {
    let script = [
        "SH=\"$(getent passwd \"$(id -un)\" 2>/dev/null | cut -d: -f7)\"".to_string(),
        "[ -n \"$SH\" ] || SH=\"${SHELL:-}\"".to_string(),
        format!("printf \"{PROBE_OUTPUT_MARKER}%s\\n\" \"$SH\""),
    ]
    .join("; ");
    format!("exec sh -c {}", quote_shell_arg(&script))
}

pub fn parse_remote_login_shell_probe_output(stdout: &str) -> Option<&'static str> {
    for line in stdout.replace('\r', "").split('\n') {
        let line = line.trim();
        let Some(rest) = line.strip_prefix(PROBE_OUTPUT_MARKER) else {
            continue;
        };
        if let Some(kind) = classify_shell_kind_from_remote_path(rest) {
            return Some(kind);
        }
    }
    None
}

/// Silent Windows OpenSSH probe (`reg query` DefaultShell via cmd.exe).
pub fn build_remote_windows_login_shell_probe_command() -> String {
    format!(
        "cmd.exe /d /s /c \"reg query HKLM\\SOFTWARE\\OpenSSH /v DefaultShell 2>&1 & if errorlevel 1 (reg query HKLM\\SOFTWARE\\OpenSSH >nul 2>&1 & if not errorlevel 1 echo {WINDOWS_NO_DEFAULT_SHELL_MARKER})\""
    )
}

pub fn parse_remote_windows_login_shell_probe_output(stdout: &str) -> Option<&'static str> {
    let text = stdout.replace('\r', "");
    let re = regex::Regex::new(r"(?i)DefaultShell\s+REG_SZ\s+([^\n]+)").unwrap();
    if let Some(m) = re.captures(&text) {
        let raw_path = m[1].trim().trim_matches('"');
        if let Some(kind) = classify_shell_kind_from_remote_path(raw_path) {
            return Some(kind);
        }
    }
    if text.contains(WINDOWS_NO_DEFAULT_SHELL_MARKER)
        || text
            .to_lowercase()
            .contains("unable to find the specified registry key or value")
    {
        return Some("cmd");
    }
    None
}

/// Per-session shell-kind state shared by every exec on that session.
#[derive(Debug, Default)]
pub struct ShellKindState {
    inner: parking_lot::Mutex<ShellKindInner>,
    probe_lock: tokio::sync::Mutex<()>,
}

#[derive(Debug, Default, Clone)]
pub struct ShellKindInner {
    /// Confirmed kind (local spawn) — never set by a remote probe.
    pub shell_kind: Option<String>,
    /// Soft hint from the remote login-shell probe.
    pub login_shell_kind: Option<String>,
    pub probe_settled: bool,
}

impl ShellKindState {
    pub fn with_shell_kind(kind: Option<String>) -> Arc<Self> {
        let state = Self::default();
        state.inner.lock().shell_kind = kind;
        Arc::new(state)
    }

    /// Set the confirmed kind (local shells, from the executable).
    pub fn set_shell_kind(&self, kind: Option<String>) {
        self.inner.lock().shell_kind = kind;
    }

    pub fn snapshot(&self) -> ShellKindInner {
        self.inner.lock().clone()
    }

    pub fn shell_kind(&self) -> String {
        self.inner.lock().shell_kind.clone().unwrap_or_default()
    }

    pub fn login_shell_hint(&self) -> String {
        self.inner.lock().login_shell_kind.clone().unwrap_or_default()
    }

    pub fn is_settled(&self) -> bool {
        let inner = self.inner.lock();
        inner.probe_settled
            || inner
                .shell_kind
                .as_deref()
                .is_some_and(is_confirmed_shell_kind)
    }
}

/// Runs one probe command on a side channel; `None` = timed out / failed.
#[async_trait::async_trait]
pub trait ExecProbe: Send + Sync {
    async fn exec_probe(&self, command: &str, timeout_ms: u64) -> Option<String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub kind: Option<&'static str>,
    pub settle_without_kind: bool,
}

async fn with_probe_timeout(fut: impl std::future::Future<Output = Option<String>>, timeout_ms: u64) -> Option<String> {
    let ms = if timeout_ms > 0 { timeout_ms } else { DEFAULT_PROBE_TIMEOUT_MS };
    tokio::time::timeout(std::time::Duration::from_millis(ms), fut)
        .await
        .ok()
        .flatten()
}

/// Probe once for the remote login shell kind.
pub async fn probe_remote_login_shell_kind(
    probe: &dyn ExecProbe,
    timeout_ms: u64,
    remote_ssh_version: &str,
) -> ProbeOutcome {
    if is_windows_openssh_remote(remote_ssh_version) {
        let win = with_probe_timeout(
            probe.exec_probe(&build_remote_windows_login_shell_probe_command(), timeout_ms),
            timeout_ms,
        )
        .await;
        return match win {
            None => ProbeOutcome { kind: None, settle_without_kind: false },
            Some(out) => match parse_remote_windows_login_shell_probe_output(&out) {
                Some(kind) => ProbeOutcome { kind: Some(kind), settle_without_kind: false },
                None => ProbeOutcome { kind: None, settle_without_kind: true },
            },
        };
    }
    let stdout = with_probe_timeout(
        probe.exec_probe(&build_remote_login_shell_probe_command(), timeout_ms),
        timeout_ms,
    )
    .await;
    let Some(stdout) = stdout else {
        return ProbeOutcome { kind: None, settle_without_kind: false };
    };
    if let Some(kind) = parse_remote_login_shell_probe_output(&stdout) {
        return ProbeOutcome { kind: Some(kind), settle_without_kind: false };
    }
    if stdout.contains(PROBE_OUTPUT_MARKER) {
        return ProbeOutcome { kind: None, settle_without_kind: false };
    }
    let win = with_probe_timeout(
        probe.exec_probe(&build_remote_windows_login_shell_probe_command(), timeout_ms),
        timeout_ms,
    )
    .await;
    match win {
        None => ProbeOutcome { kind: None, settle_without_kind: false },
        Some(out) => match parse_remote_windows_login_shell_probe_output(&out) {
            Some(kind) => ProbeOutcome { kind: Some(kind), settle_without_kind: false },
            None => ProbeOutcome { kind: None, settle_without_kind: true },
        },
    }
}

/// Ensure the login-shell hint is known: confirmed kinds and settled probes
/// short-circuit; concurrent callers share one probe. `probe` is `None`
/// for sessions without a usable side channel (bastions, local shells).
pub async fn ensure_session_shell_kind(
    state: &ShellKindState,
    probe: Option<&dyn ExecProbe>,
    remote_ssh_version: &str,
    is_local: bool,
    timeout_ms: u64,
) {
    {
        let inner = state.inner.lock();
        if inner.shell_kind.as_deref().is_some_and(is_confirmed_shell_kind) || inner.probe_settled {
            return;
        }
        if is_local && inner.shell_kind.as_deref() == Some("unknown") {
            return;
        }
    }
    let Some(probe) = probe else {
        return;
    };
    let _guard = state.probe_lock.lock().await;
    if state.is_settled() {
        return;
    }
    let outcome = probe_remote_login_shell_kind(probe, timeout_ms, remote_ssh_version).await;
    let mut inner = state.inner.lock();
    if let Some(kind) = outcome.kind {
        inner.probe_settled = true;
        inner.login_shell_kind = Some(kind.to_string());
    } else if outcome.settle_without_kind {
        inner.probe_settled = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_shells() {
        assert_eq!(classify_local_shell_type("/bin/bash", "linux"), "posix");
        assert_eq!(classify_local_shell_type("C:\\Windows\\System32\\cmd.exe", "win32"), "cmd");
        assert_eq!(classify_local_shell_type("pwsh", "linux"), "powershell");
        assert_eq!(classify_local_shell_type("/usr/bin/fish", "linux"), "fish");
        assert_eq!(classify_local_shell_type("", "win32"), "powershell");
        assert_eq!(classify_local_shell_type("", "darwin"), "posix");
        assert_eq!(classify_local_shell_type("custom-shell", "linux"), "unknown");
        assert_eq!(classify_local_shell_type("opt-homebrew-bin-bash", "linux"), "posix");
        assert_eq!(classify_shell_kind_from_remote_path(""), None);
        assert_eq!(classify_shell_kind_from_remote_path("/usr/bin/zsh"), Some("posix"));
    }

    #[test]
    fn parses_probe_outputs() {
        assert_eq!(
            parse_remote_login_shell_probe_output("banner\n__NETCATTY_SHELL_KIND__:/usr/bin/fish\n"),
            Some("fish")
        );
        assert_eq!(parse_remote_login_shell_probe_output("__NETCATTY_SHELL_KIND__:\n"), None);
        assert_eq!(
            parse_remote_windows_login_shell_probe_output(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\OpenSSH\r\n    DefaultShell    REG_SZ    \"C:\\Program Files\\PowerShell\\7\\pwsh.exe\"\r\n"
            ),
            Some("powershell")
        );
        assert_eq!(
            parse_remote_windows_login_shell_probe_output("__NETCATTY_NO_DEFAULT_SHELL__\n"),
            Some("cmd")
        );
        assert_eq!(parse_remote_windows_login_shell_probe_output("Access is denied."), None);
        assert!(is_windows_openssh_remote("OpenSSH_for_Windows_8.6"));
        assert!(remote_disallows_chunked_channel_write("BHostSSH-1.0"));
        assert!(remote_software_requires_single_channel("CLOUDBILITY_SSH"));
    }

    struct FakeProbe(Vec<Option<String>>, std::sync::Mutex<usize>);

    #[async_trait::async_trait]
    impl ExecProbe for FakeProbe {
        async fn exec_probe(&self, _command: &str, _timeout_ms: u64) -> Option<String> {
            let mut i = self.1.lock().unwrap();
            let v = self.0.get(*i).cloned().flatten();
            *i += 1;
            v
        }
    }

    #[tokio::test]
    async fn ensure_probes_once_and_stores_soft_hint() {
        let state = ShellKindState::default();
        let probe = FakeProbe(vec![Some("__NETCATTY_SHELL_KIND__:/usr/bin/fish\n".into())], Default::default());
        ensure_session_shell_kind(&state, Some(&probe), "OpenSSH_9.0", false, 100).await;
        let s = state.snapshot();
        assert_eq!(s.login_shell_kind.as_deref(), Some("fish"));
        assert!(s.shell_kind.is_none());
        assert!(s.probe_settled);
        ensure_session_shell_kind(&state, Some(&probe), "OpenSSH_9.0", false, 100).await;
        assert_eq!(*probe.1.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn timed_out_probe_leaves_state_unsettled_and_windows_denied_settles() {
        let state = ShellKindState::default();
        let probe = FakeProbe(vec![None], Default::default());
        ensure_session_shell_kind(&state, Some(&probe), "", false, 100).await;
        assert!(!state.is_settled());
        let state = ShellKindState::default();
        let probe = FakeProbe(vec![Some("garbage".into()), Some("Access denied".into())], Default::default());
        ensure_session_shell_kind(&state, Some(&probe), "", false, 100).await;
        assert!(state.is_settled());
        assert!(state.snapshot().login_shell_kind.is_none());
    }
}

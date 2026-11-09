//! Cached login-shell environment (Electron: `ai/shellUtils.cjs getShellEnv`).
//!
//! A GUI-launched app inherits a stripped PATH; CLIs installed by the user live
//! on the login shell's PATH. On macOS/Linux the user's `$SHELL -ilc env` is
//! captured once (with a lighter `-ilc 'echo $PATH'` fallback); on Windows the
//! registry PATH is re-read so CLIs installed after launch are discoverable.

use crate::cli::get_path_env_key;
use crate::EnvMap;
use regex::Regex;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Default)]
struct Cache {
    env: Option<Arc<EnvMap>>,
    generation: u64,
}

/// Process-wide shell env cache with invalidation.
#[derive(Default)]
pub struct ShellEnvCache {
    cache: Mutex<Cache>,
    invalidations: std::sync::atomic::AtomicU64,
}

impl ShellEnvCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve (and cache) the shell env. Concurrent callers share one probe.
    pub async fn get(&self) -> Arc<EnvMap> {
        let mut guard = self.cache.lock().await;
        let generation = self.invalidations.load(std::sync::atomic::Ordering::SeqCst);
        if let Some(env) = &guard.env {
            if guard.generation == generation {
                return env.clone();
            }
        }
        let env = Arc::new(probe_shell_env().await);
        guard.env = Some(env.clone());
        guard.generation = generation;
        env
    }

    /// Drop the cache so the next `get` re-spawns the login shell.
    pub fn invalidate(&self) {
        self.invalidations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

fn process_env() -> EnvMap {
    std::env::vars().collect()
}

fn login_shell() -> String {
    let shell = std::env::var("SHELL").unwrap_or_default();
    if !shell.is_empty() && Path::new(&shell).is_absolute() && Path::new(&shell).exists() {
        shell
    } else {
        "/bin/zsh".to_string()
    }
}

async fn run_login_shell(args: &[&str], timeout: Duration) -> Option<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut cmd = tokio::process::Command::new(login_shell());
    cmd.args(args)
        .env("HOME", home)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(timeout, cmd.output()).await.ok()?.ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// `mergeLoginShellPath`: login-shell PATH ahead of `base_path`, de-duplicated.
pub fn merge_login_shell_path(base_path: &str, login_shell_path: &str, delimiter: char) -> String {
    let shell_path = login_shell_path.trim();
    if shell_path.is_empty() {
        return base_path.to_string();
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for part in shell_path.split(delimiter).chain(base_path.split(delimiter)) {
        let p = part.trim();
        if !p.is_empty() && seen.insert(p.to_string()) {
            out.push(p.to_string());
        }
    }
    out.join(&delimiter.to_string())
}

/// `parseRegQueryPath`: the `Path    REG_(EXPAND_)SZ    value` line of `reg query`.
pub fn parse_reg_query_path(stdout: &str) -> String {
    let re = Regex::new(r"(?i)^\s*Path\s+REG_(?:EXPAND_)?SZ\s+(.*\S)\s*$").unwrap();
    for line in stdout.lines() {
        if let Some(cap) = re.captures(line) {
            return cap[1].to_string();
        }
    }
    String::new()
}

/// `expandWindowsEnvRefs`: `%VAR%` → value (case-insensitive), unknown refs kept.
pub fn expand_windows_env_refs(value: &str, env: &EnvMap) -> String {
    let re = Regex::new(r"%([^%]+)%").unwrap();
    re.replace_all(value, |caps: &regex::Captures| {
        let name = &caps[1];
        env.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| caps[0].to_string())
    })
    .into_owned()
}

/// `mergeWindowsPath`: `;`-joined, de-duplicated case-insensitively (trailing
/// separators and surrounding quotes ignored), first occurrence wins.
pub fn merge_windows_path(parts: &[&str]) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for path in parts {
        for part in path.split(';') {
            let trimmed = part.trim().trim_matches('"');
            if trimmed.is_empty() {
                continue;
            }
            let key = trimmed.to_ascii_lowercase().trim_end_matches(['\\', '/']).to_string();
            if seen.insert(key) {
                out.push(trimmed.to_string());
            }
        }
    }
    out.join(";")
}

fn windows_known_cli_path_dirs(env: &EnvMap) -> Vec<String> {
    let mut dirs = Vec::new();
    if let Some(appdata) = env.get("APPDATA") {
        dirs.push(Path::new(appdata).join("npm"));
    }
    if let Some(local) = env.get("LOCALAPPDATA") {
        dirs.push(Path::new(local).join("pnpm"));
        dirs.push(Path::new(local).join("Yarn").join("bin"));
    }
    dirs.into_iter().filter(|d| d.exists()).map(|d| d.to_string_lossy().into_owned()).collect()
}

#[cfg(windows)]
async fn read_windows_registry_path(env: &EnvMap) -> String {
    const HIVES: [&str; 2] = [
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
        "HKCU\\Environment",
    ];
    let mut values = Vec::new();
    for hive in HIVES {
        let mut cmd = tokio::process::Command::new("reg");
        cmd.args(["query", hive, "/v", "Path"]).kill_on_drop(true);
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        let value = match tokio::time::timeout(Duration::from_secs(1), cmd.output()).await {
            Ok(Ok(output)) => expand_windows_env_refs(&parse_reg_query_path(&String::from_utf8_lossy(&output.stdout)), env),
            _ => String::new(),
        };
        values.push(value);
    }
    merge_windows_path(&values.iter().map(String::as_str).collect::<Vec<_>>())
}

async fn probe_shell_env() -> EnvMap {
    let base = process_env();
    let home = base.get("HOME").cloned().unwrap_or_default();
    let extra_paths = [
        format!("{home}/.local/bin"),
        format!("{home}/.npm-global/bin"),
        "/usr/local/bin".to_string(),
        "/opt/homebrew/bin".to_string(),
    ];

    #[cfg(windows)]
    {
        let registry = read_windows_registry_path(&base).await;
        let known = windows_known_cli_path_dirs(&base).join(";");
        let key = get_path_env_key(&base);
        let current = base.get(&key).cloned().unwrap_or_default();
        let mut next = base.clone();
        next.insert("PATH".into(), merge_windows_path(&[&registry, &current, &known]));
        return next;
    }
    #[cfg(not(windows))]
    {
        let _ = windows_known_cli_path_dirs;
        let _ = get_path_env_key;
        let delimiter = ':';
        if let Some(env_output) = run_login_shell(&["-ilc", "env"], Duration::from_secs(10)).await {
            let mut env_map = EnvMap::new();
            for line in env_output.lines() {
                if let Some(idx) = line.find('=') {
                    if idx > 0 {
                        env_map.insert(line[..idx].to_string(), line[idx + 1..].to_string());
                    }
                }
            }
            let shell_path = env_map.get("PATH").cloned().unwrap_or_default();
            let merged_path = extra_paths
                .iter()
                .cloned()
                .chain([shell_path.clone(), base.get("PATH").cloned().unwrap_or_default()])
                .collect::<Vec<_>>()
                .join(&delimiter.to_string());
            let mut next = env_map;
            for (k, v) in &base {
                next.insert(k.clone(), v.clone());
            }
            next.insert("PATH".into(), merge_login_shell_path(&merged_path, &shell_path, delimiter));
            return next;
        }
        let base_path = extra_paths
            .iter()
            .cloned()
            .chain([base.get("PATH").cloned().unwrap_or_default()])
            .collect::<Vec<_>>()
            .join(&delimiter.to_string());
        let login_path = run_login_shell(&["-ilc", "echo -n \"$PATH\""], Duration::from_secs(4))
            .await
            .unwrap_or_default();
        let mut next = base;
        next.insert("PATH".into(), merge_login_shell_path(&base_path, &login_path, delimiter));
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_login_shell_path_fronts_and_dedupes() {
        assert_eq!(merge_login_shell_path("/usr/bin:/bin", "/opt/x/bin:/usr/bin", ':'), "/opt/x/bin:/usr/bin:/bin");
        assert_eq!(merge_login_shell_path("/usr/bin", "  ", ':'), "/usr/bin");
    }

    #[test]
    fn reg_query_parsing_and_expansion() {
        let out = "\r\nHKEY_CURRENT_USER\\Environment\r\n    Path    REG_EXPAND_SZ    %USERPROFILE%\\bin;C:\\tools\r\n";
        assert_eq!(parse_reg_query_path(out), "%USERPROFILE%\\bin;C:\\tools");
        let env: EnvMap = [("UserProfile".to_string(), "C:\\Users\\a".to_string())].into_iter().collect();
        assert_eq!(expand_windows_env_refs("%USERPROFILE%\\bin;%NOPE%", &env), "C:\\Users\\a\\bin;%NOPE%");
        assert_eq!(parse_reg_query_path("nothing"), "");
    }

    #[test]
    fn merge_windows_path_dedupes_case_insensitively() {
        assert_eq!(
            merge_windows_path(&["C:\\A;\"C:\\B\\\"", "c:\\a\\;C:\\C", ""]),
            "C:\\A;C:\\B\\;C:\\C"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shell_env_cache_resolves_and_invalidates() {
        let cache = ShellEnvCache::new();
        let first = cache.get().await;
        assert!(first.get("PATH").map(|p| p.contains("/usr")).unwrap_or(false));
        let again = cache.get().await;
        assert!(Arc::ptr_eq(&first, &again));
        cache.invalidate();
        let fresh = cache.get().await;
        assert!(!Arc::ptr_eq(&first, &fresh));
    }
}

//! CLI discovery / path helpers and bounded command execution (Electron:
//! `ai/shellUtils.cjs`, `aiBridge/agentCliHelpers.cjs`, `aiBridge/cursorCliSpawn.cjs`).

use crate::EnvMap;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::AsyncReadExt;

pub const DEFAULT_CODEX_CLI_TIMEOUT: Duration = Duration::from_millis(10_000);
pub const MAX_AGENT_CLI_BUFFER_BYTES: usize = 10 * 1024 * 1024;
/// Bun-compiled OpenCode-family CLIs answer `--version` slowly (5s+ cold).
pub const VERSION_PROBE_TIMEOUT: Duration = Duration::from_millis(15_000);
const WINDOWS_RUNNABLE_EXTENSIONS: &[&str] = &[".exe", ".cmd", ".bat", ".com"];

fn ansi_escape_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new("\u{1b}\\[[0-?]*[ -/]*[@-~]").expect("ansi regex"))
}

fn ansi_osc_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new("\u{1b}\\][^\u{7}]*?(?:\u{7}|\u{1b}\\\\)").expect("osc regex"))
}

/// Strip CSI and OSC escape sequences.
pub fn strip_ansi(input: &str) -> String {
    let without_osc = ansi_osc_re().replace_all(input, "");
    ansi_escape_re().replace_all(&without_osc, "").into_owned()
}

// ── URL helpers ──

pub fn is_localhost_hostname(hostname: &str) -> bool {
    let normalized = hostname.trim().to_ascii_lowercase();
    normalized == "localhost"
        || normalized == "127.0.0.1"
        || normalized == "::1"
        || normalized == "[::1]"
        || normalized.ends_with(".localhost")
}

/// First `http(s)://` URL in `output` whose host is not loopback.
pub fn extract_first_non_localhost_url(output: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"https?://[^\s]+").expect("url regex"));
    let clean = strip_ansi(output);
    for m in re.find_iter(&clean) {
        let candidate = m.as_str().trim().trim_end_matches(['(', ')', ',', '.', ';', '!', '?']);
        if let Ok(parsed) = url::Url::parse(candidate) {
            if let Some(host) = parsed.host_str() {
                if !is_localhost_hostname(host) {
                    return Some(parsed.to_string());
                }
            }
        }
    }
    None
}

// ── Path helpers ──

pub fn is_windows() -> bool {
    cfg!(windows)
}

/// `isPathLikeCommand`: contains a path separator or a drive letter.
pub fn is_path_like_command(command: &str) -> bool {
    let normalized = command.trim();
    normalized.contains('/')
        || normalized.contains('\\')
        || (normalized.len() >= 2
            && normalized.as_bytes()[0].is_ascii_alphabetic()
            && normalized.as_bytes()[1] == b':')
}

fn ext_lower(path: &str) -> String {
    Path::new(path)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_ascii_lowercase()))
        .unwrap_or_default()
}

fn is_file(path: &str) -> bool {
    std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

/// `normalizeCliPathForPlatform`: an existing file; on Windows an extensionless
/// path prefers its `.exe/.cmd/.bat/.com` sibling.
pub fn normalize_cli_path_for_platform(file_path: &str) -> Option<String> {
    let normalized = file_path.trim();
    if normalized.is_empty() {
        return None;
    }
    if !is_windows() {
        return is_file(normalized).then(|| normalized.to_string());
    }
    let ext = ext_lower(normalized);
    if !ext.is_empty() {
        return Path::new(normalized).exists().then(|| normalized.to_string());
    }
    for suffix in WINDOWS_RUNNABLE_EXTENSIONS {
        let candidate = format!("{normalized}{suffix}");
        if Path::new(&candidate).exists() {
            return Some(candidate);
        }
    }
    Path::new(normalized).exists().then(|| normalized.to_string())
}

/// What to actually spawn for `command args` (Windows `.cmd/.bat` shims go
/// through `cmd.exe` unless they wrap a native `.exe` we can call directly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnSpec {
    pub command: String,
    pub args: Vec<String>,
    pub shell: bool,
}

fn should_use_shell_for_command(command: &str) -> bool {
    if !is_windows() {
        return false;
    }
    let normalized = command.trim().to_ascii_lowercase();
    normalized.ends_with(".cmd") || normalized.ends_with(".bat")
}

pub fn quote_windows_shell_arg(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_string();
    }
    format!("\"{}\"", value.replace('"', "\\\""))
}

pub fn build_windows_shell_command_line(command: &str, args: &[String]) -> String {
    std::iter::once(command.to_string())
        .chain(args.iter().cloned())
        .map(|a| quote_windows_shell_arg(&a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `resolveWindowsShimToNativeExe`: `"%~dp0\..\x.exe" %*` shims → the exe.
pub fn resolve_windows_shim_to_native_exe(command: &str) -> Option<String> {
    if !is_windows() {
        return None;
    }
    let normalized = command.trim();
    let ext = ext_lower(normalized);
    if ext != ".cmd" && ext != ".bat" {
        return None;
    }
    let contents = std::fs::read_to_string(normalized).ok()?;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"(?i)"%~dp0\\([^"]+\.exe)""#).expect("shim regex"));
    let shim_dir = Path::new(normalized).parent()?;
    for cap in re.captures_iter(&contents) {
        let relative = cap[1].replace('\\', "/");
        let candidate = shim_dir.join(relative);
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

pub fn prepare_command_for_spawn(command: &str, args: &[String], unwrap_native_exe: bool) -> SpawnSpec {
    if !should_use_shell_for_command(command) {
        return SpawnSpec { command: command.to_string(), args: args.to_vec(), shell: false };
    }
    if unwrap_native_exe {
        if let Some(native) = resolve_windows_shim_to_native_exe(command) {
            return SpawnSpec { command: native, args: args.to_vec(), shell: false };
        }
    }
    SpawnSpec {
        command: build_windows_shell_command_line(command, args),
        args: Vec::new(),
        shell: true,
    }
}

/// Apply a [`SpawnSpec`] to a tokio command (shell specs run through `cmd.exe /d /s /c`).
///
/// Always sets `CREATE_NO_WINDOW` on Windows: the app is a GUI process, so a
/// console child (cmd.exe, `.cmd` shims, agent CLIs) would otherwise open its
/// own console window.
pub fn command_for_spec(spec: &SpawnSpec) -> tokio::process::Command {
    #[cfg_attr(not(windows), allow(unused_mut))] // only mutated on Windows
    let mut cmd = if spec.shell {
        let mut cmd = tokio::process::Command::new("cmd.exe");
        cmd.args(["/d", "/s", "/c", &spec.command]);
        cmd
    } else {
        let mut cmd = tokio::process::Command::new(&spec.command);
        cmd.args(&spec.args);
        cmd
    };
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    cmd
}

/// `resolveClaudeCodeExecutableForSdk` (Windows shim → `cli.js` / native exe).
pub fn resolve_claude_code_executable_for_sdk(path: &str) -> Option<String> {
    let normalized = path.trim();
    if normalized.is_empty() {
        return None;
    }
    if !is_windows() {
        return Some(normalized.to_string());
    }
    let ext = ext_lower(normalized);
    if !ext.is_empty() && ext != ".cmd" && ext != ".bat" {
        return Some(normalized.to_string());
    }
    let base_dir = Path::new(normalized).parent().unwrap_or(Path::new("."));
    let package_cli = base_dir.join("node_modules/@anthropic-ai/claude-code/cli.js");
    if package_cli.exists() {
        return Some(package_cli.to_string_lossy().into_owned());
    }
    for exe in [
        base_dir.join("node_modules/@anthropic-ai/claude-code/bin/claude.exe"),
        base_dir.join("../node_modules/@anthropic-ai/claude-code/bin/claude.exe"),
    ] {
        if exe.exists() {
            return Some(exe.to_string_lossy().into_owned());
        }
    }
    let mut shims = vec![normalized.to_string()];
    if ext.is_empty() {
        shims.push(format!("{normalized}.cmd"));
        shims.push(format!("{normalized}.bat"));
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?i)node_modules[\\/]+@anthropic-ai[\\/]+claude-code[\\/]+cli\.js").expect("re")
    });
    for shim in shims {
        if let Ok(contents) = std::fs::read_to_string(&shim) {
            if re.is_match(&contents) && package_cli.exists() {
                return Some(package_cli.to_string_lossy().into_owned());
            }
        }
    }
    Some(normalized.to_string())
}

pub fn normalize_claude_code_executable_env_for_sdk(mut env: EnvMap) -> EnvMap {
    if let Some(exe) = env.get("CLAUDE_CODE_EXECUTABLE").cloned() {
        if let Some(resolved) = resolve_claude_code_executable_for_sdk(&exe) {
            if resolved != exe {
                env.insert("CLAUDE_CODE_EXECUTABLE".into(), resolved);
            }
        }
    }
    env
}

fn codex_native_win32(search_dirs: &[PathBuf]) -> Option<String> {
    let (triple, package) = if cfg!(target_arch = "aarch64") {
        ("aarch64-pc-windows-msvc", "@openai/codex-win32-arm64")
    } else {
        ("x86_64-pc-windows-msvc", "@openai/codex-win32-x64")
    };
    for dir in search_dirs {
        for candidate in [
            dir.join("node_modules").join(package).join("vendor").join(triple).join("bin/codex.exe"),
            dir.join("node_modules").join(package).join("vendor").join(triple).join("codex/codex.exe"),
        ] {
            if candidate.exists() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn nvmd_home_from_shim_dir(shim_dir: &Path) -> Option<PathBuf> {
    if shim_dir.file_name()?.to_string_lossy().to_ascii_lowercase() != "bin" {
        return None;
    }
    let home = shim_dir.parent()?.to_path_buf();
    (home.join("versions").exists() || home.join("packages.json").exists() || home.join("default").exists())
        .then_some(home)
}

fn nvmd_codex_version_roots(nvmd_home: Option<&Path>) -> Vec<PathBuf> {
    let Some(home) = nvmd_home else { return Vec::new() };
    let versions_dir = std::fs::read_to_string(home.join("setting.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|v| v.get("directory").and_then(|d| d.as_str()).map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join("versions"));
    let mut candidates: Vec<String> = std::fs::read_to_string(home.join("packages.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|v| v.get("codex").and_then(|c| c.as_array().cloned()))
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).rev().collect())
        .unwrap_or_default();
    if let Ok(default) = std::fs::read_to_string(home.join("default")) {
        if !default.trim().is_empty() {
            candidates.push(default.trim().to_string());
        }
    }
    let mut roots = Vec::new();
    for version in candidates {
        let root = versions_dir.join(version);
        if !roots.contains(&root) && root.exists() {
            roots.push(root);
        }
    }
    roots
}

fn codex_native_search_dirs_for_shim(shim_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![shim_dir.to_path_buf()];
    if let Some(parent) = shim_dir.parent() {
        if shim_dir.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()) == Some(".bin".into())
            && parent.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()) == Some("node_modules".into())
        {
            if let Some(grand) = parent.parent() {
                dirs.push(grand.to_path_buf());
            }
        }
    }
    dirs.push(shim_dir.join("node_modules/@openai/codex"));
    let nvmd = nvmd_home_from_shim_dir(shim_dir);
    for root in nvmd_codex_version_roots(nvmd.as_deref()) {
        dirs.push(root.join("node_modules/@openai/codex"));
        dirs.push(root);
    }
    dirs
}

/// `resolveCodexExecutableForSdk`.
pub fn resolve_codex_executable_for_sdk(path: &str) -> Option<String> {
    let normalized = path.trim();
    if normalized.is_empty() {
        return None;
    }
    if !is_windows() {
        return Some(normalized.to_string());
    }
    let ext = ext_lower(normalized);
    let base_dir = Path::new(normalized).parent().unwrap_or(Path::new(".")).to_path_buf();
    let search_dirs = codex_native_search_dirs_for_shim(&base_dir);
    let nvmd = nvmd_home_from_shim_dir(&base_dir);
    if ext == ".exe" {
        if nvmd.is_some() {
            if let Some(native) = codex_native_win32(&search_dirs) {
                return Some(native);
            }
        }
        return Some(normalized.to_string());
    }
    if ext == ".js" && normalized.to_ascii_lowercase().ends_with("codex.js") {
        let package_root = Path::new(normalized).parent().and_then(|p| p.parent()).map(Path::to_path_buf);
        if let Some(root) = package_root {
            let global_prefix = root.join("../../..");
            let mut dirs = vec![global_prefix, root];
            dirs.extend(search_dirs.iter().cloned());
            if let Some(native) = codex_native_win32(&dirs) {
                return Some(native);
            }
        }
    }
    if !ext.is_empty() && ext != ".cmd" && ext != ".bat" && ext != ".ps1" {
        return Some(normalized.to_string());
    }
    if let Some(native) = codex_native_win32(&search_dirs) {
        return Some(native);
    }
    let mut shims = vec![normalized.to_string()];
    if ext.is_empty() {
        shims.push(format!("{normalized}.cmd"));
        shims.push(format!("{normalized}.bat"));
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)@openai[\\/]codex[\\/]bin[\\/]codex\.js").expect("re"));
    for shim in shims {
        if let Ok(contents) = std::fs::read_to_string(&shim) {
            if re.is_match(&contents) {
                if let Some(native) = codex_native_win32(&search_dirs) {
                    return Some(native);
                }
            }
        }
    }
    if ext == ".cmd" || ext == ".bat" || ext == ".ps1" {
        None
    } else {
        Some(normalized.to_string())
    }
}

/// `resolveCodebuddyExecutableForSdk`.
pub fn resolve_codebuddy_executable_for_sdk(path: &str) -> Option<String> {
    let normalized = path.trim();
    if normalized.is_empty() {
        return None;
    }
    if !is_windows() {
        return Some(normalized.to_string());
    }
    let ext = ext_lower(normalized);
    if ext == ".exe" || ext == ".js" {
        return Some(normalized.to_string());
    }
    if !ext.is_empty() && ext != ".cmd" && ext != ".bat" && ext != ".ps1" {
        return Some(normalized.to_string());
    }
    let base_dir = Path::new(normalized).parent().unwrap_or(Path::new("."));
    for root in [
        base_dir.join("node_modules/@tencent-ai/codebuddy-code"),
        base_dir.join("../node_modules/@tencent-ai/codebuddy-code"),
    ] {
        let bin = root.join("bin/codebuddy");
        if bin.exists() {
            return Some(bin.to_string_lossy().into_owned());
        }
    }
    let mut shims = vec![normalized.to_string()];
    if ext.is_empty() {
        shims.push(format!("{normalized}.cmd"));
        shims.push(format!("{normalized}.bat"));
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    static DP0: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"(?i)([^"\s]*codebuddy-code[\\/]bin[\\/]codebuddy)"#).expect("re"));
    let dp0 = DP0.get_or_init(|| Regex::new(r"(?i)^%~dp0[\\/]?").expect("re"));
    for shim in shims {
        if let Ok(contents) = std::fs::read_to_string(&shim) {
            if let Some(cap) = re.captures(&contents) {
                let reference = cap[1].to_string();
                let reference = dp0.replace(&reference, "").replace(['\\', '/'], std::path::MAIN_SEPARATOR_STR);
                let candidate = if Path::new(&reference).is_absolute() {
                    PathBuf::from(&reference)
                } else {
                    Path::new(&shim).parent().unwrap_or(Path::new(".")).join(&reference)
                };
                if candidate.exists() {
                    return Some(candidate.to_string_lossy().into_owned());
                }
            }
        }
    }
    if ext == ".cmd" || ext == ".bat" || ext == ".ps1" {
        None
    } else {
        Some(normalized.to_string())
    }
}

/// `resolveCopilotExecutableForSdk` (npm `.cmd` shim → `npm-loader.js`, or the
/// platform native exe when `NETCATTY_COPILOT_PREFER_NATIVE=1`).
pub fn resolve_copilot_executable_for_sdk(path: &str, prefer_native: bool) -> Option<String> {
    let normalized = path.trim();
    if normalized.is_empty() {
        return None;
    }
    if !is_windows() {
        return Some(normalized.to_string());
    }
    let ext = ext_lower(normalized);
    if ext == ".exe" || ext == ".js" {
        return Some(normalized.to_string());
    }
    if !ext.is_empty() && ext != ".cmd" && ext != ".bat" && ext != ".ps1" {
        return Some(normalized.to_string());
    }
    let shim_dir = Path::new(normalized).parent().unwrap_or(Path::new("."));
    let platform_pkg = format!("copilot-win32-{}", if cfg!(target_arch = "aarch64") { "arm64" } else { "x64" });
    for root in [shim_dir.join("node_modules/@github/copilot"), shim_dir.join("../@github/copilot")] {
        if prefer_native {
            let native = root.join("..").join(&platform_pkg).join("copilot.exe");
            if native.exists() {
                return Some(native.to_string_lossy().into_owned());
            }
        }
        let loader = root.join("npm-loader.js");
        if loader.exists() {
            return Some(loader.to_string_lossy().into_owned());
        }
    }
    let mut shims = vec![normalized.to_string()];
    if ext.is_empty() {
        shims.push(format!("{normalized}.cmd"));
        shims.push(format!("{normalized}.bat"));
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)node_modules[\\/]+@github[\\/]copilot[\\/][\w\\/.-]+\.js").expect("re"));
    for shim in shims {
        if let Ok(contents) = std::fs::read_to_string(&shim) {
            if let Some(m) = re.find(&contents) {
                let loader = Path::new(&shim).parent().unwrap_or(Path::new(".")).join(m.as_str());
                if loader.exists() {
                    if prefer_native {
                        let native = loader.parent().unwrap().join("..").join(&platform_pkg).join("copilot.exe");
                        if native.exists() {
                            return Some(native.to_string_lossy().into_owned());
                        }
                    }
                    return Some(loader.to_string_lossy().into_owned());
                }
            }
        }
    }
    Some(normalized.to_string())
}

/// `copilotHeadlessLoader.resolveCopilotPlatformExecutable`: the native exe
/// an npm loader forwards to.
pub fn resolve_copilot_platform_executable(loader_path: &str) -> Option<String> {
    let normalized = loader_path.trim();
    if normalized.is_empty() {
        return None;
    }
    let platform = if cfg!(windows) { "win32" } else if cfg!(target_os = "macos") { "darwin" } else { "linux" };
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "x64" };
    let pkg = format!("@github/copilot-{platform}-{arch}");
    let exe = if cfg!(windows) { "copilot.exe" } else { "copilot" };
    let dir = Path::new(normalized).parent()?;
    for root in [dir.to_path_buf(), dir.join("../..")] {
        for direct in [root.join("node_modules").join(&pkg).join(exe), root.join(&pkg).join(exe)] {
            if direct.exists() {
                return Some(direct.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// `getPathEnvKey`: the `PATH` key as spelled in `env` (Windows is case-insensitive).
pub fn get_path_env_key(env: &EnvMap) -> String {
    if !is_windows() {
        return "PATH".to_string();
    }
    let keys: Vec<&String> = env.keys().filter(|k| k.eq_ignore_ascii_case("path")).collect();
    if keys.iter().any(|k| k.as_str() == "Path") {
        return "Path".into();
    }
    keys.last().map(|k| k.to_string()).unwrap_or_else(|| "PATH".into())
}

fn codex_native_path_dirs_win32(exe: &str) -> Vec<PathBuf> {
    let path = Path::new(exe.trim());
    if path.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()) != Some("codex.exe".into()) {
        return Vec::new();
    }
    let Some(exe_dir) = path.parent() else { return Vec::new() };
    let Some(package_root) = exe_dir.parent() else { return Vec::new() };
    let base = exe_dir.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let dirs = if base == "bin" {
        vec![package_root.join("codex-path")]
    } else if base == "codex" {
        vec![package_root.join("path")]
    } else {
        Vec::new()
    };
    dirs.into_iter().filter(|d| d.exists()).collect()
}

/// `addCodexExecutableEnvForSdk`: on Windows front the native codex helper dirs on PATH.
pub fn add_codex_executable_env_for_sdk(mut env: EnvMap, codex_executable: Option<&str>) -> EnvMap {
    let Some(exe) = codex_executable else { return env };
    if !is_windows() || exe.is_empty() {
        return env;
    }
    let path_dirs = codex_native_path_dirs_win32(exe);
    if path_dirs.is_empty() {
        return env;
    }
    let key = get_path_env_key(&env);
    let others: Vec<String> = env.keys().filter(|k| k.eq_ignore_ascii_case("path") && **k != key).cloned().collect();
    for k in others {
        env.remove(&k);
    }
    let existing: Vec<String> = env
        .get(&key)
        .map(|p| p.split(';').filter(|e| !e.is_empty()).map(str::to_string).collect())
        .unwrap_or_default();
    let fronted: Vec<String> = path_dirs.iter().map(|p| p.to_string_lossy().into_owned()).collect();
    let rest: Vec<String> = existing.into_iter().filter(|e| !fronted.contains(e)).collect();
    env.insert(key, fronted.into_iter().chain(rest).collect::<Vec<_>>().join(";"));
    env
}

fn valid_command_name(command: &str) -> bool {
    !command.is_empty() && command.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// `resolveCliFromPath`: `which` / `where` on the shell env's PATH.
pub async fn resolve_cli_from_path(command: &str, shell_env: &EnvMap) -> Option<String> {
    if !valid_command_name(command) {
        return None;
    }
    let which = if is_windows() { "where" } else { "which" };
    let mut cmd = tokio::process::Command::new(which);
    cmd.arg(command).env_clear().envs(shell_env.iter()).stdin(std::process::Stdio::null());
    cmd.kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let output = tokio::time::timeout(Duration::from_secs(3), cmd.output()).await.ok()?.ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for candidate in stdout.lines() {
        if let Some(normalized) = normalize_cli_path_for_platform(candidate.trim()) {
            return Some(normalized);
        }
    }
    None
}

/// `resolveSdkBinPath`: PATH lookup, then Windows SDK-friendly path rewriting.
pub async fn resolve_sdk_bin_path(command: &str, shell_env: &EnvMap) -> Option<String> {
    let raw = resolve_cli_from_path(command, shell_env).await?;
    if !is_windows() {
        return Some(raw);
    }
    match command {
        "codex" => resolve_codex_executable_for_sdk(&raw),
        "claude" => resolve_claude_code_executable_for_sdk(&raw),
        _ => Some(raw),
    }
}

/// `realpathSync` with the input as fallback.
pub fn resolve_real_cli_path(path: &str) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

/// `isPlausibleCliVersionOutput`: first line carries a semver-ish token and is not an error.
pub fn is_plausible_cli_version_output(value: &str) -> bool {
    let clean = strip_ansi(value);
    let line = clean.trim().lines().next().unwrap_or("").trim();
    if line.is_empty() {
        return false;
    }
    static SCHEME: OnceLock<Regex> = OnceLock::new();
    static AT: OnceLock<Regex> = OnceLock::new();
    static ERR: OnceLock<Regex> = OnceLock::new();
    static VER: OnceLock<Regex> = OnceLock::new();
    if SCHEME.get_or_init(|| Regex::new(r"(?i)^(?:file|node)://").unwrap()).is_match(line) {
        return false;
    }
    if AT.get_or_init(|| Regex::new(r"(?i)^\s*at\s+").unwrap()).is_match(line) {
        return false;
    }
    if ERR.get_or_init(|| Regex::new(r"\b(?:Error|TypeError|ReferenceError|SyntaxError|ERR_[A-Z_]+)\b").unwrap()).is_match(line) {
        return false;
    }
    VER.get_or_init(|| Regex::new(r"(?:^|[^\d])v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?(?:$|[^\d])").unwrap())
        .is_match(line)
}

/// Result of a bounded command run (ANSI stripped).
#[derive(Debug, Clone, Default)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

impl CommandResult {
    /// stdout + stderr joined (`getCommandOutput`).
    pub fn output(&self) -> String {
        [self.stdout.as_str(), self.stderr.as_str()]
            .iter()
            .filter(|chunk| !chunk.trim().is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string()
    }

    pub fn first_output_line(&self) -> String {
        self.output().lines().next().unwrap_or("").to_string()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("Command timed out after {0}ms")]
    Timeout(u128),
    #[error("{0}")]
    Spawn(String),
}

async fn read_capped<R: tokio::io::AsyncRead + Unpin>(mut reader: R, cap: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let remaining = cap.saturating_sub(out.len());
                out.extend_from_slice(&buf[..n.min(remaining)]);
            }
        }
    }
    out
}

/// `runCommand`: spawn with the given env / cwd, capture stdout+stderr (capped
/// at [`MAX_AGENT_CLI_BUFFER_BYTES`]), kill on timeout.
pub async fn run_command(
    command: &str,
    args: &[String],
    env: &EnvMap,
    cwd: Option<&str>,
    timeout: Option<Duration>,
) -> Result<CommandResult, CommandError> {
    let spec = prepare_command_for_spawn(command, args, true);
    let mut cmd = command_for_spec(&spec);
    cmd.env_clear().envs(env.iter());
    if let Some(dir) = cwd.filter(|d| !d.trim().is_empty()) {
        cmd.current_dir(dir);
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn().map_err(|e| CommandError::Spawn(e.to_string()))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let run = async {
        let (out, err) = tokio::join!(
            async { match stdout { Some(s) => read_capped(s, MAX_AGENT_CLI_BUFFER_BYTES).await, None => Vec::new() } },
            async { match stderr { Some(s) => read_capped(s, MAX_AGENT_CLI_BUFFER_BYTES).await, None => Vec::new() } }
        );
        let status = child.wait().await.ok();
        CommandResult {
            stdout: strip_ansi(&String::from_utf8_lossy(&out)),
            stderr: strip_ansi(&String::from_utf8_lossy(&err)),
            exit_code: status.and_then(|s| s.code()),
        }
    };
    match timeout {
        Some(limit) => match tokio::time::timeout(limit, run).await {
            Ok(result) => Ok(result),
            Err(_) => Err(CommandError::Timeout(limit.as_millis())),
        },
        None => Ok(run.await),
    }
}

/// `probeCliVersion`.
#[derive(Debug, Clone, Default)]
pub struct VersionProbe {
    pub launched: bool,
    pub exit_code: Option<i32>,
    pub output: String,
    pub version: String,
}

pub async fn probe_cli_version(command: &str, args: &[String], env: &EnvMap) -> VersionProbe {
    match run_command(command, args, env, None, Some(VERSION_PROBE_TIMEOUT)).await {
        Ok(result) => VersionProbe {
            launched: true,
            exit_code: result.exit_code,
            output: result.output(),
            version: result.first_output_line(),
        },
        Err(_) => VersionProbe::default(),
    }
}

// ── Cursor Agent CLI Windows shim (cursorCliSpawn.cjs) ──

fn expand_windows_shim_path(raw: &str, shim_dir: &Path) -> PathBuf {
    let dp0 = format!("{}{}", shim_dir.display(), std::path::MAIN_SEPARATOR);
    let replaced = Regex::new("(?i)%~dp0").unwrap().replace_all(raw, dp0.as_str()).into_owned();
    let normalized = replaced.replace('\\', std::path::MAIN_SEPARATOR_STR);
    let path = Path::new(&normalized);
    if path.is_absolute() || (normalized.len() > 1 && normalized.as_bytes()[1] == b':') {
        path.to_path_buf()
    } else {
        shim_dir.join(path)
    }
}

fn parse_cursor_agent_cmd_launch(shim_path: &str) -> Option<(PathBuf, PathBuf)> {
    let contents = std::fs::read_to_string(shim_path).ok()?;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"(?i)"([^"\r\n]*node\.exe)"\s+"([^"\r\n]*index\.js)""#).unwrap());
    let cap = re.captures(&contents)?;
    let shim_dir = Path::new(shim_path).parent()?;
    let node = expand_windows_shim_path(&cap[1], shim_dir);
    let script = expand_windows_shim_path(&cap[2], shim_dir);
    (node.exists() && script.exists()).then_some((node, script))
}

fn resolve_cursor_agent_versions_launch(install_dir: &Path) -> Option<(PathBuf, PathBuf)> {
    let versions = install_dir.join("versions");
    let mut candidates: Vec<(String, PathBuf, PathBuf, std::time::SystemTime)> = Vec::new();
    for entry in std::fs::read_dir(&versions).ok()?.flatten() {
        let dir = entry.path();
        let node = dir.join("node.exe");
        let script = dir.join("index.js");
        if !node.exists() || !script.exists() {
            continue;
        }
        let mtime = std::fs::metadata(&dir).and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
        candidates.push((entry.file_name().to_string_lossy().into_owned(), node, script, mtime));
    }
    candidates.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| b.0.cmp(&a.0)));
    candidates.into_iter().next().map(|(_, n, s, _)| (n, s))
}

/// `resolveCursorCliSpawnSpec`: Windows installer `.cmd` shim → native node + script.
pub fn resolve_cursor_cli_spawn_spec(bin_path: &str, args: &[String]) -> SpawnSpec {
    let command = bin_path.trim();
    let ext = ext_lower(command);
    if !command.is_empty() && (ext == ".cmd" || ext == ".bat") {
        let native = parse_cursor_agent_cmd_launch(command).or_else(|| {
            Path::new(command).parent().and_then(resolve_cursor_agent_versions_launch)
        });
        if let Some((node, script)) = native {
            let mut full = vec![script.to_string_lossy().into_owned()];
            full.extend(args.iter().cloned());
            return SpawnSpec { command: node.to_string_lossy().into_owned(), args: full, shell: false };
        }
    }
    prepare_command_for_spawn(command, args, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_csi_and_osc() {
        assert_eq!(strip_ansi("\u{1b}[31mred\u{1b}[0m \u{1b}]0;title\u{7}x"), "red x");
    }

    #[test]
    fn plausible_version_output() {
        assert!(is_plausible_cli_version_output("1.2.3"));
        assert!(is_plausible_cli_version_output("codex-cli 0.44.0"));
        assert!(is_plausible_cli_version_output("v2.1.0-beta.1 (Claude Code)"));
        assert!(!is_plausible_cli_version_output("file:///x/y.js:12"));
        assert!(!is_plausible_cli_version_output("TypeError: boom 1.2"));
        assert!(!is_plausible_cli_version_output("    at foo (1.2.3)"));
        assert!(!is_plausible_cli_version_output("hello"));
        assert!(!is_plausible_cli_version_output(""));
    }

    #[test]
    fn path_like_commands() {
        assert!(is_path_like_command("/usr/bin/claude"));
        assert!(is_path_like_command("C:\\x\\claude.cmd"));
        assert!(is_path_like_command("c:foo"));
        assert!(!is_path_like_command("claude"));
    }

    #[test]
    fn first_non_localhost_url() {
        assert_eq!(
            extract_first_non_localhost_url("open http://localhost:1455/x then https://auth.openai.com/a?b=1."),
            Some("https://auth.openai.com/a?b=1".to_string())
        );
        assert_eq!(extract_first_non_localhost_url("http://127.0.0.1:1/x"), None);
        assert_eq!(extract_first_non_localhost_url("no urls"), None);
    }

    #[test]
    fn windows_shell_quoting() {
        assert_eq!(quote_windows_shell_arg(""), "\"\"");
        assert_eq!(quote_windows_shell_arg("a \"b\""), "\"a \\\"b\\\"\"");
        assert_eq!(build_windows_shell_command_line("x.cmd", &["1".into(), "two words".into()]), "\"x.cmd\" \"1\" \"two words\"");
    }

    #[cfg(unix)]
    #[test]
    fn prepare_command_posix_is_passthrough() {
        let spec = prepare_command_for_spawn("/bin/echo", &["a".into()], true);
        assert_eq!(spec, SpawnSpec { command: "/bin/echo".into(), args: vec!["a".into()], shell: false });
        assert_eq!(resolve_codex_executable_for_sdk("/x/codex").as_deref(), Some("/x/codex"));
        assert_eq!(resolve_codebuddy_executable_for_sdk(" ").as_deref(), None);
        assert_eq!(resolve_cursor_cli_spawn_spec("/x/cursor-agent", &["models".into()]).command, "/x/cursor-agent");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_command_captures_and_times_out() {
        let env: EnvMap = [("PATH".to_string(), "/usr/bin:/bin".to_string())].into_iter().collect();
        let result = run_command("sh", &["-c".into(), "printf '\\033[1mhi\\033[0m'; echo err 1>&2; exit 3".into()], &env, None, Some(Duration::from_secs(5))).await.unwrap();
        assert_eq!(result.stdout, "hi");
        assert_eq!(result.stderr.trim(), "err");
        assert_eq!(result.exit_code, Some(3));
        assert_eq!(result.output(), "hi\nerr");
        let err = run_command("sh", &["-c".into(), "sleep 5".into()], &env, None, Some(Duration::from_millis(200))).await.unwrap_err();
        assert!(matches!(err, CommandError::Timeout(_)));
        assert!(matches!(run_command("/nonexistent/x", &[], &env, None, None).await.unwrap_err(), CommandError::Spawn(_)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn resolve_cli_from_path_uses_which() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("mytool");
        std::fs::write(&bin, "#!/bin/sh\necho 1.0.0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let env: EnvMap = [("PATH".to_string(), format!("{}:/usr/bin:/bin", dir.path().display()))].into_iter().collect();
        assert_eq!(resolve_cli_from_path("mytool", &env).await.as_deref(), Some(bin.to_str().unwrap()));
        assert_eq!(resolve_cli_from_path("definitely-missing-tool", &env).await, None);
        assert_eq!(resolve_cli_from_path("bad name", &env).await, None);
        let probe = probe_cli_version(bin.to_str().unwrap(), &["--version".into()], &env).await;
        assert!(probe.launched);
        assert_eq!(probe.version, "1.0.0");
    }
}

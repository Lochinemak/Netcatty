//! One-click client setup for Codex, Claude Code and Grok (Electron
//! `externalMcp/codexSetup.cjs`, `claudeSetup.cjs`, `grokSetup.cjs`,
//! `boundedCliCommand.cjs`, `desktopCliResolver.cjs`).
//!
//! The launcher registered with the client is the Netcatty executable
//! itself (no arguments) with `NETCATTY_EXTERNAL_MCP_DISCOVERY_FILE` and
//! `NETCATTY_MCP_HELPER=external` in its env, which `main.rs` turns into the
//! External MCP stdio server.

use super::skill;
use crate::discovery::format_discovery_env_cli_flags;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const EXTERNAL_MCP_NAME: &str = "netcatty-external";
pub const CLI_TIMEOUT: Duration = Duration::from_secs(30);
pub const CLI_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct CliRun {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// `runBoundedCliCommand`: timeout + output cap, ANSI stripped.
pub async fn run_bounded_cli(command: &Path, args: &[String], env: &HashMap<String, String>) -> Result<CliRun, String> {
    use tokio::io::AsyncReadExt;
    let mut cmd = tokio::process::Command::new(command);
    cmd.args(args).envs(env).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).kill_on_drop(true);
    #[cfg(windows)]
    {
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let collect = async {
        let (mut a, mut b) = (Vec::new(), Vec::new());
        let (mut out_open, mut err_open) = (true, true);
        let (mut ba, mut bb) = ([0u8; 8192], [0u8; 8192]);
        while out_open || err_open {
            tokio::select! {
                r = out.read(&mut ba), if out_open => match r {
                    Ok(0) | Err(_) => out_open = false,
                    Ok(n) => a.extend_from_slice(&ba[..n]),
                },
                r = err.read(&mut bb), if err_open => match r {
                    Ok(0) | Err(_) => err_open = false,
                    Ok(n) => b.extend_from_slice(&bb[..n]),
                },
            }
            if a.len() + b.len() > CLI_MAX_OUTPUT_BYTES {
                let _ = child.start_kill();
                return Err(format!("CLI output exceeded {CLI_MAX_OUTPUT_BYTES} bytes"));
            }
        }
        let status = child.wait().await.map_err(|e| e.to_string())?;
        Ok((status.code(), a, b))
    };
    match tokio::time::timeout(CLI_TIMEOUT, collect).await {
        Err(_) => Err(format!("CLI command timed out after {} ms", CLI_TIMEOUT.as_millis())),
        Ok(Err(e)) => Err(e),
        Ok(Ok((code, a, b))) => Ok(CliRun {
            exit_code: code,
            stdout: netcatty_ptyexec::shell_utils::strip_ansi(&String::from_utf8_lossy(&a)),
            stderr: netcatty_ptyexec::shell_utils::strip_ansi(&String::from_utf8_lossy(&b)),
        }),
    }
}

/// Process env plus common user CLI dirs on PATH (login-shell PATH is not
/// resolved here; the SDK-agent module owns shell-env prewarming).
pub fn shell_env() -> HashMap<String, String> {
    let mut env: HashMap<String, String> = std::env::vars().collect();
    if let Some(home) = dirs::home_dir() {
        let extra = [home.join(".local/bin"), home.join(".npm-global/bin"), home.join(".bun/bin"), PathBuf::from("/opt/homebrew/bin"), PathBuf::from("/usr/local/bin")];
        let sep = if cfg!(windows) { ";" } else { ":" };
        let mut path = env.get("PATH").cloned().unwrap_or_default();
        for d in extra {
            let s = d.to_string_lossy().into_owned();
            if d.is_dir() && !path.split(sep).any(|p| p == s) {
                path = if path.is_empty() { s } else { format!("{path}{sep}{s}") };
            }
        }
        env.insert("PATH".into(), path);
    }
    env
}

pub fn resolve_cli_from_path(name: &str, env: &HashMap<String, String>) -> Option<PathBuf> {
    let path = env.get("PATH").or_else(|| env.get("Path"))?;
    let sep = if cfg!(windows) { ';' } else { ':' };
    let exts: &[&str] = if cfg!(windows) { &[".exe", ".cmd", ".bat", ""] } else { &[""] };
    for dir in path.split(sep).filter(|d| !d.is_empty()) {
        for ext in exts {
            let candidate = Path::new(dir).join(format!("{name}{ext}"));
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn is_executable(p: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(p) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    true
}

/// macOS desktop-app bundled CLIs (`resolveDesktopManagedCli`).
pub fn resolve_desktop_managed_cli(name: &str, home: &Path) -> Option<PathBuf> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    match name {
        "codex" => ["/Applications/ChatGPT.app", "/Applications/Codex.app"]
            .iter()
            .map(PathBuf::from)
            .chain([home.join("Applications/ChatGPT.app"), home.join("Applications/Codex.app")])
            .map(|r| r.join("Contents/Resources/codex"))
            .find(|p| is_executable(p)),
        "claude" => {
            let root = home.join("Library/Application Support/Claude/claude-code");
            let mut versions: Vec<String> = std::fs::read_dir(&root).ok()?.flatten().filter(|e| e.path().is_dir()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
            versions.sort_by(|a, b| compare_versions(b, a));
            versions.into_iter().map(|v| root.join(v).join("claude.app/Contents/MacOS/claude")).find(|p| is_executable(p))
        }
        _ => None,
    }
}

/// Numeric-aware version directory ordering.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |s: &str| -> Vec<u64> { s.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty()).map(|p| p.parse().unwrap_or(0)).collect() };
    parts(a).cmp(&parts(b))
}

pub fn quote_command_arg(v: &str) -> String {
    if v.is_empty() {
        return "\"\"".into();
    }
    if !v.chars().any(|c| c.is_whitespace() || c == '"' || c == '\'' || c == '\\') {
        return v.into();
    }
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

fn format_command(exe: &str, args: &[String]) -> String {
    std::iter::once(quote_command_arg(exe)).chain(args.iter().map(|a| quote_command_arg(a))).collect::<Vec<_>>().join(" ")
}

fn normalize_path(v: &str) -> String {
    let t = v.trim().trim_matches(['"', '\'']);
    if cfg!(windows) {
        t.trim_end_matches(".cmd").to_string()
    } else {
        t.to_string()
    }
}

fn paths_match(a: &str, b: &str) -> bool {
    normalize_path(a) == normalize_path(b)
}

fn has_required_env(entry_env: Option<&Value>, required: &[(String, String)]) -> bool {
    let req: Vec<&(String, String)> = required.iter().filter(|(_, v)| !v.is_empty()).collect();
    if req.is_empty() {
        return true;
    }
    let Some(env) = entry_env.and_then(Value::as_object) else {
        return false;
    };
    req.iter().all(|(k, v)| env.get(k).map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())) == Some(v.clone()))
}

/// Setup of one client.
pub struct ClientSetup {
    pub client: &'static str,
    pub launcher: String,
    pub discovery_env: Vec<(String, String)>,
    pub skill_source: Option<PathBuf>,
}

impl ClientSetup {
    fn add_args(&self) -> Vec<String> {
        let mut a = vec!["mcp".to_string(), "add".to_string()];
        if self.client == "claude" {
            a.extend(["-s".to_string(), "user".to_string()]);
        }
        a.push(EXTERNAL_MCP_NAME.into());
        a.extend(format_discovery_env_cli_flags(&self.discovery_env, self.client));
        a.push("--".into());
        a.push(self.launcher.clone());
        a
    }

    fn manual_command(&self, exe: &str) -> String {
        format_command(exe, &self.add_args())
    }

    fn resolve(&self, env: &HashMap<String, String>) -> (Option<PathBuf>, String) {
        let path_resolved = resolve_cli_from_path(self.client, env);
        if path_resolved.is_some() {
            return (path_resolved, self.client.to_string());
        }
        let home = dirs::home_dir().unwrap_or_default();
        let desktop = if self.client == "grok" { None } else { resolve_desktop_managed_cli(self.client, &home) };
        let exe = desktop.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| self.client.to_string());
        (desktop, exe)
    }

    fn not_found_key(&self) -> String {
        format!("{}_not_found", self.client)
    }

    fn path_key(&self) -> String {
        format!("{}Path", self.client)
    }

    fn base(&self, cli: Option<&Path>, exe: &str) -> Value {
        let mut v = json!({ "ok": true, "launcherPath": self.launcher, "command": self.manual_command(exe), "existingCommand": null, "error": null });
        v[self.path_key()] = json!(cli.map(|p| p.to_string_lossy().into_owned()));
        v
    }

    async fn skill_status(&self, env: &HashMap<String, String>) -> skill::SkillStatus {
        skill::status(self.client, &skill::client_homes(env), self.skill_source.as_deref())
    }

    /// Classify the registered entry: `configured` / `not_configured` /
    /// `conflict` / `error` / `<client>_not_found`.
    pub async fn status(&self) -> Value {
        let env = shell_env();
        let (cli, exe) = self.resolve(&env);
        let Some(cli) = cli else {
            let mut v = self.base(None, &exe);
            v["state"] = json!(self.not_found_key());
            return v;
        };
        let mut status = match self.client {
            "codex" => self.classify_codex(&cli, &exe, &env).await,
            "claude" => self.classify_claude(&cli, &exe, &env).await,
            _ => self.classify_grok(&cli, &exe, &env).await,
        };
        if status["state"] == "configured" {
            let s = self.skill_status(&env).await;
            status["mcpConfigured"] = json!(true);
            status["skillInstalled"] = json!(s.installed);
            status["skillPath"] = json!(s.skill_path.to_string_lossy());
            if !s.installed {
                status["state"] = json!("not_configured");
                if let Some(r) = s.reason {
                    status["skillError"] = json!(r);
                }
            }
        } else if status["state"] != "error" {
            status["mcpConfigured"] = json!(false);
            status["skillInstalled"] = json!(false);
        }
        status
    }

    async fn classify_codex(&self, cli: &Path, exe: &str, env: &HashMap<String, String>) -> Value {
        let mut base = self.base(Some(cli), exe);
        let r = match run_bounded_cli(cli, &["mcp".into(), "list".into(), "--json".into()], env).await {
            Ok(r) => r,
            Err(e) => {
                base["state"] = json!("error");
                base["error"] = json!(e);
                return base;
            }
        };
        if r.exit_code != Some(0) {
            base["state"] = json!("error");
            base["error"] = json!(summarize(&r, "Codex"));
            return base;
        }
        let entries: Vec<Value> = match serde_json::from_str::<Value>(if r.stdout.trim().is_empty() { "[]" } else { &r.stdout }) {
            Ok(Value::Array(a)) => a,
            _ => {
                base["state"] = json!("error");
                base["error"] = json!("Codex MCP list returned an unexpected payload.");
                return base;
            }
        };
        let Some(entry) = entries.iter().find(|e| e["name"] == EXTERNAL_MCP_NAME) else {
            base["state"] = json!("not_configured");
            return base;
        };
        let t = &entry["transport"];
        let existing = format_transport(t).unwrap_or_else(|| self.launcher.clone());
        base["existingCommand"] = json!(existing);
        if entry["enabled"] == json!(false) {
            base["state"] = json!("not_configured");
            return base;
        }
        let no_args = t["args"].as_array().is_none_or(|a| a.is_empty());
        if t["type"] == "stdio" && paths_match(t["command"].as_str().unwrap_or(""), &self.launcher) && no_args {
            let env_v = t.get("env").filter(|e| e.is_object()).or(entry.get("env"));
            base["state"] = json!(if has_required_env(env_v, &self.discovery_env) { "configured" } else { "not_configured" });
            return base;
        }
        base["state"] = json!("conflict");
        base
    }

    async fn classify_claude(&self, cli: &Path, exe: &str, env: &HashMap<String, String>) -> Value {
        let mut base = self.base(Some(cli), exe);
        let r = match run_bounded_cli(cli, &["mcp".into(), "get".into(), EXTERNAL_MCP_NAME.into()], env).await {
            Ok(r) => r,
            Err(e) => {
                base["state"] = json!("error");
                base["error"] = json!(e);
                return base;
            }
        };
        let output = format!("{}\n{}", r.stdout, r.stderr).trim().to_string();
        if r.exit_code != Some(0) {
            let missing = Regex::new(r#"(?i)No MCP server (?:found with name:|named)\s*["']?netcatty-external["']?"#).unwrap().is_match(&output);
            base["state"] = json!(if missing { "not_configured" } else { "error" });
            if !missing {
                base["error"] = json!(summarize(&r, "Claude"));
            }
            return base;
        }
        let line = |re: &str| output.lines().map(str::trim).find_map(|l| Regex::new(re).unwrap().captures(l).map(|c| c[1].trim().to_string()));
        let command = line(r"(?i)^Command:\s*(.*)$").unwrap_or_else(|| output.clone());
        let args = line(r"(?i)^Args?:\s*(.*)$").filter(|a| !matches!(a.as_str(), "" | "[]" | "(none)" | "none"));
        let scope = line(r"(?i)^Scope:\s*(.*)$").map(|s| s.to_lowercase()).and_then(|s| ["user", "local", "project"].into_iter().find(|p| s.starts_with(p)).map(str::to_string));
        let mut env_map = serde_json::Map::new();
        let pair = Regex::new(r"^\s*([A-Z0-9_]+)\s*=\s*(.+?)\s*$").unwrap();
        for l in output.lines() {
            if let Some(c) = pair.captures(l) {
                env_map.insert(c[1].to_string(), json!(c[2].trim_matches(['"', '\''])));
            }
        }
        base["existingCommand"] = json!(command);
        base["existingScope"] = json!(scope);
        let exe_of = command.rsplit(" -- ").next().unwrap_or(&command).trim().to_string();
        let single = !exe_of.is_empty() && !exe_of.contains(' ') || exe_of.starts_with('"');
        if single && paths_match(&exe_of, &self.launcher) {
            if args.is_some() {
                base["state"] = json!("conflict");
            } else if !has_required_env(Some(&Value::Object(env_map)), &self.discovery_env) || scope.as_deref().is_some_and(|s| s != "user") {
                base["state"] = json!("not_configured");
            } else {
                base["state"] = json!("configured");
            }
            return base;
        }
        base["state"] = json!("conflict");
        base
    }

    async fn classify_grok(&self, cli: &Path, exe: &str, env: &HashMap<String, String>) -> Value {
        let mut base = self.base(Some(cli), exe);
        let mut r = run_bounded_cli(cli, &["mcp".into(), "list".into(), "--json".into()], env).await;
        if r.as_ref().map(|r| r.exit_code != Some(0)).unwrap_or(true) {
            r = run_bounded_cli(cli, &["mcp".into(), "list".into()], env).await;
        }
        let r = match r {
            Ok(r) if r.exit_code == Some(0) => r,
            Ok(r) => {
                base["state"] = json!("error");
                base["error"] = json!(summarize(&r, "Grok"));
                return base;
            }
            Err(e) => {
                base["state"] = json!("error");
                base["error"] = json!(e);
                return base;
            }
        };
        let entries = parse_grok_list(&r.stdout);
        let Some(entry) = entries.iter().find(|e| e["name"] == EXTERNAL_MCP_NAME) else {
            base["state"] = json!("not_configured");
            return base;
        };
        let command = grok_entry_command(entry);
        if entry["enabled"] == json!(false) {
            base["state"] = json!("not_configured");
            base["existingCommand"] = json!(command.clone().unwrap_or_else(|| self.launcher.clone()));
            return base;
        }
        let Some(command) = command else {
            base["state"] = json!("conflict");
            base["existingCommand"] = json!(format_transport(&entry["transport"]).unwrap_or_else(|| EXTERNAL_MCP_NAME.into()));
            return base;
        };
        base["existingCommand"] = json!(command);
        if paths_match(&command, &self.launcher) {
            let env_v = entry.get("env").filter(|e| e.is_object()).or(entry["transport"].get("env"));
            base["state"] = json!(if has_required_env(env_v, &self.discovery_env) { "configured" } else { "not_configured" });
        } else {
            base["state"] = json!("conflict");
        }
        base
    }

    /// Register the server (replacing a stale Netcatty entry) and install
    /// the bundled skill.
    pub async fn add(&self) -> Value {
        let status = self.status().await;
        let state = status["state"].as_str().unwrap_or("");
        if state == self.not_found_key() || matches!(state, "conflict" | "configured" | "error") {
            return status;
        }
        let env = shell_env();
        let (Some(cli), exe) = self.resolve(&env) else {
            return status;
        };
        let mut mcp_configured = status["mcpConfigured"] == json!(true);
        let fail = |e: String, installing: bool, mcp_configured: bool| {
            let mut v = self.base(Some(&cli), &exe);
            v["state"] = json!("error");
            v["mcpConfigured"] = json!(mcp_configured);
            v["skillInstalled"] = json!(false);
            v["error"] = json!(if installing { format!("Failed to install the Netcatty {} skill: {e}", skill::client_label(self.client)) } else { e });
            v
        };
        if !mcp_configured {
            if !status["existingCommand"].is_null() {
                let scopes: Vec<String> = match (self.client, status["existingScope"].as_str()) {
                    ("claude", Some(s)) => vec![s.to_string()],
                    ("claude", None) => vec!["local".into(), "user".into(), "project".into()],
                    _ => vec![String::new()],
                };
                for scope in scopes {
                    let mut args = vec!["mcp".to_string(), "remove".to_string()];
                    if !scope.is_empty() {
                        args.extend(["-s".to_string(), scope]);
                    }
                    args.push(EXTERNAL_MCP_NAME.into());
                    let _ = run_bounded_cli(&cli, &args, &env).await;
                }
            }
            match run_bounded_cli(&cli, &self.add_args(), &env).await {
                Ok(r) if r.exit_code == Some(0) => mcp_configured = true,
                Ok(r) => {
                    let mut v = self.base(Some(&cli), &exe);
                    v["state"] = json!("error");
                    v["error"] = json!(summarize(&r, skill::client_label(self.client)));
                    return v;
                }
                Err(e) => return fail(e, false, false),
            }
        }
        if let Err(e) = skill::install(self.client, &skill::client_homes(&env), self.skill_source.as_deref()) {
            return fail(e, true, mcp_configured);
        }
        self.status().await
    }
}

fn summarize(r: &CliRun, client: &str) -> String {
    let text = if !r.stderr.trim().is_empty() { r.stderr.trim() } else { r.stdout.trim() };
    if text.is_empty() {
        format!("{client} exited with code {}", r.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "unknown".into()))
    } else {
        text.to_string()
    }
}

fn format_transport(t: &Value) -> Option<String> {
    if !t.is_object() {
        return None;
    }
    if t["type"] == "stdio" || t["command"].is_string() {
        let cmd = t["command"].as_str().unwrap_or("").trim().to_string();
        let args: Vec<String> = t["args"].as_array().map(|a| a.iter().filter_map(Value::as_str).filter(|s| !s.trim().is_empty()).map(str::to_string).collect()).unwrap_or_default();
        let joined = std::iter::once(cmd).chain(args).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
        return (!joined.is_empty()).then_some(joined);
    }
    t["url"].as_str().map(|u| u.trim().to_string()).filter(|u| !u.is_empty())
}

fn grok_entry_command(e: &Value) -> Option<String> {
    let t = &e["transport"];
    if t["type"] == "stdio" || t["command"].is_string() {
        let cmd = t["command"].as_str().unwrap_or("").trim();
        return (!cmd.is_empty() && t["args"].as_array().is_none_or(|a| a.is_empty())).then(|| cmd.to_string());
    }
    if let Some(cmd) = e["command"].as_str().map(str::trim).filter(|c| !c.is_empty()) {
        return e["args"].as_array().is_none_or(|a| a.is_empty()).then(|| cmd.to_string());
    }
    format_transport(t).or_else(|| e["url"].as_str().map(str::to_string))
}

/// `parseGrokMcpList` (JSON array / object, or `name: command` lines).
pub fn parse_grok_list(raw: &str) -> Vec<Value> {
    let text = raw.trim();
    if text.is_empty() {
        return Vec::new();
    }
    let norm = |e: &Value, name: Option<&str>| {
        let n = name.map(str::to_string).or_else(|| e["name"].as_str().map(str::to_string)).or_else(|| e["id"].as_str().map(str::to_string)).unwrap_or_default();
        json!({ "name": n, "enabled": e["enabled"] != json!(false), "command": e.get("command").filter(|c| c.is_string()), "args": e.get("args").filter(|a| a.is_array()), "transport": e.get("transport").filter(|t| t.is_object()), "url": e.get("url").filter(|u| u.is_string()), "env": e.get("env").filter(|v| v.is_object()) })
    };
    if let Ok(parsed) = serde_json::from_str::<Value>(text) {
        if let Some(a) = parsed.as_array() {
            return a.iter().filter(|e| e.is_object()).map(|e| norm(e, None)).collect();
        }
        if parsed.is_object() {
            let servers = parsed.get("servers").or(parsed.get("mcp_servers")).or(parsed.get("mcpServers")).unwrap_or(&parsed);
            if let Some(a) = servers.as_array() {
                return a.iter().filter(|e| e.is_object()).map(|e| norm(e, None)).collect();
            }
            if let Some(m) = servers.as_object() {
                return m.iter().map(|(k, v)| norm(v, Some(k))).collect();
            }
        }
    }
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            let (name, cmd) = match l.find(':') {
                Some(i) if i > 0 => (l[..i].trim().to_string(), l[i + 1..].trim().to_string()),
                _ => {
                    let mut p = l.split_whitespace();
                    (p.next().unwrap_or("").to_string(), p.collect::<Vec<_>>().join(" "))
                }
            };
            (!name.is_empty()).then(|| json!({ "name": name, "enabled": true, "command": if cmd.is_empty() { Value::Null } else { json!(cmd) } }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(client: &'static str) -> ClientSetup {
        ClientSetup {
            client,
            launcher: "/Applications/Netcatty.app/Contents/MacOS/Netcatty".into(),
            discovery_env: vec![("NETCATTY_EXTERNAL_MCP_DISCOVERY_FILE".into(), "/d.json".into()), ("NETCATTY_MCP_HELPER".into(), "external".into())],
            skill_source: None,
        }
    }

    #[test]
    fn add_commands() {
        assert_eq!(
            setup("claude").manual_command("claude"),
            "claude mcp add -s user netcatty-external -e NETCATTY_EXTERNAL_MCP_DISCOVERY_FILE=/d.json -e NETCATTY_MCP_HELPER=external -- /Applications/Netcatty.app/Contents/MacOS/Netcatty"
        );
        assert!(setup("codex").manual_command("codex").starts_with("codex mcp add netcatty-external --env "));
        assert_eq!(quote_command_arg("a b"), "\"a b\"");
        assert_eq!(quote_command_arg(""), "\"\"");
    }

    #[test]
    fn grok_list_parsing_and_versions() {
        let entries = parse_grok_list("{\"mcpServers\":{\"netcatty-external\":{\"command\":\"/x\",\"env\":{\"A\":\"1\"}}}}");
        assert_eq!(entries[0]["name"], "netcatty-external");
        assert_eq!(grok_entry_command(&entries[0]).as_deref(), Some("/x"));
        let entries = parse_grok_list("netcatty-external: /bin/netcatty\nother");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["command"], "/bin/netcatty");
        assert_eq!(compare_versions("2.10.0", "2.9.1"), std::cmp::Ordering::Greater);
        assert!(has_required_env(Some(&json!({ "NETCATTY_EXTERNAL_MCP_DISCOVERY_FILE": "/d.json", "NETCATTY_MCP_HELPER": "external" })), &setup("codex").discovery_env));
        assert!(!has_required_env(Some(&json!({})), &setup("codex").discovery_env));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn codex_classification_with_fake_cli() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cli = dir.path().join("codex");
        let s = setup("codex");
        let listing = json!([{ "name": "netcatty-external", "enabled": true, "transport": { "type": "stdio", "command": s.launcher, "args": [], "env": { "NETCATTY_EXTERNAL_MCP_DISCOVERY_FILE": "/d.json", "NETCATTY_MCP_HELPER": "external" } } }]);
        std::fs::write(&cli, format!("#!/bin/sh\necho '{listing}'\n")).unwrap();
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();
        let v = s.classify_codex(&cli, "codex", &HashMap::new()).await;
        assert_eq!(v["state"], "configured", "{v}");
        std::fs::write(&cli, "#!/bin/sh\necho '[{\"name\":\"netcatty-external\",\"transport\":{\"type\":\"stdio\",\"command\":\"/other\"}}]'\n").unwrap();
        assert_eq!(s.classify_codex(&cli, "codex", &HashMap::new()).await["state"], "conflict");
        std::fs::write(&cli, "#!/bin/sh\necho boom >&2\nexit 3\n").unwrap();
        let v = s.classify_codex(&cli, "codex", &HashMap::new()).await;
        assert_eq!(v["state"], "error");
        assert_eq!(v["error"], "boom");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bounded_cli_times_out_and_caps_output() {
        let r = run_bounded_cli(Path::new("/bin/sh"), &["-c".into(), "printf hi; echo e >&2".into()], &HashMap::new()).await.unwrap();
        assert_eq!(r.stdout, "hi");
        assert_eq!(r.stderr, "e\n");
        let e = run_bounded_cli(Path::new("/bin/sh"), &["-c".into(), "head -c 2000000 /dev/zero".into()], &HashMap::new()).await.unwrap_err();
        assert!(e.contains("exceeded"));
    }
}

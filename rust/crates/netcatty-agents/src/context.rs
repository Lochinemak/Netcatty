//! Host context handed to external agents (Electron: `aiBridge.cjs
//! buildExternalAgentSystemContext` / `buildExternalAgentContextualPrompt`,
//! `shared/vaultAgentGuidance.cjs`).

use serde::Deserialize;

pub const VAULT_HOSTS_VS_NOTES_GUIDANCE: &str = "Vault → Hosts vs Vault → Notes: When the user asks to add/create/import a host (创建主机、添加主机、保存 SSH 连接凭据), use vault_hosts_create with dryRun=true first, or vault_hosts_import for known export formats (PuTTY, MobaXterm, CSV, SecureCRT, FinalShell, ssh_config) — NOT vault_notes_create. For attached host files, use vault_hosts_import only when the attachment is a known export format; for unknown attached host/server text, read the attachment content, extract hostname, username, password, port, group, tags, and label yourself, then call vault_hosts_create with dryRun=true first. Extract hostname, username, password or local keyPath, port, group, tags, and label from the user's text; put long admin tables or remarks in the host notes field (host_notes_set / Host Details metadata), not Vault sidebar Notes. Use vault_notes_create or vault_notes_update ONLY when the user explicitly wants markdown documentation in Vault → Notes (保险箱笔记 sidebar). Use vault_notes_import to import generated or attached markdown as one or more sidebar notes. Use vault_hosts_list to resolve hostId before vault_hosts_update or vault_hosts_delete. If vault_hosts_create or vault_hosts_import fails, report the error — do not silently create a Vault note instead.";

pub const VAULT_NOTES_CLI_GUIDANCE: &str = "Vault sidebar Notes vs host metadata: use notes create or notes update ONLY when the user explicitly wants markdown documentation in Vault → Notes. Use notes import --attachment-index from attachment list for attached Markdown; use --content-stdin for generated Markdown or --documents-stdin for a batch. Never interpolate note text into a shell command. Read a note with notes get --note-id using the exact id from notes list; follow nextOffset with --expected-updated-at until null before summarizing or replacing the whole note. Host Details metadata uses vault host-notes set, not notes create. Do not create or import a Vault note when the user asked to add a host. If a host operation fails, report the error — do not silently create a Vault note instead. notes create requires a body through --content-stdin or an explicit --content (which may be empty). On notes update, an explicit empty --content clears the body and an explicit empty --group clears the folder; omit those flags to keep the current values. notes import accepts an empty --content. notes create, notes update, notes delete, and notes import require user approval; if approval is denied, stop.";

pub const VAULT_SCRIPTS_GUIDANCE: &str = "Snippets vs automation scripts: snippets_* for shell command text (optional named placeholders written with two curly braces on each side). scripts_* for nct JavaScript automation (await nct.screen.sendLine, waitForText/waitForRegex, dialogs). Call scripts_reference before authoring scripts. scripts_run with wait=true blocks until completion; use scripts_runs_list / scripts_run_stop / scripts_run_pause / scripts_run_resume for lifecycle. Triggers: manual, onConnect (runs after connect), onOutput (regex triggerPattern). Host/group linking: scripts_targets_set supports targets and dynamic targetGroups; per-host connect order: host_connect_scripts_list / host_connect_scripts_set.";

pub fn append_vault_agent_guidance(description: &str) -> String {
    let mut result = description.trim().to_string();
    for (marker, guidance) in [
        ("Vault → Hosts vs Vault → Notes", VAULT_HOSTS_VS_NOTES_GUIDANCE),
        ("Snippets vs automation scripts", VAULT_SCRIPTS_GUIDANCE),
    ] {
        if !result.contains(marker) {
            result = if result.is_empty() { guidance.to_string() } else { format!("{result} {guidance}") };
        }
    }
    result
}

/// The renderer's `defaultTargetSession`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultTargetSession {
    pub session_id: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default = "default_true")]
    pub connected: bool,
}

fn default_true() -> bool {
    true
}

/// How agents invoke the netcatty tool CLI in skills mode (`getSkillsCliInvocation`).
#[derive(Debug, Clone)]
pub struct SkillsCliInvocation {
    pub command_prefix: String,
    pub launcher_path: Option<String>,
    pub uses_launcher: bool,
    /// Whether the script form (`node "<cli>"`) exists.
    pub has_cli_script: bool,
    /// The bundled SKILL.md, when present.
    pub skill_path: Option<String>,
}

impl Default for SkillsCliInvocation {
    fn default() -> Self {
        Self { command_prefix: "netcatty-tool-cli".into(), launcher_path: None, uses_launcher: false, has_cli_script: false, skill_path: None }
    }
}

pub struct ContextInput<'a> {
    pub mode: &'a str,
    pub chat_session_id: &'a str,
    pub default_target_session: Option<&'a DefaultTargetSession>,
    pub user_skills_context: Option<&'a str>,
    pub skills_cli: &'a SkillsCliInvocation,
}

/// `buildExternalAgentSystemContext`.
pub fn build_external_agent_system_context(input: &ContextInput<'_>) -> String {
    let preamble = input.user_skills_context.filter(|s| !s.is_empty()).map(|s| format!("{s}\n\n")).unwrap_or_default();
    if input.mode == "skills" {
        let cli = input.skills_cli;
        let p = cli.command_prefix.as_str();
        let skill_hint = cli.skill_path.as_deref().map(|path| format!("The local Netcatty skill file is \"{path}\". You do not need to read it for routine read-only requests if the host instructions here are sufficient. Only open it when the task is unusual, multi-step, or you are unsure about the workflow. ")).unwrap_or_default();
        let cli_hint = if cli.uses_launcher {
            let launcher = cli.launcher_path.as_deref().unwrap_or("");
            let tail = if cfg!(windows) {
                format!("If your execution surface supports argv-style execution, use that launcher path as the executable and pass subcommands/flags as separate arguments. If you need a literal shell command line, invoke it as `{p}`. ")
            } else {
                format!("The literal shell command prefix is `{p}`. ")
            };
            format!("For this chat session, the Netcatty CLI launcher is at `{launcher}`. Invoke that launcher directly for every Netcatty CLI call, and do not prepend `node`. {tail}")
        } else if cli.has_cli_script {
            format!("For this chat session, the exact Netcatty CLI command prefix is `{p}`.")
        } else {
            "Use the exact Netcatty CLI command prefix provided by the host application for this chat session. ".to_string()
        };
        let scope_hint = if input.chat_session_id.is_empty() { String::new() } else { "The current Netcatty chat session is already bound in this process via the host environment. Keep using `--session <session-id>` to select a terminal. ".to_string() };
        let target = input.default_target_session;
        let default_target_hint = target.map(|t| {
            let head = format!("The host has already identified the default target session for this AI panel: sessionId=\"{}\", label=\"{}\", hostname=\"{}\", protocol=\"{}\", connected={}. ", t.session_id, t.label, t.hostname, t.protocol.as_deref().unwrap_or(""), t.connected);
            let tail = if t.connected {
                format!("For routine requests that do not mention another session or host, use this default target directly and prefer `{p} session --session {} --json` as the first call instead of starting with `env` discovery. Only run `env` when the user explicitly points to another session (for example with @), when the task is ambiguous, or when that direct session lookup fails. ", t.session_id)
            } else {
                "This default target is currently not connected, so do not execute against it directly. Fall back to `env` / `session` lookup if the user may want another available session. ".to_string()
            };
            format!("{head}{tail}")
        }).unwrap_or_default();
        let discovery_hint = if target.map(|t| t.connected).unwrap_or(true) {
            format!("If you do need discovery because the task is ambiguous or points to another session, start with `{p} env --json` to discover available sessions and their IDs. ")
        } else {
            format!("Start with `{p} env --json` to discover available sessions and their IDs. ")
        };
        return format!(
            "{preamble}[Context: You are inside Netcatty, a multi-session terminal manager. {skill_hint}{cli_hint}{scope_hint}{default_target_hint}\
Use Skills + CLI instead of the \"netcatty-remote-hosts\" MCP server for Netcatty session access. \
Use the local shell only to invoke Netcatty CLI commands. Do not use local shell or filesystem tools for unrelated local-machine work. \
For files explicitly attached by the user, call `{p} attachment list --json`, then read the selected file with `{p} attachment read --filename <filename> --json`. \
{VAULT_NOTES_CLI_GUIDANCE} Invoke those notes commands as `{p} notes list|get|create|update|delete|import --json`, and read the notes reference in the Netcatty skill before the first notes write. \
First classify the task: remote command execution tasks go through `exec`, while remote file or directory tasks go through `sftp`. If the user explicitly says to avoid shell or `exec`, do not use `exec`. Treat `exec` as the short-command path only: use it only for commands expected to finish within about 60 seconds. For builds, scans, watch mode, tail-following, ping, or anything likely to exceed that budget or stream output for an extended period, do not use plain `exec`; use the long-running job commands instead. \
{discovery_hint}\
After choosing a target session ID, call `{p} session --session <id> --json` before executing anything. Do not infer protocol, shell type, device type, or connection readiness from the `env` result alone when you are about to run a command. \
For remote file operations, use the Netcatty SFTP CLI surface instead of trying to reconstruct SSH credentials or open your own SSH/SFTP connection, but only when the chosen session is SSH-backed and connected. After the required `session --session <id>` confirmation step, inspect the reported protocol, shell type, device type, and connected state before picking a file-operation path. For SSH-backed sessions, prefer one-off commands such as `{p} sftp list --session <id> --remote-path <remote-path> --json`, `{p} sftp read --session <id> --remote-path <remote-path> --json`, `{p} sftp write --session <id> --remote-path <remote-path> --content <text> --json`, `{p} sftp download --session <id> --remote-path <remote-path> --local-path <local-path> --json`, or `{p} sftp upload --session <id> --local-path <local-path> --remote-path <remote-path> --json`. For local sessions, use normal local filesystem tools instead of Netcatty SFTP. For Mosh, Telnet, serial/raw, or network-device sessions, do not call SFTP; use a real SSH session, vendor CLI commands, or tell the user that the requested file transfer is unsupported on that transport. \
Keep local and remote path semantics strict: `--remote-path` always refers to the remote host, while `--local-path` always refers to the local machine running Netcatty. If the user asks to download a file to a local destination such as `/tmp`, `~/Downloads`, or a desktop path, use `sftp download`, not `sftp read` or `sftp write`. If the user asks to create or modify a file on the remote host, use `sftp write` or another remote SFTP operation, not `sftp download`. \
If you need to create or update a small text file with known content on the remote host, prefer `{p} sftp write ...` directly. Use `sftp upload` only when a real local file already exists and must be transferred to the remote host. Do not create temporary local files just to upload text that could be sent with `sftp write`. \
Keep SFTP usage one-off and explicit: every `sftp` command should include `--session <id>`. Do not open reusable SFTP handles or use `--sftp <id>`. \
Run Netcatty CLI calls strictly one at a time. Do not issue concurrent or background Netcatty CLI commands for the same chat session, and always wait for each call to finish before starting the next one. \
For simple read-only requests such as hostname, IP address, CPU info, memory info, disk usage, pwd, whoami, uname, or process checks, use the shortest possible path: one `env`, one `session`, then one `exec`. Prefer a single straightforward command over creating helper scripts or multi-step shell orchestration. \
For long-running command tasks, start them with `{p} job-start --session <id> --json -- <command>`, then use `{p} job-poll --job <job-id> --json` to fetch incremental output, and `{p} job-stop --job <job-id> --json` if the user asks to stop them. Do not poll aggressively; wait roughly 30 seconds between polls unless the output clearly justifies checking sooner. \
For those simple read-only requests, do not spend time reading extra files, designing scripts, or narrating a plan unless the first direct command fails or the session metadata shows a special device type. \
Do not create temporary scripts, JSON post-processing scripts, or extra wrapper commands unless the task genuinely requires logic that cannot fit cleanly in one direct command. \
Avoid shell command substitution such as `$()` and backticks, because Netcatty safety policy may block them. Prefer straightforward command chains such as `hostname && hostname -I && lscpu`. \
Avoid wrapping simple commands in `sh -c`, `bash -c`, or similar shell launcher patterns unless the task genuinely requires shell parsing that cannot be expressed as a direct command. \
Do not spend time narrating intent before every CLI call for routine read-only checks. Execute the minimal command sequence and then report the result. \
Only after that confirmation step should you call `{p} exec --session <id> --json -- <command>` for command execution. \
If the user stops the run or asks to abort outstanding Netcatty work, use `{p} cancel --json`, and use `resume` to re-enable execs for that scope if needed. \
For serial/raw sessions and network device sessions (deviceType: network), commands are sent as-is without shell wrapping and exit codes are unavailable. Use vendor CLI commands directly.]"
        );
    }
    append_vault_agent_guidance(&format!(
        "{preamble}[Context: You are inside Netcatty, a multi-session terminal manager. \
Use the \"netcatty-remote-hosts\" MCP tools to operate only on the terminal sessions exposed by Netcatty. \
For local files explicitly attached by the user, use the list_attachments and read_attachment tools. Do not use local shell or local filesystem tools for unrelated local-machine work. \
Those sessions may be remote hosts, a local terminal, or Mosh-backed shells. \
Call get_environment first to discover available sessions and their IDs. \
Use terminal_execute only for commands likely to finish within about 60 seconds. \
For long-running commands such as builds, scans, follow/log streaming, watch commands, or anything likely to exceed 60 seconds on PTY-backed shell sessions, use terminal_start, then terminal_poll until completed is true. Reuse the returned nextOffset for the next poll. If terminal_poll reports outputTruncated=true, only the retained tail starting at outputBaseOffset is still available. Do not poll aggressively: wait at least about 30 seconds between polls, and increase the interval further when there is no new output, to avoid wasting tokens. As soon as completed is true, stop polling and analyze the result immediately. \
Use terminal_stop if you need to interrupt a started long-running command. Note: terminal_start requires a PTY-backed session; for sessions that only support exec-channel execution (no writable PTY), use terminal_execute instead. \
For serial/raw sessions and network device sessions (deviceType: network), commands are sent as-is without shell wrapping and exit codes are unavailable. Use vendor CLI commands directly.]"
    ))
}

/// `buildExternalAgentContextualPrompt`.
pub fn build_external_agent_contextual_prompt(input: &ContextInput<'_>, prompt: &str) -> String {
    format!("{}\n\n{prompt}", build_external_agent_system_context(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_mode_context_includes_vault_guidance_once() {
        let cli = SkillsCliInvocation::default();
        let ctx = build_external_agent_system_context(&ContextInput { mode: "mcp", chat_session_id: "c", default_target_session: None, user_skills_context: Some("SKILLS"), skills_cli: &cli });
        assert!(ctx.starts_with("SKILLS\n\n[Context: You are inside Netcatty"));
        assert!(ctx.contains("get_environment"));
        assert_eq!(ctx.matches("Vault → Hosts vs Vault → Notes").count(), 1);
        assert_eq!(append_vault_agent_guidance(&ctx), ctx);
    }

    #[test]
    fn skills_mode_context_uses_prefix_and_target() {
        let cli = SkillsCliInvocation { command_prefix: "\"/app/netcatty-tool-cli\"".into(), launcher_path: Some("/app/netcatty-tool-cli".into()), uses_launcher: true, has_cli_script: false, skill_path: Some("/app/SKILL.md".into()) };
        let target = DefaultTargetSession { session_id: "s-1".into(), hostname: "h".into(), label: "L".into(), protocol: Some("ssh".into()), connected: true };
        let ctx = build_external_agent_system_context(&ContextInput { mode: "skills", chat_session_id: "c", default_target_session: Some(&target), user_skills_context: None, skills_cli: &cli });
        assert!(ctx.contains("The local Netcatty skill file is \"/app/SKILL.md\""));
        assert!(ctx.contains("launcher is at `/app/netcatty-tool-cli`"));
        assert!(ctx.contains("`\"/app/netcatty-tool-cli\" session --session s-1 --json`"));
        assert!(ctx.contains("sessionId=\"s-1\""));
        assert!(!ctx.contains("vault_hosts_create"));
        let disconnected = DefaultTargetSession { connected: false, ..target };
        let ctx = build_external_agent_system_context(&ContextInput { mode: "skills", chat_session_id: "", default_target_session: Some(&disconnected), user_skills_context: None, skills_cli: &cli });
        assert!(ctx.contains("currently not connected"));
        assert!(ctx.contains("Start with `"));
        let prompt = build_external_agent_contextual_prompt(&ContextInput { mode: "mcp", chat_session_id: "", default_target_session: None, user_skills_context: None, skills_cli: &cli }, "hello");
        assert!(prompt.ends_with("\n\nhello"));
    }
}

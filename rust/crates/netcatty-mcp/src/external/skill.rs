//! Netcatty MCP skill installer and universal setup prompt (Electron
//! `externalMcp/netcattySkillInstaller.cjs`, `universalSetupPrompt.cjs`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const SKILL_NAME: &str = "netcatty-mcp";
pub const MANAGED_MARKER: &str = "managed-by: netcatty";

/// Skill bundled with the app: `<resources>/skills/netcatty-mcp/SKILL.md`,
/// or the repository copy in development builds.
pub fn bundled_skill_path(resource_dir: Option<&Path>) -> Option<PathBuf> {
    let candidates = resource_dir
        .map(|r| vec![r.join("skills").join(SKILL_NAME).join("SKILL.md"), r.join("_up_/_up_/_up_/skills").join(SKILL_NAME).join("SKILL.md")])
        .unwrap_or_default()
        .into_iter()
        .chain(std::iter::once(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../skills").join(SKILL_NAME).join("SKILL.md")));
    candidates.into_iter().find(|p| p.is_file())
}

/// Embedded fallback copy (the repository skill at build time).
pub const EMBEDDED_SKILL: &str = include_str!("../../../../../skills/netcatty-mcp/SKILL.md");

pub fn client_label(client: &str) -> &'static str {
    match client {
        "codex" => "Codex",
        "claude" => "Claude Code",
        _ => "Grok",
    }
}

/// Home directories of the clients (`HOME`, `CLAUDE_CONFIG_DIR`, `GROK_HOME`).
#[derive(Debug, Clone)]
pub struct ClientHomes {
    pub home: PathBuf,
    pub claude_config_dir: Option<PathBuf>,
    pub grok_home: PathBuf,
}

pub fn client_homes(env: &HashMap<String, String>) -> ClientHomes {
    let home = env
        .get(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .or_else(|| env.get("HOME"))
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .unwrap_or_default();
    let grok_home = match env.get("GROK_HOME").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        None => home.join(".grok"),
        Some("~") => home.clone(),
        Some(s) if s.starts_with("~/") => home.join(&s[2..]),
        Some(s) if Path::new(s).is_absolute() => PathBuf::from(s),
        Some(s) => home.join(s),
    };
    ClientHomes { home: home.clone(), claude_config_dir: env.get("CLAUDE_CONFIG_DIR").map(PathBuf::from), grok_home }
}

pub fn user_skill_path(client: &str, homes: &ClientHomes) -> PathBuf {
    let root = match client {
        "codex" => homes.home.join(".agents").join("skills"),
        "claude" => homes.claude_config_dir.clone().unwrap_or_else(|| homes.home.join(".claude")).join("skills"),
        _ => homes.grok_home.join("skills"),
    };
    root.join(SKILL_NAME).join("SKILL.md")
}

pub fn read_bundled(source: Option<&Path>) -> Result<String, String> {
    let content = match source {
        Some(p) => std::fs::read_to_string(p).map_err(|e| e.to_string())?,
        None => EMBEDDED_SKILL.to_string(),
    };
    if !content.contains(MANAGED_MARKER) {
        return Err("Bundled Netcatty skill is missing its ownership marker.".into());
    }
    Ok(content)
}

#[derive(Debug, Clone)]
pub struct SkillStatus {
    pub installed: bool,
    pub managed: bool,
    pub conflict: bool,
    pub skill_path: PathBuf,
    pub reason: Option<String>,
}

pub fn status(client: &str, homes: &ClientHomes, source: Option<&Path>) -> SkillStatus {
    let skill_path = user_skill_path(client, homes);
    let mut st = SkillStatus { installed: false, managed: false, conflict: false, skill_path: skill_path.clone(), reason: None };
    let Ok(expected) = read_bundled(source) else {
        st.reason = Some("Bundled Netcatty skill is missing its ownership marker.".into());
        return st;
    };
    let dir = skill_path.parent().unwrap();
    if let Ok(m) = std::fs::symlink_metadata(dir) {
        if m.file_type().is_symlink() || !m.is_dir() {
            st.conflict = true;
            st.reason = Some("The Netcatty skill directory is not a regular directory.".into());
            return st;
        }
    }
    match std::fs::symlink_metadata(&skill_path) {
        Err(_) => st,
        Ok(m) if m.file_type().is_symlink() || !m.is_file() => {
            st.conflict = true;
            st.reason = Some("The Netcatty SKILL.md path is not a regular file.".into());
            st
        }
        Ok(_) => {
            let current = std::fs::read_to_string(&skill_path).unwrap_or_default();
            st.managed = current.contains(MANAGED_MARKER);
            st.installed = current == expected;
            st.conflict = !st.managed;
            if !st.managed {
                st.reason = Some("An unmanaged skill already exists at this path.".into());
            }
            st
        }
    }
}

pub fn install(client: &str, homes: &ClientHomes, source: Option<&Path>) -> Result<SkillStatus, String> {
    let st = status(client, homes, source);
    if st.installed {
        return Ok(st);
    }
    if st.conflict {
        return Err(format!("{} Refusing to overwrite {}.", st.reason.unwrap_or_default(), st.skill_path.display()));
    }
    let content = read_bundled(source)?;
    let dir = st.skill_path.parent().unwrap();
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::write(&st.skill_path, content).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(&st.skill_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(status(client, homes, source))
}

/// `buildUniversalSetupPrompt`.
pub fn build_universal_setup_prompt(launcher: &str, discovery_env: &[(String, String)], skill: &str) -> Result<String, String> {
    if launcher.trim().is_empty() {
        return Err("Netcatty External MCP launcher path is unavailable.".into());
    }
    if discovery_env.is_empty() {
        return Err("Netcatty External MCP discovery path is unavailable.".into());
    }
    if skill.trim().is_empty() {
        return Err("Netcatty MCP skill content is unavailable.".into());
    }
    let env: serde_json::Map<String, serde_json::Value> = discovery_env.iter().map(|(k, v)| (k.clone(), serde_json::json!(v))).collect();
    let snippet = serde_json::to_string_pretty(&serde_json::json!({ "mcpServers": { super::setup::EXTERNAL_MCP_NAME: { "command": launcher, "args": [], "env": env } } })).unwrap_or_default();
    let name = super::setup::EXTERNAL_MCP_NAME;
    Ok(format!(
        "Install the Netcatty integration in the AI coding client you are currently running in.\n\nComplete the installation directly when the client supports it. Inspect the local client version, CLI help, and existing configuration to determine its native MCP and Agent Skills conventions. Do not invent configuration paths or formats.\n\nRequirements:\n\n1. Add a user-level stdio MCP server named `{name}` using the exact values below. Merge it into the existing configuration and preserve every unrelated server and setting.\n2. If an entry named `{name}` already exists and is clearly an older Netcatty entry, update it. If it points to an unrelated command, stop and report the conflict instead of overwriting it.\n3. If the client supports Agent Skills, install the supplied skill as `netcatty-mcp/SKILL.md` in the client's native user-level skills directory. Preserve an existing same-name skill unless it contains `managed-by: netcatty`; Netcatty-managed copies may be updated.\n4. If Agent Skills are unsupported, add the behavioral instructions from the supplied skill to the client's user-level persistent instructions. Keep existing instructions intact and use clearly marked Netcatty boundaries. If no user-level persistent instruction mechanism exists, configure MCP only and report that limitation.\n5. Do not install dependencies, use network access, or modify project files just to complete this setup.\n6. After writing the configuration, use the client's native MCP status/list command or configuration parser to validate it. If the current process can reload MCP servers, call `get_environment` on `{name}`. Otherwise explain that a new client session is required and give the exact verification command or action.\n7. Report the MCP configuration path, Skill or persistent-instruction path, validation result, and any required restart. Never claim success without checking the files you wrote.\n\nMCP configuration to adapt to the client's native format:\n\n```json\n{snippet}\n```\n\nExact Skill content:\n\n```markdown\n{}\n```\n",
        skill.trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn homes(dir: &Path) -> ClientHomes {
        ClientHomes { home: dir.to_path_buf(), claude_config_dir: None, grok_home: dir.join(".grok") }
    }

    #[test]
    fn installs_managed_skill_and_refuses_unmanaged() {
        let dir = tempfile::tempdir().unwrap();
        let h = homes(dir.path());
        assert!(!status("codex", &h, None).installed);
        let st = install("codex", &h, None).unwrap();
        assert!(st.installed);
        assert_eq!(st.skill_path, dir.path().join(".agents/skills/netcatty-mcp/SKILL.md"));
        std::fs::write(user_skill_path("claude", &h), "x").ok();
        std::fs::create_dir_all(user_skill_path("claude", &h).parent().unwrap()).unwrap();
        std::fs::write(user_skill_path("claude", &h), "mine").unwrap();
        assert!(install("claude", &h, None).unwrap_err().contains("Refusing to overwrite"));
        assert_eq!(user_skill_path("grok", &h), dir.path().join(".grok/skills/netcatty-mcp/SKILL.md"));
    }

    #[test]
    fn universal_prompt_contains_config_and_skill() {
        let env = vec![("NETCATTY_EXTERNAL_MCP_DISCOVERY_FILE".to_string(), "/d.json".to_string())];
        let p = build_universal_setup_prompt("/bin/netcatty", &env, EMBEDDED_SKILL).unwrap();
        assert!(p.contains("\"netcatty-external\"") && p.contains("/d.json") && p.contains("managed-by: netcatty"));
        assert!(build_universal_setup_prompt("", &env, "x").is_err());
    }
}

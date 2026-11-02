//! Shell discovery (mirrors `shellDiscovery.cjs`).
//!
//! Unix: `$SHELL`, then `/etc/shells` entries that exist, mapped to friendly
//! names and icon ids (`bash`, `zsh`, `fish`, `nu`, `pwsh`, ...).
//! Windows: cmd, Windows PowerShell, PowerShell 7 (`pwsh`), WSL distros
//! (`wsl -l -q`), Git Bash and Cygwin when installed.

use netcatty_core::ipc::DiscoveredShell;
use std::path::Path;

/// Shells launched as login shells (`-l`) when the caller passes no
/// arguments (same set as `terminalBridge.cjs`).
pub const LOGIN_SHELLS: &[&str] = &["bash", "zsh", "fish", "ksh"];

/// Basename of a shell path, without a Windows `.exe` suffix.
pub fn shell_basename(shell: &str) -> String {
    // Split on both separators so Windows-style paths map correctly even
    // when the string is inspected on Unix (shell ids in saved settings).
    let trimmed = shell.trim().trim_end_matches(['/', '\\']);
    let base = trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed);
    let lower = base.to_ascii_lowercase();
    match lower.strip_suffix(".exe") {
        Some(stripped) => stripped.to_string(),
        None => lower,
    }
}

/// Whether the shell should be started with `-l` when no arguments are
/// given (Unix only; Windows shells never get it).
pub fn is_login_shell(shell: &str) -> bool {
    cfg!(unix) && LOGIN_SHELLS.contains(&shell_basename(shell).as_str())
}

/// Default arguments for a shell when the caller supplies none: `-l` for
/// login shells on Unix, `-NoLogo` for PowerShell on Windows.
pub fn default_shell_args(shell: &str) -> Vec<String> {
    let base = shell_basename(shell);
    if cfg!(windows) {
        if matches!(base.as_str(), "powershell" | "pwsh") {
            return vec!["-NoLogo".to_string()];
        }
        return Vec::new();
    }
    if LOGIN_SHELLS.contains(&base.as_str()) {
        vec!["-l".to_string()]
    } else {
        Vec::new()
    }
}

/// The user's default shell (`$SHELL`, `/bin/sh` fallback; `cmd.exe` /
/// PowerShell on Windows).
pub fn default_shell() -> String {
    if cfg!(windows) {
        return std::env::var("COMSPEC")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "cmd.exe".to_string());
    }
    if let Some(shell) = env_shell() {
        return shell;
    }
    let preferred = if cfg!(target_os = "macos") {
        "/bin/zsh"
    } else {
        "/bin/bash"
    };
    if Path::new(preferred).is_file() {
        return preferred.to_string();
    }
    "/bin/sh".to_string()
}

fn env_shell() -> Option<String> {
    std::env::var("SHELL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty() && Path::new(v).is_file())
}

/// Discover installed shells. Never fails: returns at least the default.
pub fn discover_shells() -> Vec<DiscoveredShell> {
    let mut shells = if cfg!(windows) {
        windows::discover()
    } else {
        unix::discover()
    };
    if shells.is_empty() {
        let command = default_shell();
        let (name, icon) = describe_shell(&shell_basename(&command));
        let args = default_shell_args(&command);
        shells.push(DiscoveredShell {
            id: shell_basename(&command),
            name,
            command,
            args: Some(args),
            icon,
            is_default: Some(true),
        });
    }
    if !shells.iter().any(|s| s.is_default == Some(true)) {
        shells[0].is_default = Some(true);
    }
    shells
}

/// Friendly name + icon id for a shell basename.
pub fn describe_shell(basename: &str) -> (String, String) {
    let base = shell_basename(basename);
    let (name, icon) = match base.as_str() {
        "bash" => ("Bash", "bash"),
        "zsh" => ("Zsh", "zsh"),
        "fish" => ("Fish", "fish"),
        "sh" | "dash" | "ash" => ("sh", "terminal"),
        "nu" => ("Nushell", "nushell"),
        "pwsh" => ("PowerShell", "powershell"),
        "powershell" => ("Windows PowerShell", "powershell"),
        "cmd" => ("CMD", "cmd"),
        "tcsh" | "csh" => ("tcsh", "terminal"),
        "ksh" => ("ksh", "terminal"),
        "" => ("Shell", "terminal"),
        other => {
            let mut chars = other.chars();
            let capitalized = match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            };
            return (capitalized, "terminal".to_string());
        }
    };
    (name.to_string(), icon.to_string())
}

/// Allocate a unique id from a basename (`bash`, `bash-2`, ...).
fn unique_id(base: &str, taken: &[DiscoveredShell]) -> String {
    let base = if base.is_empty() { "shell" } else { base };
    if !taken.iter().any(|s| s.id == base) {
        return base.to_string();
    }
    let mut n = 2;
    loop {
        let candidate = format!("{base}-{n}");
        if !taken.iter().any(|s| s.id == candidate) {
            return candidate;
        }
        n += 1;
    }
}

mod unix {
    use super::*;
    use std::collections::HashSet;
    use std::path::PathBuf;

    fn canonical(path: &str) -> PathBuf {
        std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path))
    }

    fn push(
        shells: &mut Vec<DiscoveredShell>,
        seen: &mut HashSet<PathBuf>,
        command: &str,
        is_default: bool,
    ) {
        if command.is_empty() || !Path::new(command).is_file() {
            return;
        }
        let real = canonical(command);
        if !seen.insert(real) {
            return;
        }
        let base = shell_basename(command);
        let (name, icon) = describe_shell(&base);
        shells.push(DiscoveredShell {
            id: unique_id(&base, shells),
            name,
            command: command.to_string(),
            args: Some(default_shell_args(command)),
            icon,
            is_default: if is_default { Some(true) } else { None },
        });
    }

    pub fn discover() -> Vec<DiscoveredShell> {
        let mut shells = Vec::new();
        let mut seen = HashSet::new();

        if let Some(shell) = env_shell() {
            push(&mut shells, &mut seen, &shell, true);
        }

        if let Ok(content) = std::fs::read_to_string("/etc/shells") {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                push(&mut shells, &mut seen, line, false);
            }
        }

        if shells.is_empty() {
            for candidate in ["/bin/zsh", "/bin/bash", "/bin/sh"] {
                push(&mut shells, &mut seen, candidate, false);
            }
        }
        shells
    }
}

mod windows {
    use super::*;

    #[cfg(windows)]
    fn env(key: &str) -> Option<String> {
        std::env::var(key)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    #[cfg(windows)]
    fn find_on_path(exe: &str) -> Option<String> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|dir| dir.join(exe))
            .find(|candidate| candidate.is_file())
            .map(|p| p.to_string_lossy().into_owned())
    }

    #[cfg(windows)]
    fn existing(path: String) -> Option<String> {
        Path::new(&path).is_file().then_some(path)
    }

    #[cfg(windows)]
    fn shell(id: &str, name: &str, command: String, args: &[&str], icon: &str) -> DiscoveredShell {
        DiscoveredShell {
            id: id.to_string(),
            name: name.to_string(),
            command,
            args: Some(args.iter().map(|a| a.to_string()).collect()),
            icon: icon.to_string(),
            is_default: None,
        }
    }

    #[cfg(windows)]
    pub fn wsl_distro_icon(distro: &str) -> &'static str {
        let lower = distro.to_ascii_lowercase();
        if lower.contains("ubuntu") {
            "ubuntu"
        } else if lower.contains("debian") {
            "debian"
        } else if lower.contains("kali") {
            "kali"
        } else if lower.contains("alpine") {
            "alpine"
        } else if lower.contains("suse") {
            "opensuse"
        } else if lower.contains("fedora") {
            "fedora"
        } else if lower.contains("arch") {
            "arch"
        } else if lower.contains("oracle") {
            "oracle"
        } else {
            "linux"
        }
    }

    /// Decode `wsl.exe -l -q` output, which is UTF-16LE on most builds.
    #[cfg(windows)]
    fn decode_wsl_output(bytes: &[u8]) -> String {
        if bytes.len() >= 2 && bytes.contains(&0) {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(bytes).into_owned()
        }
    }

    #[cfg(windows)]
    fn wsl_distros(system_root: &str) -> Vec<DiscoveredShell> {
        let wsl = format!("{system_root}\\System32\\wsl.exe");
        if !Path::new(&wsl).is_file() {
            return Vec::new();
        }
        let output = match std::process::Command::new(&wsl).args(["-l", "-q"]).output() {
            Ok(out) if out.status.success() => out,
            _ => return Vec::new(),
        };
        decode_wsl_output(&output.stdout)
            .lines()
            .map(|l| l.replace('\0', "").trim().to_string())
            .filter(|l| !l.is_empty())
            .map(|distro| {
                let slug: String = distro
                    .to_ascii_lowercase()
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || c == '-' {
                            c
                        } else {
                            '-'
                        }
                    })
                    .collect();
                DiscoveredShell {
                    id: format!("wsl-{slug}"),
                    name: format!("{distro} (WSL)"),
                    command: wsl.clone(),
                    args: Some(vec!["-d".to_string(), distro.clone()]),
                    icon: wsl_distro_icon(&distro).to_string(),
                    is_default: None,
                }
            })
            .collect()
    }

    #[cfg(windows)]
    pub fn discover() -> Vec<DiscoveredShell> {
        let system_root = env("SystemRoot").unwrap_or_else(|| "C:\\Windows".to_string());
        let program_files = env("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".to_string());
        let program_files_x86 =
            env("ProgramFiles(x86)").unwrap_or_else(|| "C:\\Program Files (x86)".to_string());
        let mut shells = Vec::new();

        let cmd = env("COMSPEC")
            .and_then(existing)
            .unwrap_or_else(|| "cmd.exe".to_string());
        shells.push(shell("cmd", "CMD", cmd, &[], "cmd"));

        if let Some(ps) = find_on_path("powershell.exe").or_else(|| {
            existing(format!(
                "{system_root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            ))
        }) {
            shells.push(shell(
                "powershell",
                "Windows PowerShell",
                ps,
                &["-NoLogo"],
                "powershell",
            ));
        }

        if let Some(pwsh) = find_on_path("pwsh.exe")
            .or_else(|| existing(format!("{program_files}\\PowerShell\\7\\pwsh.exe")))
        {
            shells.push(shell("pwsh", "PowerShell 7", pwsh, &["-NoLogo"], "pwsh"));
        }

        shells.extend(wsl_distros(&system_root));

        if let Some(bash) = existing(format!("{program_files}\\Git\\bin\\bash.exe"))
            .or_else(|| existing(format!("{program_files_x86}\\Git\\bin\\bash.exe")))
        {
            shells.push(shell(
                "git-bash",
                "Git Bash",
                bash,
                &["--login", "-i"],
                "git-bash",
            ));
        }

        if let Some(bash) = existing("C:\\cygwin64\\bin\\bash.exe".to_string()) {
            shells.push(shell(
                "cygwin",
                "Cygwin",
                bash,
                &["--login", "-i"],
                "cygwin",
            ));
        }

        for id in ["pwsh", "powershell", "cmd"] {
            if let Some(entry) = shells.iter_mut().find(|s| s.id == id) {
                entry.is_default = Some(true);
                break;
            }
        }
        shells
    }

    #[cfg(not(windows))]
    pub fn discover() -> Vec<DiscoveredShell> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_shell_mapping() {
        assert_eq!(describe_shell("bash"), ("Bash".into(), "bash".into()));
        assert_eq!(describe_shell("zsh"), ("Zsh".into(), "zsh".into()));
        assert_eq!(describe_shell("fish"), ("Fish".into(), "fish".into()));
        assert_eq!(describe_shell("sh"), ("sh".into(), "terminal".into()));
        assert_eq!(describe_shell("dash"), ("sh".into(), "terminal".into()));
        assert_eq!(describe_shell("ash"), ("sh".into(), "terminal".into()));
        assert_eq!(describe_shell("nu"), ("Nushell".into(), "nushell".into()));
        assert_eq!(
            describe_shell("pwsh"),
            ("PowerShell".into(), "powershell".into())
        );
        assert_eq!(describe_shell("tcsh"), ("tcsh".into(), "terminal".into()));
        assert_eq!(describe_shell("csh"), ("tcsh".into(), "terminal".into()));
        assert_eq!(describe_shell("ksh"), ("ksh".into(), "terminal".into()));
        assert_eq!(
            describe_shell("elvish"),
            ("Elvish".into(), "terminal".into())
        );
        assert_eq!(
            describe_shell("/usr/local/bin/xonsh"),
            ("Xonsh".into(), "terminal".into())
        );
        assert_eq!(
            describe_shell("pwsh.exe"),
            ("PowerShell".into(), "powershell".into())
        );
    }

    #[test]
    fn basename_and_login_args() {
        assert_eq!(shell_basename("/bin/zsh"), "zsh");
        assert_eq!(shell_basename("C:\\Windows\\System32\\cmd.exe"), "cmd");
        assert_eq!(shell_basename("Bash.EXE"), "bash");
        if cfg!(unix) {
            assert_eq!(default_shell_args("/bin/bash"), vec!["-l".to_string()]);
            assert_eq!(
                default_shell_args("/usr/local/bin/fish"),
                vec!["-l".to_string()]
            );
            assert!(default_shell_args("/bin/sh").is_empty());
            assert!(default_shell_args("/usr/bin/nu").is_empty());
            assert!(is_login_shell("/bin/zsh"));
            assert!(!is_login_shell("/bin/sh"));
        }
    }

    #[test]
    fn unique_ids() {
        let mut shells = Vec::new();
        for _ in 0..3 {
            let id = unique_id("bash", &shells);
            shells.push(DiscoveredShell {
                id,
                name: "Bash".into(),
                command: "/bin/bash".into(),
                args: None,
                icon: "bash".into(),
                is_default: None,
            });
        }
        let ids: Vec<&str> = shells.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["bash", "bash-2", "bash-3"]);
    }

    #[test]
    fn default_shell_exists() {
        let shell = default_shell();
        assert!(!shell.is_empty());
        if cfg!(unix) {
            assert!(Path::new(&shell).is_file(), "{shell}");
        }
    }

    #[test]
    fn discovery_has_entries_and_one_default() {
        let shells = discover_shells();
        assert!(!shells.is_empty());
        assert_eq!(
            shells.iter().filter(|s| s.is_default == Some(true)).count(),
            1
        );
        let mut ids: Vec<&str> = shells.iter().map(|s| s.id.as_str()).collect();
        let before = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), before, "ids must be unique");
        for shell in &shells {
            assert!(!shell.name.is_empty());
            assert!(!shell.icon.is_empty());
            assert!(!shell.command.is_empty());
        }
        if cfg!(unix) {
            if let Ok(env_shell) = std::env::var("SHELL") {
                if Path::new(&env_shell).is_file() {
                    assert_eq!(shells[0].command, env_shell);
                    assert_eq!(shells[0].is_default, Some(true));
                }
            }
        }
    }
}

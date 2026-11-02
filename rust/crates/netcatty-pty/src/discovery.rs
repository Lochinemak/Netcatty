//! Shell discovery (mirrors `shellDiscovery.cjs`).
//!
//! Unix: `$SHELL`, then `/etc/shells` entries that exist, mapped to friendly
//! names and icon ids (`bash`, `zsh`, `fish`, `nu`, `pwsh`, ...).
//! Windows: cmd, Windows PowerShell, PowerShell 7 (`pwsh`), WSL distros
//! (`wsl -l -q`), Git Bash and Cygwin when installed.

use netcatty_core::ipc::DiscoveredShell;

/// The user's default shell (`$SHELL`, `/bin/sh` fallback; `cmd.exe` /
/// PowerShell on Windows).
pub fn default_shell() -> String {
    todo!("default shell (pty agent task)")
}

/// Discover installed shells. Never fails: returns at least the default.
pub fn discover_shells() -> Vec<DiscoveredShell> {
    todo!("shell discovery (pty agent task)")
}

/// Friendly name + icon id for a shell basename.
pub fn describe_shell(basename: &str) -> (String, String) {
    let _ = basename;
    todo!()
}

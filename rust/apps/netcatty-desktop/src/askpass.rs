//! `SSH_ASKPASS` helper mode of the Netcatty executable.
//!
//! EternalTerminal's internal `ssh` asks for saved passwords / passphrases
//! through `SSH_ASKPASS`. Electron runs a Node script for that; the Tauri
//! build runs its own executable with [`ASKPASS_MARKER_ENV`] and
//! [`ASKPASS_MAP_ENV`] set (see `netcatty_mosh::et`). In that mode it prints
//! the matching secret for the prompt in `argv[1..]` and exits.

use netcatty_mosh::askpass::{answer, ASKPASS_MAP_ENV, ASKPASS_MARKER_ENV};
use std::io::Write;

/// `Some(exit_code)` when this process was started as the askpass helper.
pub fn run_if_requested() -> Option<i32> {
    if std::env::var(ASKPASS_MARKER_ENV).ok().as_deref() != Some("1") {
        return None;
    }
    let map = std::env::var(ASKPASS_MAP_ENV).ok()?;
    let prompt: Vec<String> = std::env::args().skip(1).collect();
    if let Some(secret) = answer(&map, &prompt.join(" ")) {
        let mut stdout = std::io::stdout();
        let _ = stdout.write_all(secret.as_bytes());
        let _ = stdout.flush();
    }
    Some(0)
}

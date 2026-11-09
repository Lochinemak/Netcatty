//! `netcatty-integration` — OS shell integration ported from the Electron
//! main process:
//!
//! * [`putty`], [`securecrt`] — PuTTY / SecureCRT compatible command lines
//!   (bastion / PAM launchers) turned into `ssh://` / `telnet://` URLs;
//! * [`deeplink`] — `ssh://`, `telnet://`, JumpServer `jms://` deep links,
//!   their enable switches and persisted preferences;
//! * [`open_terminal`] — `--open-terminal-path` / `--open-terminal-shell`;
//! * [`launch`] — cold-start intents and second-instance routing;
//! * [`explorer`] — the Windows Explorer "Open in Netcatty" verbs;
//! * [`app_icon`], [`dock`] — app icon variants and the macOS Dock menu
//!   model; [`macos`] holds the AppKit / Launch Services calls.
//!
//! Everything except [`macos`] and [`explorer::WindowsRegistry`] is pure and
//! platform independent, so it is unit tested on every OS.

pub mod app_icon;
pub mod deeplink;
pub mod dock;
pub mod explorer;
pub mod launch;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod open_terminal;
pub mod putty;
pub mod securecrt;

//! System manager + server monitor logic shared by the Tauri commands.
//!
//! This crate performs no I/O of its own. Every operation receives a
//! [`exec::SessionExec`] that runs one shell command on the session's target
//! (an exec channel on the live SSH connection, or `sh -c` / PowerShell for
//! local terminals) and returns its output. Command builders, output parsers
//! and the small amount of per-session state (tmux environment cache, stats
//! deltas) live here so they can be unit-tested with [`exec::FakeExec`] — the
//! Rust counterparts of the Electron `systemManager/*.test.cjs` cases.
//!
//! Results are `serde_json::Value`s shaped exactly like the Electron bridge
//! replies (same keys, same user-visible error strings), because the renderer
//! parses them unchanged.

pub mod exec;

pub mod container_runtime;
pub mod cwd;
pub mod docker;
pub mod gpu;
pub mod history;
pub mod kubectl;
pub mod ports;
pub mod services;
pub mod stats;
pub mod system;
pub mod tmux;

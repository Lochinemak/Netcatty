//! Headless IPC tests (`tauri::test` mock runtime, no window).
//!
//! One test binary: every file under `tests/` is otherwise its own binary
//! that links the whole application again (~200 MB and a full link each).

use std::sync::Mutex;

/// Serialises `NETCATTY_PORTABLE_DATA_DIR` + app construction across all
/// modules: the variable is process-wide and read while the app is built.
pub static BUILD_LOCK: Mutex<()> = Mutex::new(());

mod support;

mod agents_ipc;
mod ipc_ai;
mod ipc_hostbrowser;
mod ipc_integration;
mod ipc_plugins;
mod ipc_scripts;
mod ipc_security;
mod ipc_smoke;
mod ipc_transfers;
mod ipc_windows;
mod ipc_zmodem_terminal;
mod perf_terminal;

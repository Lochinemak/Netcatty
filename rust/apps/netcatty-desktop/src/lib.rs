//! Netcatty desktop — Tauri 2 application shell.
//!
//! Architecture (see `rust/docs/ipc-contract.md`):
//!
//! * [`state::AppState`] is the single managed state: session registry,
//!   SFTP registry, tunnel registry, prompt broker, store and cipher.
//! * `commands::*` are thin `#[tauri::command]` functions that validate the
//!   renderer payload, call into the capability crates and map errors to
//!   [`netcatty_core::CoreError`] (serialized as `{ code, message }`).
//! * `events` emits renderer-facing events using the channel names in
//!   [`netcatty_core::ipc::events`].

pub mod commands;
pub mod events;
pub mod prompts;
pub mod sessions;
pub mod state;

use tauri::Manager;

/// Build and run the Tauri application.
pub fn run() {
    init_tracing();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let state = state::AppState::new(app.handle().clone());
            app.manage(state);
            tracing::info!("netcatty-desktop started");
            Ok(())
        })
        .invoke_handler(commands::handler())
        .run(tauri::generate_context!())
        .expect("error while running Netcatty");
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("NETCATTY_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,russh=warn,tauri=warn"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_target(false).try_init();
}

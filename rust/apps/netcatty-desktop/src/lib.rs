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
pub mod connect;
pub mod decoder;
pub mod events;
pub mod prompts;
pub mod sessions;
pub mod state;

use netcatty_store::CredentialCipher;
use tauri::Manager;

/// Knobs for [`configure_with`]. `Default` is what the real app uses.
#[derive(Default)]
pub struct SetupOptions {
    /// Credential cipher to manage instead of loading the master key from
    /// the OS keychain. Tests inject a fixed key here; the app leaves it
    /// `None`.
    pub cipher: Option<CredentialCipher>,
}

/// Register plugins, managed state and the command handler on `builder`.
///
/// Generic over the runtime so the same wiring runs under the real `Wry`
/// runtime (see [`run`]) and under `tauri::test::MockRuntime` in the
/// headless IPC smoke tests (`tests/ipc_smoke.rs`).
pub fn configure<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    configure_with(builder, SetupOptions::default())
}

/// [`configure`] with explicit [`SetupOptions`].
pub fn configure_with<R: tauri::Runtime>(
    builder: tauri::Builder<R>,
    options: SetupOptions,
) -> tauri::Builder<R> {
    builder
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(move |app| {
            // `AppState::new` also subscribes to the tunnel registry and
            // forwards its events to the renderer; directory creation
            // failures are logged, never fatal.
            let handle = app.handle().clone();
            let state = match options.cipher {
                Some(cipher) => state::AppState::with_cipher(handle, cipher),
                None => state::AppState::new(handle),
            };
            app.manage(state);
            app.manage(commands::window::WindowState::default());
            // Tray (+ hidden auto-launch), global hotkey, autostart, notifications.
            commands::tray::setup(app);
            commands::hotkey::setup(app);
            commands::autostart::setup(app);
            commands::notification::setup(app);
            tracing::info!("netcatty-desktop started");
            Ok(())
        })
        .on_window_event(commands::window::on_window_event)
        .invoke_handler(commands::handler())
}

/// Build and run the Tauri application.
pub fn run() {
    init_tracing();

    configure(tauri::Builder::default())
        .build(tauri::generate_context!())
        .expect("error while building Netcatty")
        .run(commands::tray::on_run_event);
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("NETCATTY_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,russh=warn,tauri=warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

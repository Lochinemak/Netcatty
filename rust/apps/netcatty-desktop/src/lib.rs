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

pub mod askpass;
pub mod mcp_helper;
pub mod commands;
pub mod connect;
pub mod decoder;
pub mod events;
pub mod prompts;
pub mod sessions;
pub mod state;
pub mod stream;

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
/// headless IPC smoke tests (`tests/ipc/ipc_smoke.rs`).
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
        .plugin(tauri_plugin_process::init())
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
            commands::scripts::setup(app);
            app.manage(commands::window::WindowState::default());
            commands::windows::setup(app);
            let crash_log = commands::diagnostics::crash_log_for(
                &netcatty_store::AppPaths::resolve(),
                &app.package_info().version.to_string(),
            );
            crash_log.init();
            app.manage(crash_log);
            app.manage(commands::filewatch::FileWatchState::default());
            app.manage(commands::sessionlog::SessionLogState::default());
            app.manage(commands::ai::AiState::new(&netcatty_store::AppPaths::resolve()));
            app.manage(commands::hostbrowser::HostBrowserState::default());
            app.manage(commands::agents::AgentsState::new(app.handle().clone()));
            app.manage(commands::tempdir::TempDirState::load(
                &netcatty_store::AppPaths::resolve(),
            ));
            app.manage(commands::mcp::McpState::new(app.handle()));
            commands::transfers2::setup(app);
            app.manage(commands::zmodem::ZmodemState::default());
            app.manage(commands::terminal::TerminalState::default());
            commands::agents::wire_mcp(app.handle());
            // Tray (+ hidden auto-launch), global hotkey, autostart, notifications.
            commands::tray::setup(app);
            commands::hotkey::setup(app);
            commands::autostart::setup(app);
            commands::notification::setup(app);
            commands::update::setup(app);
            // App lock (locks on startup when enabled), FIDO2, SSH debug log.
            commands::security::setup(app);
            // Deep links, launch intents, Explorer verbs, Dock menu.
            commands::integration::setup(app);
            commands::plugins::setup(app);
            tracing::info!("netcatty-desktop started");
            Ok(())
        })
        .register_uri_scheme_protocol(
            commands::hostbrowser::ASSET_SCHEME,
            commands::hostbrowser::asset_protocol,
        )
        .register_uri_scheme_protocol(commands::plugins::SCHEME, commands::plugins::protocol)
        .on_window_event(commands::window::on_window_event)
        .invoke_handler(commands::handler())
}

/// Build and run the Tauri application.
pub fn run() {
    init_tracing();
    // One process-level rustls provider before anything can open TLS.
    netcatty_rdesktop::rdp::ensure_crypto_provider();

    let context = tauri::generate_context!();
    commands::diagnostics::install_panic_hook(commands::diagnostics::crash_log_for(
        &netcatty_store::AppPaths::resolve(),
        &context.package_info().version.to_string(),
    ));
    // Single instance first: a second launch forwards its argv and exits.
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(commands::integration::on_second_instance));
    configure(builder)
        .build(context)
        .expect("error while building Netcatty")
        .run(|app, event| {
            // Unsaved-editor quit guard first; it may hold the exit.
            commands::windows::on_run_event(app, &event);
            commands::tray::on_run_event(app, event);
        });
}

fn init_tracing() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, Layer};
    let filter = EnvFilter::try_from_env("NETCATTY_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,russh=warn,tauri=warn"));
    // Console output keeps its own filter; the SSH debug log layer
    // (Settings → System) has a per-layer filter of its own.
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_filter(filter),
        )
        .with(commands::security::ssh_debug::layer())
        .try_init();
}

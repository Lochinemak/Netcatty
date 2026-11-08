//! Security module (see `rust/docs/ipc-security.md`):
//!
//! * [`applock`]: App lock (`netcatty:appLock:*`), logic in `netcatty-applock`.
//! * [`fido`]: FIDO2 security keys: prompt responses, sk key generation,
//!   session / Mosh / ET agent preparation; logic in `netcatty-fido`.
//! * [`totp_scan`]: `scanTotpQrFromScreen`.
//! * [`ssh_debug`]: SSH diagnostic log (`getSshDebugLogInfo`,
//!   `openSshDebugLogDir`) and its `tracing` layer.

pub mod applock;
pub mod fido;
pub mod ssh_debug;
pub mod totp_scan;

pub use applock::{defer_window_title, is_app_locked, lock_for_background, notify_reopen};

/// Wire the module's managed state (called once from `lib.rs` setup).
pub fn setup<R: tauri::Runtime>(app: &tauri::App<R>) {
    applock::setup(app);
    fido::setup(app);
    ssh_debug::setup(app);
}

/// App exit: stop the Netcatty-owned FIDO agent and askpass server.
pub fn shutdown<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    fido::shutdown(app);
}

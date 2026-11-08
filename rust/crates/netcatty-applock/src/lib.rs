//! `netcatty-applock` — the App Lock feature (Electron:
//! `appLockSettingsStore.cjs`, `appLockRuntimeBridge.cjs`,
//! `appLockSystemAuthBridge.cjs` and the Windows Hello helper).
//!
//! * [`settings`]: the PBKDF2-SHA256 verifier (210 000 rounds, 16-byte salt,
//!   32-byte hash) and the settings normalisation rules, byte-compatible
//!   with the Electron `app-lock-settings.json`.
//! * [`store`]: atomic persistence of that file.
//! * [`runtime`]: the lock state machine (`initialized / locked / reason /
//!   version / last*At`).
//! * [`controller`]: the renderer-facing operations, idle timer, failure
//!   backoff and shared in-flight unlock attempts.
//! * [`system_auth`]: Touch ID and Windows Hello.

pub mod controller;
pub mod runtime;
pub mod settings;
pub mod store;
pub mod system_auth;

pub use controller::{
    tokio_failure_delay, wall_clock, AppLockController, AppLockEvents, ControllerOptions,
    MutationResult, OkResult, SystemUnlockStatus,
};
pub use runtime::RuntimeState;
pub use settings::AppLockSettings;
pub use store::{SettingsStore, APP_LOCK_SETTINGS_FILE};
pub use system_auth::{PlatformSystemAuth, SystemAuth, SystemAuthStatus, SystemAuthUnlock};

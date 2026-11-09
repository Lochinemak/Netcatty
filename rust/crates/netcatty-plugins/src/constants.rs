//! Host constants (port of `electron/plugins/constants.cjs`).

use std::time::Duration;

/// Environment gate for advanced (Node / utility) plugins.
pub const PLUGIN_DEV_ENV: &str = "NETCATTY_PLUGIN_DEV";
pub const PLUGIN_PROTOCOL_SCHEME: &str = "netcatty-plugin";
pub const PLUGIN_API_VERSION: &str = "0.1.0-internal.1";
pub const PLUGIN_ACTIVATION_TIMEOUT: Duration = Duration::from_millis(5_000);
pub const PLUGIN_DEACTIVATION_TIMEOUT: Duration = Duration::from_millis(2_000);
pub const PLUGIN_UTILITY_TERMINATION_GRACE: Duration = Duration::from_millis(500);
pub const PLUGIN_UTILITY_FORCE_EXIT_TIMEOUT: Duration = Duration::from_millis(1_000);
pub const PLUGIN_RPC_DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const PLUGIN_RPC_MAX_PENDING: usize = 256;
pub const PLUGIN_RPC_MAX_JSON_BYTES: usize = 1024 * 1024;
/// Broker payloads live inside the control-plane JSON envelope (six wire bytes
/// per raw byte worst case plus headers).
pub const PLUGIN_RPC_MAX_RAW_BYTES: usize = PLUGIN_RPC_MAX_JSON_BYTES / 8;
pub const PLUGIN_STREAM_MAX_FRAME_JSON_BYTES: usize = 24 * 1024 * 1024;
pub const PLUGIN_CRASH_WINDOW_MS: i64 = 5 * 60_000;
pub const PLUGIN_CRASH_QUARANTINE_THRESHOLD: i64 = 3;
pub const PLUGIN_LOG_MAX_BYTES: u64 = 1024 * 1024;
pub const PLUGIN_LOG_MAX_FILES: usize = 3;

/// `NETCATTY_PLUGIN_DEV=1` enables advanced (Node utility) plugins.
pub fn is_plugin_development_enabled() -> bool {
    std::env::var(PLUGIN_DEV_ENV).map(|v| v == "1").unwrap_or(false)
}

/// Current wall-clock time in milliseconds (the database clock).
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

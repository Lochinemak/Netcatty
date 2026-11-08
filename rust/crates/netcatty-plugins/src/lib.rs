//! Netcatty plugin host runtime: the Rust port of `electron/plugins/`.
//!
//! The host speaks the same JSON-RPC contract as the Electron host
//! (`packages/plugin-contract`), so plugins built with
//! `@netcatty/plugin-sdk` run unchanged. Layout:
//!
//! * [`contract`] — the committed JSON Schema contract and JSON budgets.
//! * [`package`] — `.ncpkg` validation / extraction, manifests, policy.
//! * [`database`] — `plugins.sqlite` (same schema as `database.cjs`).
//! * [`store`] — install / uninstall transactions and startup recovery.
//! * [`secrets`] — OS-encrypted plugin secrets.
//! * [`logs`] — opt-in local audit / diagnostic logs.

pub mod constants;
pub mod contract;
pub mod database;
pub mod error;
pub mod logs;
pub mod package;
pub mod quota;
pub mod secrets;
pub mod source;
pub mod store;

pub use error::{codes, PluginError, PluginResult};

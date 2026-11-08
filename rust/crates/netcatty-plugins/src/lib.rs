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

#![allow(clippy::type_complexity)]

pub mod browser;
pub mod capabilities;
pub mod constants;
pub mod context_keys;
pub mod contract;
pub mod contributions;
pub mod database;
pub mod error;
pub mod host;
pub mod interactions;
pub mod logs;
pub mod manager;
pub mod package;
pub mod permissions;
pub mod providers;
pub mod quota;
pub mod registry;
pub mod rpc;
pub mod runtime;
pub mod secrets;
pub mod sidecars;
pub mod source;
pub mod store;
pub mod supervisor;
pub mod ui;

pub use error::{codes, PluginError, PluginResult};

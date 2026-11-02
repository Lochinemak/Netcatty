//! `netcatty-core` — pure domain layer of the Rust rewrite.
//!
//! Mirrors the TypeScript `domain/` layer of the Electron app: data models,
//! IPC payload shapes and small pure helpers. This crate performs **no I/O**
//! and has no async runtime dependency so every other crate can depend on it.
//!
//! Serialization conventions
//! -------------------------
//! Every struct that crosses the renderer boundary derives `Serialize` /
//! `Deserialize` with `#[serde(rename_all = "camelCase")]` so the JSON stays
//! byte-compatible with the existing React renderer and the existing vault
//! files. Optional fields use `skip_serializing_if = "Option::is_none"` so the
//! output matches the Electron bridge (which omits undefined fields).

pub mod error;
pub mod format;
pub mod ids;
pub mod ipc;
pub mod models;

pub use error::{CoreError, CoreResult, ErrorCode};
pub use ids::new_id;

//! `netcatty-store` — on-disk persistence for the Rust build.
//!
//! The Electron renderer keeps the vault in `localStorage` and encrypts
//! sensitive fields through `safeStorage` (`credentialBridge.cjs`). The Rust
//! build offers the same two primitives to the renderer:
//!
//! * [`kv`]: a key/value document store (`<app-data>/netcatty/store/<key>.json`)
//!   with atomic writes, used by the renderer-side storage adapter so the
//!   vault, settings and workspace survive WebView storage eviction.
//! * [`credentials`]: field-level encryption with a random 256-bit master
//!   key kept in the OS keychain (`keyring`), AES-256-GCM, values prefixed
//!   `enc:v2:` (the Electron prefix is `enc:v1:`; v1 blobs cannot be
//!   decrypted by Rust and are passed through unchanged so the renderer can
//!   re-encrypt after the user re-enters them).
//! * [`backups`]: vault backup rotation (`vaultBackupBridge.cjs`).

pub mod backups;
pub mod crashlog;
pub mod credentials;
pub mod kv;
pub mod paths;

pub use credentials::{CredentialCipher, ENC_PREFIX_V1, ENC_PREFIX_V2};
pub use kv::KvStore;
pub use paths::AppPaths;

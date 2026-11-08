//! `netcatty-transfers` — transfer features shared by the Tauri commands in
//! `apps/netcatty-desktop/src/commands/transfers2.rs`:
//!
//! * [`admission`] — the global transfer queue (Electron `transferBridge`
//!   admission: per-endpoint concurrency limit, `queued` ordering,
//!   prioritize, pause / cancel while queued).
//! * [`compress`] — compressed folder upload helpers (Electron
//!   `compressUploadBridge.cjs`): local `tar` arguments, remote archive path,
//!   atomic remote extraction script, extraction timeout, per-target lock key.
//! * [`cleanup`] — which transfer artifacts may be deleted
//!   (`cleanupTransferArtifacts`).
//! * [`drag`] — validation of native file-drag requests
//!   (`localFileDragBridge.cjs`).

pub mod admission;
pub mod cleanup;
pub mod compress;
pub mod drag;

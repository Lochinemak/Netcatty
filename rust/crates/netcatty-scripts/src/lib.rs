//! Script automation (Electron: `electron/bridges/scriptBridge.cjs`,
//! `electron/scripts/*.cjs`).
//!
//! * [`engine`] — the QuickJS worker running the user's JavaScript with the
//!   `nct` API shim; one thread per run.
//! * [`runtime`] — the host side of the `nct` API (`createScriptRuntime`):
//!   steps, waits with timeout recovery dialogs, progress, dialogs, pause /
//!   abort handling.
//! * [`buffer`] — the per-session output buffer the waits run against.
//! * [`manager`] — run bookkeeping, per-session queues, pending dialog /
//!   snapshot requests, recordings (the IPC handlers of `scriptBridge.cjs`).
//! * [`pattern`], [`prompt_patterns`], [`dialog`], [`codegen`],
//!   [`retention`], [`source`], [`run`] — the pure helpers.

pub mod buffer;
pub mod codegen;
pub mod dialog;
pub mod engine;
pub mod pattern;
pub mod prompt_patterns;
pub mod retention;
pub mod run;
pub mod runtime;
pub mod source;

pub use buffer::{BufferRegistry, OutputBuffer, WaitError};
pub use engine::{RuntimeSnapshot, ScriptError, SessionSnapshot};
pub use pattern::WaitPattern;
pub use run::{RunStatus, ScriptRun, SerializedRun};

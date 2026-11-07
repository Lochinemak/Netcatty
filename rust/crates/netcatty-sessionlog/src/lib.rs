//! Session logs (Electron: `sessionLogsBridge.cjs`,
//! `sessionLogStreamManager.cjs`, `terminalLogSanitizer.cjs`,
//! `programmaticCommandLog.cjs`).
//!
//! * [`sanitizer`] replays terminal output (cursor moves, erases, SGR,
//!   alternate screen) into the text a log should contain, as plain text or
//!   styled HTML. It is a faithful port of Electron's renderer so txt / html
//!   logs written by either backend are identical.
//! * [`html`] wraps rendered content into the standalone light / dark HTML
//!   page Electron writes.
//! * [`naming`] holds the file-naming rules (safe path segments, local
//!   timestamps, artifact detection for "clear all").
//! * [`rewrite`] hides Netcatty's own injected commands (sudo autofill
//!   markers, programmatic setup commands) from logs.
//! * [`stream`] is the live log stream manager fed with session output.
//! * [`files`] holds the one-shot file operations (auto-save, export content,
//!   clear directory).
//!
//! Everything here is synchronous and runtime-agnostic: live streams flush
//! on a small background thread each, and callers in async contexts wrap the
//! blocking operations (`stop`, `prepare`) in `spawn_blocking`.

pub mod files;
pub mod html;
pub mod naming;
pub mod rewrite;
pub mod sanitizer;
pub mod stream;

pub use sanitizer::{
    terminal_data_to_html_content, terminal_data_to_plain_text, RenderOptions, TerminalTextRenderer,
};
pub use stream::{FileStreamOptions, LogFormat, StreamManager, StreamOptions, StreamToken};

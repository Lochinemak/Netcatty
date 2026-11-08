//! `netcatty-ptyexec` — AI command execution inside live terminal sessions.
//!
//! Port of Electron's `electron/bridges/ai/` exec layer:
//!
//! * [`job`] — marker-wrapped PTY jobs (`startPtyJob` / `execViaPty`):
//!   readiness wait, live shell probe, wrapper typing with pacing, start /
//!   end marker detection, bounded capture, inactivity / wall / startup
//!   deadlines, cancellation and the PowerShell returned-prompt rule.
//! * [`raw`] — `execViaRawPty` for network devices and serial consoles.
//! * [`helpers`] — wrapper builders (posix / fish / PowerShell / cmd),
//!   marker parsing, output normalisation.
//! * [`shell_utils`] — ANSI stripping, default prompt recognition, the
//!   per-session [`shell_utils::PromptTracker`].
//! * [`shell_kind`] — local shell classification and the one-time remote
//!   login-shell probe (`sessionShellKind.cjs`).
//! * [`safety`] — the shell-aware command blocklist.
//! * [`cancel`] — chat-scoped cancellation registry (`activePtyExecs`).
//!
//! The crate never touches a terminal itself: a job is given a
//! [`job::PtyInput`] writer and an output receiver by the application,
//! which taps the session pump.

pub mod cancel;
pub mod helpers;
pub mod job;
pub mod live_probe;
pub mod raw;
pub mod safety;
pub mod shell_kind;
pub mod shell_utils;

pub use cancel::{ActiveExecs, ExecGuard};
pub use job::{exec_via_pty, start_pty_job, JobCallbacks, JobOptions, JobResult, JobSnapshot, OutputRx, PtyInput, PtyJobHandle};
pub use raw::{exec_via_raw_pty, RawCancel};
pub use safety::{check_blocklist_common_only, check_blocklist_for_shell, SafetyCheck};
pub use shell_kind::{ensure_session_shell_kind, ExecProbe, ShellKindState};
pub use shell_utils::{format_synthetic_echo, PromptTracker};

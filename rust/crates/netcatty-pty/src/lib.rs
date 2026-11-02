//! `netcatty-pty` — local terminal sessions and shell discovery.
//!
//! Mirrors the `netcatty:local:start` path of `terminalBridge.cjs`,
//! `shellDiscovery.cjs` and `localSessionCwd.cjs`.

pub mod cwd;
pub mod discovery;
pub mod error;
pub mod session;

pub use discovery::{
    default_shell, default_shell_args, describe_shell, discover_shells, shell_basename,
};
pub use error::{PtyError, PtyResult};
pub use session::{LocalPtyOptions, PtyEvent, PtySession};

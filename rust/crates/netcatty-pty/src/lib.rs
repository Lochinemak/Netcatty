//! `netcatty-pty` — local terminal sessions and shell discovery.
//!
//! Mirrors the `netcatty:local:start` path of `terminalBridge.cjs`,
//! `shellDiscovery.cjs` and `localSessionCwd.cjs`.

pub mod discovery;
pub mod error;
pub mod session;

pub use discovery::{default_shell, discover_shells};
pub use error::{PtyError, PtyResult};
pub use session::{LocalPtyOptions, PtyEvent, PtySession};

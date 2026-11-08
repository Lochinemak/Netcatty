//! OpenCode driver (`opencode serve` HTTP + SSE).

use std::time::Duration;

/// Generous startup deadline (Windows cold starts exceed 8s, #3579).
pub const OPENCODE_SERVER_START_TIMEOUT: Duration = if cfg!(windows) { Duration::from_secs(60) } else { Duration::from_secs(30) };

//! `netcatty-mcp` — the control plane that lets AI agents operate Netcatty.
//!
//! * [`host`] — the per-chat control host: scopes, approvals, exec, jobs,
//!   SFTP, the loopback NDJSON JSON-RPC TCP server and its discovery file.
//! * [`inject`] — [`inject::build_injected_mcp_servers`], the stdio MCP launch
//!   spec SDK agents receive.
//! * [`discovery`] — discovery file paths and helper-mode environment.

pub mod discovery;
pub mod host;
pub mod inject;

pub use host::{McpHost, EXTERNAL_MCP_CHAT_SESSION_ID};
pub use inject::{build_injected_mcp_servers, InjectedMcpServer};

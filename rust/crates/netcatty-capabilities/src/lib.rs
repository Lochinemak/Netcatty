//! `netcatty-capabilities` — the AI capability layer shared by the MCP host,
//! the stdio MCP server, the tool CLI and the renderer harness.
//!
//! Port of `electron/capabilities/`:
//!
//! * [`catalog`] — the capability catalog and tool input schemas (verbatim
//!   JSON export of the Electron catalog).
//! * [`registry`] — lookups by id / RPC method / MCP tool / CLI command,
//!   RPC timeouts and scope helpers.
//! * [`policy`] + [`grants`] — observer / confirm / auto policy and the
//!   permission-grant memory table.
//! * [`surfaces`] — MCP tool definitions (JSON schemas) and the CLI adapter.
//! * [`services`] — vault / port-forward / session services over the
//!   renderer request bridge ([`services::VaultAgent`]).
//! * [`dispatch`] — service-backed capability RPC dispatch with approvals.
//! * [`transport`] — NDJSON JSON-RPC client.

pub mod catalog;
pub mod dispatch;
pub mod grants;
pub mod policy;
pub mod registry;
pub mod services;
pub mod surfaces;
pub mod transport;

pub use catalog::{all_capabilities, Capability, CapabilityPolicy};
pub use dispatch::{CapabilityDispatcher, CapabilityHost, DispatchContext};
pub use grants::PermissionGrant;
pub use services::{ExecGuard, PortForwardRuntime, SessionHooks, SessionService, VaultAgent};

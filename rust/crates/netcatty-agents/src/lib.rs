//! Managed SDK agents for Netcatty's AI side panel.
//!
//! Port of `electron/bridges/aiBridge/sdk/*`, `agentDiscoveryHandlers.cjs`,
//! `agentAuthProbes.cjs`, `agentCliHelpers.cjs`, `codexAppServer/*` and
//! `electron/bridges/ai/{shellUtils,claudeAuth,codexHelpers}.cjs`.
//!
//! Electron drives most backends through their Node SDKs; the Rust build drives
//! the users' CLIs directly over the same wire protocols the SDKs use:
//!
//! * Claude Code / CodeBuddy: `--input-format stream-json --output-format stream-json`
//!   with control requests (`initialize`, `can_use_tool`, `hook_callback`,
//!   `elicitation_create`) over stdin/stdout ([`drivers::claude`], [`drivers::codebuddy`]).
//! * Codex: `codex exec --experimental-json` (the codex-sdk transport,
//!   [`drivers::codex_exec`]) and `codex app-server` JSON-RPC
//!   ([`drivers::codex_app_server`]).
//! * Grok: ACP (`grok agent stdio`, [`drivers::grok_acp`]) and the headless
//!   `streaming-json` fallback ([`drivers::grok`]).
//! * OpenCode / MiMo: `opencode serve` / `mimo serve` HTTP + SSE
//!   ([`drivers::opencode`], [`drivers::mimo`]).
//! * Copilot: `copilot --headless --stdio` JSON-RPC ([`drivers::copilot`]).
//! * Cursor: `cursor-agent --print --output-format stream-json`
//!   ([`drivers::cursor_cli`]).
//!
//! Everything the renderer sees keeps the Electron event protocol
//! (`netcatty:ai:sdk-agent:event|done|error`, see [`emit`]).

pub mod auth;
pub mod catalog;
pub mod cli;
pub mod codex_helpers;
pub mod context;
pub mod discovery;
pub mod drivers;
pub mod emit;
pub mod env;
pub mod mcp;
pub mod process;
// WIP pub mod runtime;
pub mod session;
pub mod shell_env;

pub use mcp::{McpInjectionProvider, McpServerConfig, NoopMcpInjectionProvider};
// WIP pub use runtime::{AgentEventSink, AgentsRuntime, ApprovalProvider, NoopApprovalProvider, RuntimeConfig};

/// Env map handed to child processes (`Record<string,string>` on the JS side).
pub type EnvMap = std::collections::BTreeMap<String, String>;

/// Canonical renderer event names (Electron IPC channels).
pub mod events {
    pub const SDK_AGENT_EVENT: &str = "netcatty:ai:sdk-agent:event";
    pub const SDK_AGENT_DONE: &str = "netcatty:ai:sdk-agent:done";
    pub const SDK_AGENT_ERROR: &str = "netcatty:ai:sdk-agent:error";
    pub const AGENT_STDOUT: &str = "netcatty:ai:agent:stdout";
    pub const AGENT_STDERR: &str = "netcatty:ai:agent:stderr";
    pub const AGENT_EXIT: &str = "netcatty:ai:agent:exit";
    pub const CODEX_APP_SERVER_INTERACTION_REQUEST: &str =
        "netcatty:ai:codex-app-server:interaction-request";
    pub const CODEX_APP_SERVER_INTERACTION_CLEARED: &str =
        "netcatty:ai:codex-app-server:interaction-cleared";
}

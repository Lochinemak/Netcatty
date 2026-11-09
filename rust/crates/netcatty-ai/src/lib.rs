//! `netcatty-ai` — the AI core of the Rust build (Electron: `aiBridge.cjs`,
//! `aiBridge/providerHandlers.cjs`, `aiBridge/privacyHandlers.cjs`,
//! `ai/userSkills.cjs`, `aiSessionsBackupBridge.cjs`,
//! `shared/aiPrivacyService.cjs`, `mcp/externalMcpRedaction.cjs`).
//!
//! | module        | what it ports                                                        |
//! |---------------|----------------------------------------------------------------------|
//! | [`sse`]       | `data:` line extraction (`ai/sseDataLine.cjs`)                        |
//! | [`allowlist`] | provider / web-search host allowlist, localhost ports, SSRF guard     |
//! | [`providers`] | synced provider configs, API-key / custom-header injection            |
//! | [`http`]      | reqwest clients honouring the app HTTP proxy and per-provider TLS    |
//! | [`fetch`]     | `netcatty:ai:fetch` — bounded non-streaming HTTP proxy with redirects |
//! | [`stream`]    | `netcatty:ai:chat:stream` — SSE streaming with idle / total deadlines |
//! | [`privacy`]   | reversible redaction sessions and the per-chat privacy service        |
//! | [`skills`]    | user skills folder scan and prompt context                            |
//! | [`backup`]    | rolling AI sessions backup generations and export / import files     |
//!
//! Nothing here touches Tauri: the desktop app wires these into commands,
//! events and managed state (`apps/netcatty-desktop/src/commands/ai.rs`).
//! Credentials, API keys and request bodies are never logged.

pub mod allowlist;
pub mod backup;
pub mod fetch;
pub mod http;
pub mod privacy;
pub mod providers;
pub mod skills;
pub mod sse;
pub mod stream;
#[cfg(test)]
pub(crate) mod test_support;

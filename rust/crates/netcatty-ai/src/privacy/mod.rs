//! AI privacy: reversible, session-local redaction of secrets, hosts and
//! public IP addresses before values cross a model boundary.
//!
//! * [`redaction`] — the detector / pseudonym engine (Electron
//!   `electron/mcp/externalMcpRedaction.cjs`). Operates on parsed JSON
//!   (`serde_json::Value`), never on RPC envelopes or encoded attachments.
//! * [`service`] — per-chat sessions pinned to one validated policy
//!   (Electron `electron/shared/aiPrivacyService.cjs`), the state behind
//!   `aiPrivacyStatus` / `aiPrivacyTransform` / `aiPrivacyClearSession`.

pub mod redaction;
pub mod service;

pub use redaction::{normalize_redaction_config, RedactOptions, RedactionConfig, RedactionError, RedactionSession};
pub use service::{AiPrivacyError, AiPrivacyService, PolicyGuard};

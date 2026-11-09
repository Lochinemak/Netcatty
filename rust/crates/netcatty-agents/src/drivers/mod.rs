//! Per-backend drivers (Electron: `sdk/index.cjs DRIVER_REGISTRY`). Each driver
//! exposes `run_turn(&TurnContext) -> TurnResult` and `list_models(&ListContext)`
//! and reports everything through `ctx.emitter`.

pub mod claude;
pub mod codebuddy;
pub mod codex_app_server;
pub mod codex_exec;
pub mod copilot;
pub mod cursor_cli;
pub mod grok;
pub mod grok_acp;
pub mod jsonrpc;
pub mod mimo;
pub mod opencode;
pub mod stream_json;

use crate::emit::Emitter;
use crate::mcp::McpServerConfig;
use crate::session::StagedAttachment;
use crate::EnvMap;
use dashmap::DashMap;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// Renderer approval channel (`mcpServerBridge.requestApprovalFromRenderer`).
#[async_trait::async_trait]
pub trait ApprovalProvider: Send + Sync {
    async fn request_approval(&self, tool_name: &str, args: Value, chat_session_id: &str) -> bool;
    fn clear_pending_approvals(&self, _chat_session_id: &str) {}
}

/// No approval UI wired: every request is denied (confirm-mode safety).
#[derive(Default)]
pub struct NoopApprovalProvider;

#[async_trait::async_trait]
impl ApprovalProvider for NoopApprovalProvider {
    async fn request_approval(&self, _tool: &str, _args: Value, _chat: &str) -> bool {
        false
    }
}

/// Pending CodeBuddy elicitations waiting for `aiSdkAgentElicitationResponse`.
#[derive(Default)]
pub struct ElicitationRegistry {
    pending: DashMap<String, (String, oneshot::Sender<Value>)>,
}

impl ElicitationRegistry {
    pub fn register(&self, id: &str, chat_session_id: &str) -> oneshot::Receiver<Value> {
        let (tx, rx) = oneshot::channel();
        if let Some((_, (_, previous))) = self.pending.remove(id) {
            let _ = previous.send(serde_json::json!({ "action": "cancel" }));
        }
        self.pending.insert(id.to_string(), (chat_session_id.to_string(), tx));
        rx
    }

    pub fn resolve(&self, id: &str, response: Value) -> bool {
        match self.pending.remove(id) {
            Some((_, (_, tx))) => tx.send(response).is_ok(),
            None => false,
        }
    }

    pub fn contains(&self, id: &str) -> bool {
        self.pending.contains_key(id)
    }

    pub fn remove(&self, id: &str) {
        self.pending.remove(id);
    }

    pub fn cancel_for_chat(&self, chat_session_id: &str) {
        let ids: Vec<String> = self.pending.iter().filter(|e| e.value().0 == chat_session_id).map(|e| e.key().clone()).collect();
        for id in ids {
            self.resolve(&id, serde_json::json!({ "action": "cancel" }));
        }
    }

    pub fn cancel_all(&self) {
        let ids: Vec<String> = self.pending.iter().map(|e| e.key().clone()).collect();
        for id in ids {
            self.resolve(&id, serde_json::json!({ "action": "cancel" }));
        }
    }
}

/// CodeBuddy advanced options (`codebuddyOptions`).
#[derive(Debug, Clone, Default)]
pub struct AdvancedOptions {
    pub effort: Option<String>,
    pub max_turns: Option<u64>,
    pub max_budget_usd: Option<f64>,
    pub fallback_model: Option<String>,
    pub sandbox: Option<Value>,
    pub enable_file_checkpointing: Option<bool>,
    pub persist_session: Option<bool>,
}

/// Neutral per-turn context (built by the runtime, `commonTurnContext`).
pub struct TurnContext {
    pub request_id: String,
    pub chat_session_id: String,
    pub prompt: String,
    pub system_prompt: Option<String>,
    pub cwd: PathBuf,
    pub model: Option<String>,
    pub permission_mode: String,
    pub env: EnvMap,
    pub bin_path: Option<String>,
    pub injected_mcp_servers: Vec<McpServerConfig>,
    pub claude_settings: Option<String>,
    pub tool_integration_mode: String,
    pub skills_cli_prefix: Option<String>,
    pub skills_path_allowlist: Vec<String>,
    pub emitter: Emitter,
    pub cancel: CancellationToken,
    pub resume_session_id: Option<String>,
    pub attachments: Vec<StagedAttachment>,
    pub history_seed: Option<String>,
    pub grok_runtime: String,
    pub cursor_auth_mode: String,
    pub cursor_cli_bin_path: Option<String>,
    pub temp_dir: PathBuf,
    pub approvals: Arc<dyn ApprovalProvider>,
    pub elicitations: Arc<ElicitationRegistry>,
    pub advanced: AdvancedOptions,
}

impl TurnContext {
    pub fn aborted(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

#[derive(Debug, Clone, Default)]
pub struct TurnResult {
    pub session_id: Option<String>,
}

/// Context for model catalog probes.
pub struct ListContext {
    pub bin_path: Option<String>,
    pub env: EnvMap,
    pub cwd: PathBuf,
    pub cancel: CancellationToken,
    pub deadline: Instant,
    pub cursor_auth_mode: String,
    pub cursor_cli_bin_path: Option<String>,
}

impl ListContext {
    pub fn remaining(&self) -> std::time::Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

/// Split `<model>/<effort>` when the suffix is a known effort.
pub fn split_model_effort(model: Option<&str>, efforts: &[&str], lowercase: bool) -> (Option<String>, Option<String>) {
    let value = model.unwrap_or("").trim();
    if value.is_empty() {
        return (None, None);
    }
    if let Some(slash) = value.rfind('/') {
        if slash > 0 {
            let raw = &value[slash + 1..];
            let effort = if lowercase { raw.to_ascii_lowercase() } else { raw.to_string() };
            if efforts.contains(&effort.as_str()) {
                return (Some(value[..slash].to_string()), Some(effort));
            }
        }
    }
    (Some(value.to_string()), None)
}

/// `resultToText` used by several CLI translators.
pub fn result_to_text(result: &Value) -> String {
    match result {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Number(_) | Value::Bool(_) => result.to_string(),
        Value::Object(map) => {
            if let Some(Value::String(s)) = map.get("content") {
                return s.clone();
            }
            if let Some(Value::String(s)) = map.get("text") {
                return s.clone();
            }
            result.to_string()
        }
        Value::Array(_) => result.to_string(),
    }
}

/// Merge an optional `cwd` into an absolute path.
pub fn absolute_cwd(cwd: &std::path::Path) -> PathBuf {
    std::path::absolute(cwd).unwrap_or_else(|_| cwd.to_path_buf())
}

/// Minimal turn context for driver tests.
#[cfg(test)]
pub fn test_turn_context(emitter: Emitter, bin_path: Option<String>, env: EnvMap) -> TurnContext {
    TurnContext {
        request_id: emitter.request_id().to_string(),
        chat_session_id: "chat-1".into(),
        prompt: "hello".into(),
        system_prompt: None,
        cwd: std::env::temp_dir(),
        model: None,
        permission_mode: "confirm".into(),
        env,
        bin_path,
        injected_mcp_servers: Vec::new(),
        claude_settings: None,
        tool_integration_mode: "mcp".into(),
        skills_cli_prefix: None,
        skills_path_allowlist: Vec::new(),
        emitter,
        cancel: CancellationToken::new(),
        resume_session_id: None,
        attachments: Vec::new(),
        history_seed: None,
        grok_runtime: "acp".into(),
        cursor_auth_mode: "api-key".into(),
        cursor_cli_bin_path: None,
        temp_dir: std::env::temp_dir(),
        approvals: Arc::new(NoopApprovalProvider),
        elicitations: Arc::new(ElicitationRegistry::default()),
        advanced: AdvancedOptions::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_effort_split() {
        let efforts = ["low", "high"];
        assert_eq!(split_model_effort(Some("gpt/high"), &efforts, true), (Some("gpt".into()), Some("high".into())));
        assert_eq!(split_model_effort(Some("org/model"), &efforts, true), (Some("org/model".into()), None));
        assert_eq!(split_model_effort(Some("/high"), &efforts, true), (Some("/high".into()), None));
        assert_eq!(split_model_effort(Some("m/HIGH"), &efforts, true), (Some("m".into()), Some("high".into())));
        assert_eq!(split_model_effort(Some("m/HIGH"), &efforts, false), (Some("m/HIGH".into()), None));
        assert_eq!(split_model_effort(None, &efforts, true), (None, None));
    }

    #[tokio::test]
    async fn elicitation_registry_lifecycle() {
        let reg = ElicitationRegistry::default();
        let rx = reg.register("e1", "chat");
        assert!(reg.resolve("e1", serde_json::json!({ "action": "accept" })));
        assert_eq!(rx.await.unwrap()["action"], "accept");
        assert!(!reg.resolve("e1", Value::Null));
        let rx = reg.register("e2", "chat");
        let other = reg.register("e3", "other");
        reg.cancel_for_chat("chat");
        assert_eq!(rx.await.unwrap()["action"], "cancel");
        assert!(reg.contains("e3"));
        reg.cancel_all();
        assert_eq!(other.await.unwrap()["action"], "cancel");
    }

    #[test]
    fn result_text() {
        assert_eq!(result_to_text(&serde_json::json!({ "content": "x" })), "x");
        assert_eq!(result_to_text(&serde_json::json!(3)), "3");
        assert_eq!(result_to_text(&Value::Null), "");
        assert_eq!(result_to_text(&serde_json::json!({ "a": 1 })), "{\"a\":1}");
    }
}

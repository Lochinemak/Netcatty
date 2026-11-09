//! Session identity, resume resolution and turn-prompt building (Electron:
//! `shared/sdkSessionIdentity.cjs`, `sdk/sdkStreamHandlers.cjs`).

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const SDK_SESSION_ID_PREFIX: &str = "netcatty-sdk-session:";

/// `encodeURIComponent` character set.
const ENCODE_URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

pub fn encode_uri_component(value: &str) -> String {
    utf8_percent_encode(value, ENCODE_URI_COMPONENT).to_string()
}

/// `normalizeSdkRuntime`: `app-server` | `acp` | `streaming-json` | `sdk`.
pub fn normalize_sdk_runtime(runtime: Option<&str>) -> &'static str {
    match runtime.unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "app-server" => "app-server",
        "acp" => "acp",
        "streaming-json" | "cli" | "headless" => "streaming-json",
        _ => "sdk",
    }
}

pub fn normalize_cursor_auth_mode(auth_mode: Option<&str>) -> Option<&'static str> {
    match auth_mode {
        Some("cli-login") => Some("cli-login"),
        Some("api-key") => Some("api-key"),
        _ => None,
    }
}

pub fn normalize_cursor_cli_mode(cli_mode: Option<&str>) -> Option<&'static str> {
    match cli_mode {
        Some("ask") => Some("ask"),
        Some("agent") => Some("agent"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdkSessionIdentity {
    pub v: u32,
    pub id: String,
    pub backend: String,
    #[serde(default, rename = "binPath")]
    pub bin_path: String,
    #[serde(default)]
    pub runtime: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "authMode")]
    pub auth_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cliMode")]
    pub cli_mode: Option<String>,
}

pub fn encode_sdk_session_identity(
    session_id: &str,
    backend: &str,
    bin_path: &str,
    runtime: Option<&str>,
    auth_mode: Option<&str>,
    cli_mode: Option<&str>,
) -> String {
    if session_id.is_empty() || backend.is_empty() {
        return session_id.to_string();
    }
    let payload = SdkSessionIdentity {
        v: 1,
        id: session_id.to_string(),
        backend: backend.to_string(),
        bin_path: bin_path.to_string(),
        runtime: normalize_sdk_runtime(runtime).to_string(),
        auth_mode: normalize_cursor_auth_mode(auth_mode).map(str::to_string),
        cli_mode: normalize_cursor_cli_mode(cli_mode).map(str::to_string),
    };
    format!("{SDK_SESSION_ID_PREFIX}{}", encode_uri_component(&serde_json::to_string(&payload).unwrap_or_default()))
}

pub fn parse_sdk_session_identity(value: &str) -> Option<SdkSessionIdentity> {
    let raw = value.trim();
    let encoded = raw.strip_prefix(SDK_SESSION_ID_PREFIX)?;
    let decoded = percent_decode_str(encoded).decode_utf8().ok()?;
    let parsed: SdkSessionIdentity = serde_json::from_str(&decoded).ok()?;
    if parsed.v != 1 || parsed.id.is_empty() || parsed.backend.is_empty() {
        return None;
    }
    Some(SdkSessionIdentity {
        runtime: normalize_sdk_runtime(Some(&parsed.runtime)).to_string(),
        auth_mode: normalize_cursor_auth_mode(parsed.auth_mode.as_deref()).map(str::to_string),
        cli_mode: normalize_cursor_cli_mode(parsed.cli_mode.as_deref()).map(str::to_string),
        ..parsed
    })
}

/// `buildSdkSessionKey`: NUL-joined chat / backend / binPath / runtime / authMode / cliMode.
pub fn build_sdk_session_key(chat_session_id: &str, backend: &str, bin_path: &str, runtime: &str, auth_mode: &str, cli_mode: &str) -> String {
    let runtime = if runtime.is_empty() { "sdk" } else { runtime };
    [chat_session_id, backend, bin_path, runtime, auth_mode, cli_mode].join("\0")
}

/// In-memory `sdkSessionKey → native session id` map.
pub type SessionIdMap = HashMap<String, String>;

pub fn delete_sdk_session_keys_for_chat(map: &mut SessionIdMap, chat_session_id: &str) {
    let prefix = format!("{chat_session_id}\0");
    map.retain(|k, _| !k.starts_with(&prefix));
}

/// Cursor CLI `--resume` is sticky for ask vs agent: drop the sibling mode.
pub fn expire_sibling_cursor_cli_mode_sessions(map: &mut SessionIdMap, chat: &str, backend: &str, bin_path: &str, runtime: &str, auth_mode: &str, cli_mode: &str) -> bool {
    let Some(active) = normalize_cursor_cli_mode(Some(cli_mode)) else { return false };
    let sibling = if active == "ask" { "agent" } else { "ask" };
    map.remove(&build_sdk_session_key(chat, backend, bin_path, runtime, auth_mode, sibling)).is_some()
}

/// Grok ACP vs streaming-json sessions must not resume across each other.
pub fn expire_sibling_grok_runtime_sessions(map: &mut SessionIdMap, chat: &str, backend: &str, bin_path: &str, runtime: &str) -> bool {
    if backend != "grok" {
        return false;
    }
    let active = normalize_sdk_runtime(Some(runtime));
    if active != "acp" && active != "streaming-json" {
        return false;
    }
    let sibling = if active == "acp" { "streaming-json" } else { "acp" };
    map.remove(&build_sdk_session_key(chat, backend, bin_path, sibling, "", "")).is_some()
}

pub struct ResumeInput<'a> {
    pub existing_session_id: Option<&'a str>,
    pub backend: &'a str,
    pub bin_path: &'a str,
    pub runtime: &'a str,
    pub auth_mode: &'a str,
    pub cli_mode: &'a str,
    pub has_configured_command: bool,
}

/// `resolveSdkResumeSessionId`.
pub fn resolve_sdk_resume_session_id(map: &SessionIdMap, session_key: &str, input: &ResumeInput<'_>) -> Option<String> {
    if let Some(in_memory) = map.get(session_key) {
        return Some(in_memory.clone());
    }
    let requested_auth = normalize_cursor_auth_mode(Some(input.auth_mode));
    let requested_cli = normalize_cursor_cli_mode(Some(input.cli_mode));
    let existing = input.existing_session_id.unwrap_or("");
    if let Some(persisted) = parse_sdk_session_identity(existing) {
        let persisted_auth = normalize_cursor_auth_mode(persisted.auth_mode.as_deref()).unwrap_or("api-key");
        let effective_requested_auth = requested_auth.unwrap_or("api-key");
        if let Some(requested_cli) = requested_cli {
            match normalize_cursor_cli_mode(persisted.cli_mode.as_deref()) {
                Some(persisted_cli) if persisted_cli == requested_cli => {}
                _ => return None,
            }
        }
        return (persisted.backend == input.backend
            && persisted.bin_path == input.bin_path
            && persisted.runtime == input.runtime
            && persisted_auth == effective_requested_auth)
            .then_some(persisted.id);
    }
    if requested_auth == Some("cli-login") {
        return None;
    }
    (input.runtime == "sdk" && !existing.is_empty() && !input.has_configured_command).then(|| existing.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryMessage {
    pub role: String,
    pub content: String,
}

pub fn normalize_history_messages(history: Option<&serde_json::Value>) -> Vec<HistoryMessage> {
    let Some(serde_json::Value::Array(items)) = history else { return Vec::new() };
    items
        .iter()
        .filter_map(|msg| {
            let role = msg.get("role")?.as_str()?;
            if role != "user" && role != "assistant" {
                return None;
            }
            let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("").trim().to_string();
            (!content.is_empty()).then(|| HistoryMessage { role: role.to_string(), content })
        })
        .collect()
}

/// `formatSdkHistoryReplaySection`.
pub fn format_sdk_history_replay_section(history: Option<&serde_json::Value>) -> String {
    let messages = normalize_history_messages(history);
    if messages.is_empty() {
        return String::new();
    }
    let mut lines = vec!["[Conversation context replay: the agent SDK may be starting from a fresh local session, so use these prior turns as context and answer only the latest user request.]".to_string()];
    for msg in messages {
        let role = if msg.role == "assistant" { "ASSISTANT" } else { "USER" };
        lines.push(format!("{role}: {}", msg.content));
    }
    lines.join("\n")
}

/// `shouldReplaySdkHistory`.
pub fn should_replay_sdk_history(backend: &str, codex_runtime: &str, resume_session_id: Option<&str>, has_in_memory_session: bool) -> bool {
    if backend == "codebuddy" || backend == "grok" || codex_runtime == "app-server" {
        return resume_session_id.is_none();
    }
    !has_in_memory_session
}

/// An attachment staged on disk for the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StagedAttachment {
    pub filename: String,
    pub media_type: String,
    pub file_path: String,
    #[serde(default)]
    pub base64_data: String,
}

/// Renderer attachment (`{ base64Data, mediaType, filename?, filePath? }`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentInput {
    #[serde(default)]
    pub base64_data: Option<String>,
    #[serde(default)]
    pub media_type: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub file_path: Option<String>,
}

/// Write an attachment to `temp_dir` (`defaultWriteAttachmentToTemp`).
pub fn write_attachment_to_temp(attachment: &AttachmentInput, temp_dir: &Path) -> Option<PathBuf> {
    if let Some(path) = attachment.file_path.as_deref().filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(path));
    }
    let data = attachment.base64_data.as_deref().filter(|d| !d.is_empty())?;
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(data).ok()?;
    std::fs::create_dir_all(temp_dir).ok()?;
    let fallback = format!("ai-attachment-{}", netcatty_core::ids::now_ms());
    let name = attachment.filename.as_deref().filter(|n| !n.is_empty()).unwrap_or(&fallback);
    let safe: String = name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c => c,
        })
        .collect();
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let target = temp_dir.join(format!("{}_{counter}_{safe}", netcatty_core::ids::now_ms()));
    std::fs::write(&target, bytes).ok()?;
    Some(target)
}

pub struct TurnPromptInput<'a> {
    pub prompt: &'a str,
    pub history_messages: Option<&'a serde_json::Value>,
    pub replay_history: bool,
    pub attachments: &'a [AttachmentInput],
    pub tool_integration_mode: &'a str,
    pub temp_dir: &'a Path,
}

/// `buildSdkTurnPrompt`: history replay section + attachment hints + prompt.
/// Returns the prompt and the attachments staged on disk.
pub fn build_sdk_turn_prompt(input: &TurnPromptInput<'_>) -> (String, Vec<StagedAttachment>) {
    let mut sections = Vec::new();
    if input.replay_history {
        let history = format_sdk_history_replay_section(input.history_messages);
        if !history.is_empty() {
            sections.push(history);
        }
    }
    let mut staged = Vec::new();
    if !input.attachments.is_empty() {
        let mut hints = Vec::new();
        for attachment in input.attachments {
            let (Some(data), Some(media)) = (attachment.base64_data.as_deref(), attachment.media_type.as_deref()) else { continue };
            if data.is_empty() || media.is_empty() {
                continue;
            }
            let Some(local_path) = write_attachment_to_temp(attachment, input.temp_dir) else {
                tracing::error!("failed to stage attachment");
                continue;
            };
            let name = attachment.filename.clone().unwrap_or_else(|| "attachment".to_string());
            let path_text = local_path.to_string_lossy().into_owned();
            hints.push(format!("- \"{name}\" ({media}) is saved on the local machine at: {path_text}"));
            staged.push(StagedAttachment {
                filename: name,
                media_type: media.to_string(),
                file_path: path_text,
                base64_data: data.to_string(),
            });
        }
        if !hints.is_empty() {
            let access_hint = if input.tool_integration_mode == "skills" {
                "[If direct local filesystem tools are unavailable, use Netcatty's attachment list/read CLI commands described in the host context.]"
            } else {
                "[If local filesystem tools are unavailable, use Netcatty's list_attachments and read_attachment MCP tools to inspect these user-supplied files.]"
            };
            let mut lines = vec![
                "[Attached files: these paths are local to the machine running Netcatty, not remote hosts. Inspect them locally if needed.]".to_string(),
                access_hint.to_string(),
            ];
            lines.extend(hints);
            sections.push(lines.join("\n"));
        }
    }
    let prompt = if sections.is_empty() {
        input.prompt.to_string()
    } else {
        format!("{}\n\n{}", sections.join("\n\n"), input.prompt)
    };
    (prompt, staged)
}

/// `resolveSdkPromptPlacement`: backends with a system-prompt slot keep the
/// host context out of the user turn.
pub fn resolve_sdk_prompt_placement(backend: &str, turn_prompt: &str, contextual_prompt: &str, system_context: &str) -> (String, Option<String>) {
    if backend == "opencode" || backend == "mimo" || backend == "codebuddy" {
        (turn_prompt.to_string(), Some(system_context.to_string()))
    } else {
        (contextual_prompt.to_string(), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trip() {
        let encoded = encode_sdk_session_identity("abc", "cursor", "/bin/cursor-agent", Some("sdk"), Some("cli-login"), Some("ask"));
        assert!(encoded.starts_with(SDK_SESSION_ID_PREFIX));
        let parsed = parse_sdk_session_identity(&encoded).unwrap();
        assert_eq!(parsed.id, "abc");
        assert_eq!(parsed.backend, "cursor");
        assert_eq!(parsed.auth_mode.as_deref(), Some("cli-login"));
        assert_eq!(parsed.cli_mode.as_deref(), Some("ask"));
        assert_eq!(parsed.runtime, "sdk");
        assert_eq!(encode_sdk_session_identity("x", "", "", None, None, None), "x");
        assert!(parse_sdk_session_identity("plain-uuid").is_none());
        assert!(parse_sdk_session_identity(&format!("{SDK_SESSION_ID_PREFIX}%7B%22v%22%3A2%7D")).is_none());
        assert_eq!(normalize_sdk_runtime(Some("CLI")), "streaming-json");
        assert_eq!(normalize_sdk_runtime(Some("app-server")), "app-server");
        assert_eq!(normalize_sdk_runtime(None), "sdk");
    }

    #[test]
    fn encode_uri_component_matches_js() {
        assert_eq!(encode_uri_component("{\"a\":\"b c/d\"}"), "%7B%22a%22%3A%22b%20c%2Fd%22%7D");
        assert_eq!(encode_uri_component("a-_.!~*'()"), "a-_.!~*'()");
    }

    #[test]
    fn resume_resolution_rules() {
        let mut map = SessionIdMap::new();
        let key = build_sdk_session_key("chat", "claude", "/bin/claude", "sdk", "", "");
        let base = ResumeInput { existing_session_id: Some("legacy-id"), backend: "claude", bin_path: "/bin/claude", runtime: "sdk", auth_mode: "", cli_mode: "", has_configured_command: false };
        assert_eq!(resolve_sdk_resume_session_id(&map, &key, &base).as_deref(), Some("legacy-id"));
        let configured = ResumeInput { has_configured_command: true, ..base };
        assert_eq!(resolve_sdk_resume_session_id(&map, &key, &configured), None);
        map.insert(key.clone(), "mem".into());
        assert_eq!(resolve_sdk_resume_session_id(&map, &key, &configured).as_deref(), Some("mem"));
        map.clear();
        let encoded = encode_sdk_session_identity("native", "claude", "/bin/claude", Some("sdk"), None, None);
        let persisted = ResumeInput { existing_session_id: Some(&encoded), ..base };
        assert_eq!(resolve_sdk_resume_session_id(&map, &key, &persisted).as_deref(), Some("native"));
        let other_bin = ResumeInput { bin_path: "/other/claude", ..persisted };
        assert_eq!(resolve_sdk_resume_session_id(&map, &key, &other_bin), None);
        let cli_login = ResumeInput { existing_session_id: Some("bare"), backend: "cursor", auth_mode: "cli-login", ..base };
        assert_eq!(resolve_sdk_resume_session_id(&map, &key, &cli_login), None);
        let cursor = encode_sdk_session_identity("c1", "cursor", "/bin/cursor-agent", Some("sdk"), Some("cli-login"), Some("agent"));
        let ask = ResumeInput { existing_session_id: Some(&cursor), backend: "cursor", bin_path: "/bin/cursor-agent", auth_mode: "cli-login", cli_mode: "ask", ..base };
        assert_eq!(resolve_sdk_resume_session_id(&map, &key, &ask), None);
        let agent = ResumeInput { cli_mode: "agent", ..ask };
        assert_eq!(resolve_sdk_resume_session_id(&map, &key, &agent).as_deref(), Some("c1"));
        let app_server = ResumeInput { existing_session_id: Some("bare"), backend: "codex", runtime: "app-server", ..base };
        assert_eq!(resolve_sdk_resume_session_id(&map, &key, &app_server), None);
    }

    #[test]
    fn sibling_expiry_and_chat_cleanup() {
        let mut map = SessionIdMap::new();
        map.insert(build_sdk_session_key("c", "cursor", "/b", "sdk", "cli-login", "ask"), "a".into());
        assert!(expire_sibling_cursor_cli_mode_sessions(&mut map, "c", "cursor", "/b", "sdk", "cli-login", "agent"));
        assert!(map.is_empty());
        assert!(!expire_sibling_cursor_cli_mode_sessions(&mut map, "c", "cursor", "/b", "sdk", "cli-login", ""));
        map.insert(build_sdk_session_key("c", "grok", "/g", "acp", "", ""), "s".into());
        assert!(expire_sibling_grok_runtime_sessions(&mut map, "c", "grok", "/g", "streaming-json"));
        assert!(!expire_sibling_grok_runtime_sessions(&mut map, "c", "claude", "/g", "acp"));
        map.insert(build_sdk_session_key("c", "x", "/g", "sdk", "", ""), "1".into());
        map.insert(build_sdk_session_key("d", "x", "/g", "sdk", "", ""), "2".into());
        delete_sdk_session_keys_for_chat(&mut map, "c");
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn history_replay_and_prompt_building() {
        let history = serde_json::json!([
            { "role": "user", "content": " hi " }, { "role": "assistant", "content": "hello" },
            { "role": "system", "content": "x" }, { "role": "user", "content": "   " }
        ]);
        let section = format_sdk_history_replay_section(Some(&history));
        assert!(section.starts_with("[Conversation context replay"));
        assert!(section.ends_with("USER: hi\nASSISTANT: hello"));
        assert_eq!(format_sdk_history_replay_section(None), "");
        assert!(should_replay_sdk_history("claude", "sdk", Some("s"), false));
        assert!(!should_replay_sdk_history("claude", "sdk", None, true));
        assert!(!should_replay_sdk_history("grok", "sdk", Some("s"), false));
        assert!(should_replay_sdk_history("codex", "app-server", None, true));

        let temp = tempfile::tempdir().unwrap();
        let attachments = vec![
            AttachmentInput { base64_data: Some("aGk=".into()), media_type: Some("text/plain".into()), filename: Some("a.txt".into()), file_path: None },
            AttachmentInput { base64_data: None, media_type: Some("image/png".into()), filename: None, file_path: None },
        ];
        let (prompt, staged) = build_sdk_turn_prompt(&TurnPromptInput { prompt: "do it", history_messages: Some(&history), replay_history: true, attachments: &attachments, tool_integration_mode: "skills", temp_dir: temp.path() });
        assert_eq!(staged.len(), 1);
        assert_eq!(std::fs::read_to_string(&staged[0].file_path).unwrap(), "hi");
        assert!(prompt.contains("attachment list/read CLI"));
        assert!(prompt.contains("\"a.txt\" (text/plain) is saved on the local machine at:"));
        assert!(prompt.ends_with("\n\ndo it"));
        let (plain, none) = build_sdk_turn_prompt(&TurnPromptInput { prompt: "p", history_messages: None, replay_history: false, attachments: &[], tool_integration_mode: "mcp", temp_dir: temp.path() });
        assert_eq!(plain, "p");
        assert!(none.is_empty());
        let (p, s) = resolve_sdk_prompt_placement("opencode", "turn", "ctx", "sys");
        assert_eq!((p.as_str(), s.as_deref()), ("turn", Some("sys")));
        let (p, s) = resolve_sdk_prompt_placement("claude", "turn", "ctx", "sys");
        assert_eq!((p.as_str(), s), ("ctx", None));
    }
}

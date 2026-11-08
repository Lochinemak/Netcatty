//! MiMo Code driver (Electron: `sdk/mimoDriver.cjs`). MiMo is an OpenCode
//! fork: `mimo serve` (config in `MIMOCODE_CONFIG_CONTENT`, basic auth via
//! `MIMOCODE_SERVER_USERNAME/PASSWORD`) speaks the OpenCode 1.x HTTP API, so
//! the shared v1 session loop is reused. Native permission prompts are routed
//! through the Netcatty approval UI in confirm mode.

use super::opencode::{build_opencode_config, default_model_ids, drive_v1_session, filter_mimo_trusted_skill_paths, map_opencode_models, spawn_serve, HttpClient, NativeSkillOptions, PermissionHook, SessionOutcome};
use super::{ListContext, TurnContext, TurnResult};
use crate::catalog::ModelCatalog;
use crate::EnvMap;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub const MIMO_SERVE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MIMO_CATALOG_SETUP_TIMEOUT: Duration = Duration::from_secs(25);
const MIMO_AUTO_CHANNEL_PROVIDER_ID: &str = "mimo";
const BRAND: &str = "MiMo Code";

fn resolve_bin(bin: Option<&str>, env: &EnvMap) -> Option<String> {
    [bin.map(str::to_string), env.get("MIMOCODE_BIN").cloned(), env.get("MIMOCODE_BIN_PATH").cloned()].into_iter().flatten().find(|c| Path::new(c).is_file())
}

fn listen_re() -> regex::Regex {
    regex::Regex::new(r"server listening on\s+(https?://\S+)").unwrap()
}

fn random_password() -> String {
    use base64::Engine;
    use rand::RngExt;
    let bytes: [u8; 32] = rand::rng().random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

struct MimoServer {
    serve: super::opencode::ServeProcess,
    client: HttpClient,
}

async fn spawn_mimo_server(bin: &str, config: &Value, env: &EnvMap, cwd: Option<&Path>, timeout: Duration) -> Result<MimoServer, String> {
    use base64::Engine;
    let port = crate::process::available_port("127.0.0.1", 4096).await.map_err(|e| e.to_string())?;
    let password = random_password();
    let mut child_env = crate::env::build_sdk_agent_env(env, None, None);
    child_env.insert("MIMOCODE_CONFIG_CONTENT".into(), config.to_string());
    child_env.insert("MIMOCODE_SERVER_USERNAME".into(), "netcatty".into());
    child_env.insert("MIMOCODE_SERVER_PASSWORD".into(), password.clone());
    child_env.remove("MIMOCODE_PERMISSION");
    let args = vec!["serve".to_string(), "--hostname=127.0.0.1".into(), format!("--port={port}")];
    let serve = spawn_serve(bin, &args, &child_env, cwd, timeout, &listen_re(), false).await.map_err(|e| e.replace("Server", "mimo server"))?;
    let auth = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("netcatty:{password}")));
    let client = HttpClient::new(&serve.url, Some(auth));
    Ok(MimoServer { serve, client })
}

/// `mimo debug config` → `skills.paths` (resolved by the same CLI).
async fn read_resolved_config(bin: &str, env: &EnvMap, cwd: &Path) -> Result<Value, String> {
    let mut child_env = crate::env::build_sdk_agent_env(env, None, None);
    child_env.remove("MIMOCODE_CONFIG_CONTENT");
    child_env.remove("MIMOCODE_PERMISSION");
    let cwd_text = cwd.to_string_lossy().into_owned();
    let r = crate::cli::run_command(bin, &["debug".into(), "config".into()], &child_env, Some(&cwd_text), Some(MIMO_SERVE_TIMEOUT)).await.map_err(|e| e.to_string())?;
    if r.exit_code != Some(0) {
        return Err(format!("MiMo Code configuration command exited with code {}", r.exit_code.unwrap_or(-1)));
    }
    serde_json::from_str(&r.stdout).map_err(|_| "MiMo Code configuration is invalid".to_string())
}

fn string_list(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

async fn read_skill_paths(bin: &str, env: &EnvMap, cwd: &Path) -> (Vec<String>, Vec<String>) {
    let Ok(project) = read_resolved_config(bin, env, cwd).await else { return (Vec::new(), Vec::new()) };
    let paths = string_list(&project.pointer("/skills/paths").cloned().unwrap_or(Value::Null));
    if paths.is_empty() {
        return (paths, Vec::new());
    }
    let merged_env: EnvMap = std::env::vars().chain(env.clone()).collect();
    if filter_mimo_trusted_skill_paths(&paths, cwd, &merged_env, &[]).len() == paths.len() {
        return (paths, Vec::new());
    }
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_else(std::env::temp_dir);
    let global = read_resolved_config(bin, env, &exe_dir).await.ok().map(|g| string_list(&g.pointer("/skills/paths").cloned().unwrap_or(Value::Null))).unwrap_or_default();
    (paths, global)
}

/// Routes `permission.updated|asked` through the approval UI.
struct MimoPermissions {
    client: HttpClient,
    permission_mode: String,
    chat_session_id: String,
    approvals: Arc<dyn super::ApprovalProvider>,
    answered: parking_lot::Mutex<HashSet<String>>,
    pending: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl PermissionHook for MimoPermissions {
    async fn handle(&self, payload: &Value) -> Result<bool, String> {
        let request = &payload["properties"];
        let id = request["id"].as_str().ok_or("MiMo Code permission request could not be answered")?.to_string();
        if !self.answered.lock().insert(id.clone()) {
            return Ok(true);
        }
        self.pending.store(true, std::sync::atomic::Ordering::SeqCst);
        let approved = if self.permission_mode == "confirm" {
            self.approvals
                .request_approval(
                    "MiMo Code permission",
                    json!({ "permission": request.get("permission").or(request.get("type")), "patterns": request.get("patterns").or(request.get("pattern")), "title": request["title"], "metadata": request["metadata"] }),
                    &self.chat_session_id,
                )
                .await
        } else {
            false
        };
        self.pending.store(false, std::sync::atomic::Ordering::SeqCst);
        let legacy = payload["type"] == "permission.updated";
        let enc = crate::session::encode_uri_component;
        let (path, body) = if legacy {
            (format!("/session/{}/permissions/{}", enc(request["sessionID"].as_str().unwrap_or("")), enc(&id)), json!({ "response": if approved { "once" } else { "reject" } }))
        } else {
            (format!("/permission/{}/reply", enc(&id)), json!({ "reply": if approved { "once" } else { "reject" } }))
        };
        self.client.json(reqwest::Method::POST, &path, &[], Some(&body)).await.map_err(|(s, _)| format!("MiMo Code permission reply failed ({s})"))?;
        Ok(true)
    }
}

const NOT_FOUND: &str = "MiMo Code CLI not found or not runnable. Install MiMo Code and ensure `mimo` is on PATH, or set a custom path in Settings.";

pub async fn run_turn(ctx: &TurnContext) -> TurnResult {
    let emitter = &ctx.emitter;
    let mut session_id = ctx.resume_session_id.clone();
    let bin = resolve_bin(ctx.bin_path.as_deref(), &ctx.env).or_else(|| ctx.bin_path.clone()).unwrap_or_else(|| "mimo".into());
    let (project_paths, global_paths) = tokio::select! {
        _ = ctx.cancel.cancelled() => return TurnResult { session_id },
        p = read_skill_paths(&bin, &ctx.env, &ctx.cwd) => p,
    };
    let merged_env: EnvMap = std::env::vars().chain(ctx.env.clone()).collect();
    let trusted = filter_mimo_trusted_skill_paths(&project_paths, &ctx.cwd, &merged_env, &global_paths);
    let native = NativeSkillOptions { mimo: true, env: merged_env, cwd: Some(ctx.cwd.clone()), skill_paths: trusted.clone() };
    let mut config = build_opencode_config(ctx.model.as_deref(), &ctx.injected_mcp_servers, &ctx.tool_integration_mode, &ctx.skills_path_allowlist, &native);
    if ctx.tool_integration_mode == "skills" {
        config["permission"]["bash"] = json!(match ctx.permission_mode.as_str() {
            "auto" => "allow",
            "observer" => "deny",
            _ => "ask",
        });
    }
    if !project_paths.is_empty() {
        config["skills"] = json!({ "paths": trusted });
    }
    let server = tokio::select! {
        _ = ctx.cancel.cancelled() => return TurnResult { session_id },
        s = spawn_mimo_server(&bin, &config, &ctx.env, Some(&ctx.cwd), MIMO_SERVE_TIMEOUT) => s,
    };
    let mut server = match server {
        Ok(s) => s,
        Err(e) => {
            emitter.emit_error(if e.contains("No such file") || e.contains("os error 2") { NOT_FOUND.to_string() } else { e });
            return TurnResult { session_id };
        }
    };
    let hook = MimoPermissions {
        client: server.client.clone(),
        permission_mode: ctx.permission_mode.clone(),
        chat_session_id: ctx.chat_session_id.clone(),
        approvals: ctx.approvals.clone(),
        answered: Default::default(),
        pending: Default::default(),
    };
    let result = drive_v1_session(ctx, &server.client, &mut session_id, "Netcatty MiMo Code", Some(&hook), BRAND).await;
    if hook.pending.load(std::sync::atomic::Ordering::SeqCst) {
        ctx.approvals.clear_pending_approvals(&ctx.chat_session_id);
    }
    if ctx.aborted() {
        if let Some(id) = &session_id {
            let dir = ctx.cwd.to_string_lossy().into_owned();
            let _ = server.client.json(reqwest::Method::POST, &format!("/session/{id}/abort"), &[("directory", &dir)], None).await;
        }
    }
    server.serve.stop().await;
    match result {
        _ if ctx.aborted() => {}
        Ok(SessionOutcome { failed: true, .. }) => {}
        Ok(SessionOutcome { has_content: true, completed: false, .. }) => emitter.emit_error("MiMo Code reply ended before it was complete."),
        Ok(SessionOutcome { has_content: false, .. }) => emitter.emit_error("MiMo Code returned an empty response. Run `mimo` in a terminal to configure authentication and models."),
        Ok(_) => emitter.emit_done(),
        Err(e) => emitter.emit_error(e.replace("OpenCode", BRAND)),
    }
    TurnResult { session_id }
}

/// Drop Xiaomi's auto-routing channel provider from the catalog.
pub fn filter_auto_channel(response: &Value) -> Value {
    let mut out = response.clone();
    if let Some(providers) = response["providers"].as_array() {
        out["providers"] = Value::Array(providers.iter().filter(|p| p["id"].as_str().or(p["providerID"].as_str()) != Some(MIMO_AUTO_CHANNEL_PROVIDER_ID)).cloned().collect());
    }
    out
}

pub async fn list_models(ctx: &ListContext) -> ModelCatalog {
    let bin = resolve_bin(ctx.bin_path.as_deref(), &ctx.env).or_else(|| ctx.bin_path.clone()).unwrap_or_else(|| "mimo".into());
    let phase = || MIMO_CATALOG_SETUP_TIMEOUT.min(ctx.remaining());
    let config = json!({ "autoupdate": false });
    let server = tokio::select! {
        _ = ctx.cancel.cancelled() => return ModelCatalog::default(),
        s = spawn_mimo_server(&bin, &config, &ctx.env, Some(&ctx.cwd), phase()) => s,
    };
    let Ok(mut server) = server else { return ModelCatalog::default() };
    let response = tokio::select! {
        _ = ctx.cancel.cancelled() => None,
        r = tokio::time::timeout(phase(), server.client.json(reqwest::Method::GET, "/config/providers", &[], None)) => r.ok().and_then(|r| r.ok()),
    };
    server.serve.stop().await;
    let Some(data) = response else { return ModelCatalog::default() };
    let data = if data.get("data").is_some() { data["data"].clone() } else { data };
    let models = map_opencode_models(&filter_auto_channel(&data));
    let visible: HashSet<String> = models.iter().filter_map(|m| m["id"].as_str().map(str::to_string)).collect();
    let current = default_model_ids(&data).into_iter().find(|id| visible.contains(id)).or_else(|| models.first().and_then(|m| m["id"].as_str().map(str::to_string)));
    ModelCatalog { current_model_id: current, models }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::{Emitter, RecordingSink};

    #[test]
    fn auto_channel_filter_keeps_visible_default() {
        let data = json!({ "providers": [{ "id": "mimo", "models": { "/models": {} } }, { "id": "xiaomi", "name": "Xiaomi", "models": { "mimo-v2": { "name": "MiMo V2" } } }], "default": { "mimo": "/models", "xiaomi": "mimo-v2" } });
        let models = map_opencode_models(&filter_auto_channel(&data));
        assert_eq!(models, vec![json!({ "id": "xiaomi/mimo-v2", "name": "Xiaomi MiMo V2" })]);
        let visible: HashSet<String> = models.iter().filter_map(|m| m["id"].as_str().map(str::to_string)).collect();
        assert_eq!(default_model_ids(&data).into_iter().find(|id| visible.contains(id)).as_deref(), Some("xiaomi/mimo-v2"));
    }

    struct Approve;
    #[async_trait::async_trait]
    impl crate::drivers::ApprovalProvider for Approve {
        async fn request_approval(&self, tool: &str, _args: Value, chat: &str) -> bool {
            tool == "MiMo Code permission" && chat == "chat-1"
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn turn_with_native_permission() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("mimo");
        std::fs::write(&bin, r#"#!/usr/bin/env python3
import sys, json, queue, os, base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
if sys.argv[1:3] == ["debug", "config"]:
    print("{}"); sys.exit(0)
port = int([a for a in sys.argv if a.startswith("--port=")][0].split("=")[1])
expected = "Basic " + base64.b64encode(("netcatty:" + os.environ["MIMOCODE_SERVER_PASSWORD"]).encode()).decode()
events = queue.Queue()
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, o, code=200):
        b = json.dumps(o).encode(); self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.headers.get("Authorization") != expected: return self._json({}, 401)
        self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
        while True:
            self.wfile.write(("data: " + json.dumps(events.get()) + "\n\n").encode()); self.wfile.flush()
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = json.loads(self.rfile.read(n) or b"{}")
        if self.path.startswith("/session?"): return self._json({"id": "m1"})
        if "/prompt_async" in self.path:
            self._json({})
            events.put({"payload": {"type": "session.status", "properties": {"sessionID": "m1", "status": {"type": "busy"}}}})
            events.put({"payload": {"type": "permission.asked", "properties": {"id": "perm1", "sessionID": "m1", "permission": "bash"}}})
            return
        if self.path.startswith("/permission/perm1/reply"):
            self._json(True)
            events.put({"payload": {"type": "message.part.updated", "properties": {"part": {"id": "p", "sessionID": "m1", "type": "text", "text": "reply=" + body["reply"]}}}})
            events.put({"payload": {"type": "session.idle", "properties": {"sessionID": "m1"}}})
            return
        self._json({})
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
print("mimocode server listening on http://127.0.0.1:%d" % port, flush=True)
srv.serve_forever()
"#).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sink = Arc::new(RecordingSink::default());
        let env: EnvMap = std::env::vars().collect();
        let mut ctx = crate::drivers::test_turn_context(Emitter::new(sink.clone(), "r"), Some(bin.to_string_lossy().into_owned()), env);
        ctx.approvals = Arc::new(Approve);
        let result = tokio::time::timeout(Duration::from_secs(20), run_turn(&ctx)).await.unwrap();
        assert_eq!(result.session_id.as_deref(), Some("m1"));
        let text: String = sink.stream_events().iter().filter(|x| x["type"] == "text-delta").map(|x| x["textDelta"].as_str().unwrap().to_string()).collect();
        assert_eq!(text, "reply=once");
        assert!(sink.stream_events().iter().any(|x| x["message"] == "MiMo Code session idle"));
        assert_eq!(sink.done_count(), 1);
    }
}

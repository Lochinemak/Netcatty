//! Session-backed SFTP handlers (Electron `mcpServerBridge/sftpHandlers.cjs`):
//! each call opens SFTP on the session's own connection, is bounded by the
//! command timeout and cancellable per chat / terminal.

use super::backend::SftpOp;
use super::McpHost;
use netcatty_capabilities::services::{run_guard, ExecGuard};
use serde_json::{json, Map, Value};
use std::time::Duration;

pub const GLOBAL_TRANSFER_EVENT: &str = "netcatty:sftp:global-transfer";

fn s<'a>(p: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    p.get(k).and_then(Value::as_str).filter(|v| !v.is_empty())
}

impl McpHost {
    async fn with_session_sftp(&self, params: &Map<String, Value>, op: SftpOp, name: &str, guard: Option<&ExecGuard>) -> Result<Value, String> {
        let session_id = s(params, "sessionId").ok_or("sessionId is required")?.to_string();
        let chat = params.get("chatSessionId").and_then(Value::as_str).unwrap_or("");
        let op_guard = self.register_sftp_op(chat, &session_id);
        let token = op_guard.token.clone();
        run_guard(guard)?;
        let timeout_ms = self.command_timeout_ms();
        let fut = self.backend.sftp(&session_id, op, token.clone());
        let result = tokio::select! {
            _ = token.cancelled() => Err("Cancelled".to_string()),
            r = tokio::time::timeout(Duration::from_millis(timeout_ms), fut) => match r {
                Ok(r) => r,
                Err(_) => Err(format!("{name} timed out after {timeout_ms}ms")),
            },
        };
        drop(op_guard);
        result
    }

    /// Dispatch a `netcatty/sftp/*` method. `Err` becomes a JSON-RPC error
    /// (Electron throws in these handlers).
    pub async fn handle_sftp(&self, method: &str, params: &Map<String, Value>, guard: Option<&ExecGuard>) -> Result<Value, String> {
        match method {
            "netcatty/sftp/list" => {
                let path = s(params, "path").unwrap_or(".").to_string();
                let entries = self.with_session_sftp(params, SftpOp::List { path }, "SFTP list", guard).await?;
                Ok(json!({ "ok": true, "entries": entries }))
            }
            "netcatty/sftp/read" => {
                let path = s(params, "path").ok_or("path is required")?.to_string();
                let content = self.with_session_sftp(params, SftpOp::Read { path: path.clone() }, "SFTP read", guard).await?;
                Ok(json!({ "ok": true, "path": path, "content": content }))
            }
            "netcatty/sftp/write" => {
                let path = s(params, "path").ok_or("path is required")?.to_string();
                let content = params.get("content").and_then(Value::as_str).ok_or("content is required")?.to_string();
                self.with_session_sftp(params, SftpOp::Write { path: path.clone(), content }, "SFTP write", guard).await?;
                Ok(json!({ "ok": true, "path": path }))
            }
            "netcatty/sftp/mkdir" => {
                let path = s(params, "path").ok_or("path is required")?.to_string();
                self.with_session_sftp(params, SftpOp::Mkdir { path: path.clone() }, "SFTP mkdir", guard).await?;
                Ok(json!({ "ok": true, "path": path }))
            }
            "netcatty/sftp/delete" => {
                let path = s(params, "path").ok_or("path is required")?.to_string();
                self.with_session_sftp(params, SftpOp::Delete { path: path.clone() }, "SFTP delete", guard).await?;
                Ok(json!({ "ok": true, "path": path }))
            }
            "netcatty/sftp/rename" => {
                let (Some(old), Some(new)) = (s(params, "oldPath"), s(params, "newPath")) else {
                    return Err("oldPath and newPath are required".into());
                };
                let (old, new) = (old.to_string(), new.to_string());
                self.with_session_sftp(params, SftpOp::Rename { old_path: old.clone(), new_path: new.clone() }, "SFTP rename", guard).await?;
                Ok(json!({ "ok": true, "oldPath": old, "newPath": new }))
            }
            "netcatty/sftp/stat" => {
                let path = s(params, "path").ok_or("path is required")?.to_string();
                let stat = self.with_session_sftp(params, SftpOp::Stat { path }, "SFTP stat", guard).await?;
                Ok(json!({ "ok": true, "stat": stat }))
            }
            "netcatty/sftp/chmod" => {
                let (Some(path), Some(mode)) = (s(params, "path"), s(params, "mode")) else {
                    return Err("path and mode are required".into());
                };
                let (path, mode) = (path.to_string(), mode.to_string());
                self.with_session_sftp(params, SftpOp::Chmod { path: path.clone(), mode: mode.clone() }, "SFTP chmod", guard).await?;
                Ok(json!({ "ok": true, "path": path, "mode": mode }))
            }
            "netcatty/sftp/home" => {
                let home = self.with_session_sftp(params, SftpOp::Home, "SFTP home", guard).await?;
                match home.as_str().filter(|h| !h.is_empty()) {
                    Some(h) => Ok(json!({ "ok": true, "homeDir": h })),
                    None => Err("Could not determine home directory".into()),
                }
            }
            "netcatty/sftp/download" | "netcatty/sftp/upload" => self.handle_sftp_transfer(method, params, guard).await,
            other => Err(format!("Unknown method: {other}")),
        }
    }

    async fn handle_sftp_transfer(&self, method: &str, params: &Map<String, Value>, guard: Option<&ExecGuard>) -> Result<Value, String> {
        let (Some(remote), Some(local)) = (s(params, "remotePath"), s(params, "localPath")) else {
            return Err("remotePath and localPath are required".into());
        };
        let (remote, local) = (remote.to_string(), local.to_string());
        let download = method.ends_with("download");
        let transfer_id = super::vault_agent::uuid_v4();
        let session_id = s(params, "sessionId").unwrap_or("").to_string();
        let host_id = s(params, "hostId")
            .map(str::to_string)
            .or_else(|| self.backend.session(&session_id).map(|t| t.host_id()).filter(|h| !h.is_empty()))
            .unwrap_or_else(|| session_id.clone());
        let (source, target) = if download { (&remote, &local) } else { (&local, &remote) };
        let mut queued = json!({
            "type": "queued", "transferId": transfer_id, "origin": "agent", "background": true,
            "direction": if download { "download" } else { "upload" },
            "sourcePath": source, "targetPath": target, "sessionId": session_id, "startedAt": super::now_ms(),
        });
        queued[if download { "sourceHostId" } else { "targetHostId" }] = json!(host_id);
        self.backend.emit(GLOBAL_TRANSFER_EVENT, queued);
        let op = if download {
            SftpOp::Download { remote_path: remote, local_path: local, transfer_id: transfer_id.clone(), host_id: Some(host_id) }
        } else {
            SftpOp::Upload { local_path: local, remote_path: remote, transfer_id: transfer_id.clone(), host_id: Some(host_id) }
        };
        let name = if download { "SFTP download" } else { "SFTP upload" };
        match self.with_session_sftp(params, op, name, guard).await {
            Ok(result) => {
                if result.get("cancelled").and_then(Value::as_bool) == Some(true) || result.get("error").and_then(Value::as_str) == Some("Transfer cancelled") {
                    self.backend.emit(GLOBAL_TRANSFER_EVENT, json!({ "type": "cancelled", "transferId": transfer_id, "endedAt": super::now_ms() }));
                    return Ok(json!({ "ok": false, "cancelled": true, "transferId": transfer_id }));
                }
                if let Some(e) = result.get("error").and_then(Value::as_str).filter(|e| !e.is_empty()) {
                    self.backend.emit(GLOBAL_TRANSFER_EVENT, json!({ "type": "failed", "transferId": transfer_id, "endedAt": super::now_ms(), "error": e }));
                    return Err(e.to_string());
                }
                self.backend.emit(GLOBAL_TRANSFER_EVENT, json!({ "type": "completed", "transferId": transfer_id, "endedAt": super::now_ms() }));
                let mut out = json!({ "ok": true, "transferId": transfer_id });
                if let Some(obj) = result.as_object() {
                    for (k, v) in obj {
                        out[k] = v.clone();
                    }
                }
                out["ok"] = json!(true);
                Ok(out)
            }
            Err(e) => {
                if e == "Cancelled" {
                    self.backend.emit(GLOBAL_TRANSFER_EVENT, json!({ "type": "cancelled", "transferId": transfer_id, "endedAt": super::now_ms() }));
                    return Ok(json!({ "ok": false, "cancelled": true, "transferId": transfer_id }));
                }
                self.backend.emit(GLOBAL_TRANSFER_EVENT, json!({ "type": "failed", "transferId": transfer_id, "endedAt": super::now_ms(), "error": e }));
                Err(e)
            }
        }
    }
}

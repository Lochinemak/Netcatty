//! Session-backed SFTP handlers (Electron `mcpServerBridge/sftpHandlers.cjs`):
//! each call opens SFTP on the session's own connection, is bounded by the
//! command timeout and cancellable per chat / terminal.

use super::backend::SftpOp;
use super::find::{EntryKind, FindOptions, DEFAULT_MAX_DEPTH, DEFAULT_MAX_RESULTS};
use super::McpHost;
use netcatty_capabilities::services::{run_guard, ExecGuard};
use serde_json::{json, Map, Value};
use std::time::Duration;

pub const GLOBAL_TRANSFER_EVENT: &str = "netcatty:sftp:global-transfer";
/// Most bytes one `netcatty/sftp/read` returns when the caller sets a limit.
pub const MAX_READ_BYTES: u64 = 8 * 1024 * 1024;
/// A limit below one UTF-8 sequence could never make progress.
const MIN_READ_BYTES: u64 = 4;
/// Share of the command timeout a search may use before it returns what it
/// has, so a slow search ends as a truncated result rather than a timeout.
const FIND_TIME_SHARE: f64 = 0.75;

/// Bytes at the end of `bytes` that start a UTF-8 sequence without
/// finishing it (0–3).
fn incomplete_utf8_tail(bytes: &[u8]) -> usize {
    for back in 1..=bytes.len().min(3) {
        let byte = bytes[bytes.len() - back];
        if byte & 0b1100_0000 == 0b1000_0000 {
            continue; // continuation byte: keep looking for the lead byte
        }
        let needed = match byte {
            b if b & 0b1110_0000 == 0b1100_0000 => 2,
            b if b & 0b1111_0000 == 0b1110_0000 => 3,
            b if b & 0b1111_1000 == 0b1111_0000 => 4,
            _ => return 0,
        };
        return if needed > back { back } else { 0 };
    }
    0
}

/// The result fragment of a read that started at `offset`: the text, how
/// much of the file it covers and where to continue. `total` is the file
/// size when the server reported one; `max_bytes` the limit the read ran
/// with. A chunk that stops inside a multi-byte character gives that
/// character back, so the next read (from `nextOffset`) starts on a boundary.
pub fn read_chunk(mut bytes: Vec<u8>, offset: u64, total: Option<u64>, max_bytes: Option<u64>) -> Value {
    let read_end = offset + bytes.len() as u64;
    let more = match (total, max_bytes) {
        (Some(total), _) => read_end < total,
        (None, Some(max)) => bytes.len() as u64 >= max,
        (None, None) => false,
    };
    if more {
        let tail = incomplete_utf8_tail(&bytes);
        if tail < bytes.len() {
            bytes.truncate(bytes.len() - tail);
        }
    }
    let mut out = json!({
        "content": String::from_utf8_lossy(&bytes),
        "offset": offset,
        "bytesRead": bytes.len(),
        "truncated": more,
    });
    if let Some(total) = total {
        out["totalBytes"] = json!(total);
    }
    if more {
        out["nextOffset"] = json!(offset + bytes.len() as u64);
    }
    out
}

/// A non-negative integer parameter (the CLI sends numbers as floats).
fn u(p: &Map<String, Value>, k: &str) -> Option<u64> {
    let v = p.get(k)?;
    v.as_u64().or_else(|| v.as_f64().filter(|f| *f >= 0.0 && f.fract() == 0.0).map(|f| f as u64))
}

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
                let offset = u(params, "offset").unwrap_or(0);
                let max_bytes = u(params, "maxBytes").map(|m| m.clamp(MIN_READ_BYTES, MAX_READ_BYTES));
                let chunk = self.with_session_sftp(params, SftpOp::Read { path: path.clone(), offset, max_bytes }, "SFTP read", guard).await?;
                let mut out = json!({ "ok": true, "path": path });
                match chunk {
                    Value::Object(fields) => out.as_object_mut().unwrap().extend(fields),
                    content => out["content"] = content,
                }
                Ok(out)
            }
            "netcatty/sftp/find" => {
                let pattern = s(params, "pattern").ok_or("pattern is required")?.to_string();
                let kind = match s(params, "type") {
                    None => None,
                    Some(t) => Some(EntryKind::parse(t).ok_or("type must be file, directory, or symlink")?),
                };
                let options = FindOptions {
                    root: s(params, "path").ok_or("path is required")?.to_string(),
                    pattern,
                    kind,
                    max_depth: u(params, "maxDepth").map(|d| d.min(u32::MAX as u64) as u32).unwrap_or(DEFAULT_MAX_DEPTH),
                    max_results: u(params, "maxResults").map(|n| n as usize).unwrap_or(DEFAULT_MAX_RESULTS),
                    time_budget: Duration::from_millis((self.command_timeout_ms() as f64 * FIND_TIME_SHARE) as u64),
                };
                // Reject a bad pattern before a connection is opened for it.
                super::find::NameGlob::new(&options.pattern)?;
                let found = self.with_session_sftp(params, SftpOp::Find { options }, "SFTP find", guard).await?;
                let mut out = json!({ "ok": true });
                if let Value::Object(fields) = found {
                    out.as_object_mut().unwrap().extend(fields);
                }
                Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_whole_read_is_not_truncated() {
        let r = read_chunk(b"hello".to_vec(), 0, Some(5), None);
        assert_eq!(r, json!({ "content": "hello", "offset": 0, "bytesRead": 5, "truncated": false, "totalBytes": 5 }));
        // No size from the server and no limit: everything there was.
        let r = read_chunk(b"hello".to_vec(), 0, None, None);
        assert_eq!(r["truncated"], false);
        assert!(r.get("totalBytes").is_none() && r.get("nextOffset").is_none());
    }

    #[test]
    fn a_partial_read_says_where_to_continue() {
        let r = read_chunk(b"hel".to_vec(), 0, Some(5), Some(3));
        assert_eq!(r, json!({ "content": "hel", "offset": 0, "bytesRead": 3, "truncated": true, "totalBytes": 5, "nextOffset": 3 }));
        let r = read_chunk(b"lo".to_vec(), 3, Some(5), Some(3));
        assert_eq!((r["truncated"].clone(), r["offset"].clone()), (json!(false), json!(3)));
        // Size unknown: a full chunk may have more behind it, a short one cannot.
        assert_eq!(read_chunk(b"abc".to_vec(), 0, None, Some(3))["nextOffset"], 3);
        assert_eq!(read_chunk(b"ab".to_vec(), 0, None, Some(3))["truncated"], false);
        // Reading past the end is empty, not an error.
        let r = read_chunk(Vec::new(), 9, Some(5), Some(3));
        assert_eq!((r["content"].clone(), r["truncated"].clone()), (json!(""), json!(false)));
    }

    #[test]
    fn a_chunk_never_ends_inside_a_character() {
        let text = "ab中文"; // 2 + 3 + 3 bytes
        let bytes = text.as_bytes();
        for cut in 1..bytes.len() {
            let first = read_chunk(bytes[..cut].to_vec(), 0, Some(bytes.len() as u64), Some(cut as u64));
            let next = first["nextOffset"].as_u64().unwrap() as usize;
            assert!(text.is_char_boundary(next), "cut {cut} continues at {next}");
            assert!(!first["content"].as_str().unwrap().contains('\u{fffd}'), "cut {cut}");
            let rest = read_chunk(bytes[next..].to_vec(), next as u64, Some(bytes.len() as u64), None);
            assert_eq!(format!("{}{}", first["content"].as_str().unwrap(), rest["content"].as_str().unwrap()), text, "cut {cut}");
        }
        // The last chunk of a file keeps whatever bytes it has.
        assert_eq!(read_chunk(vec![b'a', 0xE4], 0, Some(2), None)["bytesRead"], 2);
        // A chunk that is nothing but a partial character is returned as is
        // rather than as an empty read that would never advance.
        assert_eq!(read_chunk(vec![0xE4, 0xB8], 0, Some(9), Some(2))["nextOffset"], 2);
        assert_eq!(incomplete_utf8_tail(b"abc"), 0);
        assert_eq!(incomplete_utf8_tail(&[b'a', 0xF0, 0x9F, 0x98]), 3);
        assert_eq!(incomplete_utf8_tail("😀".as_bytes()), 0);
    }
}

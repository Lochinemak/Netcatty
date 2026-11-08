//! Themes, icons, views, Providers, sync and importer methods of
//! `plugin_call` (the rest of `pluginBridge.cjs`).
//!
//! Plugin connection sessions are ordinary terminal sessions: they are
//! registered in the session registry as `SessionBackend::Stream` with a
//! transport that forwards input / resize / close to the connection
//! Provider, so `netcatty:data` / `netcatty:exit`, session logs and the
//! output taps work unchanged.

use super::PluginsState;
use crate::sessions::{SessionBackend, SessionEntry};
use crate::state::AppState;
use crate::stream::{InputMeta, SessionInput, StreamEvent, StreamExit, StreamTransport};
use base64::Engine;
use netcatty_core::ipc::SessionDataMeta;
use netcatty_core::CoreResult;
use netcatty_plugins::host::{channels, PluginHost};
use netcatty_plugins::providers::ConnectionSink;
use netcatty_plugins::{codes, PluginError, PluginResult};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const MAX_ACTIVE_REQUESTS: usize = 64;
const MAX_IMPORT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const SYNC_TRANSFER_TTL_MS: i64 = 5 * 60_000;

/// Per-app transient state of the provider workflows.
#[derive(Default)]
pub struct ProviderState {
    requests: Mutex<HashMap<String, CancellationToken>>,
    terminal_requests: Mutex<HashMap<String, CancellationToken>>,
    importer_selections: Mutex<HashMap<String, (std::path::PathBuf, String, u64, i64)>>,
    sync_transfers: Mutex<HashMap<String, SyncTransfer>>,
    challenges: Mutex<HashMap<String, (String, Value, oneshot::Sender<PluginResult<Value>>)>>,
}

enum SyncTransfer {
    Read { request_id: String, bytes: Vec<u8>, offset: usize, expires: i64 },
    Write { request_id: String, provider_id: String, key: String, expected_revision: Option<Value>, deadline_ms: Value, byte_length: usize, received: Vec<u8>, sequence: i64, expires: i64 },
}

fn providers() -> &'static ProviderState {
    static STATE: OnceLock<ProviderState> = OnceLock::new();
    STATE.get_or_init(ProviderState::default)
}

fn s<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

fn request_id(payload: &Value) -> PluginResult<String> {
    let id = s(payload, "requestId").unwrap_or("");
    if id.is_empty() || id.len() > 128 || id.contains('\0') {
        return Err(PluginError::invalid("Plugin extension request ID is invalid"));
    }
    Ok(id.to_string())
}

/// Register a cancellable request (`runExtensionRequest`).
fn begin(map: &Mutex<HashMap<String, CancellationToken>>, id: &str) -> PluginResult<CancellationToken> {
    let mut requests = map.lock();
    if requests.contains_key(id) {
        return Err(PluginError::host("Plugin extension request ID is already active"));
    }
    if requests.len() >= MAX_ACTIVE_REQUESTS {
        return Err(PluginError::exhausted("Too many active Plugin extension requests"));
    }
    let token = CancellationToken::new();
    requests.insert(id.to_string(), token.clone());
    Ok(token)
}

fn bytes_field(payload: &Value, key: &str) -> PluginResult<Vec<u8>> {
    B64.decode(s(payload, &format!("{key}Base64")).unwrap_or("")).map_err(|_| PluginError::invalid(format!("{key} must be binary bytes")))
}

pub(super) async fn dispatch<R: Runtime>(
    app: &AppHandle<R>,
    _state: &PluginsState,
    host: &Arc<PluginHost>,
    owner: &str,
    method: &str,
    payload: Value,
) -> PluginResult<Value> {
    let p = providers();
    match method {
        // -- themes / icons -------------------------------------------------
        "theme-catalog" => host.themes.catalog(),
        "theme-apply" => host.themes.apply(&payload).await,
        "brand-icon" => host.icons.resolve_brand(s(&payload, "pluginId").unwrap_or("")),
        "contribution-icon" => host.icons.resolve(s(&payload, "pluginId").unwrap_or(""), &payload["icon"]),
        // -- host-drawn views --------------------------------------------------
        "host-ui-open" => host.views.open(owner, &payload).await,
        "host-ui-close" => {
            host.views.close(s(&payload, "instanceId").unwrap_or(""), Some(owner), "renderer-requested").await;
            Ok(Value::Null)
        }
        "host-ui-resource" => host.views.resource(owner, &payload),
        "host-ui-event" => {
            host.views.event(owner, s(&payload, "instanceId").unwrap_or(""), &payload["event"]).await?;
            Ok(Value::Null)
        }
        // -- terminal providers -------------------------------------------------
        "terminal-providers" => Ok(json!(host.terminal_providers.list(&payload)?)),
        "terminal-provide" => {
            let id = request_id(&payload)?;
            let token = begin(&p.terminal_requests, &id)?;
            let mut request = payload.clone();
            request.as_object_mut().map(|o| o.remove("requestId"));
            let result = host.terminal_providers.provide(&request, token).await;
            p.terminal_requests.lock().remove(&id);
            result
        }
        "terminal-cancel" => {
            let token = p.terminal_requests.lock().remove(s(&payload, "requestId").unwrap_or(""));
            Ok(json!(token.map(|t| t.cancel()).is_some()))
        }
        "terminal-session-event" => host.terminal_providers.publish_session_event(&payload).await,
        // -- extension providers ------------------------------------------------
        "extension-providers" => Ok(json!(host.extensions.list(&payload)?)),
        "extension-invoke" => {
            let kind = s(&payload, "kind").unwrap_or("");
            let operation = s(&payload, "operation").unwrap_or("");
            if (kind == "connection" && !matches!(operation, "validateConfiguration" | "probe")) || kind == "authentication" || (kind == "importer" && operation == "parse") {
                return Err(PluginError::invalid("Stateful Provider operations require their dedicated host workflow"));
            }
            let id = request_id(&payload)?;
            let token = begin(&p.requests, &id)?;
            let result = host.extensions.invoke(&payload, None, &token).await;
            p.requests.lock().remove(&id);
            result
        }
        "extension-cancel" => {
            let token = p.requests.lock().remove(s(&payload, "requestId").unwrap_or(""));
            Ok(json!(token.map(|t| t.cancel()).is_some()))
        }
        // -- connections ---------------------------------------------------------
        "connection-start" => connection_start(app, host, payload).await,
        "connection-write" => {
            host.extensions.write(s(&payload, "sessionId").unwrap_or(""), &bytes_field(&payload, "data")?).await?;
            Ok(Value::Null)
        }
        "connection-control" => {
            let session_id = s(&payload, "sessionId").unwrap_or("").to_string();
            let operation = s(&payload, "operation").unwrap_or("");
            let result = host.extensions.control(&session_id, operation, &payload["payload"]).await;
            if operation == "close" {
                if let Some(state) = app.try_state::<AppState<R>>() {
                    let _ = state.sessions.close(&session_id).await;
                }
            }
            result
        }
        "authentication-respond" => {
            let id = s(&payload, "challengeRequestId").unwrap_or("").to_string();
            let pending = p.challenges.lock().remove(&id);
            let Some((request, challenge_id, tx)) = pending else {
                return Err(PluginError::host("Plugin authentication challenge is not owned by this window"));
            };
            if s(&payload, "requestId") != Some(request.as_str()) || payload["challengeId"] != challenge_id {
                return Err(PluginError::host("Plugin authentication challenge is not owned by this window"));
            }
            let _ = tx.send(if payload["cancelled"] == true { Err(PluginError::cancelled()) } else { Ok(payload["response"].clone()) });
            Ok(Value::Null)
        }
        // -- importers ----------------------------------------------------------
        "importer-detect" => {
            let id = request_id(&payload)?;
            let token = begin(&p.requests, &id)?;
            let result = host.extensions.detect_importer(&payload, &bytes_field(&payload, "sample")?, &token).await;
            p.requests.lock().remove(&id);
            result
        }
        "importer-select-file" => {
            use tauri_plugin_dialog::DialogExt;
            let (tx, rx) = oneshot::channel();
            app.dialog().file().set_title("Select file to import").pick_file(move |path| {
                let _ = tx.send(path);
            });
            let Some(path) = rx.await.ok().flatten().and_then(|p| p.into_path().ok()) else { return Ok(Value::Null) };
            let meta = std::fs::metadata(&path)?;
            if !meta.is_file() || meta.len() < 1 || meta.len() > MAX_IMPORT_FILE_BYTES {
                return Err(PluginError::invalid("Plugin importer file is not a supported regular file"));
            }
            let mut sample = vec![0u8; meta.len().min(128 * 1024) as usize];
            use std::io::Read;
            std::fs::File::open(&path)?.read_exact(&mut sample)?;
            let mut selections = p.importer_selections.lock();
            let now = netcatty_core::ids::now_ms();
            selections.retain(|_, (_, _, _, expires)| *expires > now);
            if selections.len() >= 8 {
                return Err(PluginError::exhausted("Too many pending Plugin importer file selections"));
            }
            let token = uuid::Uuid::new_v4().to_string();
            let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "import".into());
            selections.insert(token.clone(), (path, file_name.clone(), meta.len(), now + 5 * 60_000));
            Ok(json!({ "selectionToken": token, "fileName": file_name, "sampleBase64": B64.encode(&sample) }))
        }
        "importer-release-file" => Ok(json!(p.importer_selections.lock().remove(s(&payload, "selectionToken").unwrap_or("")).is_some())),
        "importer-parse-file" => {
            let id = request_id(&payload)?;
            let selection = p.importer_selections.lock().remove(s(&payload, "selectionToken").unwrap_or(""));
            let Some((path, file_name, size, expires)) = selection.filter(|sel| sel.3 > netcatty_core::ids::now_ms()) else {
                return Err(PluginError::host("Plugin importer file selection expired"));
            };
            let _ = expires;
            let data = std::fs::read(&path)?;
            if data.len() as u64 != size {
                return Err(PluginError::host("Plugin importer file changed after selection"));
            }
            let token = begin(&p.requests, &id)?;
            let mut request = payload.clone();
            request["fileName"] = json!(file_name);
            let emitter = app.clone();
            let provider_id = payload["providerId"].clone();
            let request_id_value = json!(id);
            let progress = move |record: Value| {
                crate::events::emit(&emitter, channels::IMPORTER_PROGRESS, json!({ "requestId": request_id_value, "providerId": provider_id, "progress": record }));
            };
            let result = host.extensions.parse_importer(&request, &data, &progress, &token).await;
            p.requests.lock().remove(&id);
            result
        }
        // -- sync providers ------------------------------------------------------
        "sync-connect" | "sync-disconnect" | "sync-get-account" | "sync-get-capabilities" | "sync-delete-object" => {
            let operation = match method {
                "sync-connect" => "connect",
                "sync-disconnect" => "disconnect",
                "sync-get-account" => "getAccount",
                "sync-get-capabilities" => "getCapabilities",
                _ => "deleteObject",
            };
            let id = request_id(&payload)?;
            let token = begin(&p.requests, &id)?;
            let result = host.extensions.sync_simple(operation, &payload, &token).await;
            p.requests.lock().remove(&id);
            result
        }
        "sync-read-object" => {
            let id = request_id(&payload)?;
            let token = begin(&p.requests, &id)?;
            let result = host.extensions.read_sync_object(&payload, &token).await;
            p.requests.lock().remove(&id);
            let (meta, bytes) = result?;
            let Some(bytes) = bytes else { return Ok(json!({ "found": false, "key": payload["key"], "data": null })) };
            let inline = netcatty_plugins::contract::def_const("SyncLimits").and_then(|l| l["inlineObjectBytes"].as_u64()).unwrap_or(96 * 1024) as usize;
            if payload["preferStream"] != true && bytes.len() <= inline {
                let mut out = meta;
                out["dataBase64"] = json!(B64.encode(&bytes));
                return Ok(out);
            }
            let transfer_id = uuid::Uuid::new_v4().to_string();
            let mut out = meta;
            out["streamed"] = json!(true);
            out["transferId"] = json!(transfer_id);
            out["byteLength"] = json!(bytes.len());
            p.sync_transfers.lock().insert(transfer_id, SyncTransfer::Read { request_id: id, bytes, offset: 0, expires: netcatty_core::ids::now_ms() + SYNC_TRANSFER_TTL_MS });
            Ok(out)
        }
        "sync-read-chunk" => {
            let transfer_id = s(&payload, "transferId").unwrap_or("").to_string();
            let mut transfers = p.sync_transfers.lock();
            let Some(SyncTransfer::Read { request_id, bytes, offset, expires }) = transfers.get_mut(&transfer_id) else {
                return Err(PluginError::host("Sync read transfer is not owned by this window"));
            };
            if s(&payload, "requestId") != Some(request_id.as_str()) {
                return Err(PluginError::host("Sync read transfer request ID mismatch"));
            }
            *expires = netcatty_core::ids::now_ms() + SYNC_TRANSFER_TTL_MS;
            let max = payload["maxBytes"].as_u64().filter(|m| *m > 0).map_or(256 * 1024, |m| m.min(256 * 1024)) as usize;
            let end = (*offset + max).min(bytes.len());
            let chunk = B64.encode(&bytes[*offset..end]);
            *offset = end;
            let done = end >= bytes.len();
            if done {
                transfers.remove(&transfer_id);
            }
            Ok(json!({ "chunkBase64": chunk, "done": done }))
        }
        "sync-write-object" => {
            let id = request_id(&payload)?;
            let data = if payload.get("dataBase64").is_some() { bytes_field(&payload, "data")? } else { bytes_field(&payload, "bytes")? };
            let token = begin(&p.requests, &id)?;
            let result = host.extensions.write_sync_object(&payload, &data, false, &token).await;
            p.requests.lock().remove(&id);
            result
        }
        "sync-write-begin" => {
            let id = request_id(&payload)?;
            let byte_length = payload["byteLength"].as_u64().filter(|b| *b >= 1).ok_or_else(|| PluginError::invalid("Sync writeObject byteLength is invalid"))? as usize;
            let mut transfers = p.sync_transfers.lock();
            if transfers.len() >= 8 {
                return Err(PluginError::exhausted("Too many active Plugin sync transfers"));
            }
            let transfer_id = uuid::Uuid::new_v4().to_string();
            transfers.insert(
                transfer_id.clone(),
                SyncTransfer::Write {
                    request_id: id,
                    provider_id: s(&payload, "providerId").unwrap_or("").into(),
                    key: s(&payload, "key").unwrap_or("").into(),
                    expected_revision: payload.get("expectedRevision").cloned(),
                    deadline_ms: payload["deadlineMs"].clone(),
                    byte_length,
                    received: Vec::new(),
                    sequence: -1,
                    expires: netcatty_core::ids::now_ms() + SYNC_TRANSFER_TTL_MS,
                },
            );
            Ok(json!({ "transferId": transfer_id, "windowBytes": 256 * 1024 }))
        }
        "sync-write-chunk" => {
            let transfer_id = s(&payload, "transferId").unwrap_or("").to_string();
            let chunk = bytes_field(&payload, "chunk")?;
            let mut transfers = p.sync_transfers.lock();
            let Some(SyncTransfer::Write { request_id, byte_length, received, sequence, expires, .. }) = transfers.get_mut(&transfer_id) else {
                return Err(PluginError::host("Sync write transfer is not owned by this window"));
            };
            let valid = s(&payload, "requestId") == Some(request_id.as_str())
                && payload["sequence"].as_i64() == Some(*sequence + 1)
                && !chunk.is_empty()
                && chunk.len() <= 256 * 1024
                && received.len() + chunk.len() <= *byte_length;
            if !valid {
                transfers.remove(&transfer_id);
                return Err(PluginError::invalid("Sync write chunk is invalid"));
            }
            received.extend_from_slice(&chunk);
            *sequence += 1;
            *expires = netcatty_core::ids::now_ms() + SYNC_TRANSFER_TTL_MS;
            Ok(json!({ "accepted": chunk.len() }))
        }
        "sync-write-commit" => {
            let transfer_id = s(&payload, "transferId").unwrap_or("").to_string();
            let transfer = p.sync_transfers.lock().remove(&transfer_id);
            let Some(SyncTransfer::Write { request_id, provider_id, key, expected_revision, deadline_ms, byte_length, received, .. }) = transfer else {
                return Err(PluginError::host("Sync write transfer is not owned by this window"));
            };
            if s(&payload, "requestId") != Some(request_id.as_str()) || received.len() != byte_length {
                return Err(PluginError::host("Sync write commit size does not match byteLength"));
            }
            let mut request = json!({ "providerId": provider_id, "key": key, "deadlineMs": deadline_ms });
            if let Some(r) = expected_revision {
                request["expectedRevision"] = r;
            }
            let token = begin(&p.requests, &request_id)?;
            let result = host.extensions.write_sync_object(&request, &received, true, &token).await;
            p.requests.lock().remove(&request_id);
            result
        }
        "sync-put-secret" => {
            let provider_id = s(&payload, "providerId").filter(|p| !p.is_empty()).ok_or_else(|| PluginError::invalid("Sync provider ID is invalid"))?;
            let key = s(&payload, "key").filter(|k| !k.is_empty()).unwrap_or("sync-credential");
            let value = s(&payload, "value").filter(|v| !v.is_empty()).ok_or_else(|| PluginError::invalid("Sync secret value is invalid"))?;
            let entry = host.extensions.list(&json!({ "kind": "sync" }))?.into_iter().find(|e| e["provider"]["id"] == provider_id);
            let plugin_id = entry.and_then(|e| e["pluginId"].as_str().map(str::to_string)).ok_or_else(|| PluginError::host(format!("Plugin sync provider is unavailable: {provider_id}")))?;
            let existing = host.secrets.get_reference(&plugin_id, key)?;
            let mut stored = host.secrets.set(&plugin_id, key, value, true)?;
            let _ = host.secrets.bind_sync_provider_plugin(&plugin_id, provider_id);
            stored["created"] = json!(existing.is_none());
            Ok(stored)
        }
        "sync-delete-secrets" | "sync-restore-secrets" => {
            let provider_id = s(&payload, "providerId").filter(|p| !p.is_empty()).ok_or_else(|| PluginError::invalid("Sync provider ID is invalid"))?;
            let live = host.extensions.list(&json!({ "kind": "sync" }))?.into_iter().find(|e| e["provider"]["id"] == provider_id).and_then(|e| e["pluginId"].as_str().map(str::to_string));
            let plugin_id = match live {
                Some(id) => Some(id),
                None => host.secrets.resolve_sync_provider_plugin(provider_id)?,
            };
            let keys: Vec<String> = payload["keys"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
            if method == "sync-delete-secrets" {
                let Some(plugin_id) = plugin_id else { return Ok(json!({ "deleted": 0 })) };
                if keys.is_empty() {
                    let deleted = host.secrets.delete_by_key_prefix(&plugin_id, "sync-credential")?;
                    host.secrets.unbind_sync_provider_plugin(&plugin_id, provider_id)?;
                    return Ok(json!({ "deleted": deleted }));
                }
                let deleted = keys.iter().filter(|k| host.secrets.delete(&plugin_id, k).is_ok()).count();
                Ok(json!({ "deleted": deleted }))
            } else {
                let Some(plugin_id) = plugin_id.filter(|_| !keys.is_empty()) else { return Ok(json!({ "restored": 0, "discarded": 0 })) };
                let (mut restored, mut discarded) = (0, 0);
                for key in &keys {
                    if payload["discard"] == true {
                        if host.secrets.clear_overwrite_stash(&plugin_id, key).is_ok() {
                            discarded += 1;
                        }
                    } else if host.secrets.restore_overwrite(&plugin_id, key).unwrap_or(false) {
                        restored += 1;
                    }
                }
                Ok(json!({ "restored": restored, "discarded": discarded }))
            }
        }
        "sync-sidecars-collect" => host.sidecars.collect(),
        "sync-sidecars-apply" => {
            let entries = host.sidecars.apply(&payload).await?;
            Ok(json!({ "applied": true, "count": entries.as_array().map_or(0, Vec::len), "entries": entries }))
        }
        // -- market sources / catalog ---------------------------------------------
        "sources" => Ok(json!([builtin_source()])),
        "catalog" => Ok(json!({ "entries": [], "source": "builtin", "error": "The plugin marketplace is not available in this build; install .ncpkg packages locally" })),
        "add-source" | "update-source" | "remove-source" | "author" | "catalog-readme" | "catalog-readme-images" | "catalog-install" => {
            Err(PluginError::rpc(codes::UNSUPPORTED, "The plugin marketplace is not available in this build"))
        }
        // -- AI / agent host adapters -------------------------------------------------
        "ai-host-ready" | "agent-host-ready" => Ok(json!(false)),
        "ai-host-response" | "agent-host-response" => Ok(json!(false)),
        other => Err(PluginError::rpc(codes::UNSUPPORTED, format!("Unsupported plugin bridge method: {other}"))),
    }
}

fn builtin_source() -> Value {
    serde_json::to_value(netcatty_plugins::source::Source::official()).unwrap_or(Value::Null)
}

// ---- plugin connection sessions --------------------------------------------------

struct ConnectionTransport {
    host: Arc<PluginHost>,
    session_id: String,
}

#[async_trait::async_trait]
impl StreamTransport for ConnectionTransport {
    async fn write_input(&self, input: SessionInput, _meta: &InputMeta, _charset: crate::decoder::Charset) -> CoreResult<()> {
        let bytes = match input {
            SessionInput::Text(text) => text.into_bytes(),
            SessionInput::Bytes(bytes) => bytes.to_vec(),
        };
        self.host.extensions.write(&self.session_id, &bytes).await.map_err(Into::into)
    }
    fn resize(&self, cols: u16, rows: u16) -> CoreResult<()> {
        let (host, id) = (self.host.clone(), self.session_id.clone());
        tauri::async_runtime::spawn(async move {
            let _ = host.extensions.control(&id, "resize", &json!({ "columns": cols, "rows": rows })).await;
        });
        Ok(())
    }
    fn close(&self) {
        let (host, id) = (self.host.clone(), self.session_id.clone());
        tauri::async_runtime::spawn(async move {
            if host.extensions.control(&id, "close", &json!({})).await.is_err() {
                host.extensions.close_local(&id);
            }
        });
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct EventSink(mpsc::UnboundedSender<StreamEvent>);
impl ConnectionSink for EventSink {
    fn data(&self, bytes: Vec<u8>) {
        let _ = self.0.send(StreamEvent::Data(bytes.into()));
    }
    fn closed(&self, reason: Value) {
        let exit = match reason.as_str() {
            Some("end") => StreamExit::process(Some(0), None),
            Some(_) => StreamExit::closed(),
            None => StreamExit::error(reason["message"].as_str().unwrap_or("Plugin connection output stream failed").to_string()),
        };
        let _ = self.0.send(StreamEvent::Exit(exit));
    }
}

fn ready_event() -> StreamEvent {
    StreamEvent::Text { text: String::new(), meta: Some(SessionDataMeta { plugin_connection_ready: Some(true), ..Default::default() }) }
}

async fn connection_start<R: Runtime>(app: &AppHandle<R>, host: &Arc<PluginHost>, payload: Value) -> PluginResult<Value> {
    let p = providers();
    let id = request_id(&payload)?;
    let token = begin(&p.requests, &id)?;
    let state = app.try_state::<AppState<R>>().ok_or_else(|| PluginError::unavailable("Host terminal pipeline is unavailable for plugin connections"))?;
    let session_id = s(&payload, "sessionId").map(str::to_string).unwrap_or_else(|| format!("plugin-session-{}", uuid::Uuid::new_v4()));
    let (events_tx, events_rx) = mpsc::channel(super::super::telnet::STREAM_CHANNEL_CAPACITY);
    let (sink_tx, mut sink_rx) = mpsc::unbounded_channel::<StreamEvent>();
    // Bounded forwarder keeps ordering and backpressure toward the pump.
    let forward = events_tx.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = sink_rx.recv().await {
            let exit = matches!(event, StreamEvent::Exit(_));
            if forward.send(event).await.is_err() || exit {
                break;
            }
        }
    });
    let mut request = payload.clone();
    request["sessionId"] = json!(session_id);
    let run = async {
        let mut credential = payload.get("credential").cloned().filter(|c| !c.is_null());
        if let Some(auth_provider) = s(&payload, "authenticationProviderId") {
            let emitter = app.clone();
            let request_id = id.clone();
            let ask = move |challenge: Value| -> futures::future::BoxFuture<'static, PluginResult<Value>> {
                let challenge_request_id = uuid::Uuid::new_v4().to_string();
                let (tx, rx) = oneshot::channel();
                providers().challenges.lock().insert(challenge_request_id.clone(), (request_id.clone(), challenge["id"].clone(), tx));
                let _ = emitter.emit(channels::AUTHENTICATION_CHALLENGE, json!({ "requestId": request_id, "challengeRequestId": challenge_request_id, "challenge": challenge }));
                Box::pin(async move { rx.await.unwrap_or_else(|_| Err(PluginError::cancelled())) })
            };
            let mut auth = json!({ "providerId": auth_provider, "connectionProviderId": payload["providerId"], "configuration": payload["configuration"] });
            if let Some(c) = &credential {
                auth["credential"] = c.clone();
            }
            let result = host.extensions.authenticate(&auth, ask, &token).await?;
            if result["status"] != "authenticated" {
                return Err(PluginError::host(result["message"].as_str().unwrap_or("Plugin authentication did not complete").to_string()));
            }
            credential = Some(result["credential"].clone());
        }
        if let Some(c) = credential {
            request["credential"] = c;
        }
        host.extensions.open_connection(&request, Arc::new(EventSink(sink_tx.clone())), &token).await
    };
    let opened = run.await;
    p.requests.lock().remove(&id);
    let opened = opened?;
    let label = s(&payload, "hostLabel").or(s(&payload, "hostname")).unwrap_or("Plugin connection").to_string();
    state.sessions.insert(SessionEntry {
        session_id: session_id.clone(),
        host_id: None,
        label,
        protocol: "plugin",
        backend: SessionBackend::Stream { transport: Arc::new(ConnectionTransport { host: host.clone(), session_id: session_id.clone() }), events: events_rx },
        charset: "utf-8".into(),
        connection: None,
        created_at: netcatty_core::ids::now_ms(),
    });
    if opened["status"] == "connected" {
        let _ = events_tx.send(ready_event()).await;
    }
    // Status monitor (`monitorPluginConnection`).
    let (monitor_host, monitor_id) = (host.clone(), session_id.clone());
    let mut ready = opened["status"] == "connected";
    tauri::async_runtime::spawn(async move {
        let mut reconnected = false;
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if !monitor_host.extensions.has_session(&monitor_id) {
                return;
            }
            let Ok(status) = monitor_host.extensions.control(&monitor_id, "getStatus", &json!({})).await else {
                let _ = events_tx.send(StreamEvent::Exit(StreamExit::error("Plugin connection status failed"))).await;
                monitor_host.extensions.close_local(&monitor_id);
                return;
            };
            match status["status"].as_str() {
                Some("connected") => {
                    reconnected = false;
                    if !ready {
                        ready = true;
                        let _ = events_tx.send(ready_event()).await;
                    }
                }
                Some("closed" | "error") => {
                    if status["retryable"] == true && !reconnected {
                        reconnected = true;
                        let _ = monitor_host.extensions.control(&monitor_id, "reconnect", &json!({})).await;
                        continue;
                    }
                    let exit = if status["status"] == "error" {
                        StreamExit::error(status["message"].as_str().unwrap_or("Plugin connection failed").to_string())
                    } else {
                        StreamExit::closed()
                    };
                    let _ = events_tx.send(StreamEvent::Exit(exit)).await;
                    monitor_host.extensions.close_local(&monitor_id);
                    return;
                }
                _ => {}
            }
        }
    });
    Ok(opened)
}

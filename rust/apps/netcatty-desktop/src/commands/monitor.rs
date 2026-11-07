//! Server monitor panels — port of `electron/bridges/monitorBridge.cjs`.
//!
//! The renderer declares which hosts each monitor panel watches
//! (`monitor_update`) and polls `monitor_snapshot`. Every distinct endpoint
//! gets one entry with a background task that acquires a connection (an
//! existing session transport to the same `user@host:port`, else a new
//! login with the usual prompts, serialized), then samples stats on the
//! panel cadence through the shared per-connection sampler of
//! [`super::system`]. Panels are owned by the calling window (Electron:
//! `webContents`), so several windows do not clobber each other's demand.

use super::CmdResult;
use crate::connect;
use crate::state::{AppState, Ctx};
use netcatty_core::ipc::SshSessionOptions;
use netcatty_core::CoreError;
use netcatty_ssh::SshConnection;
use netcatty_sysmgr::exec::now_ms;
use netcatty_sysmgr::system::{
    detect_vendor_from_ssh_version, remote_software_requires_single_channel,
};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{Manager, Runtime};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Max monitored endpoints (Electron: 256).
const MAX_ENTRIES: usize = 256;
const ALLOWED_INTERVALS: [u64; 7] = [1, 2, 3, 5, 10, 30, 60];

/// Monitor runtime: panels, per-endpoint entries, retry requests.
pub struct MonitorService {
    inner: parking_lot::Mutex<Inner>,
    runtime_id: String,
    /// New logins are serialized (one prompt at a time).
    dial_lock: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct Inner {
    /// Panels in insertion order, keyed by `owner:panelId`.
    panels: Vec<(String, Panel)>,
    entries: HashMap<String, Arc<Entry>>,
    retries: HashMap<String, HashSet<String>>,
    epoch: u64,
}

#[derive(Clone)]
struct Panel {
    owner: String,
    id: String,
    keys: Vec<String>,
    hosts: Vec<PanelHost>,
    interval: u64,
    run_id: Value,
    started_at: i64,
}

#[derive(Clone)]
struct PanelHost {
    id: String,
    key: Option<String>,
    status: Option<&'static str>,
    options: Option<SshSessionOptions>,
}

/// One monitored endpoint.
struct Entry {
    key: String,
    history_id: String,
    session_id: String,
    owner: String,
    status: parking_lot::Mutex<&'static str>,
    failures: AtomicU32,
    conn: parking_lot::Mutex<Option<Arc<SshConnection>>>,
    /// The connection was dialed for this entry (not a session's).
    owned: AtomicBool,
    ready: AtomicBool,
    sampling: AtomicBool,
    /// Next sample time (ms).
    due: AtomicI64,
    sample_now: AtomicBool,
    wake: Notify,
    cancel: CancellationToken,
}

impl Entry {
    fn set_status(&self, status: &'static str) {
        *self.status.lock() = status;
    }
    fn status(&self) -> &'static str {
        *self.status.lock()
    }
    fn cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

impl Default for MonitorService {
    fn default() -> Self {
        Self::new()
    }
}

/// Electron `buildEndpointKey(buildConnectionReuseEndpoint(options))`:
/// profile, route, identity and keepalive policy of a monitored host.
pub fn endpoint_key(options: &SshSessionOptions) -> Option<String> {
    let hostname = options.hostname.trim();
    if hostname.is_empty() {
        return None;
    }
    let username = if options.username.is_empty() {
        "root"
    } else {
        options.username.as_str()
    };
    let sudo = if options.sudo == Some(true)
        || options.extra.get("sftpSudo").and_then(Value::as_bool) == Some(true)
    {
        "sudo"
    } else {
        "nosudo"
    };
    let jump = match options.jump_hosts.as_ref().filter(|j| !j.is_empty()) {
        Some(j) => serde_json::to_string(j).unwrap_or_default(),
        None => "-".to_string(),
    };
    let proxy = match &options.proxy {
        Some(p) => serde_json::to_string(p).unwrap_or_default(),
        None => "-".to_string(),
    };
    let auth = [
        options
            .auth_method
            .as_ref()
            .and_then(|a| serde_json::to_value(a).ok())
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default(),
        options.key_id.clone().unwrap_or_default(),
        options
            .certificate
            .as_ref()
            .map(|_| "cert".to_string())
            .unwrap_or_default(),
        if options.requires_mfa == Some(true) {
            "mfa".into()
        } else {
            String::new()
        },
    ]
    .join(":");
    Some(
        [
            options
                .host_id
                .clone()
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "-".into()),
            hostname.to_string(),
            options.port().to_string(),
            username.to_string(),
            "ssh".to_string(),
            sudo.to_string(),
            jump,
            proxy,
            auth,
            format!(
                "keepalive:{}:{}",
                options.keepalive_interval.unwrap_or(0) as u64 * 1000,
                options.keepalive_count_max.unwrap_or(3)
            ),
        ]
        .join("|"),
    )
}

/// Banners the monitor never samples: network devices and single-channel
/// servers (an extra exec channel would hurt the interactive session).
pub fn monitor_unsupported_banner(banner: Option<&str>) -> bool {
    banner.is_some_and(|b| {
        !detect_vendor_from_ssh_version(b).is_empty() || remote_software_requires_single_channel(b)
    })
}

impl MonitorService {
    pub fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(Inner::default()),
            runtime_id: netcatty_core::new_id(),
            dial_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Smallest interval (ms) and latest start of the panels watching `key`.
    fn params_for(&self, key: &str) -> (i64, i64) {
        let inner = self.inner.lock();
        let watching = inner
            .panels
            .iter()
            .filter(|(_, p)| p.keys.iter().any(|k| k == key));
        let mut interval = None::<u64>;
        let mut fresh_after = 0i64;
        for (_, p) in watching {
            interval = Some(interval.map_or(p.interval, |i| i.min(p.interval)));
            fresh_after = fresh_after.max(p.started_at);
        }
        (interval.unwrap_or(5) as i64 * 1000, fresh_after)
    }

    /// `monitor:update` — replace `owner`'s panel demand.
    pub fn reconcile<R: Runtime>(
        &self,
        state: &AppState<R>,
        owner: &str,
        input: &Value,
    ) -> CmdResult<Value> {
        let Some(list) = input.as_array() else {
            return Err(CoreError::invalid("Invalid monitor configuration"));
        };
        let now = now_ms();
        let mut spawn: Vec<(Arc<Entry>, SshSessionOptions)> = Vec::new();
        let mut released: Vec<Arc<Entry>> = Vec::new();
        {
            let mut inner = self.inner.lock();
            let mut wanted = HashSet::new();
            let mut fresh_keys = HashSet::new();
            for panel in list {
                let (Some(panel_id), Some(hosts_in)) = (
                    panel.get("id").and_then(Value::as_str),
                    panel.get("hosts").and_then(Value::as_array),
                ) else {
                    continue;
                };
                let full_id = format!("{owner}:{panel_id}");
                wanted.insert(full_id.clone());
                let mut keys = Vec::new();
                let mut hosts = Vec::new();
                for host in hosts_in {
                    let Some(host_id) = host.get("id").and_then(Value::as_str) else {
                        continue;
                    };
                    let options = host
                        .get("options")
                        .filter(|o| o.is_object())
                        .and_then(|o| serde_json::from_value::<SshSessionOptions>(o.clone()).ok())
                        .filter(|o| o.single_channel_ssh != Some(true));
                    let key = options.as_ref().and_then(endpoint_key);
                    match (options, key) {
                        (Some(options), Some(key)) => {
                            keys.push(key.clone());
                            hosts.push(PanelHost {
                                id: host_id.to_string(),
                                key: Some(key),
                                status: None,
                                options: Some(options),
                            });
                        }
                        _ => {
                            let status = match host.get("status").and_then(Value::as_str) {
                                Some("login") => "login",
                                Some("error") => "error",
                                _ => "unsupported",
                            };
                            hosts.push(PanelHost {
                                id: host_id.to_string(),
                                key: None,
                                status: Some(status),
                                options: None,
                            });
                        }
                    }
                }
                let interval = panel
                    .get("interval")
                    .and_then(Value::as_u64)
                    .filter(|i| ALLOWED_INTERVALS.contains(i))
                    .unwrap_or(5);
                let run_id = panel.get("runId").cloned().unwrap_or(Value::Null);
                let previous = inner.panels.iter().position(|(id, _)| *id == full_id);
                let fresh = previous.is_none_or(|at| {
                    let p = &inner.panels[at].1;
                    p.interval != interval || p.run_id != run_id
                });
                if fresh {
                    fresh_keys.extend(keys.iter().cloned());
                }
                let next = Panel {
                    owner: owner.to_string(),
                    id: panel_id.to_string(),
                    keys,
                    hosts,
                    interval,
                    run_id,
                    started_at: match previous {
                        Some(at) if !fresh => inner.panels[at].1.started_at,
                        _ => now,
                    },
                };
                match previous {
                    Some(at) => inner.panels[at].1 = next,
                    None => inner.panels.push((full_id, next)),
                }
            }
            inner
                .panels
                .retain(|(id, p)| p.owner != owner || wanted.contains(id));
            let needed: HashSet<String> = inner
                .panels
                .iter()
                .flat_map(|(_, p)| p.keys.iter().cloned())
                .collect();
            let own_keys: HashSet<String> = inner
                .panels
                .iter()
                .filter(|(_, p)| p.owner == owner)
                .flat_map(|(_, p)| p.keys.iter().cloned())
                .collect();
            let retry_keys = inner.retries.remove(owner).unwrap_or_default();
            let release_keys: Vec<String> = inner
                .entries
                .values()
                .filter(|e| {
                    !needed.contains(&e.key)
                        || (e.conn.lock().is_none()
                            && e.owner == owner
                            && !own_keys.contains(&e.key))
                        || (own_keys.contains(&e.key) && retry_keys.contains(&e.key))
                })
                .map(|e| e.key.clone())
                .collect();
            for key in release_keys {
                if let Some(entry) = inner.entries.remove(&key) {
                    released.push(entry);
                }
            }
            spawn.extend(admit(&mut inner, Some(owner)));

            // Fresh panels sample at once; a shorter cadence pulls the next
            // sample forward.
            for entry in inner.entries.values() {
                if fresh_keys.contains(&entry.key)
                    && entry.ready.load(Ordering::SeqCst)
                    && entry.conn.lock().is_some()
                    && !entry.sampling.load(Ordering::SeqCst)
                {
                    entry.sample_now.store(true, Ordering::SeqCst);
                    entry.wake.notify_one();
                } else {
                    entry.wake.notify_one();
                }
            }
        }
        for entry in released {
            release(state, entry);
        }
        for (entry, options) in spawn {
            start_entry(state, entry, options);
        }
        Ok(self.snapshot(state, owner, None))
    }

    /// `monitor:snapshot` for `owner`; `cursor` enables incremental history.
    pub fn snapshot<R: Runtime>(
        &self,
        state: &AppState<R>,
        owner: &str,
        cursor: Option<&Value>,
    ) -> Value {
        let (own, entries, epoch, count, host_count) = {
            let inner = self.inner.lock();
            let own: Vec<Panel> = inner
                .panels
                .iter()
                .filter(|(_, p)| p.owner == owner)
                .map(|(_, p)| p.clone())
                .collect();
            (
                own,
                inner.entries.clone(),
                inner.epoch,
                inner.panels.len(),
                inner.entries.len(),
            )
        };
        let append = cursor.is_some_and(|c| {
            c.get("runtimeId").and_then(Value::as_str) == Some(self.runtime_id.as_str())
                && c.get("epoch").and_then(Value::as_u64) == Some(epoch)
        });
        let mut hosts = Map::new();
        for panel in &own {
            for host in &panel.hosts {
                let entry = host.key.as_ref().and_then(|k| entries.get(k));
                let conn = entry.and_then(|e| e.conn.lock().clone());
                let shared = conn.as_ref().map(|c| state.system.read_shared(c));
                let history_id = entry.map(|e| e.history_id.clone()).unwrap_or_default();
                let at = shared.as_ref().map(|s| s.at).unwrap_or(0);
                let stats_at = shared
                    .as_ref()
                    .map(|s| if s.stats_at != 0 { s.stats_at } else { s.at })
                    .unwrap_or(0);
                let last = cursor
                    .and_then(|c| c.get("after"))
                    .and_then(|a| a.get(&host.id));
                let same_history = append
                    && last
                        .and_then(|l| l.get("historyId"))
                        .and_then(Value::as_str)
                        == Some(history_id.as_str());
                let status = entry.map(|e| e.status()).or(host.status).unwrap_or("limit");
                let mut state_json = Map::new();
                state_json.insert("historyId".into(), json!(history_id));
                state_json.insert("status".into(), json!(status));
                state_json.insert("at".into(), json!(at));
                state_json.insert("statsAt".into(), json!(stats_at));
                let unchanged = same_history
                    && last.and_then(|l| l.get("statsAt")).and_then(Value::as_i64)
                        == Some(stats_at);
                if !unchanged {
                    let stats = shared
                        .as_ref()
                        .and_then(|s| s.result.as_ref())
                        .filter(|r| r.get("success").and_then(Value::as_bool) == Some(true))
                        .and_then(|r| r.get("stats").cloned())
                        .unwrap_or(Value::Null);
                    state_json.insert("stats".into(), stats);
                }
                let points = shared.map(|s| s.points).unwrap_or_default();
                let points: Vec<_> = if same_history {
                    let after = last
                        .and_then(|l| l.get("at"))
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    points.into_iter().filter(|p| p.at > after).collect()
                } else {
                    points
                };
                state_json.insert("points".into(), json!(points));
                hosts.insert(host.id.clone(), Value::Object(state_json));
            }
        }
        let mut active: Vec<String> = Vec::new();
        for panel in &own {
            for key in &panel.keys {
                if let Some(entry) = entries.get(key).filter(|e| !e.cancelled()) {
                    if !active.contains(&entry.session_id) {
                        active.push(entry.session_id.clone());
                    }
                }
            }
        }
        let started: Map<String, Value> = own
            .iter()
            .map(|p| (p.id.clone(), json!(p.started_at)))
            .collect();
        json!({
            "epoch": epoch,
            "historyMode": if append { "append" } else { "replace" },
            "runtimeId": self.runtime_id,
            "takenAt": now_ms(),
            "activeSessions": active,
            "running": own.iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
            "startedAt": started,
            "count": count,
            "hostCount": host_count,
            "hosts": hosts,
        })
    }

    /// `monitor:stop-all`.
    pub fn stop_all<R: Runtime>(&self, state: &AppState<R>) {
        let released: Vec<Arc<Entry>> = {
            let mut inner = self.inner.lock();
            inner.epoch += 1;
            inner.panels.clear();
            inner.retries.clear();
            inner.entries.drain().map(|(_, e)| e).collect()
        };
        for entry in released {
            release(state, entry);
        }
    }

    /// `monitor:retry` — the next `monitor_update` from `owner` re-dials
    /// `host_id` if it is in a failed state.
    pub fn retry(&self, owner: &str, host_id: &str) {
        let mut inner = self.inner.lock();
        let mut keys = inner.retries.remove(owner).unwrap_or_default();
        for (_, panel) in inner.panels.iter().filter(|(_, p)| p.owner == owner) {
            for host in panel.hosts.iter().filter(|h| h.id == host_id) {
                let Some(key) = &host.key else { continue };
                if let Some(entry) = inner.entries.get(key) {
                    if matches!(
                        entry.status(),
                        "login" | "error" | "unsupported" | "disconnected"
                    ) {
                        keys.insert(key.clone());
                    }
                }
            }
        }
        inner.retries.insert(owner.to_string(), keys);
    }

    /// Number of endpoint entries (tests).
    pub fn entry_count(&self) -> usize {
        self.inner.lock().entries.len()
    }
}

/// Electron `admitEntries`: create entries for watched hosts, preferred
/// owner first, up to [`MAX_ENTRIES`].
fn admit(inner: &mut Inner, preferred: Option<&str>) -> Vec<(Arc<Entry>, SshSessionOptions)> {
    let mut candidates: Vec<Panel> = inner.panels.iter().map(|(_, p)| p.clone()).collect();
    candidates.sort_by_key(|p| Some(p.owner.as_str()) != preferred);
    let mut out = Vec::new();
    for panel in candidates {
        for host in &panel.hosts {
            let (Some(key), Some(options)) = (&host.key, &host.options) else {
                continue;
            };
            if inner.entries.contains_key(key) || inner.entries.len() >= MAX_ENTRIES {
                continue;
            }
            let entry = Arc::new(Entry {
                key: key.clone(),
                history_id: netcatty_core::new_id(),
                session_id: format!("monitor-{}", netcatty_core::new_id()),
                owner: panel.owner.clone(),
                status: parking_lot::Mutex::new("queued"),
                failures: AtomicU32::new(0),
                conn: parking_lot::Mutex::new(None),
                owned: AtomicBool::new(false),
                ready: AtomicBool::new(false),
                sampling: AtomicBool::new(false),
                due: AtomicI64::new(0),
                sample_now: AtomicBool::new(false),
                wake: Notify::new(),
                cancel: CancellationToken::new(),
            });
            inner.entries.insert(key.clone(), entry.clone());
            out.push((entry, options.clone()));
        }
    }
    out
}

/// Stop an entry: cancel its task (which releases its connection) and any
/// pending login prompt.
fn release<R: Runtime>(state: &AppState<R>, entry: Arc<Entry>) {
    entry.cancel.cancel();
    entry.wake.notify_one();
    state.prompts.cancel_session(&entry.session_id);
}

fn start_entry<R: Runtime>(state: &AppState<R>, entry: Arc<Entry>, options: SshSessionOptions) {
    let app = state.app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState<R>>();
        run_entry(state.inner(), &entry, options).await;
        // Whatever the exit path, give up a connection this entry dialed
        // (a reused session transport stays with its session).
        let conn = entry.conn.lock().take();
        if let Some(conn) = conn {
            if entry.owned.load(Ordering::SeqCst) && !state.sessions.connection_in_use(&conn) {
                let _ = conn.disconnect().await;
            }
        }
    });
}

/// `monitorBridge` `collect` failure classification.
fn failure_status(reply: &Value) -> &'static str {
    let error = reply
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    if error.contains("not supported") || error.contains("unsupported") || error.contains("parse") {
        "unsupported"
    } else {
        "error"
    }
}

/// Connect, then sample until cancelled, unsupported or disconnected.
async fn run_entry<R: Runtime>(
    state: &AppState<R>,
    entry: &Arc<Entry>,
    options: SshSessionOptions,
) {
    let service = &state.system.monitor;
    // Connect: reuse a live session transport to the same endpoint, else a
    // new login (serialized; prompts are bound to the entry's session id).
    let acquired = {
        let _turn = tokio::select! {
            turn = service.dial_lock.lock() => turn,
            _ = entry.cancel.cancelled() => return,
        };
        entry.set_status("connecting");
        tokio::select! {
            acquired = connect::acquire(state, &options, &entry.session_id, true) => acquired,
            _ = entry.cancel.cancelled() => return,
        }
    };
    let acquired = match acquired {
        Ok(acquired) => acquired,
        Err(err) => {
            tracing::debug!(code = ?err.code, "monitor login failed");
            if !entry.cancelled() {
                entry.set_status("login");
            }
            return;
        }
    };
    let conn = acquired.connection;
    entry.owned.store(!acquired.reused, Ordering::SeqCst);
    *entry.conn.lock() = Some(conn.clone());
    if entry.cancelled() {
        return;
    }
    if monitor_unsupported_banner(conn.server_banner.as_deref()) {
        entry.set_status("unsupported");
        return;
    }
    entry.ready.store(true, Ordering::SeqCst);

    loop {
        if entry.cancelled() {
            return;
        }
        if conn.is_closed() {
            entry.set_status("disconnected");
            return;
        }
        let (interval_ms, fresh_after) = service.params_for(&entry.key);
        entry.sampling.store(true, Ordering::SeqCst);
        let reply = tokio::select! {
            reply = state.system.monitor_sample(conn.clone(), interval_ms, fresh_after) => reply,
            _ = entry.cancel.cancelled() => return,
        };
        entry.sampling.store(false, Ordering::SeqCst);
        if reply.get("success").and_then(Value::as_bool) == Some(true) {
            entry.failures.store(0, Ordering::SeqCst);
            entry.set_status("live");
        } else {
            entry.failures.fetch_add(1, Ordering::SeqCst);
            let status = failure_status(&reply);
            entry.set_status(status);
            if status == "unsupported" {
                return;
            }
        }
        // Back off on failures: interval × min(6, 2^failures).
        let failures = entry.failures.load(Ordering::SeqCst).min(3);
        let factor = (1i64 << failures).min(6);
        entry
            .due
            .store(now_ms() + interval_ms * factor, Ordering::SeqCst);
        loop {
            let wait = (entry.due.load(Ordering::SeqCst) - now_ms()).max(0) as u64;
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(wait)) => break,
                _ = entry.wake.notified() => {
                    if entry.cancelled() {
                        return;
                    }
                    if entry.sample_now.swap(false, Ordering::SeqCst) {
                        break;
                    }
                    // Cadence changed: never wait longer than one interval.
                    let (interval_ms, _) = service.params_for(&entry.key);
                    let capped = now_ms() + interval_ms;
                    if entry.due.load(Ordering::SeqCst) > capped {
                        entry.due.store(capped, Ordering::SeqCst);
                    }
                }
                _ = entry.cancel.cancelled() => return,
            }
        }
    }
}

#[tauri::command]
pub async fn monitor_update<R: Runtime>(
    state: Ctx<'_, R>,
    window: tauri::Window<R>,
    panels: Value,
) -> CmdResult<Value> {
    state
        .system
        .monitor
        .reconcile(&state, window.label(), &panels)
}

#[tauri::command]
pub async fn monitor_snapshot<R: Runtime>(
    state: Ctx<'_, R>,
    window: tauri::Window<R>,
    cursor: Option<Value>,
) -> CmdResult<Value> {
    Ok(state
        .system
        .monitor
        .snapshot(&state, window.label(), cursor.as_ref()))
}

#[tauri::command]
pub async fn monitor_stop_all<R: Runtime>(state: Ctx<'_, R>) -> CmdResult<()> {
    state.system.monitor.stop_all(&state);
    Ok(())
}

#[tauri::command]
pub async fn monitor_retry<R: Runtime>(
    state: Ctx<'_, R>,
    window: tauri::Window<R>,
    host_id: String,
) -> CmdResult<()> {
    state.system.monitor.retry(window.label(), &host_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(v: Value) -> SshSessionOptions {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn endpoint_keys_distinguish_route_and_identity() {
        let a = endpoint_key(&opts(json!({"hostname": "h", "username": "u"}))).unwrap();
        let b = endpoint_key(&opts(
            json!({"hostname": "h", "username": "u", "port": 2222}),
        ))
        .unwrap();
        let c = endpoint_key(&opts(json!({"hostname": "h", "username": "u",
            "jumpHosts": [{"hostname": "j", "username": "u"}]})))
        .unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert!(endpoint_key(&opts(json!({"hostname": " ", "username": "u"}))).is_none());
    }

    #[test]
    fn unsupported_banners() {
        assert!(monitor_unsupported_banner(Some("SSH-2.0-Cisco-1.25")));
        assert!(monitor_unsupported_banner(Some("BHostSSH_7.0")));
        assert!(!monitor_unsupported_banner(Some("OpenSSH_9.6")));
        assert!(!monitor_unsupported_banner(None));
    }
}

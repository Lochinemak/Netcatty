//! System manager (processes, tmux, containers, kubectl, GPUs, ports,
//! services), server stats, distro / history probes and local PTY child
//! processes.
//!
//! The command builders and parsers live in `netcatty-sysmgr`; this module
//! resolves the session's transport ([`exec::DesktopExec`]), keeps the small
//! amount of per-session / per-connection state (exec queues, sudo
//! passwords, tmux cache, stats samplers) and exposes the commands. Replies
//! are the Electron bridge's JSON objects verbatim.

pub(crate) mod exec;

use super::CmdResult;
use crate::sessions::SessionBackend;
use crate::state::{AppState, Ctx};
use exec::{bounded_exec, DesktopExec, ExecTarget, SshStatsTransport};
use netcatty_core::ipc::SshSessionOptions;
use netcatty_ssh::SshConnection;
use netcatty_sysmgr::exec::{now_ms, ExecResult};
use netcatty_sysmgr::stats::{
    collect_stats, monitor_gpu_command, GpuCache, StatsBaseline, StatsHistory, GPU_PROBE_TIMEOUT_MS,
};
use netcatty_sysmgr::system::session_id_of;
use netcatty_sysmgr::{docker, gpu, history, kubectl, ports, services, stats, system};
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tauri::Runtime;

/// Electron's single-channel bastion error.
const SINGLE_CHANNEL_ERROR: &str = "Remote SSH server does not support extra exec channels";

/// State behind the system-manager, stats and monitor commands.
#[derive(Default)]
pub struct SystemState {
    queues: dashmap::DashMap<String, Arc<tokio::sync::Mutex<()>>>,
    /// Session id → `sudoAutofillPassword` (Electron
    /// `session.systemManagerSudoPassword`).
    sudo: dashmap::DashMap<String, String>,
    /// Sessions started with `singleChannelSsh`.
    single_channel: dashmap::DashSet<String>,
    pub tmux: netcatty_sysmgr::tmux::TmuxOps,
    /// Stats samplers keyed by connection identity.
    samplers: dashmap::DashMap<usize, Arc<Sampler>>,
    pub monitor: super::monitor::MonitorService,
}

/// One stats sampler per physical connection (Electron `sharedStats.cjs`):
/// terminal stats and the monitor share the CPU / network baselines, the
/// history and the GPU cache of a transport.
pub(crate) struct Sampler {
    conn: Weak<SshConnection>,
    /// Held while a sample is collected; waiting on it joins that sample.
    collect: tokio::sync::Mutex<StatsBaseline>,
    shared: parking_lot::Mutex<SharedView>,
}

#[derive(Default)]
struct SharedView {
    history: StatsHistory,
    gpu: GpuCache,
}

/// Snapshot of a sampler for the monitor.
pub(crate) struct SharedRead {
    pub result: Option<Value>,
    pub at: i64,
    pub stats_at: i64,
    pub points: Vec<netcatty_sysmgr::stats::MonitorPoint>,
}

/// Terminal (full) samples are reused for 4 s.
const FULL_CACHE_MS: i64 = 4000;

fn reply_ok(reply: &Value) -> bool {
    reply.get("success").and_then(Value::as_bool) == Some(true)
}

impl SystemState {
    /// Record the options of a newly started SSH session.
    pub fn remember_session(&self, session_id: &str, options: &SshSessionOptions) {
        if let Some(password) = options
            .extra
            .get("sudoAutofillPassword")
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
        {
            self.sudo
                .insert(session_id.to_string(), password.to_string());
        }
        if options.single_channel_ssh == Some(true) {
            self.single_channel.insert(session_id.to_string());
        }
    }

    /// Drop per-session state of a session that no longer exists.
    pub fn forget_session(&self, session_id: &str) {
        self.queues.remove(session_id);
        self.sudo.remove(session_id);
        self.single_channel.remove(session_id);
        self.tmux.forget(session_id);
    }

    fn queue(&self, session_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.queues
            .entry(session_id.to_string())
            .or_default()
            .clone()
    }

    pub(crate) fn sampler_for(&self, conn: &Arc<SshConnection>) -> Arc<Sampler> {
        // Drop samplers of connections that are gone.
        self.samplers.retain(|_, s| s.conn.strong_count() > 0);
        let key = Arc::as_ptr(conn) as usize;
        let mut entry = self.samplers.entry(key).or_insert_with(|| {
            Arc::new(Sampler {
                conn: Arc::downgrade(conn),
                collect: tokio::sync::Mutex::new(StatsBaseline::default()),
                shared: parking_lot::Mutex::new(SharedView::default()),
            })
        });
        // Address reuse after a connection was dropped: start fresh.
        if !entry.conn.upgrade().is_some_and(|c| Arc::ptr_eq(&c, conn)) {
            *entry = Arc::new(Sampler {
                conn: Arc::downgrade(conn),
                collect: tokio::sync::Mutex::new(StatsBaseline::default()),
                shared: parking_lot::Mutex::new(SharedView::default()),
            });
        }
        entry.clone()
    }

    /// Terminal `getServerStats` sample (process list + GPU included).
    pub(crate) async fn full_sample(&self, conn: Arc<SshConnection>) -> Value {
        let sampler = self.sampler_for(&conn);
        let cached = |s: &Sampler| {
            let view = s.shared.lock();
            view.history
                .full_result
                .as_ref()
                .filter(|r| reply_ok(r) && now_ms() - view.history.full_at < FULL_CACHE_MS)
                .cloned()
        };
        if let Some(hit) = cached(&sampler) {
            return hit;
        }
        let mut baseline = sampler.collect.lock().await;
        if let Some(hit) = cached(&sampler) {
            return hit;
        }
        let transport = stats_transport(conn);
        let reply = collect_stats(&transport, &mut baseline, false, now_ms).await;
        let at = now_ms();
        let mut view = sampler.shared.lock();
        view.history.record(&reply, true, at, 0);
        if reply_ok(&reply) {
            if let Some(stats) = reply.get("stats") {
                view.gpu.cache_full(stats, at);
            }
        }
        reply
    }

    /// Monitor sample (no process list; GPU via a separate cached probe).
    pub(crate) async fn monitor_sample(
        &self,
        conn: Arc<SshConnection>,
        interval_ms: i64,
        fresh_after: i64,
    ) -> Value {
        let sampler = self.sampler_for(&conn);
        let cache_ms = interval_ms.min(FULL_CACHE_MS);
        let cached = |s: &Sampler| {
            let view = s.shared.lock();
            let h = &view.history;
            h.latest
                .as_ref()
                .filter(|r| reply_ok(r) && now_ms() - h.at < cache_ms && h.at > fresh_after)
                .cloned()
        };
        let mut reply = match cached(&sampler) {
            Some(hit) => hit,
            None => {
                let mut baseline = sampler.collect.lock().await;
                match cached(&sampler) {
                    Some(hit) => hit,
                    None => {
                        let transport = stats_transport(conn.clone());
                        let reply = collect_stats(&transport, &mut baseline, true, now_ms).await;
                        sampler
                            .shared
                            .lock()
                            .history
                            .record(&reply, false, now_ms(), fresh_after);
                        reply
                    }
                }
            }
        };
        if reply_ok(&reply) && !single_channel_banner(&conn) {
            start_gpu_probe(&sampler, &conn);
        }
        if reply_ok(&reply) {
            if let Some(stats) = reply.get_mut("stats") {
                sampler.shared.lock().gpu.overlay(stats);
            }
        }
        reply
    }

    /// Latest sample, its times and the history of `conn`.
    pub(crate) fn read_shared(&self, conn: &Arc<SshConnection>) -> SharedRead {
        let sampler = self.sampler_for(conn);
        let mut view = sampler.shared.lock();
        let now = now_ms();
        view.history.prune(now);
        let mut result = view.history.latest.clone();
        if !view.history.latest_full {
            if let Some(stats) = result.as_mut().and_then(|r| r.get_mut("stats")) {
                view.gpu.overlay(stats);
            }
        }
        SharedRead {
            result,
            at: view.history.at,
            stats_at: view.history.at.max(view.gpu.updated_at),
            points: view.history.points.clone(),
        }
    }
}

fn stats_transport(conn: Arc<SshConnection>) -> SshStatsTransport {
    // Honour a keepalive opt-out: no transport pings on that connection.
    let ping = conn.options.target.keepalive_interval.is_some();
    SshStatsTransport { conn, ping }
}

/// Optional GPU probe for monitor samples; never blocks the CPU sample.
fn start_gpu_probe(sampler: &Arc<Sampler>, conn: &Arc<SshConnection>) {
    {
        let mut view = sampler.shared.lock();
        let now = now_ms();
        if !view.gpu.due(now) {
            return;
        }
        view.gpu.pending = true;
        view.gpu.next_at = now + 30_000;
    }
    let sampler = sampler.clone();
    let conn = conn.clone();
    tauri::async_runtime::spawn(async move {
        let bound = Duration::from_millis(GPU_PROBE_TIMEOUT_MS);
        let outcome = bounded_exec(&conn, &monitor_gpu_command(), None, bound, bound, 65_536).await;
        let mut view = sampler.shared.lock();
        match outcome {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
                view.gpu.finish_probe(Some(&stdout), false, now_ms());
            }
            Err(err) => {
                let open_timeout = matches!(err, exec::BoundedError::OpenTimeout(_));
                view.gpu.finish_probe(None, open_timeout, now_ms());
            }
        }
    });
}

/// Single-channel SSH software (one session channel per TCP connection):
/// any extra exec would tear down the interactive shell.
pub(crate) fn single_channel_banner(conn: &SshConnection) -> bool {
    conn.server_banner
        .as_deref()
        .is_some_and(system::remote_software_requires_single_channel)
}

fn single_channel_result() -> ExecResult {
    ExecResult {
        success: false,
        error: Some(SINGLE_CHANNEL_ERROR.to_string()),
        error_code: Some("ERR_SINGLE_CHANNEL_BASTION".to_string()),
        ..Default::default()
    }
}

/// What a session is, for the stats / history probes.
enum SessionKind {
    Missing,
    SingleChannel,
    Ssh(Arc<SshConnection>),
    /// Exists but has no SSH connection (local, telnet, closed, ...).
    NoConnection {
        local: bool,
    },
}

async fn session_kind<R: Runtime>(state: &AppState<R>, session_id: &str) -> SessionKind {
    let Some(entry) = state.sessions.get(session_id) else {
        state.system.forget_session(session_id);
        return SessionKind::Missing;
    };
    let local = entry.lock().await.protocol == "local";
    if state.system.single_channel.contains(session_id) {
        return SessionKind::SingleChannel;
    }
    match state.sessions.connection_of(session_id) {
        Some(conn) if single_channel_banner(&conn) => SessionKind::SingleChannel,
        Some(conn) => SessionKind::Ssh(conn),
        None => SessionKind::NoConnection { local },
    }
}

/// Electron `execOnSession` target resolution for `session_id`.
pub(crate) async fn resolve_exec<R: Runtime>(state: &AppState<R>, session_id: &str) -> DesktopExec {
    let target = match session_kind(state, session_id).await {
        SessionKind::Missing => ExecTarget::Unavailable(ExecResult::fail("Session not found")),
        SessionKind::SingleChannel => ExecTarget::Unavailable(single_channel_result()),
        SessionKind::Ssh(conn) => ExecTarget::Ssh(conn),
        SessionKind::NoConnection { local: true } => ExecTarget::Local,
        SessionKind::NoConnection { local: false } => {
            let protocol = match state.sessions.get(session_id) {
                Some(entry) => entry.lock().await.protocol,
                None => "",
            };
            ExecTarget::Unavailable(ExecResult::fail(if protocol == "ssh" {
                "Session not found or not connected"
            } else {
                "Session not supported for system management"
            }))
        }
    };
    DesktopExec {
        target,
        queue: state.system.queue(session_id),
        sudo: state.system.sudo.get(session_id).map(|s| s.value().clone()),
    }
}

async fn exec_for<R: Runtime>(state: &AppState<R>, payload: &Value) -> DesktopExec {
    resolve_exec(state, session_id_of(payload).unwrap_or("")).await
}

/// Declare a command that forwards its payload to a stateless sysmgr op.
macro_rules! sysmgr_commands {
    ($($name:ident => $op:path;)*) => {$(
        #[tauri::command]
        pub async fn $name<R: Runtime>(state: Ctx<'_, R>, payload: Value) -> CmdResult<Value> {
            let exec = exec_for(&state, &payload).await;
            Ok($op(&exec, &payload).await)
        }
    )*};
}

sysmgr_commands! {
    system_probe_capabilities => system::probe_capabilities;
    system_list_processes => system::list_processes;
    system_signal_process => system::signal_process;
    system_setup_osc7_tracking => system::setup_osc7_tracking;
    system_list_docker_containers => docker::list_containers;
    system_list_docker_images => docker::list_images;
    system_docker_stats => docker::get_stats;
    system_docker_inspect => docker::inspect_container;
    system_docker_image_inspect => docker::inspect_image;
    system_docker_action => docker::container_action;
    system_docker_image_action => docker::image_action;
    system_kubectl => kubectl::run;
    system_list_accelerators => gpu::list_accelerators;
    system_list_listening_ports => ports::list_listening_ports;
    system_list_services => services::list_services;
    system_service_action => services::service_action;
}

#[tauri::command]
pub async fn system_list_tmux_sessions<R: Runtime>(
    state: Ctx<'_, R>,
    payload: Value,
) -> CmdResult<Value> {
    let exec = exec_for(&state, &payload).await;
    Ok(state.system.tmux.list_sessions(&exec, &payload).await)
}

#[tauri::command]
pub async fn system_create_tmux_session<R: Runtime>(
    state: Ctx<'_, R>,
    payload: Value,
) -> CmdResult<Value> {
    let exec = exec_for(&state, &payload).await;
    Ok(state.system.tmux.create_session(&exec, &payload).await)
}

#[tauri::command]
pub async fn system_list_tmux_windows<R: Runtime>(
    state: Ctx<'_, R>,
    payload: Value,
) -> CmdResult<Value> {
    let exec = exec_for(&state, &payload).await;
    Ok(state.system.tmux.list_windows(&exec, &payload).await)
}

#[tauri::command]
pub async fn system_list_tmux_panes<R: Runtime>(
    state: Ctx<'_, R>,
    payload: Value,
) -> CmdResult<Value> {
    let exec = exec_for(&state, &payload).await;
    Ok(state.system.tmux.list_panes(&exec, &payload).await)
}

#[tauri::command]
pub async fn system_list_tmux_clients<R: Runtime>(
    state: Ctx<'_, R>,
    payload: Value,
) -> CmdResult<Value> {
    let exec = exec_for(&state, &payload).await;
    Ok(state.system.tmux.list_clients(&exec, &payload).await)
}

#[tauri::command]
pub async fn system_tmux_action<R: Runtime>(state: Ctx<'_, R>, payload: Value) -> CmdResult<Value> {
    let exec = exec_for(&state, &payload).await;
    Ok(state.system.tmux.action(&exec, &payload).await)
}

fn fail(error: &str) -> Value {
    json!({ "success": false, "error": error })
}

/// `getServerStats`: CPU / memory / disk / network / GPU of the session's
/// host, sampled on its existing SSH connection.
#[tauri::command]
pub async fn session_server_stats<R: Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
) -> CmdResult<Value> {
    Ok(match session_kind(&state, &session_id).await {
        SessionKind::Ssh(conn) => state.system.full_sample(conn).await,
        SessionKind::SingleChannel => fail(SINGLE_CHANNEL_ERROR),
        SessionKind::Missing | SessionKind::NoConnection { .. } => {
            fail("Session not found or not connected")
        }
    })
}

/// `getSessionDistroInfo`: `cat /etc/os-release || uname -a` on the
/// session's connection.
#[tauri::command]
pub async fn session_distro_info<R: Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
) -> CmdResult<Value> {
    let conn = match session_kind(&state, &session_id).await {
        SessionKind::Ssh(conn) => conn,
        SessionKind::SingleChannel => return Ok(fail(SINGLE_CHANNEL_ERROR)),
        _ => return Ok(fail("Session not found or not connected")),
    };
    let bound = Duration::from_millis(stats::DISTRO_TIMEOUT_MS);
    Ok(
        match bounded_exec(
            &conn,
            &stats::distro_command(),
            None,
            bound,
            bound,
            256 * 1024,
        )
        .await
        {
            Ok(out) => json!({
                "success": true,
                "stdout": String::from_utf8_lossy(&out.stdout),
                "stderr": String::from_utf8_lossy(&out.stderr),
            }),
            Err(err) => fail(&err.to_string()),
        },
    )
}

/// `readRemoteHistory`: the login shell's history file(s).
#[tauri::command]
pub async fn session_read_remote_history<R: Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
    limit: Option<Value>,
) -> CmdResult<Value> {
    let conn = match session_kind(&state, &session_id).await {
        SessionKind::Ssh(conn) => conn,
        SessionKind::Missing => return Ok(fail("Session not found")),
        SessionKind::SingleChannel => return Ok(fail(SINGLE_CHANNEL_ERROR)),
        SessionKind::NoConnection { .. } => return Ok(fail("Session not found or not connected")),
    };
    let command = history::remote_history_command(history::safe_limit(limit.as_ref()));
    let bound = Duration::from_millis(history::HISTORY_TIMEOUT_MS);
    Ok(
        match bounded_exec(
            &conn,
            &command,
            None,
            bound,
            bound,
            history::HISTORY_MAX_OUTPUT_BYTES,
        )
        .await
        {
            Ok(out) => history::history_reply(&String::from_utf8_lossy(&out.stdout)),
            Err(err) => fail(&err.to_string()),
        },
    )
}

/// One direct child of a local terminal's shell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChildProcess {
    pub pid: u32,
    pub command: String,
}

/// Electron `defaultListPosix` filter: `pid ppid args` rows whose ppid is
/// `parent`.
pub fn parse_child_processes(stdout: &str, parent: u32) -> Vec<ChildProcess> {
    stdout
        .lines()
        .filter_map(|line| {
            let (pid, rest) = line.trim().split_once(char::is_whitespace)?;
            let (ppid, command) = rest.trim_start().split_once(char::is_whitespace)?;
            let pid: u32 = pid.parse().ok()?;
            let ppid: u32 = ppid.parse().ok()?;
            let command = command.trim();
            (ppid == parent && !command.is_empty()).then(|| ChildProcess {
                pid,
                command: command.to_string(),
            })
        })
        .collect()
}

async fn list_children(parent: u32) -> Vec<ChildProcess> {
    let timeout = Duration::from_secs(3);
    if cfg!(windows) {
        let script = format!(
            "Get-CimInstance Win32_Process -Filter \"ParentProcessId={parent}\" | Select-Object ProcessId,Name | ConvertTo-Json -Compress"
        );
        let result = exec::local_exec(
            &netcatty_sysmgr::exec::ExecRequest::new(script, timeout.as_millis() as u64)
                .with_max_buffer(4 * 1024 * 1024),
        )
        .await;
        let Ok(raw) = serde_json::from_str::<Value>(result.stdout.trim()) else {
            return Vec::new();
        };
        let items = match raw {
            Value::Array(items) => items,
            other => vec![other],
        };
        return items
            .iter()
            .filter_map(|p| {
                Some(ChildProcess {
                    pid: p.get("ProcessId")?.as_u64()? as u32,
                    command: p.get("Name")?.as_str()?.to_string(),
                })
            })
            .collect();
    }
    let output = tokio::time::timeout(
        timeout,
        tokio::process::Command::new("ps")
            .args(["-A", "-o", "pid=", "-o", "ppid=", "-o", "args="])
            .kill_on_drop(true)
            .output(),
    )
    .await;
    match output {
        Ok(Ok(out)) if out.status.success() && out.stdout.len() <= 4 * 1024 * 1024 => {
            parse_child_processes(&String::from_utf8_lossy(&out.stdout), parent)
        }
        _ => Vec::new(),
    }
}

/// `ptyGetChildProcesses`: processes started from a local terminal's shell
/// (busy check before closing the tab).
#[tauri::command]
pub async fn pty_child_processes<R: Runtime>(
    state: Ctx<'_, R>,
    session_id: String,
) -> CmdResult<Vec<ChildProcess>> {
    let Some(entry) = state.sessions.get(&session_id) else {
        return Ok(Vec::new());
    };
    let pid = match &entry.lock().await.backend {
        SessionBackend::Local { pty } => pty.pid,
        _ => None,
    };
    Ok(match pid {
        Some(pid) if pid > 0 => list_children(pid).await,
        _ => Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_process_rows() {
        let out = "  1     0 /sbin/launchd\n 501   42 vim notes.txt\n 502   42   sleep 10\n 503 41 other\nbad row\n";
        assert_eq!(
            parse_child_processes(out, 42),
            vec![
                ChildProcess {
                    pid: 501,
                    command: "vim notes.txt".into()
                },
                ChildProcess {
                    pid: 502,
                    command: "sleep 10".into()
                },
            ]
        );
    }

    #[test]
    fn remembers_sudo_and_single_channel_options() {
        let state = SystemState::default();
        let options: SshSessionOptions = serde_json::from_value(json!({
            "hostname": "h", "username": "u",
            "sudoAutofillPassword": "pw", "singleChannelSsh": true
        }))
        .unwrap();
        state.remember_session("s1", &options);
        assert_eq!(state.sudo.get("s1").unwrap().value(), "pw");
        assert!(state.single_channel.contains("s1"));
        state.forget_session("s1");
        assert!(state.sudo.get("s1").is_none());
    }
}

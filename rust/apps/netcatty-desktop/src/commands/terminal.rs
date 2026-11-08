//! Terminal plumbing and autocomplete (`rust/docs/ipc-terminal.md`).
//!
//! * Paste write receipts (`netcatty:paste-write`, `onTerminalPasteWrite`)
//!   and cancellation of paced (line-by-line) writes, mirroring
//!   `createPasteWriteReceipt` / `clearPendingAutomatedWrites` in
//!   `electron/bridges/terminalBridge.cjs`.
//! * `netcatty:connection-reuse:fallback` when a terminal asked to reuse a
//!   source session's transport and had to dial a fresh one.
//! * `getWindowsPtyInfo` (xterm `windowsPty`).
//! * Fig autocomplete specs (`listFigSpecs` / `loadFigSpec`) and the
//!   directory listings autocomplete uses (`listAutocompleteLocalDir`,
//!   `listAutocompleteRemoteDir`).

use super::CmdResult;
use crate::events;
use crate::state::Ctx;
use netcatty_core::ipc::{SshSessionOptions, WriteToSessionPayload};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Manager, Runtime};

pub const PASTE_WRITE_EVENT: &str = "netcatty:paste-write";
pub const CONNECTION_REUSE_FALLBACK_EVENT: &str = "netcatty:connection-reuse:fallback";

// ---------------------------------------------------------------------------
// Paste write receipts
// ---------------------------------------------------------------------------

/// Managed state: in-flight receipted / paced writes per session.
#[derive(Default)]
pub struct TerminalState {
    pending: dashmap::DashMap<String, Vec<Arc<PasteWrite>>>,
}

/// One receipted or paced write batch (`createPasteWriteReceipt`).
/// Receipts confirm the transport write returned, not remote execution.
pub struct PasteWrite {
    session_id: String,
    request_id: Option<String>,
    active: AtomicBool,
    remaining: AtomicUsize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PasteWriteEvent {
    pub session_id: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub done: Option<bool>,
}

impl PasteWrite {
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Receipt to emit for finishing chunk `index` (`None`: the whole batch
    /// was cancelled or blocked), or `None` when nothing is reported.
    fn finish_event(&self, index: Option<usize>, skipped: bool) -> Option<PasteWriteEvent> {
        if !self.is_active() {
            return None;
        }
        let done = index.is_none() || self.remaining.fetch_sub(1, Ordering::SeqCst) <= 1;
        if done {
            self.active.store(false, Ordering::SeqCst);
        }
        let request_id = self.request_id.clone()?;
        if skipped && !done {
            return None;
        }
        Some(PasteWriteEvent {
            session_id: self.session_id.clone(),
            request_id,
            index: if skipped { None } else { index },
            done: done.then_some(true),
        })
    }

    /// Chunk `index` was handed to the transport (`skipped`: it failed).
    pub fn finish<R: Runtime>(&self, app: &AppHandle<R>, index: Option<usize>, skipped: bool) {
        if let Some(event) = self.finish_event(index, skipped) {
            events::emit(app, PASTE_WRITE_EVENT, event);
        }
        if !self.is_active() {
            if let Some(state) = app.try_state::<TerminalState>() {
                if let Some(mut list) = state.pending.get_mut(&self.session_id) {
                    list.retain(|p| p.is_active());
                }
            }
        }
    }
}

/// Does this write supersede pending paced writes of the session? (Pastes,
/// paced writes and real keystrokes do; xterm's automatic reports do not.)
fn supersedes_pending(payload: &WriteToSessionPayload) -> bool {
    let is_paste = payload.paste_request_id.as_deref().is_some_and(|id| !id.is_empty());
    is_paste
        || payload.line_delay_ms.is_some_and(|ms| ms > 0)
        || (!payload.automated
            && (payload.binary || !netcatty_telnet::is_terminal_report_sequence(&payload.data)))
}

/// Cancel every pending paced / receipted write of a session.
pub fn cancel_pending_writes<R: Runtime>(app: &AppHandle<R>, session_id: &str) {
    let Some(state) = app.try_state::<TerminalState>() else {
        return;
    };
    let pending = state
        .pending
        .remove(session_id)
        .map(|(_, list)| list)
        .unwrap_or_default();
    for paste in pending {
        paste.finish(app, None, false);
    }
}

/// `session_write` hook, before the write: cancel superseded writes and
/// create the receipt of this one (`chunks` transport writes).
pub fn begin_write<R: Runtime>(
    app: &AppHandle<R>,
    payload: &WriteToSessionPayload,
    chunks: usize,
) -> Option<Arc<PasteWrite>> {
    if supersedes_pending(payload) {
        cancel_pending_writes(app, &payload.session_id);
    }
    let request_id = payload.paste_request_id.clone().filter(|id| !id.is_empty());
    let paced = payload.line_delay_ms.is_some_and(|ms| ms > 0);
    // Paced batches need a handle (cancellation) even without a receipt.
    if request_id.is_none() && !paced {
        return None;
    }
    let paste = Arc::new(PasteWrite {
        session_id: payload.session_id.clone(),
        request_id,
        active: AtomicBool::new(true),
        remaining: AtomicUsize::new(chunks.max(1)),
    });
    if let Some(state) = app.try_state::<TerminalState>() {
        state
            .pending
            .entry(payload.session_id.clone())
            .or_default()
            .push(paste.clone());
    }
    Some(paste)
}

/// `interruptSession(id, trace, { cancelPendingWritesOnly: true })`: drop
/// queued paste lines without sending Ctrl+C.
#[tauri::command]
pub fn terminal_cancel_pending_writes<R: Runtime>(app: AppHandle<R>, session_id: String) {
    cancel_pending_writes(&app, &session_id);
}

// ---------------------------------------------------------------------------
// Connection reuse fallback
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionReuseFallback<'a> {
    session_id: &'a str,
    source_session_id: &'a str,
}

/// Should `session_start_ssh` report that it could not reuse the source
/// session's transport?
pub fn reuse_fell_back(payload: &SshSessionOptions, reused: bool) -> bool {
    !reused
        && payload.reuse_transport != Some(false)
        && payload.single_channel_ssh != Some(true)
        && payload
            .source_session_id
            .as_deref()
            .is_some_and(|s| !s.is_empty())
}

/// `session_start_ssh` hook: emit `netcatty:connection-reuse:fallback`
/// when `sourceSessionId` was requested but a fresh connection was dialed.
pub fn notify_reuse_fallback<R: Runtime>(
    app: &AppHandle<R>,
    session_id: &str,
    payload: &SshSessionOptions,
    reused: bool,
) {
    if !reuse_fell_back(payload, reused) {
        return;
    }
    let source = payload.source_session_id.as_deref().unwrap_or_default();
    events::emit(
        app,
        CONNECTION_REUSE_FALLBACK_EVENT,
        ConnectionReuseFallback {
            session_id,
            source_session_id: source,
        },
    );
}

// ---------------------------------------------------------------------------
// Windows PTY info
// ---------------------------------------------------------------------------

/// xterm `windowsPty` option. portable-pty always uses ConPTY (it has no
/// winpty fallback), so the backend is `conpty`; the build number lets
/// xterm pick its reflow heuristics.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsPtyInfo {
    pub backend: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_number: Option<u32>,
}

/// Build number from `ver` output ("Microsoft Windows [Version 10.0.19045.3803]").
pub fn parse_windows_build(ver: &str) -> Option<u32> {
    let start = ver.find("Version ")? + "Version ".len();
    let version: String = ver[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    version.split('.').nth(2)?.parse().ok()
}

#[cfg(windows)]
fn windows_build_number() -> Option<u32> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("cmd")
        .args(["/d", "/c", "ver"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    parse_windows_build(&String::from_utf8_lossy(&out.stdout))
}

/// `getWindowsPtyInfo()`: `null` off Windows.
#[tauri::command]
pub async fn terminal_windows_pty_info() -> Option<WindowsPtyInfo> {
    #[cfg(windows)]
    {
        static INFO: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
        let build = match INFO.get() {
            Some(build) => *build,
            None => {
                let build = tokio::task::spawn_blocking(windows_build_number)
                    .await
                    .ok()
                    .flatten();
                *INFO.get_or_init(|| build)
            }
        };
        Some(WindowsPtyInfo {
            backend: "conpty",
            build_number: build,
        })
    }
    #[cfg(not(windows))]
    {
        None
    }
}

// ---------------------------------------------------------------------------
// Fig autocomplete specs
// ---------------------------------------------------------------------------

/// Heavy cloud specs Electron does not ship either.
const EXCLUDED_FIGSPEC_PREFIXES: [&str; 3] = ["aws", "gcloud", "az"];

pub fn is_excluded_figspec(name: &str) -> bool {
    EXCLUDED_FIGSPEC_PREFIXES
        .iter()
        .any(|p| name == *p || name.starts_with(&format!("{p}/")))
}

/// `netcatty:figspec:load` name check: no absolute paths, traversal or
/// characters outside `[@a-zA-Z0-9._/+-]`.
pub fn valid_figspec_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.starts_with('\\')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._/+-".contains(&b))
}

/// Spec directories: `<resources>/figspecs/{withfig,local}` (staged by
/// `rust/scripts/stage-figspecs.cjs`), else the repository checkout in
/// debug builds (`node_modules/@withfig/autocomplete/build`, `electron/specs`).
fn figspec_dirs<R: Runtime>(app: &AppHandle<R>) -> (Option<PathBuf>, Option<PathBuf>) {
    let mut withfig = Vec::new();
    let mut local = Vec::new();
    if let Ok(resources) = app.path().resource_dir() {
        withfig.push(resources.join("figspecs").join("withfig"));
        local.push(resources.join("figspecs").join("local"));
    }
    if cfg!(debug_assertions) {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        withfig.push(repo.join("node_modules/@withfig/autocomplete/build"));
        local.push(repo.join("electron/specs"));
    }
    (
        withfig.into_iter().find(|p| p.is_dir()),
        local.into_iter().find(|p| p.is_dir()),
    )
}

/// Spec names in `@withfig/autocomplete/build/index.js`
/// (`var e=[...];…export{t as default}`).
pub fn parse_figspec_index(source: &str) -> Vec<String> {
    let Some(start) = source.find('[') else {
        return Vec::new();
    };
    let bytes = source.as_bytes();
    let (mut depth, mut in_str, mut escaped) = (0usize, false, false);
    let mut end = None;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_str {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    end.and_then(|end| serde_json::from_str(&source[start..=end]).ok())
        .unwrap_or_default()
}

fn local_spec_names(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    name.strip_suffix(".js").map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `listFigSpecs()`: `@withfig/autocomplete` names plus Netcatty's own
/// specs, without the excluded cloud CLIs.
#[tauri::command]
pub async fn figspec_list<R: Runtime>(app: AppHandle<R>) -> Vec<String> {
    let (withfig, local) = figspec_dirs(&app);
    tokio::task::spawn_blocking(move || {
        let mut names = withfig
            .and_then(|dir| std::fs::read_to_string(dir.join("index.js")).ok())
            .map(|src| parse_figspec_index(&src))
            .unwrap_or_default();
        if let Some(dir) = local {
            names.extend(local_spec_names(&dir));
        }
        let mut seen = std::collections::HashSet::new();
        names.retain(|n| !is_excluded_figspec(n) && seen.insert(n.clone()));
        names
    })
    .await
    .unwrap_or_default()
}

/// `loadFigSpec(name)`: the spec module's JavaScript source (an ES module
/// whose default export is the spec), or `null`. The renderer adapter
/// evaluates it and JSON round-trips the result like Electron's main
/// process did.
#[tauri::command]
pub async fn figspec_load<R: Runtime>(app: AppHandle<R>, command_name: String) -> Option<String> {
    if !valid_figspec_name(&command_name) || is_excluded_figspec(&command_name) {
        return None;
    }
    let (withfig, local) = figspec_dirs(&app);
    let file = format!("{command_name}.js");
    for dir in [local, withfig].into_iter().flatten() {
        let path = dir.join(&file);
        if let Ok(source) = tokio::fs::read_to_string(&path).await {
            return Some(source);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Directory listings for autocomplete
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDirPayload {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub folders_only: Option<bool>,
    #[serde(default)]
    pub filter_prefix: Option<String>,
    #[serde(default)]
    pub limit: Option<f64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ListDirResult {
    pub success: bool,
    pub entries: Vec<DirEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ListDirResult {
    fn fail(error: Option<&str>) -> Self {
        Self {
            success: false,
            entries: Vec::new(),
            error: error.map(str::to_string),
        }
    }
}

/// `limit` clamped to 1..=200 (default 100).
pub fn clamp_limit(limit: Option<f64>) -> usize {
    match limit {
        Some(l) if l.is_finite() => (l.floor() as i64).clamp(1, 200) as usize,
        _ => 100,
    }
}

/// `listAutocompleteLocalDir(path, foldersOnly, filterPrefix, limit)`.
#[tauri::command]
pub async fn autocomplete_local_listdir(payload: ListDirPayload) -> ListDirResult {
    let Some(path) = payload.path.filter(|p| !p.is_empty()) else {
        return ListDirResult::fail(Some("Invalid directory path"));
    };
    let resolved = match path.strip_prefix('~') {
        Some(rest) => match dirs::home_dir() {
            Some(home) => PathBuf::from(format!("{}{rest}", home.to_string_lossy())),
            None => PathBuf::from(&path),
        },
        None => PathBuf::from(&path),
    };
    let prefix = payload.filter_prefix.unwrap_or_default().to_lowercase();
    let max = clamp_limit(payload.limit);
    let folders_only = payload.folders_only.unwrap_or(false);
    let Ok(mut rd) = tokio::fs::read_dir(&resolved).await else {
        return ListDirResult::fail(None);
    };
    let mut entries = Vec::new();
    while let Ok(Some(entry)) = rd.next_entry().await {
        if entries.len() >= max {
            break;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." {
            continue;
        }
        if !prefix.is_empty() && !name.to_lowercase().starts_with(&prefix) {
            continue;
        }
        let Ok(ft) = entry.file_type().await else {
            continue;
        };
        let kind = if ft.is_dir() {
            "directory"
        } else if ft.is_symlink() {
            "symlink"
        } else {
            "file"
        };
        if folders_only {
            match kind {
                "directory" => {}
                "symlink" => {
                    let target_is_dir = tokio::fs::metadata(resolved.join(&name))
                        .await
                        .map(|m| m.is_dir())
                        .unwrap_or(false);
                    if !target_is_dir {
                        continue;
                    }
                }
                _ => continue,
            }
        }
        entries.push(DirEntry {
            name,
            kind: kind.to_string(),
        });
    }
    ListDirResult {
        success: true,
        entries,
        error: None,
    }
}

/// Resolve the interactive shell's cwd first for relative paths (exec
/// channels start in the home directory).
const REMOTE_CWD_RESOLVE: &str = r#"_sc_p=$(ps --ppid $PPID -o pid= -o comm= 2>/dev/null | awk -v self=$$ '$1!=self && $2~/^(ba|z|fi|k|da)?sh$/{pid=$1}END{print pid}'); [ -z "$_sc_p" ] && _sc_p=$(ps -e -o pid= -o ppid= -o comm= 2>/dev/null | awk -v pp=$PPID -v self=$$ '$1!=self && $2==pp && $3~/^(ba|z|fi|k|da)?sh$/{pid=$1}END{print pid}'); [ -n "$_sc_p" ] && { _sc_d=$(readlink /proc/$_sc_p/cwd 2>/dev/null); [ -n "$_sc_d" ] && cd "$_sc_d" 2>/dev/null; }; "#;

/// NUL-delimited `name\0type\0` stream from plain POSIX sh / find.
const REMOTE_LIST_SCRIPT: &str = r#"
          prefix="$1"
          folders_only="$2"
          limit="$3"
          shift 3
          count=0
          for path do
            name=${path##*/}
            lower_name=$(printf "%s" "$name" | tr "[:upper:]" "[:lower:]")
            if [ -n "$prefix" ]; then
              case "$lower_name" in
                "$prefix"*) ;;
                *) continue ;;
              esac
            fi
            if [ "$folders_only" -eq 1 ] && [ ! -d "$path" ]; then
              continue
            fi
            if [ -L "$path" ]; then
              type="symlink"
            elif [ -d "$path" ]; then
              type="directory"
            else
              type="file"
            fi
            printf "%s\0%s\0" "$name" "$type"
            count=$((count + 1))
            if [ "$count" -ge "$limit" ]; then
              break
            fi
          done
        "#;

/// The remote listing command (`listSessionDir` in `sshBridge/sessionOps.cjs`).
pub fn remote_listdir_command(path: &str, folders_only: bool, filter_prefix: &str, max: usize) -> String {
    let safe_path = path.replace('\'', "'\\''");
    let prefix = filter_prefix.to_lowercase().replace('\'', "'\\''");
    let path_expr = if path == "~" {
        "\"$HOME\"".to_string()
    } else if let Some(rest) = path.strip_prefix("~/") {
        let mut escaped = String::new();
        for c in rest.chars() {
            if matches!(c, '"' | '\\' | '$' | '`') {
                escaped.push('\\');
            }
            escaped.push(c);
        }
        format!("\"$HOME/{escaped}\"")
    } else {
        format!("'{safe_path}'")
    };
    let needs_cwd = !path.starts_with('/') && path != "~" && !path.starts_with("~/");
    format!(
        "{}find {path_expr} -mindepth 1 -maxdepth 1 -exec sh -c '{REMOTE_LIST_SCRIPT}' sh '{prefix}' {} {max} {{}} + 2>/dev/null",
        if needs_cwd { REMOTE_CWD_RESOLVE } else { "" },
        u8::from(folders_only),
    )
}

/// Parse the `name\0type\0` stream; `None` when a name has no type.
pub fn parse_remote_listing(output: &[u8], max: usize) -> Option<Vec<DirEntry>> {
    let mut entries = Vec::new();
    let mut pending: Option<String> = None;
    let mut fields = output.split(|&b| b == 0).peekable();
    while let Some(field) = fields.next() {
        // The trailing NUL produces one empty final field.
        if fields.peek().is_none() && field.is_empty() {
            break;
        }
        let field = String::from_utf8_lossy(field).into_owned();
        match pending.take() {
            None => pending = Some(field),
            Some(name) => {
                entries.push(DirEntry { name, kind: field });
                if entries.len() >= max {
                    return Some(entries);
                }
            }
        }
    }
    if pending.is_some() {
        return None;
    }
    Some(entries)
}

/// `listAutocompleteRemoteDir(sessionId, path, foldersOnly, filterPrefix, limit)`:
/// one exec on the session's SSH connection.
#[tauri::command]
pub async fn autocomplete_remote_listdir<R: Runtime>(
    state: Ctx<'_, R>,
    payload: ListDirPayload,
) -> CmdResult<ListDirResult> {
    let session_id = payload.session_id.clone().unwrap_or_default();
    let Some(conn) = state.sessions.connection_of(&session_id) else {
        return Ok(ListDirResult::fail(Some("Session not found")));
    };
    if state.system.is_single_channel(&session_id) || super::system::single_channel_banner(&conn) {
        return Ok(ListDirResult::fail(Some(
            "Remote SSH server does not support extra exec channels",
        )));
    }
    let Some(path) = payload.path.filter(|p| !p.is_empty()) else {
        return Ok(ListDirResult::fail(Some("Invalid directory path")));
    };
    let max = clamp_limit(payload.limit);
    let cmd = remote_listdir_command(
        &path,
        payload.folders_only.unwrap_or(false),
        payload.filter_prefix.as_deref().unwrap_or(""),
        max,
    );
    match conn.exec(&cmd, Some(Duration::from_secs(6))).await {
        Ok(out) => Ok(match parse_remote_listing(&out.stdout, max) {
            Some(entries) => ListDirResult {
                success: true,
                entries,
                error: None,
            },
            None => ListDirResult::fail(Some("Invalid directory listing response")),
        }),
        Err(err) => Ok(ListDirResult::fail(Some(&err.to_string()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_payload(data: &str) -> WriteToSessionPayload {
        WriteToSessionPayload {
            session_id: "s".into(),
            data: data.into(),
            ..Default::default()
        }
    }

    fn paste(request: Option<&str>, chunks: usize) -> PasteWrite {
        PasteWrite {
            session_id: "s".into(),
            request_id: request.map(str::to_string),
            active: AtomicBool::new(true),
            remaining: AtomicUsize::new(chunks),
        }
    }

    #[test]
    fn paced_receipts_report_each_line_then_done() {
        // terminalBridge.pasteWriteReceipt.test.cjs: one receipt per line,
        // `done` on the last.
        let p = paste(Some("r1"), 3);
        let e0 = p.finish_event(Some(0), false).unwrap();
        assert_eq!((e0.index, e0.done), (Some(0), None));
        let e1 = p.finish_event(Some(1), false).unwrap();
        assert_eq!((e1.index, e1.done), (Some(1), None));
        let e2 = p.finish_event(Some(2), false).unwrap();
        assert_eq!((e2.index, e2.done), (Some(2), Some(true)));
        assert!(!p.is_active());
        assert!(p.finish_event(Some(3), false).is_none());
    }

    #[test]
    fn cancelled_batches_end_with_done_and_no_index() {
        let p = paste(Some("r2"), 3);
        p.finish_event(Some(0), false);
        let e = p.finish_event(None, false).unwrap();
        assert_eq!((e.index, e.done), (None, Some(true)));
        assert!(p.finish_event(Some(1), false).is_none());
        // Skipped middle chunks are silent; a skipped last one reports done.
        let q = paste(Some("r3"), 2);
        assert!(q.finish_event(Some(0), true).is_none());
        let e = q.finish_event(Some(1), true).unwrap();
        assert_eq!((e.index, e.done), (None, Some(true)));
        // Without a request id (paced broadcast peers) nothing is emitted.
        let silent = paste(None, 1);
        assert!(silent.finish_event(Some(0), false).is_none());
        assert!(!silent.is_active());
    }

    #[test]
    fn superseding_rules() {
        assert!(supersedes_pending(&write_payload("a")));
        let mut report = write_payload("\x1b[12;3R");
        assert!(!supersedes_pending(&report));
        report.paste_request_id = Some("p".into());
        assert!(supersedes_pending(&report));
        let mut automated = write_payload("ls\r");
        automated.automated = true;
        assert!(!supersedes_pending(&automated));
        automated.line_delay_ms = Some(10);
        assert!(supersedes_pending(&automated));
    }

    #[test]
    fn reuse_fallback_conditions() {
        let mut p = SshSessionOptions {
            source_session_id: Some("src".into()),
            ..Default::default()
        };
        assert!(reuse_fell_back(&p, false));
        assert!(!reuse_fell_back(&p, true));
        p.reuse_transport = Some(false);
        assert!(!reuse_fell_back(&p, false));
        p.reuse_transport = None;
        p.source_session_id = Some(String::new());
        assert!(!reuse_fell_back(&p, false));
    }

    #[test]
    fn windows_build_parsing() {
        assert_eq!(
            parse_windows_build("\r\nMicrosoft Windows [Version 10.0.19045.3803]\r\n"),
            Some(19045)
        );
        assert_eq!(parse_windows_build("garbage"), None);
    }

    #[test]
    fn figspec_names_and_index() {
        assert!(valid_figspec_name("git"));
        assert!(valid_figspec_name("@withfig/autocomplete-tools"));
        assert!(!valid_figspec_name("../etc/passwd"));
        assert!(!valid_figspec_name("/abs"));
        assert!(!valid_figspec_name("a b"));
        assert!(is_excluded_figspec("aws") && is_excluded_figspec("gcloud/x"));
        assert!(!is_excluded_figspec("awsx") && !is_excluded_figspec("azure"));
        let index = r#"var e=["-","@usermn/sdc/0.0.0","git","we]ird"];var t=e;export{t as default};"#;
        assert_eq!(
            parse_figspec_index(index),
            vec!["-", "@usermn/sdc/0.0.0", "git", "we]ird"]
        );
        assert!(parse_figspec_index("nothing").is_empty());
    }

    #[test]
    fn figspec_index_of_the_installed_package_parses() {
        let index = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../node_modules/@withfig/autocomplete/build/index.js");
        if let Ok(src) = std::fs::read_to_string(index) {
            let names = parse_figspec_index(&src);
            assert!(names.len() > 100);
            assert!(names.iter().any(|n| n == "git"));
        }
    }

    #[test]
    fn remote_listing_command_and_parser() {
        let cmd = remote_listdir_command("~/my \"dir\"", true, "Sr'c", 50);
        assert!(cmd.starts_with("find \"$HOME/my \\\"dir\\\"\" -mindepth 1"));
        assert!(cmd.contains("sh 'sr'\\''c' 1 50 {} +"));
        let rel = remote_listdir_command("src", false, "", 100);
        assert!(rel.starts_with("_sc_p=$(ps"));
        assert!(rel.contains("find 'src' "));
        assert!(remote_listdir_command("/etc", false, "", 1).starts_with("find '/etc'"));

        let out = b"a\0file\0dir x\0directory\0";
        let entries = parse_remote_listing(out, 10).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1], DirEntry { name: "dir x".into(), kind: "directory".into() });
        assert_eq!(parse_remote_listing(out, 1).unwrap().len(), 1);
        assert!(parse_remote_listing(b"orphan\0", 10).is_none());
        assert_eq!(parse_remote_listing(b"", 10).unwrap(), vec![]);
    }

    #[test]
    fn limits_are_clamped() {
        assert_eq!(clamp_limit(None), 100);
        assert_eq!(clamp_limit(Some(0.0)), 1);
        assert_eq!(clamp_limit(Some(500.0)), 200);
        assert_eq!(clamp_limit(Some(12.7)), 12);
        assert_eq!(clamp_limit(Some(f64::NAN)), 100);
    }

    #[tokio::test]
    async fn local_listing_filters_and_marks_types() {
        let dir = std::env::temp_dir().join(format!("ac-listdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Src")).unwrap();
        std::fs::write(dir.join("setup.py"), b"").unwrap();
        std::fs::write(dir.join("readme"), b"").unwrap();
        let list = |folders_only: bool, prefix: &str| ListDirPayload {
            session_id: None,
            path: Some(dir.to_string_lossy().into_owned()),
            folders_only: Some(folders_only),
            filter_prefix: Some(prefix.into()),
            limit: None,
        };
        let r = autocomplete_local_listdir(list(false, "s")).await;
        assert!(r.success);
        let mut names: Vec<_> = r.entries.iter().map(|e| e.name.clone()).collect();
        names.sort();
        assert_eq!(names, vec!["Src", "setup.py"]);
        let r = autocomplete_local_listdir(list(true, "")).await;
        assert_eq!(r.entries, vec![DirEntry { name: "Src".into(), kind: "directory".into() }]);
        let missing = autocomplete_local_listdir(ListDirPayload {
            path: Some("/definitely/missing".into()),
            ..list(false, "")
        })
        .await;
        assert!(!missing.success && missing.error.is_none());
        let invalid = autocomplete_local_listdir(ListDirPayload { path: None, ..list(false, "") }).await;
        assert_eq!(invalid.error.as_deref(), Some("Invalid directory path"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

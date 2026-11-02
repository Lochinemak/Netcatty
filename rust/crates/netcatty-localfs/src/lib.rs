//! `netcatty-localfs` — local filesystem operations for the file browser and
//! transfers (mirrors `electron/bridges/localFsBridge.cjs`).
//!
//! All functions are async and run blocking filesystem work on the tokio
//! blocking pool. Paths are passed as received from the renderer.

use futures::StreamExt;
use netcatty_core::format::{iso_from_ms, raw_bytes_string};
use netcatty_core::ipc::{LocalTreeEntry, LocalTreeProgressEvent, PathValidation, SystemInfo};
use netcatty_core::models::{FileEntryType, LinkTargetType, RemoteFile, StatResult};
use netcatty_core::{CoreError, CoreResult};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

mod owner;

/// Concurrency for per-entry `stat` calls in [`list_dir`].
const LIST_DIR_CONCURRENCY: usize = 32;
/// Default traversal budget of [`list_tree`] (same as the Electron bridge).
pub const MAX_LOCAL_TREE_DIRECTORIES: u64 = 50_000;
pub const MAX_LOCAL_TREE_ENTRIES: u64 = 200_000;
/// Progress batching for [`list_tree`].
const TREE_PROGRESS_BATCH_ENTRIES: usize = 200;
const TREE_PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
/// Upper bound for one archive extraction.
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

// ---------------------------------------------------------------------------
// Directory listing
// ---------------------------------------------------------------------------

/// List a directory. Mirrors `listLocalDir`: stat follows symlinks for
/// size/mtime/type, `linkTarget` records the target kind (`None` inside
/// `Some` for broken links), owner is the directory entry's uid as a string
/// (name when resolvable), and `hidden` reflects the Windows hidden
/// attribute (always `false` elsewhere). Entries that cannot be stat'ed are
/// skipped.
pub async fn list_dir(path: &str) -> CoreResult<Vec<RemoteFile>> {
    let dir = PathBuf::from(path);
    let mut read_dir = tokio::fs::read_dir(&dir)
        .await
        .map_err(|err| io_error("list", &dir, err))?;
    let mut entries = Vec::new();
    while let Some(entry) = read_dir
        .next_entry()
        .await
        .map_err(|err| io_error("list", &dir, err))?
    {
        entries.push(entry.path());
    }

    let files: Vec<Option<RemoteFile>> = futures::stream::iter(entries)
        .map(|full_path| async move { describe_entry(&full_path).await })
        .buffered(LIST_DIR_CONCURRENCY)
        .collect()
        .await;
    Ok(files.into_iter().flatten().collect())
}

async fn describe_entry(full_path: &Path) -> Option<RemoteFile> {
    let name = full_path.file_name()?.to_string_lossy().into_owned();
    let lstat = match tokio::fs::symlink_metadata(full_path).await {
        Ok(meta) => meta,
        Err(err) => {
            tracing::warn!(entry = %name, error = %err, "could not lstat directory entry; skipping");
            return None;
        }
    };

    let (entry_type, link_target, target_meta) = if lstat.file_type().is_symlink() {
        match tokio::fs::metadata(full_path).await {
            Ok(target) => {
                let kind = if target.is_dir() {
                    LinkTargetType::Directory
                } else {
                    LinkTargetType::File
                };
                (FileEntryType::Symlink, Some(Some(kind)), Some(target))
            }
            Err(err) => {
                tracing::debug!(entry = %name, error = %err, "broken symlink");
                (FileEntryType::Symlink, Some(None), None)
            }
        }
    } else if lstat.is_dir() {
        (FileEntryType::Directory, None, None)
    } else {
        (FileEntryType::File, None, None)
    };

    // Follow the target for size/mtime; owner is the directory entry itself.
    let size_meta = target_meta.as_ref().unwrap_or(&lstat);
    Some(RemoteFile {
        name,
        entry_type,
        size: raw_bytes_string(size_meta.len()),
        last_modified: iso_from_ms(modified_ms(size_meta)),
        link_target,
        permissions: None,
        owner: owner::owner_name(&lstat),
        group: None,
        hidden: Some(is_hidden(&lstat)),
    })
}

#[cfg(windows)]
fn is_hidden(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    meta.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0
}

#[cfg(not(windows))]
fn is_hidden(_meta: &std::fs::Metadata) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// Read a file. With `max_bytes`, return the **last** `max_bytes` bytes
/// (log tailing semantics of the Electron bridge).
pub async fn read_file(path: &str, max_bytes: Option<u64>) -> CoreResult<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let path = Path::new(path);
    let max_bytes = max_bytes.filter(|m| *m > 0);
    let Some(max_bytes) = max_bytes else {
        return tokio::fs::read(path)
            .await
            .map_err(|err| io_error("read", path, err));
    };

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|err| io_error("read", path, err))?;
    let size = file
        .metadata()
        .await
        .map_err(|err| io_error("read", path, err))?
        .len();
    let mut buf = Vec::with_capacity(size.min(max_bytes) as usize);
    if size > max_bytes {
        file.seek(std::io::SeekFrom::Start(size - max_bytes))
            .await
            .map_err(|err| io_error("read", path, err))?;
    }
    file.read_to_end(&mut buf)
        .await
        .map_err(|err| io_error("read", path, err))?;
    if buf.len() as u64 > max_bytes {
        // The file grew between stat and read; keep the tail.
        let drop = buf.len() - max_bytes as usize;
        buf.drain(..drop);
    }
    Ok(buf)
}

pub async fn write_file(path: &str, content: &[u8]) -> CoreResult<()> {
    let path = Path::new(path);
    tokio::fs::write(path, content)
        .await
        .map_err(|err| io_error("write", path, err))
}

/// Delete a file / symlink / directory tree. When `expected_type` is given
/// and differs from the current type, fail with `InvalidArgument` and the
/// message `Local target changed before replace: expected X, found Y`.
pub async fn delete(path: &str, expected_type: Option<FileEntryType>) -> CoreResult<()> {
    let path = Path::new(path);
    let meta = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|err| io_error("delete", path, err))?;
    let actual = entry_type_of(&meta.file_type());
    if let Some(expected) = expected_type {
        if expected != actual {
            return Err(CoreError::invalid(format!(
                "Local target changed before replace: expected {}, found {}",
                type_name(expected),
                type_name(actual)
            )));
        }
    }
    match actual {
        FileEntryType::Directory => tokio::fs::remove_dir_all(path).await,
        FileEntryType::Symlink => remove_symlink(path).await,
        FileEntryType::File => tokio::fs::remove_file(path).await,
    }
    .map_err(|err| io_error("delete", path, err))
}

#[cfg(windows)]
async fn remove_symlink(path: &Path) -> std::io::Result<()> {
    // Directory symlinks / junctions must be removed with RemoveDirectory.
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(first) => match tokio::fs::remove_dir(path).await {
            Ok(()) => Ok(()),
            Err(_) => Err(first),
        },
    }
}

#[cfg(not(windows))]
async fn remove_symlink(path: &Path) -> std::io::Result<()> {
    tokio::fs::remove_file(path).await
}

pub async fn rename(old_path: &str, new_path: &str) -> CoreResult<()> {
    let old = Path::new(old_path);
    tokio::fs::rename(old, new_path)
        .await
        .map_err(|err| io_error("rename", old, err))
}

/// `mkdir -p`; an existing directory is not an error (Windows drive roots).
pub async fn mkdir(path: &str) -> CoreResult<()> {
    let path = Path::new(path);
    match tokio::fs::create_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(err) => match tokio::fs::metadata(path).await {
            Ok(meta) if meta.is_dir() => Ok(()),
            _ => Err(io_error("create directory", path, err)),
        },
    }
}

/// Stat following symlinks; includes `dev`/`ino` except on Windows.
pub async fn stat(path: &str) -> CoreResult<StatResult> {
    let p = Path::new(path);
    let meta = tokio::fs::metadata(p)
        .await
        .map_err(|err| io_error("stat", p, err))?;
    let entry_type = if meta.is_dir() {
        FileEntryType::Directory
    } else {
        FileEntryType::File
    };
    Ok(stat_result(p, &meta, entry_type))
}

/// Stat without following symlinks.
pub async fn lstat(path: &str) -> CoreResult<StatResult> {
    let p = Path::new(path);
    let meta = tokio::fs::symlink_metadata(p)
        .await
        .map_err(|err| io_error("lstat", p, err))?;
    let entry_type = entry_type_of(&meta.file_type());
    Ok(stat_result(p, &meta, entry_type))
}

fn stat_result(path: &Path, meta: &std::fs::Metadata, entry_type: FileEntryType) -> StatResult {
    let (dev, ino) = fs_identity(meta);
    StatResult {
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        entry_type,
        size: meta.len(),
        size_known: None,
        last_modified: modified_ms(meta),
        permissions: None,
        owner: None,
        group: None,
        dev,
        ino,
    }
}

#[cfg(unix)]
fn fs_identity(meta: &std::fs::Metadata) -> (Option<u64>, Option<u64>) {
    use std::os::unix::fs::MetadataExt;
    (Some(meta.dev()), Some(meta.ino()))
}

#[cfg(not(unix))]
fn fs_identity(_meta: &std::fs::Metadata) -> (Option<u64>, Option<u64>) {
    (None, None)
}

pub async fn realpath(path: &str) -> CoreResult<String> {
    let p = Path::new(path);
    let resolved = tokio::fs::canonicalize(p)
        .await
        .map_err(|err| io_error("resolve", p, err))?;
    Ok(strip_verbatim_prefix(resolved))
}

#[cfg(windows)]
fn strip_verbatim_prefix(path: PathBuf) -> String {
    let text = path.to_string_lossy().into_owned();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        text
    }
}

#[cfg(not(windows))]
fn strip_verbatim_prefix(path: PathBuf) -> String {
    path.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// Archives
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    TarGz,
    TarBz2,
    TarXz,
    TarZst,
    Tar,
    Zip,
    Gz,
    Bz2,
    Xz,
}

const ARCHIVE_SUFFIXES: &[(&str, ArchiveKind)] = &[
    (".tar.gz", ArchiveKind::TarGz),
    (".tgz", ArchiveKind::TarGz),
    (".tar.bz2", ArchiveKind::TarBz2),
    (".tbz2", ArchiveKind::TarBz2),
    (".tar.bzip2", ArchiveKind::TarBz2),
    (".tar.xz", ArchiveKind::TarXz),
    (".txz", ArchiveKind::TarXz),
    (".tar.zst", ArchiveKind::TarZst),
    (".tzst", ArchiveKind::TarZst),
    (".tar", ArchiveKind::Tar),
    (".zip", ArchiveKind::Zip),
    (".gz", ArchiveKind::Gz),
    (".bz2", ArchiveKind::Bz2),
    (".xz", ArchiveKind::Xz),
];

fn archive_kind(file_name: &str) -> Option<ArchiveKind> {
    let lower = file_name.to_ascii_lowercase();
    ARCHIVE_SUFFIXES
        .iter()
        .find(|(suffix, _)| lower.ends_with(suffix) && lower.len() > suffix.len())
        .map(|(_, kind)| *kind)
}

/// Whether [`extract_archive`] knows how to unpack this file name.
pub fn is_extractable_archive(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(archive_kind)
        .is_some()
}

struct ExtractPlan {
    command: &'static str,
    args: Vec<String>,
    fallback: Option<(&'static str, Vec<String>)>,
}

fn build_extract_plan(archive: &Path) -> CoreResult<ExtractPlan> {
    let file_name = archive
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let kind = archive_kind(file_name)
        .ok_or_else(|| CoreError::unsupported(format!("Unsupported archive type: {file_name}")))?;
    let parent = archive
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| CoreError::invalid("Archive path has no parent directory"))?;
    let archive_s = archive.to_string_lossy().into_owned();
    let parent_s = parent.to_string_lossy().into_owned();
    let tar = |flag: &str| {
        vec![
            flag.to_string(),
            archive_s.clone(),
            "-C".to_string(),
            parent_s.clone(),
        ]
    };

    let plan = match kind {
        ArchiveKind::Tar => ExtractPlan {
            command: "tar",
            args: tar("-xf"),
            fallback: None,
        },
        ArchiveKind::TarGz => ExtractPlan {
            command: "tar",
            args: tar("-xzf"),
            fallback: None,
        },
        ArchiveKind::TarBz2 => ExtractPlan {
            command: "tar",
            args: tar("-xjf"),
            fallback: None,
        },
        ArchiveKind::TarXz => ExtractPlan {
            command: "tar",
            args: tar("-xJf"),
            fallback: None,
        },
        ArchiveKind::TarZst => ExtractPlan {
            command: "tar",
            args: vec![
                "--zstd".into(),
                "-xf".into(),
                archive_s.clone(),
                "-C".into(),
                parent_s.clone(),
            ],
            fallback: None,
        },
        ArchiveKind::Zip if cfg!(windows) => ExtractPlan {
            command: "tar",
            args: tar("-xf"),
            fallback: None,
        },
        ArchiveKind::Zip => ExtractPlan {
            command: "unzip",
            args: vec![
                "-qo".into(),
                archive_s.clone(),
                "-d".into(),
                parent_s.clone(),
            ],
            fallback: Some(("tar", tar("-xf"))),
        },
        // `-k` keeps the archive, `-f` overwrites an existing output file
        // (the Electron bridge stages + replaces, which is equivalent).
        ArchiveKind::Gz => ExtractPlan {
            command: "gunzip",
            args: vec!["-k".into(), "-f".into(), archive_s],
            fallback: None,
        },
        ArchiveKind::Bz2 => ExtractPlan {
            command: "bzip2",
            args: vec!["-d".into(), "-k".into(), "-f".into(), archive_s],
            fallback: None,
        },
        ArchiveKind::Xz => ExtractPlan {
            command: "xz",
            args: vec!["-d".into(), "-k".into(), "-f".into(), archive_s],
            fallback: None,
        },
    };
    Ok(plan)
}

async fn run_extract(command: &str, args: &[String], cwd: &Path) -> CoreResult<()> {
    let mut cmd = tokio::process::Command::new(command);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let child = cmd.spawn().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            CoreError::unsupported(format!(
                "Local extraction failed: `{command}` is not installed"
            ))
        } else {
            CoreError::io(format!(
                "Local extraction failed: could not start `{command}`: {err}"
            ))
        }
    })?;
    let output = match tokio::time::timeout(EXTRACT_TIMEOUT, child.wait_with_output()).await {
        Ok(result) => {
            result.map_err(|err| CoreError::io(format!("Local extraction failed: {err}")))?
        }
        Err(_) => {
            return Err(CoreError::timeout(format!(
                "Local extraction timed out after {} ms",
                EXTRACT_TIMEOUT.as_millis()
            )))
        }
    };
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    let stderr: String = stderr.chars().take(4096).collect();
    let code = output
        .status
        .code()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "signal".to_string());
    let detail = if stderr.is_empty() {
        String::new()
    } else {
        format!(": {stderr}")
    };
    Err(CoreError::io(format!(
        "Local extraction failed (code {code}){detail}"
    )))
}

/// Extract `.zip`, `.tar`, `.tar.gz`/`.tgz`, `.tar.bz2`, `.tar.xz` next to
/// the archive using the system `tar` / `unzip` binaries.
pub async fn extract_archive(path: &str) -> CoreResult<()> {
    let archive = Path::new(path);
    let meta = tokio::fs::metadata(archive)
        .await
        .map_err(|err| io_error("extract", archive, err))?;
    if !meta.is_file() {
        return Err(CoreError::invalid("Archive path is not a file"));
    }
    let plan = build_extract_plan(archive)?;
    let cwd = archive.parent().unwrap_or(Path::new("."));
    match run_extract(plan.command, &plan.args, cwd).await {
        Ok(()) => Ok(()),
        Err(err)
            if err.code == netcatty_core::ErrorCode::Unsupported && plan.fallback.is_some() =>
        {
            let (command, args) = plan.fallback.expect("checked");
            run_extract(command, &args, cwd).await
        }
        Err(err) => Err(err),
    }
}

// ---------------------------------------------------------------------------
// Tree walk
// ---------------------------------------------------------------------------

/// Limits for [`list_tree`].
#[derive(Debug, Clone, Copy, Default)]
pub struct TreeLimits {
    pub max_directories: Option<u64>,
    pub max_entries: Option<u64>,
}

/// Recursively walk `path` (not following symlinks). Progress events with
/// batched entries are pushed to `progress` roughly every 200 entries or
/// 100 ms; the full list is returned at the end. Cancel with `cancel`.
///
/// Rows use `<root basename>/<relative>` paths with `/` separators (the
/// shape the renderer's upload planner expects); the root itself is not
/// emitted. Symlinks are never descended into: a link to a file becomes a
/// file row with the target's size, a link to a directory becomes an
/// (empty) directory row, broken links are skipped. When a limit is hit the
/// walk stops and returns what was collected so far.
pub async fn list_tree(
    scan_id: &str,
    path: &str,
    limits: TreeLimits,
    progress: Option<mpsc::UnboundedSender<LocalTreeProgressEvent>>,
    cancel: CancellationToken,
) -> CoreResult<Vec<LocalTreeEntry>> {
    let scan_id = scan_id.to_string();
    let root = PathBuf::from(path);
    tokio::task::spawn_blocking(move || walk_tree(&scan_id, &root, limits, progress, &cancel))
        .await
        .map_err(|err| CoreError::internal(format!("tree scan task failed: {err}")))?
}

struct TreeProgress {
    scan_id: String,
    sender: Option<mpsc::UnboundedSender<LocalTreeProgressEvent>>,
    pending: Vec<LocalTreeEntry>,
    file_count: u64,
    directory_count: u64,
    last_flush: Instant,
}

impl TreeProgress {
    fn push(&mut self, row: LocalTreeEntry) {
        match row.entry_type {
            FileEntryType::Directory => self.directory_count += 1,
            _ => self.file_count += 1,
        }
        if self.sender.is_some() {
            self.pending.push(row);
        }
    }

    fn maybe_flush(&mut self) {
        if self.pending.len() >= TREE_PROGRESS_BATCH_ENTRIES
            || self.last_flush.elapsed() >= TREE_PROGRESS_INTERVAL
        {
            self.flush(false);
        }
    }

    fn flush(&mut self, done: bool) {
        let Some(sender) = self.sender.as_ref() else {
            return;
        };
        if !done && self.pending.is_empty() {
            self.last_flush = Instant::now();
            return;
        }
        let event = LocalTreeProgressEvent {
            scan_id: self.scan_id.clone(),
            file_count: self.file_count,
            directory_count: self.directory_count,
            entry_count: self.file_count + self.directory_count,
            entries: std::mem::take(&mut self.pending),
            done,
        };
        if sender.send(event).is_err() {
            // Receiver went away; stop buffering rows for nobody.
            self.sender = None;
            self.pending = Vec::new();
        }
        self.last_flush = Instant::now();
    }
}

fn walk_tree(
    scan_id: &str,
    root: &Path,
    limits: TreeLimits,
    progress: Option<mpsc::UnboundedSender<LocalTreeProgressEvent>>,
    cancel: &CancellationToken,
) -> CoreResult<Vec<LocalTreeEntry>> {
    let root_meta = std::fs::metadata(root).map_err(|err| io_error("scan", root, err))?;
    if !root_meta.is_dir() {
        return Err(CoreError::invalid("Selected path is not a directory"));
    }
    let max_directories = limits.max_directories.unwrap_or(MAX_LOCAL_TREE_DIRECTORIES);
    let max_entries = limits.max_entries.unwrap_or(MAX_LOCAL_TREE_ENTRIES);
    let root_name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| {
            root.to_string_lossy()
                .trim_end_matches(['/', '\\'])
                .to_string()
        });

    let mut progress = TreeProgress {
        scan_id: scan_id.to_string(),
        sender: progress,
        pending: Vec::new(),
        file_count: 0,
        directory_count: 0,
        last_flush: Instant::now(),
    };

    let result = walk_tree_inner(
        root,
        &root_name,
        max_directories,
        max_entries,
        &mut progress,
        cancel,
    );
    // Always terminate the event stream, even on cancel/error, so listeners
    // can tear down (the Electron bridge sends `tree-end` in `finally`).
    progress.flush(true);
    result
}

fn walk_tree_inner(
    root: &Path,
    root_name: &str,
    max_directories: u64,
    max_entries: u64,
    progress: &mut TreeProgress,
    cancel: &CancellationToken,
) -> CoreResult<Vec<LocalTreeEntry>> {
    let cancelled = || CoreError::cancelled("Local directory traversal cancelled");
    if cancel.is_cancelled() {
        return Err(cancelled());
    }

    let mut collected: Vec<LocalTreeEntry> = Vec::new();
    let mut queue: VecDeque<(PathBuf, String)> = VecDeque::new();
    queue.push_back((root.to_path_buf(), root_name.to_string()));
    // The root counts as the first directory, as in the Electron bridge.
    let mut directories_visited: u64 = 1;
    let mut truncated = false;

    'walk: while let Some((dir_path, dir_rel)) = queue.pop_front() {
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        let read_dir = match std::fs::read_dir(&dir_path) {
            Ok(rd) => rd,
            Err(err) => {
                tracing::warn!(path = %dir_path.display(), error = %err, "could not read directory; skipping");
                continue;
            }
        };
        let mut children: Vec<(String, PathBuf)> = read_dir
            .filter_map(|entry| match entry {
                Ok(entry) => Some((entry.file_name().to_string_lossy().into_owned(), entry.path())),
                Err(err) => {
                    tracing::warn!(path = %dir_path.display(), error = %err, "could not read directory entry; skipping");
                    None
                }
            })
            .collect();
        children.sort_by(|a, b| a.0.cmp(&b.0));

        for (index, (name, child_path)) in children.into_iter().enumerate() {
            if index % 64 == 63 && cancel.is_cancelled() {
                return Err(cancelled());
            }
            if collected.len() as u64 >= max_entries {
                truncated = true;
                break 'walk;
            }
            let lstat = match std::fs::symlink_metadata(&child_path) {
                Ok(meta) => meta,
                Err(err) => {
                    tracing::warn!(path = %child_path.display(), error = %err, "could not inspect entry; skipping");
                    continue;
                }
            };
            let is_link = lstat.file_type().is_symlink();
            let meta = if is_link {
                match std::fs::metadata(&child_path) {
                    Ok(target) => target,
                    Err(err) => {
                        tracing::warn!(path = %child_path.display(), error = %err, "broken symlink; skipping");
                        continue;
                    }
                }
            } else {
                lstat
            };
            let is_directory = meta.is_dir();
            if is_directory {
                if directories_visited >= max_directories {
                    truncated = true;
                    break 'walk;
                }
                directories_visited += 1;
            }
            let relative_path = format!("{dir_rel}/{name}");
            let row = LocalTreeEntry {
                local_path: child_path.to_string_lossy().into_owned(),
                relative_path: relative_path.clone(),
                entry_type: if is_directory {
                    FileEntryType::Directory
                } else {
                    FileEntryType::File
                },
                size: meta.len(),
                last_modified: modified_ms(&meta),
            };
            collected.push(row.clone());
            progress.push(row);
            progress.maybe_flush();
            if is_directory && !is_link {
                queue.push_back((child_path, relative_path));
            }
        }
    }

    if truncated {
        tracing::warn!(
            entries = collected.len(),
            directories = directories_visited,
            "local tree scan stopped at its traversal budget; returning the partial tree"
        );
    }
    if cancel.is_cancelled() {
        return Err(cancelled());
    }
    Ok(collected)
}

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

pub fn home_dir() -> CoreResult<String> {
    dirs::home_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .ok_or_else(|| CoreError::not_found("home directory not found"))
}

/// Windows: drive letters (`C:\`, `D:\`); elsewhere: `["/"]`.
pub async fn list_drives() -> CoreResult<Vec<String>> {
    if !cfg!(windows) {
        return Ok(vec!["/".to_string()]);
    }
    tokio::task::spawn_blocking(|| {
        (b'A'..=b'Z')
            .map(|letter| format!("{}:\\", letter as char))
            .filter(|root| std::fs::metadata(root).is_ok())
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|err| CoreError::internal(format!("drive probe failed: {err}")))
}

pub fn system_info() -> SystemInfo {
    let username = ["USER", "USERNAME", "LOGNAME"]
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .map(|v| v.trim().to_string())
        .find(|v| !v.is_empty())
        .or_else(owner::current_user_name)
        .unwrap_or_else(|| "local".to_string());
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".to_string());
    SystemInfo { username, hostname }
}

/// `validatePath` IPC: existence and kind of a path.
pub async fn validate_path(path: &str) -> PathValidation {
    match tokio::fs::metadata(path).await {
        Ok(meta) => PathValidation {
            exists: true,
            is_file: meta.is_file(),
            is_directory: meta.is_dir(),
        },
        Err(_) => PathValidation::default(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn entry_type_of(file_type: &std::fs::FileType) -> FileEntryType {
    if file_type.is_symlink() {
        FileEntryType::Symlink
    } else if file_type.is_dir() {
        FileEntryType::Directory
    } else {
        FileEntryType::File
    }
}

fn type_name(entry_type: FileEntryType) -> &'static str {
    match entry_type {
        FileEntryType::File => "file",
        FileEntryType::Directory => "directory",
        FileEntryType::Symlink => "symlink",
    }
}

fn modified_ms(meta: &std::fs::Metadata) -> i64 {
    meta.modified().map(system_time_ms).unwrap_or(0)
}

fn system_time_ms(time: SystemTime) -> i64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

fn io_error(action: &str, path: &Path, err: std::io::Error) -> CoreError {
    let mut core = CoreError::from(err);
    core.message = format!("failed to {action} {}: {}", path.display(), core.message);
    core
}

#[cfg(test)]
mod tests;

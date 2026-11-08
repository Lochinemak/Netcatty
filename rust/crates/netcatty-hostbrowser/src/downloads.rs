//! Download history per host (Electron: `downloadStore.cjs`) and the
//! synchronous download file reservation (`downloadFile.cjs`).
//!
//! Byte progress of a running download is replaceable: it is applied in
//! memory immediately and written at most once a second; new records, state
//! transitions and recovery metadata are always written before returning.

use crate::fs::{atomic_write, now_ms, read_json};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub const MAX_DOWNLOADS: usize = 500;
pub const PROGRESS_PERSIST_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DownloadStatus {
    Waiting,
    Progressing,
    Completed,
    Cancelled,
    Interrupted,
}

impl DownloadStatus {
    pub fn is_active(self) -> bool {
        matches!(self, DownloadStatus::Waiting | DownloadStatus::Progressing)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Download {
    pub id: String,
    pub host_id: String,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub save_path: String,
    #[serde(default = "interrupted")]
    pub status: DownloadStatus,
    #[serde(default)]
    pub received: u64,
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub started_at: i64,
    #[serde(default)]
    pub ended_at: Option<i64>,
}

fn interrupted() -> DownloadStatus {
    DownloadStatus::Interrupted
}

/// A listed download: the record plus whether a completed file has gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadListed {
    #[serde(flatten)]
    pub item: Download,
    pub missing: bool,
}

fn take_chars(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn normalize_download(raw: Download) -> Result<Download, String> {
    if raw.id.is_empty() || raw.id.len() > 128 || raw.host_id.is_empty() || raw.host_id.len() > 256 {
        return Err("Invalid download".into());
    }
    Ok(Download {
        id: raw.id,
        host_id: raw.host_id,
        filename: take_chars(
            if raw.filename.is_empty() { "download" } else { &raw.filename },
            255,
        ),
        url: take_chars(&raw.url, 4096),
        save_path: take_chars(&raw.save_path, 4096),
        status: raw.status,
        received: raw.received,
        total: raw.total,
        started_at: if raw.started_at > 0 { raw.started_at } else { now_ms() },
        ended_at: raw.ended_at.filter(|n| *n > 0),
    })
}

type Writer = Arc<dyn Fn(&Path, &[u8]) -> io::Result<()> + Send + Sync>;
type TimerSpawner = Arc<dyn Fn(DownloadStore) + Send + Sync>;

struct Inner {
    items: Vec<Download>,
    dirty: bool,
    /// Generation of the pending progress timer (`None` when no timer runs).
    timer: Option<u64>,
    next_timer: u64,
}

struct Shared {
    file: PathBuf,
    inner: Mutex<Inner>,
    writer: Writer,
    spawn_timer: TimerSpawner,
}

/// `host-browser-downloads.json`. Cheap to clone (shared state).
#[derive(Clone)]
pub struct DownloadStore {
    shared: Arc<Shared>,
}

/// Knobs for tests: a fallible writer and a manual timer.
pub struct DownloadStoreOptions {
    pub writer: Writer,
    pub spawn_timer: TimerSpawner,
}

impl Default for DownloadStoreOptions {
    fn default() -> Self {
        Self {
            writer: Arc::new(atomic_write),
            spawn_timer: Arc::new(|store: DownloadStore| {
                std::thread::Builder::new()
                    .name("hostbrowser-download-progress".into())
                    .spawn(move || {
                        std::thread::sleep(PROGRESS_PERSIST_INTERVAL);
                        store.tick();
                    })
                    .ok();
            }),
        }
    }
}

impl DownloadStore {
    pub fn open(dir: &Path) -> Self {
        Self::open_with(dir, DownloadStoreOptions::default())
    }

    pub fn open_with(dir: &Path, options: DownloadStoreOptions) -> Self {
        let file = dir.join("host-browser-downloads.json");
        let mut items = Vec::new();
        match read_json(&file) {
            Ok(Some(serde_json::Value::Array(parsed))) => {
                for raw in parsed.into_iter().take(MAX_DOWNLOADS) {
                    let Ok(raw) = serde_json::from_value::<Download>(raw) else {
                        continue;
                    };
                    if let Ok(mut item) = normalize_download(raw) {
                        if item.status.is_active() {
                            item.status = DownloadStatus::Interrupted;
                        }
                        items.push(item);
                    }
                }
            }
            Ok(_) => {}
            Err(err) => tracing::warn!(%err, "[HostBrowser] Could not read downloads"),
        }
        Self {
            shared: Arc::new(Shared {
                file,
                inner: Mutex::new(Inner {
                    items,
                    dirty: false,
                    timer: None,
                    next_timer: 0,
                }),
                writer: options.writer,
                spawn_timer: options.spawn_timer,
            }),
        }
    }

    /// Write when dirty; a pending progress timer is cancelled.
    fn persist_locked(&self, inner: &mut Inner) -> io::Result<()> {
        inner.timer = None;
        if !inner.dirty {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&inner.items)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        (self.shared.writer)(&self.shared.file, &bytes)?;
        inner.dirty = false;
        Ok(())
    }

    fn schedule_progress_persist(&self, inner: &mut Inner) {
        if inner.timer.is_some() {
            return;
        }
        inner.next_timer += 1;
        inner.timer = Some(inner.next_timer);
        (self.shared.spawn_timer)(self.clone());
    }

    /// The deferred progress write. A timer cancelled by an earlier persist
    /// is a no-op; a failed write keeps the dirty state for the next change
    /// or shutdown without retrying.
    pub fn tick(&self) {
        let mut inner = self.shared.inner.lock();
        if inner.timer.take().is_none() {
            return;
        }
        if let Err(err) = self.persist_locked(&mut inner) {
            tracing::warn!(%err, "[HostBrowser] Could not save download progress");
        }
    }

    /// Is a deferred progress write pending?
    pub fn progress_pending(&self) -> bool {
        self.shared.inner.lock().timer.is_some()
    }

    pub fn flush(&self) -> io::Result<()> {
        let mut inner = self.shared.inner.lock();
        self.persist_locked(&mut inner)
    }

    fn is_missing(item: &Download) -> bool {
        item.status == DownloadStatus::Completed
            && (item.save_path.is_empty() || !Path::new(&item.save_path).exists())
    }

    pub fn list(&self, host_id: &str) -> Vec<DownloadListed> {
        let inner = self.shared.inner.lock();
        let mut items: Vec<&Download> = inner.items.iter().filter(|i| i.host_id == host_id).collect();
        items.sort_by_key(|item| std::cmp::Reverse(item.started_at));
        items
            .into_iter()
            .map(|item| DownloadListed {
                missing: Self::is_missing(item),
                item: item.clone(),
            })
            .collect()
    }

    pub fn get(&self, host_id: &str, id: &str) -> Option<Download> {
        self.shared
            .inner
            .lock()
            .items
            .iter()
            .find(|item| item.host_id == host_id && item.id == id)
            .cloned()
    }

    /// Insert or replace. With `defer_progress`, a pure byte-progress update
    /// of a running download is written later (coalesced).
    pub fn upsert(&self, raw: Download, defer_progress: bool) -> Result<Download, String> {
        let next = normalize_download(raw)?;
        let mut inner = self.shared.inner.lock();
        let index = inner.items.iter().position(|item| item.id == next.id);
        if let Some(i) = index {
            if inner.items[i].host_id != next.host_id {
                return Err("Download belongs to another host".into());
            }
        }
        let previous = index.map(|i| &inner.items[i]);
        let replaceable_progress = defer_progress
            && previous.is_some_and(|p| {
                p.status == DownloadStatus::Progressing
                    && next.status == DownloadStatus::Progressing
                    && p.filename == next.filename
                    && p.url == next.url
                    && p.save_path == next.save_path
                    && p.total == next.total
                    && p.started_at == next.started_at
                    && p.ended_at == next.ended_at
            });
        match index {
            Some(i) => inner.items[i] = next.clone(),
            None => inner.items.insert(0, next.clone()),
        }
        inner.items.sort_by_key(|item| std::cmp::Reverse(item.started_at));
        inner.items.truncate(MAX_DOWNLOADS);
        inner.dirty = true;
        if replaceable_progress {
            self.schedule_progress_persist(&mut inner);
        } else {
            self.persist_locked(&mut inner).map_err(|e| e.to_string())?;
        }
        Ok(next)
    }

    /// Remove a finished download from the history; running ones stay.
    pub fn remove(&self, host_id: &str, id: &str) -> bool {
        let mut inner = self.shared.inner.lock();
        let before = inner.items.len();
        inner
            .items
            .retain(|item| item.host_id != host_id || item.id != id || item.status.is_active());
        if inner.items.len() == before {
            return false;
        }
        inner.dirty = true;
        if let Err(err) = self.persist_locked(&mut inner) {
            tracing::warn!(%err, "[HostBrowser] Could not save downloads");
        }
        true
    }

    pub fn clear_finished(&self, host_id: &str) {
        let mut inner = self.shared.inner.lock();
        let before = inner.items.len();
        inner
            .items
            .retain(|item| item.host_id != host_id || item.status.is_active());
        if inner.items.len() != before {
            inner.dirty = true;
            if let Err(err) = self.persist_locked(&mut inner) {
                tracing::warn!(%err, "[HostBrowser] Could not save downloads");
            }
        }
    }
}

/// A file name reserved in the downloads directory. The empty placeholder
/// is created with `O_EXCL` so simultaneous downloads cannot collide with
/// each other or with a file already present.
pub struct ReservedFile {
    pub save_path: PathBuf,
    #[cfg(unix)]
    identity: (u64, u64),
}

impl ReservedFile {
    /// Remove the placeholder if it is still the empty file we created
    /// (a cancelled download the engine already removed is fine).
    pub fn cleanup_empty(&self) {
        let Ok(current) = std::fs::symlink_metadata(&self.save_path) else {
            return;
        };
        if !current.is_file() || current.len() != 0 {
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (current.dev(), current.ino()) != self.identity {
                return;
            }
        }
        let _ = std::fs::remove_file(&self.save_path);
    }
}

/// Reserve `suggested_name` (or `name (n).ext`) in `directory`.
pub fn reserve_download_file(directory: &Path, suggested_name: &str) -> io::Result<ReservedFile> {
    std::fs::create_dir_all(directory)?;
    let cleaned = suggested_name.replace('\\', "/");
    let basename = cleaned.rsplit('/').next().unwrap_or("").trim();
    let filename = if basename.is_empty() || basename == "." || basename == ".." {
        "download"
    } else {
        basename
    };
    let (stem, extension) = match filename.rfind('.') {
        Some(index) if index > 0 => filename.split_at(index),
        _ => (filename, ""),
    };
    for suffix in 0u32.. {
        let candidate = if suffix == 0 {
            filename.to_string()
        } else {
            format!("{stem} ({suffix}){extension}")
        };
        let save_path = directory.join(candidate);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&save_path) {
            Ok(file) => {
                #[cfg(unix)]
                let identity = {
                    use std::os::unix::fs::MetadataExt;
                    let meta = file.metadata()?;
                    (meta.dev(), meta.ino())
                };
                drop(file);
                return Ok(ReservedFile {
                    save_path,
                    #[cfg(unix)]
                    identity,
                });
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn row(dir: &Path) -> Download {
        Download {
            id: "active".into(),
            host_id: "a".into(),
            filename: "file.zip".into(),
            url: String::new(),
            save_path: dir.join("file.zip").to_string_lossy().into_owned(),
            status: DownloadStatus::Progressing,
            received: 0,
            total: 100,
            started_at: 1,
            ended_at: None,
        }
    }

    #[test]
    fn download_history_stays_local_to_its_host_and_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("download.bin");
        std::fs::write(&file, "downloaded").unwrap();
        let first = DownloadStore::open(dir.path());
        first
            .upsert(
                Download {
                    id: "one".into(),
                    host_id: "host-a".into(),
                    filename: "download.bin".into(),
                    url: String::new(),
                    save_path: file.to_string_lossy().into_owned(),
                    status: DownloadStatus::Completed,
                    received: 10,
                    total: 10,
                    started_at: 100,
                    ended_at: None,
                },
                false,
            )
            .unwrap();
        first
            .upsert(
                Download {
                    id: "two".into(),
                    host_id: "host-b".into(),
                    filename: "other.bin".into(),
                    url: String::new(),
                    save_path: String::new(),
                    status: DownloadStatus::Waiting,
                    received: 0,
                    total: 0,
                    started_at: 200,
                    ended_at: None,
                },
                false,
            )
            .unwrap();
        assert_eq!(first.list("host-b").len(), 1);
        let restored = DownloadStore::open(dir.path());
        assert_eq!(restored.list("host-a")[0].item.status, DownloadStatus::Completed);
        assert_eq!(restored.list("host-b")[0].item.status, DownloadStatus::Interrupted);
        std::fs::remove_file(&file).unwrap();
        assert!(restored.list("host-a")[0].missing);
        restored.clear_finished("host-a");
        assert_eq!(restored.list("host-a").len(), 0);
        assert_eq!(restored.list("host-b").len(), 1);
    }

    #[test]
    fn automatic_downloads_reserve_separate_names_without_replacing_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("report.txt"), "existing file").unwrap();
        std::fs::create_dir(dir.path().join("report (1).txt")).unwrap();
        let first = reserve_download_file(dir.path(), "report.txt").unwrap();
        let second = reserve_download_file(dir.path(), "report.txt").unwrap();
        assert_eq!(first.save_path.file_name().unwrap(), "report (2).txt");
        assert_eq!(second.save_path.file_name().unwrap(), "report (3).txt");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("report.txt")).unwrap(),
            "existing file"
        );
        first.cleanup_empty();
        assert!(!first.save_path.exists());
        std::fs::write(&second.save_path, "downloaded content").unwrap();
        second.cleanup_empty();
        assert_eq!(
            std::fs::read_to_string(&second.save_path).unwrap(),
            "downloaded content"
        );
        assert_eq!(
            reserve_download_file(dir.path(), "").unwrap().save_path.file_name().unwrap(),
            "download"
        );
        assert_eq!(
            reserve_download_file(dir.path(), "..").unwrap().save_path.file_name().unwrap(),
            "download (1)"
        );
        assert_eq!(
            reserve_download_file(dir.path(), ".bashrc").unwrap().save_path.file_name().unwrap(),
            ".bashrc"
        );
        assert_eq!(
            reserve_download_file(dir.path(), ".bashrc").unwrap().save_path.file_name().unwrap(),
            ".bashrc (1)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_removes_only_its_own_empty_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let reserved = reserve_download_file(dir.path(), "../report.txt").unwrap();
        assert_eq!(reserved.save_path, dir.path().join("report.txt"));
        let other = dir.path().join("replacement");
        std::fs::write(&other, "").unwrap();
        std::fs::rename(&other, &reserved.save_path).unwrap();
        reserved.cleanup_empty();
        assert!(
            reserved.save_path.exists(),
            "a replacement made by someone else is left alone"
        );
    }

    struct Fixture {
        store: DownloadStore,
        dir: tempfile::TempDir,
        timers: Arc<AtomicUsize>,
        writes: Arc<AtomicUsize>,
        fail: Arc<AtomicBool>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let timers = Arc::new(AtomicUsize::new(0));
            let writes = Arc::new(AtomicUsize::new(0));
            let fail = Arc::new(AtomicBool::new(false));
            let (t, w, f) = (timers.clone(), writes.clone(), fail.clone());
            let store = DownloadStore::open_with(
                dir.path(),
                DownloadStoreOptions {
                    writer: Arc::new(move |file, bytes| {
                        if f.load(Ordering::SeqCst) {
                            return Err(io::Error::other("disk full"));
                        }
                        w.fetch_add(1, Ordering::SeqCst);
                        atomic_write(file, bytes)
                    }),
                    spawn_timer: Arc::new(move |_| {
                        t.fetch_add(1, Ordering::SeqCst);
                    }),
                },
            );
            Self {
                store,
                dir,
                timers,
                writes,
                fail,
            }
        }
        fn row(&self) -> Download {
            row(self.dir.path())
        }
        fn writes(&self) -> usize {
            self.writes.load(Ordering::SeqCst)
        }
        fn saved(&self) -> Vec<Download> {
            let bytes = std::fs::read(self.dir.path().join("host-browser-downloads.json")).unwrap();
            serde_json::from_slice(&bytes).unwrap()
        }
    }

    #[test]
    fn progress_is_immediate_in_memory_and_coalesced_then_terminal_state_is_durable() {
        let f = Fixture::new();
        f.store.upsert(f.row(), false).unwrap();
        f.store
            .upsert(Download { id: "second".into(), ..f.row() }, false)
            .unwrap();
        for received in 1..=20u64 {
            for id in ["active", "second"] {
                f.store
                    .upsert(Download { id: id.into(), received, ..f.row() }, true)
                    .unwrap();
            }
        }
        assert_eq!(f.writes(), 2);
        assert_eq!(f.timers.load(Ordering::SeqCst), 1);
        assert!(f.store.progress_pending());
        assert_eq!(f.store.list("a")[0].item.received, 20);
        assert_eq!(f.saved()[0].received, 0);
        f.store.tick();
        assert_eq!(f.writes(), 3);
        assert_eq!(f.saved()[0].received, 20);
        f.store.upsert(Download { received: 50, ..f.row() }, true).unwrap();
        f.store
            .upsert(
                Download {
                    status: DownloadStatus::Completed,
                    received: 100,
                    ended_at: Some(2),
                    ..f.row()
                },
                false,
            )
            .unwrap();
        assert!(!f.store.progress_pending());
        assert_eq!(
            f.saved().iter().find(|i| i.id == "active").unwrap().status,
            DownloadStatus::Completed
        );
        f.store.tick();
        assert_eq!(f.writes(), 4, "a cancelled timer does not write again");
    }

    #[test]
    fn new_records_metadata_and_interrupted_or_cancelled_transitions_never_defer() {
        let f = Fixture::new();
        f.store.upsert(f.row(), true).unwrap();
        assert_eq!(f.writes(), 1);
        let updates: Vec<Box<dyn Fn(Download) -> Download>> = vec![
            Box::new(|d| Download { save_path: "changed".into(), ..d }),
            Box::new(|d| Download { total: 200, ..d }),
            Box::new(|d| Download { status: DownloadStatus::Interrupted, ..d }),
            Box::new(|d| Download { status: DownloadStatus::Cancelled, ..d }),
        ];
        for update in updates {
            let next = update(f.store.get("a", "active").unwrap());
            let before = f.writes();
            f.store.upsert(next, true).unwrap();
            assert_eq!(f.writes(), before + 1);
            assert!(!f.store.progress_pending());
        }
        let err = f
            .store
            .upsert(Download { host_id: "b".into(), ..f.row() }, true)
            .unwrap_err();
        assert!(err.contains("another host"));
        assert_eq!(f.store.get("a", "active").unwrap().status, DownloadStatus::Cancelled);
    }

    #[test]
    fn flush_persists_pending_progress_and_removal_cannot_be_resurrected() {
        let f = Fixture::new();
        f.store.upsert(f.row(), false).unwrap();
        f.store.upsert(Download { received: 10, ..f.row() }, true).unwrap();
        f.store.flush().unwrap();
        assert!(!f.store.progress_pending());
        assert_eq!(f.saved()[0].received, 10);
        f.store.flush().unwrap();
        assert_eq!(f.writes(), 2);
        f.store
            .upsert(
                Download { id: "finished".into(), status: DownloadStatus::Completed, ..f.row() },
                false,
            )
            .unwrap();
        f.store.upsert(Download { received: 20, ..f.row() }, true).unwrap();
        assert!(!f.store.remove("b", "finished"));
        assert!(!f.store.remove("a", "active"), "running downloads stay");
        assert!(f.store.remove("a", "finished"));
        assert!(!f.store.progress_pending());
        f.store.tick();
        assert_eq!(f.saved().len(), 1);
        assert_eq!(f.saved()[0].received, 20);
        f.store
            .upsert(
                Download { id: "finished".into(), status: DownloadStatus::Cancelled, ..f.row() },
                false,
            )
            .unwrap();
        f.store.upsert(Download { received: 30, ..f.row() }, true).unwrap();
        f.store.clear_finished("a");
        assert!(!f.store.progress_pending());
        assert_eq!(f.saved().len(), 1);
        assert_eq!(f.saved()[0].received, 30);
    }

    #[test]
    fn failed_deferred_writes_retain_dirty_state_preserve_disk_snapshot_and_do_not_spin() {
        let f = Fixture::new();
        f.store.upsert(f.row(), false).unwrap();
        f.store.upsert(Download { received: 10, ..f.row() }, true).unwrap();
        f.fail.store(true, Ordering::SeqCst);
        f.store.tick();
        assert!(!f.store.progress_pending());
        assert_eq!(f.saved()[0].received, 0);
        assert!(f.store.flush().is_err());
        f.fail.store(false, Ordering::SeqCst);
        f.store.flush().unwrap();
        assert_eq!(f.saved()[0].received, 10);
        assert!(!f.store.progress_pending());
    }

    #[test]
    fn real_timer_writes_progress_after_the_interval() {
        let dir = tempfile::tempdir().unwrap();
        let store = DownloadStore::open(dir.path());
        store.upsert(row(dir.path()), false).unwrap();
        store.upsert(Download { received: 42, ..row(dir.path()) }, true).unwrap();
        assert!(store.progress_pending());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while store.progress_pending() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!store.progress_pending());
        let bytes = std::fs::read(dir.path().join("host-browser-downloads.json")).unwrap();
        let saved: Vec<Download> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(saved[0].received, 42);
    }
}

use super::*;
use netcatty_core::ErrorCode;
use std::fs;

fn s(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[cfg(windows)]
fn symlink(target: &Path, link: &Path) {
    if target.is_dir() {
        std::os::windows::fs::symlink_dir(target, link).unwrap();
    } else {
        std::os::windows::fs::symlink_file(target, link).unwrap();
    }
}

#[tokio::test]
async fn list_dir_describes_files_dirs_and_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(root.join("file.txt"), b"hello world").unwrap();
    fs::create_dir(root.join("sub")).unwrap();
    symlink(&root.join("file.txt"), &root.join("link-to-file"));
    symlink(&root.join("sub"), &root.join("link-to-dir"));
    symlink(&root.join("missing"), &root.join("broken"));

    let mut entries = list_dir(&s(root)).await.unwrap();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["broken", "file.txt", "link-to-dir", "link-to-file", "sub"]
    );

    let by_name = |n: &str| entries.iter().find(|e| e.name == n).unwrap();

    let file = by_name("file.txt");
    assert_eq!(file.entry_type, FileEntryType::File);
    assert_eq!(file.size, "11 bytes");
    assert_eq!(file.link_target, None);
    assert_eq!(file.hidden, Some(false));
    assert!(file.last_modified.ends_with('Z'));
    if cfg!(unix) {
        assert!(file.owner.as_deref().is_some_and(|o| !o.is_empty()));
    }

    let sub = by_name("sub");
    assert_eq!(sub.entry_type, FileEntryType::Directory);
    assert_eq!(sub.link_target, None);

    let link_file = by_name("link-to-file");
    assert_eq!(link_file.entry_type, FileEntryType::Symlink);
    assert_eq!(link_file.link_target, Some(Some(LinkTargetType::File)));
    assert_eq!(link_file.size, "11 bytes", "size follows the target");

    let link_dir = by_name("link-to-dir");
    assert_eq!(link_dir.entry_type, FileEntryType::Symlink);
    assert_eq!(link_dir.link_target, Some(Some(LinkTargetType::Directory)));

    let broken = by_name("broken");
    assert_eq!(broken.entry_type, FileEntryType::Symlink);
    assert_eq!(broken.link_target, Some(None));
    let json = serde_json::to_value(broken).unwrap();
    assert!(json.get("linkTarget").is_some_and(|v| v.is_null()));
}

#[tokio::test]
async fn list_dir_missing_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let err = list_dir(&s(&dir.path().join("nope"))).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn read_file_tail_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log.txt");
    fs::write(&path, b"0123456789").unwrap();
    let p = s(&path);
    assert_eq!(read_file(&p, None).await.unwrap(), b"0123456789");
    assert_eq!(read_file(&p, Some(0)).await.unwrap(), b"0123456789");
    assert_eq!(read_file(&p, Some(4)).await.unwrap(), b"6789");
    assert_eq!(read_file(&p, Some(10)).await.unwrap(), b"0123456789");
    assert_eq!(read_file(&p, Some(100)).await.unwrap(), b"0123456789");
    assert_eq!(
        read_file(&s(&dir.path().join("none")), Some(4))
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn write_rename_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    write_file(&s(&a), b"data").await.unwrap();
    rename(&s(&a), &s(&b)).await.unwrap();
    assert!(!a.exists());
    assert_eq!(fs::read(&b).unwrap(), b"data");
}

#[tokio::test]
async fn delete_checks_expected_type_and_removes_trees() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("f");
    fs::write(&file, b"x").unwrap();
    let sub = dir.path().join("d");
    fs::create_dir_all(sub.join("nested")).unwrap();
    fs::write(sub.join("nested/x"), b"y").unwrap();
    let link = dir.path().join("l");
    symlink(&file, &link);

    let err = delete(&s(&file), Some(FileEntryType::Directory))
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert_eq!(
        err.message,
        "Local target changed before replace: expected directory, found file"
    );
    assert!(file.exists());

    let err = delete(&s(&link), Some(FileEntryType::File))
        .await
        .unwrap_err();
    assert_eq!(
        err.message,
        "Local target changed before replace: expected file, found symlink"
    );

    delete(&s(&link), Some(FileEntryType::Symlink))
        .await
        .unwrap();
    assert!(fs::symlink_metadata(&link).is_err());
    assert!(file.exists(), "deleting the link must not touch the target");

    delete(&s(&file), Some(FileEntryType::File)).await.unwrap();
    assert!(!file.exists());

    delete(&s(&sub), None).await.unwrap();
    assert!(!sub.exists());

    assert_eq!(
        delete(&s(&sub), None).await.unwrap_err().code,
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn mkdir_is_idempotent_and_recursive() {
    let dir = tempfile::tempdir().unwrap();
    let deep = dir.path().join("a/b/c");
    mkdir(&s(&deep)).await.unwrap();
    assert!(deep.is_dir());
    mkdir(&s(&deep)).await.unwrap();
    mkdir(&s(dir.path())).await.unwrap();

    let file = dir.path().join("file");
    fs::write(&file, b"").unwrap();
    let err = mkdir(&s(&file)).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Io);
}

#[tokio::test]
async fn stat_and_lstat_on_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.bin");
    fs::write(&target, vec![0u8; 1234]).unwrap();
    let link = dir.path().join("link");
    symlink(&target, &link);

    let st = stat(&s(&link)).await.unwrap();
    assert_eq!(st.name, "link");
    assert_eq!(st.entry_type, FileEntryType::File);
    assert_eq!(st.size, 1234);
    assert!(st.last_modified > 0);

    let lst = lstat(&s(&link)).await.unwrap();
    assert_eq!(lst.entry_type, FileEntryType::Symlink);
    assert_ne!(lst.size, 1234);

    let dst = stat(&s(dir.path())).await.unwrap();
    assert_eq!(dst.entry_type, FileEntryType::Directory);

    if cfg!(unix) {
        assert!(st.dev.is_some() && st.ino.is_some());
        let target_stat = stat(&s(&target)).await.unwrap();
        assert_eq!(
            (st.dev, st.ino),
            (target_stat.dev, target_stat.ino),
            "stat follows the link"
        );
        assert_ne!(lst.ino, st.ino, "lstat identifies the link itself");
    } else {
        assert!(st.dev.is_none() && st.ino.is_none());
    }

    assert_eq!(
        stat(&s(&dir.path().join("missing")))
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn realpath_resolves_links() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real");
    fs::create_dir(&target).unwrap();
    let link = dir.path().join("alias");
    symlink(&target, &link);
    let resolved = realpath(&s(&link)).await.unwrap();
    let expected = realpath(&s(&target)).await.unwrap();
    assert_eq!(resolved, expected);
    assert!(resolved.ends_with("real"));
    #[cfg(windows)]
    assert!(!resolved.starts_with(r"\\?\"));
}

#[test]
fn archive_kind_detection() {
    assert_eq!(archive_kind("a.tar.gz"), Some(ArchiveKind::TarGz));
    assert_eq!(archive_kind("A.TGZ"), Some(ArchiveKind::TarGz));
    assert_eq!(archive_kind("a.tar.bz2"), Some(ArchiveKind::TarBz2));
    assert_eq!(archive_kind("a.tar.xz"), Some(ArchiveKind::TarXz));
    assert_eq!(archive_kind("a.txz"), Some(ArchiveKind::TarXz));
    assert_eq!(archive_kind("a.tar"), Some(ArchiveKind::Tar));
    assert_eq!(archive_kind("a.zip"), Some(ArchiveKind::Zip));
    assert_eq!(archive_kind("a.gz"), Some(ArchiveKind::Gz));
    assert_eq!(archive_kind(".gz"), None, "a bare suffix is not an archive");
    assert_eq!(archive_kind("a.txt"), None);
    assert!(is_extractable_archive("/x/y/z.tar.gz"));
    assert!(!is_extractable_archive("/x/y/z.rar"));
}

#[tokio::test]
async fn extract_rejects_unsupported_and_missing() {
    let dir = tempfile::tempdir().unwrap();
    let txt = dir.path().join("notes.txt");
    fs::write(&txt, b"x").unwrap();
    assert_eq!(
        extract_archive(&s(&txt)).await.unwrap_err().code,
        ErrorCode::Unsupported
    );
    assert_eq!(
        extract_archive(&s(&dir.path().join("none.zip")))
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        extract_archive(&s(dir.path())).await.unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}

#[cfg(unix)]
#[tokio::test]
async fn extract_tar_archive_next_to_itself() {
    if std::process::Command::new("tar")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("tar not available; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("hello.txt"), b"hi").unwrap();
    let archive = dir.path().join("bundle.tar.gz");
    let status = std::process::Command::new("tar")
        .args(["-czf", &s(&archive), "-C", &s(dir.path()), "src"])
        .status()
        .unwrap();
    assert!(status.success());
    fs::remove_dir_all(&src).unwrap();

    extract_archive(&s(&archive)).await.unwrap();
    assert_eq!(fs::read(src.join("hello.txt")).unwrap(), b"hi");

    // A corrupt archive surfaces the tool's stderr.
    let bad = dir.path().join("bad.tar");
    fs::write(&bad, b"definitely not a tar file").unwrap();
    let err = extract_archive(&s(&bad)).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Io);
    assert!(
        err.message.starts_with("Local extraction failed"),
        "{}",
        err.message
    );
}

fn build_tree(root: &Path) {
    fs::create_dir_all(root.join("a/b")).unwrap();
    fs::create_dir_all(root.join("c")).unwrap();
    fs::write(root.join("top.txt"), b"1").unwrap();
    fs::write(root.join("a/one.txt"), b"22").unwrap();
    fs::write(root.join("a/b/two.txt"), b"333").unwrap();
    fs::write(root.join("c/three.txt"), b"4444").unwrap();
}

#[tokio::test]
async fn list_tree_walks_without_following_symlinks_and_streams_progress() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("proj");
    build_tree(&root);
    // A symlink to the root inside the tree must not recurse forever.
    symlink(&root, &root.join("c/loop"));
    symlink(&root.join("top.txt"), &root.join("c/alias.txt"));
    symlink(&root.join("missing"), &root.join("c/broken"));

    let (tx, mut rx) = mpsc::unbounded_channel();
    let entries = list_tree(
        "scan-1",
        &s(&root),
        TreeLimits::default(),
        Some(tx),
        CancellationToken::new(),
    )
    .await
    .unwrap();

    // Breadth-first, children sorted by name, root row omitted, root name kept
    // as the first path segment, symlinked dir present but not descended.
    let rel: Vec<&str> = entries.iter().map(|e| e.relative_path.as_str()).collect();
    assert_eq!(
        rel,
        vec![
            "proj/a",
            "proj/c",
            "proj/top.txt",
            "proj/a/b",
            "proj/a/one.txt",
            "proj/c/alias.txt",
            "proj/c/loop",
            "proj/c/three.txt",
            "proj/a/b/two.txt",
        ]
    );
    let by_rel = |r: &str| entries.iter().find(|e| e.relative_path == r).unwrap();
    assert_eq!(by_rel("proj/a").entry_type, FileEntryType::Directory);
    assert_eq!(by_rel("proj/c/loop").entry_type, FileEntryType::Directory);
    assert_eq!(by_rel("proj/c/alias.txt").entry_type, FileEntryType::File);
    assert_eq!(
        by_rel("proj/c/alias.txt").size,
        1,
        "link size follows the target"
    );
    assert_eq!(by_rel("proj/a/b/two.txt").size, 3);
    assert!(by_rel("proj/top.txt").local_path.ends_with("top.txt"));
    assert!(entries.iter().all(|e| e.last_modified > 0));

    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }
    assert!(!events.is_empty());
    let last = events.last().unwrap();
    assert!(last.done);
    assert!(events[..events.len() - 1].iter().all(|e| !e.done));
    assert!(events.iter().all(|e| e.scan_id == "scan-1"));
    let streamed: usize = events.iter().map(|e| e.entries.len()).sum();
    assert_eq!(
        streamed,
        entries.len(),
        "every row is streamed exactly once"
    );
    assert_eq!(last.file_count, 5);
    assert_eq!(last.directory_count, 4);
    assert_eq!(last.entry_count, 9);
}

#[tokio::test]
async fn list_tree_batches_large_directories() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("many");
    fs::create_dir(&root).unwrap();
    for i in 0..450 {
        fs::write(root.join(format!("f{i:04}.txt")), b"x").unwrap();
    }
    let (tx, mut rx) = mpsc::unbounded_channel();
    let entries = list_tree(
        "scan-2",
        &s(&root),
        TreeLimits::default(),
        Some(tx),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(entries.len(), 450);
    let mut events = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        events.push(ev);
    }
    assert!(
        events.len() >= 3,
        "expected batches of ~200 entries, got {}",
        events.len()
    );
    assert!(events
        .iter()
        .rev()
        .skip(1)
        .all(|e| e.entries.len() <= TREE_PROGRESS_BATCH_ENTRIES));
    assert!(events.last().unwrap().done);
    assert_eq!(events.iter().map(|e| e.entries.len()).sum::<usize>(), 450);
}

#[tokio::test]
async fn list_tree_honors_limits() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("proj");
    build_tree(&root);

    let limits = TreeLimits {
        max_entries: Some(4),
        max_directories: None,
    };
    let (tx, mut rx) = mpsc::unbounded_channel();
    let entries = list_tree(
        "scan-3",
        &s(&root),
        limits,
        Some(tx),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(entries.len(), 4);
    let mut last = None;
    while let Ok(ev) = rx.try_recv() {
        last = Some(ev);
    }
    assert!(last.unwrap().done);

    // Root counts as the first directory, so a budget of 2 admits one child dir.
    let limits = TreeLimits {
        max_entries: None,
        max_directories: Some(2),
    };
    let entries = list_tree("scan-4", &s(&root), limits, None, CancellationToken::new())
        .await
        .unwrap();
    let dirs = entries
        .iter()
        .filter(|e| e.entry_type == FileEntryType::Directory)
        .count();
    assert_eq!(dirs, 1);

    let (tx, _rx) = mpsc::unbounded_channel();
    let empty = list_tree(
        "scan-5",
        &s(&root),
        TreeLimits {
            max_entries: Some(0),
            max_directories: None,
        },
        Some(tx),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(empty.is_empty());
}

#[tokio::test]
async fn list_tree_cancel_and_errors() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("proj");
    build_tree(&root);

    let cancel = CancellationToken::new();
    cancel.cancel();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let err = list_tree("scan-6", &s(&root), TreeLimits::default(), Some(tx), cancel)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Cancelled);
    let mut saw_done = false;
    while let Ok(ev) = rx.try_recv() {
        saw_done |= ev.done;
    }
    assert!(saw_done, "the stream is terminated even when cancelled");

    let file = root.join("top.txt");
    let err = list_tree(
        "scan-7",
        &s(&file),
        TreeLimits::default(),
        None,
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    let err = list_tree(
        "scan-8",
        &s(&root.join("none")),
        TreeLimits::default(),
        None,
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn validate_path_reports_kind() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("f");
    fs::write(&file, b"").unwrap();

    let v = validate_path(&s(dir.path())).await;
    assert_eq!(
        v,
        PathValidation {
            exists: true,
            is_file: false,
            is_directory: true
        }
    );
    let v = validate_path(&s(&file)).await;
    assert_eq!(
        v,
        PathValidation {
            exists: true,
            is_file: true,
            is_directory: false
        }
    );
    let v = validate_path(&s(&dir.path().join("missing"))).await;
    assert_eq!(v, PathValidation::default());
}

#[tokio::test]
async fn drives_home_and_system_info() {
    let drives = list_drives().await.unwrap();
    assert!(!drives.is_empty());
    if cfg!(windows) {
        assert!(drives.iter().all(|d| d.len() == 3 && d.ends_with(":\\")));
    } else {
        assert_eq!(drives, vec!["/".to_string()]);
    }

    assert!(!home_dir().unwrap().is_empty());

    let info = system_info();
    assert!(!info.username.is_empty());
    assert!(!info.hostname.is_empty());
}

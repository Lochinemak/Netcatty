//! Compressed folder upload helpers (Electron `compressUploadBridge.cjs`).
//!
//! Flow (driven by `commands/transfers2.rs`): local `tar -czf -` of the
//! folder into a temp archive (0–30 %), SFTP upload of the archive next to
//! the target (30–90 %), then one remote `sh` script that extracts into a
//! sibling staging directory and atomically swaps the folder into place
//! (90–100 %). Every remote value is single-quoted ([`escape_shell_arg`]);
//! the folder name is reduced to a POSIX basename and `.` / `..` are refused.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// `tar --version` probe bound on the remote host.
pub const REMOTE_TAR_PROBE_TIMEOUT_MS: u64 = 15_000;
/// Remote archive removal bound.
pub const REMOTE_CLEANUP_TIMEOUT_MS: u64 = 15_000;
/// Local `tar --version` probe bound.
pub const LOCAL_TAR_PROBE_TIMEOUT_MS: u64 = 10_000;
/// Grace between SIGTERM and SIGKILL for the local tar.
pub const LOCAL_TAR_KILL_GRACE_MS: u64 = 750;
/// Diagnostics cap for remote / local tar stderr.
pub const MAX_STDERR_BYTES: usize = 64 * 1024;
/// Support probe cache lifetime and size.
pub const SUPPORT_CACHE_TTL_MS: u64 = 10_000;
pub const SUPPORT_CACHE_MAX_ENTRIES: usize = 64;

/// `'...'` with `'` as `'\''`.
pub fn escape_shell_arg(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn sha256_prefix(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    hex::encode(digest)[..16].to_string()
}

/// `path.posix.basename` after turning `\` into `/`.
pub fn posix_basename(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or("").to_string()
}

/// `path.posix.normalize`.
pub fn posix_normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let absolute = path.starts_with('/');
    let trailing = path.ends_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|p| *p != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let mut out = parts.join("/");
    if absolute {
        out.insert(0, '/');
    }
    if out.is_empty() {
        out = ".".to_string();
    }
    if trailing && out != "/" {
        out.push('/');
    }
    out
}

/// `path.posix.join(a, b)`.
pub fn posix_join(a: &str, b: &str) -> String {
    let joined = match (a.is_empty(), b.is_empty()) {
        (true, true) => String::new(),
        (true, false) => b.to_string(),
        (false, true) => a.to_string(),
        (false, false) => format!("{a}/{b}"),
    };
    posix_normalize(&joined)
}

/// The folder name as it will exist on the remote side, or an error for
/// names that would escape the target directory.
pub fn normalized_folder_name(folder_name: &str) -> Result<String, String> {
    let name = posix_basename(folder_name);
    if name.is_empty() || name == "." || name == ".." {
        return Err("Invalid compressed upload folder name".to_string());
    }
    Ok(name)
}

/// Electron `buildAtomicRemoteExtractionCommand`. Stage / backup names are
/// stable per destination (not per attempt) so a failed cleanup is
/// reconciled by the next upload.
pub fn build_atomic_remote_extraction_command(
    archive_path: &str,
    target_dir: &str,
    folder_name: &str,
) -> Result<String, String> {
    let name = normalized_folder_name(folder_name)?;
    let suffix = sha256_prefix(&format!("{target_dir}\0{name}"));
    let stage_dir = posix_join(target_dir, &format!(".netcatty-compress-{suffix}.stage"));
    let backup_dir = posix_join(target_dir, &format!(".netcatty-compress-{suffix}.backup"));
    let final_dir = posix_join(target_dir, &name);
    let staged_final_dir = posix_join(&stage_dir, &name);
    let lines: Vec<String> = vec![
        "set -e".into(),
        format!("archive={}", escape_shell_arg(archive_path)),
        format!("stage={}", escape_shell_arg(&stage_dir)),
        format!("backup={}", escape_shell_arg(&backup_dir)),
        format!("final={}", escape_shell_arg(&final_dir)),
        format!("staged_final={}", escape_shell_arg(&staged_final_dir)),
        "rollback_compressed_upload() {".into(),
        "  status=$1".into(),
        "  trap - EXIT HUP INT TERM".into(),
        "  if [ ! -e \"$final\" ] && [ ! -L \"$final\" ] && { [ -e \"$backup\" ] || [ -L \"$backup\" ]; }; then".into(),
        "    mv -- \"$backup\" \"$final\" 2>/dev/null || true".into(),
        "  fi".into(),
        "  make_tree_writable \"$stage\"".into(),
        "  rm -rf -- \"$stage\"".into(),
        "  rm -f -- \"$archive\"".into(),
        "  exit \"$status\"".into(),
        "}".into(),
        "make_tree_writable() {".into(),
        "  candidate=$1".into(),
        "  if [ -d \"$candidate\" ] && [ ! -L \"$candidate\" ]; then chmod -R u+w -- \"$candidate\" 2>/dev/null || true; fi".into(),
        "}".into(),
        "trap 'rollback_compressed_upload $?' EXIT".into(),
        "trap 'rollback_compressed_upload 129' HUP".into(),
        "trap 'rollback_compressed_upload 130' INT".into(),
        "trap 'rollback_compressed_upload 143' TERM".into(),
        "if [ ! -e \"$final\" ] && [ ! -L \"$final\" ] && { [ -e \"$backup\" ] || [ -L \"$backup\" ]; }; then mv -- \"$backup\" \"$final\"; fi".into(),
        "if [ -L \"$final\" ]; then echo 'Refusing to replace a symlink target' >&2; exit 1; fi".into(),
        "if [ -e \"$backup\" ] || [ -L \"$backup\" ]; then make_tree_writable \"$backup\"; rm -rf -- \"$backup\"; fi".into(),
        "make_tree_writable \"$stage\"".into(),
        "rm -rf -- \"$stage\"".into(),
        "mkdir -p -- \"$stage\"".into(),
        "if [ -e \"$final\" ]; then".into(),
        "  if ! cp -a -- \"$final\" \"$staged_final\" 2>/dev/null; then".into(),
        "    rm -rf -- \"$staged_final\"".into(),
        "    cp -Rp -- \"$final\" \"$staged_final\"".into(),
        "  fi".into(),
        "fi".into(),
        "tar -xzf \"$archive\" -C \"$stage\" --exclude='._*' --exclude='.DS_Store'".into(),
        "if [ ! -d \"$staged_final\" ]; then echo 'Compressed archive did not contain the expected folder' >&2; exit 1; fi".into(),
        "if [ -e \"$final\" ]; then mv -- \"$final\" \"$backup\"; fi".into(),
        "mv -- \"$staged_final\" \"$final\"".into(),
        "make_tree_writable \"$backup\"".into(),
        "make_tree_writable \"$stage\"".into(),
        "rm -rf -- \"$backup\" \"$stage\"".into(),
        "rm -f -- \"$archive\"".into(),
        "trap - EXIT HUP INT TERM".into(),
    ];
    Ok(lines.join("\n"))
}

/// Electron `buildRemoteArchivePath`: a hidden archive next to the target,
/// unique per compression id.
pub fn build_remote_archive_path(target_path: &str, folder_name: &str, compression_id: &str) -> String {
    let base: String = posix_basename(if folder_name.is_empty() { "folder" } else { folder_name })
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let base = if base.is_empty() { "folder".to_string() } else { base };
    let id = if compression_id.is_empty() { "compression" } else { compression_id };
    posix_join(
        target_path,
        &format!(".{base}.netcatty-{}.tar.gz", sha256_prefix(id)),
    )
}

/// Electron `buildCompressionTargetKey`: the per-destination lock key
/// (connection identity + normalized final folder path).
pub fn compression_target_key(
    connection_identity: &str,
    target_path: &str,
    folder_name: &str,
) -> Result<String, String> {
    if connection_identity.is_empty() {
        return Err("SFTP connection identity unavailable for compressed upload".to_string());
    }
    let name = normalized_folder_name(folder_name)?;
    let target = if target_path.is_empty() { "." } else { target_path };
    let normalized = posix_normalize(&posix_join(&target.replace('\\', "/"), &name));
    Ok(format!("{connection_identity}\0{normalized}"))
}

/// Remote extraction bound: 60 s base + 30 s per started 10 MiB of
/// archive, at most 10 minutes.
pub fn extraction_timeout_ms(archive_size: u64) -> u64 {
    const BASE: u64 = 60_000;
    const MAX: u64 = 600_000;
    let size_based = if archive_size > 0 {
        archive_size.div_ceil(10 * 1024 * 1024) * 30_000
    } else {
        0
    };
    MAX.min(BASE.max(BASE + size_based))
}

/// The local `tar` executable (`%SystemRoot%\System32\tar.exe` on Windows).
pub fn local_tar_command() -> PathBuf {
    if cfg!(windows) {
        let root = std::env::var("SystemRoot")
            .or_else(|_| std::env::var("windir"))
            .unwrap_or_else(|_| "C:\\Windows".to_string());
        Path::new(&root).join("System32").join("tar.exe")
    } else {
        PathBuf::from("tar")
    }
}

/// How to run the local compressor: the working directory and argv. Local
/// paths never reach argv (Windows `tar.exe` mangles non-ANSI argv): the
/// parent is the cwd and the archive is tar's stdout. An archive inside
/// the source folder is excluded from itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTarInvocation {
    pub cwd: PathBuf,
    pub args: Vec<String>,
}

pub fn local_tar_invocation(folder_path: &Path, output_path: &Path) -> Result<LocalTarInvocation, String> {
    let folder_name = folder_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| "Invalid compressed upload folder".to_string())?;
    let parent = folder_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "Invalid compressed upload folder".to_string())?;
    let mut args: Vec<String> = [
        "-czf",
        "-",
        "--exclude=._*",
        "--exclude=.DS_Store",
        "--exclude=.Spotlight-V100",
        "--exclude=.Trashes",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if let Ok(relative) = output_path.strip_prefix(folder_path) {
        if !relative.as_os_str().is_empty() {
            if let Ok(from_parent) = output_path.strip_prefix(&parent) {
                let parts: Vec<String> = from_parent
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                args.push(format!("--exclude={}", parts.join("/")));
            }
        }
    }
    args.push(folder_name);
    Ok(LocalTarInvocation { cwd: parent, args })
}

/// Overall progress percentage of a phase (Electron mapping).
pub fn compressing_percent(archive_bytes: u64) -> f64 {
    (archive_bytes as f64 / 1024.0 / 1024.0).min(30.0)
}

/// Upload progress mapped into 30–90 %.
pub fn uploading_percent(transferred: u64, total: u64) -> f64 {
    if total == 0 {
        return 30.0;
    }
    30.0 + (transferred as f64 / total as f64 * 60.0).min(60.0)
}

/// Electron `sendProgress`: percentage → byte estimate of the folder.
pub fn transferred_bytes(percent: f64, total: f64, total_bytes: u64) -> u64 {
    if total <= 0.0 {
        return 0;
    }
    let ratio = (percent / total).clamp(0.0, 1.0);
    (ratio * total_bytes as f64).floor() as u64
}

/// Bounded UTF-8 collector for diagnostics: keeps at most `limit` bytes and
/// drops a character cut by the cap instead of producing U+FFFD.
#[derive(Debug, Clone)]
pub struct BoundedUtf8 {
    limit: usize,
    bytes: Vec<u8>,
    truncated: bool,
}

impl BoundedUtf8 {
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            bytes: Vec::new(),
            truncated: false,
        }
    }

    pub fn append(&mut self, chunk: &[u8]) {
        let room = self.limit.saturating_sub(self.bytes.len());
        let take = chunk.len().min(room);
        self.bytes.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            self.truncated = true;
        }
    }

    pub fn finish(&self) -> String {
        match std::str::from_utf8(&self.bytes) {
            Ok(text) => text.to_string(),
            Err(err) if self.truncated && err.error_len().is_none() => {
                String::from_utf8_lossy(&self.bytes[..err.valid_up_to()]).into_owned()
            }
            Err(_) => String::from_utf8_lossy(&self.bytes).into_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_names_cannot_escape_the_target() {
        assert_eq!(normalized_folder_name("a/b/folder").unwrap(), "folder");
        assert_eq!(normalized_folder_name("C:\\x\\folder").unwrap(), "folder");
        assert!(normalized_folder_name("..").is_err());
        assert!(normalized_folder_name(".").is_err());
        assert!(normalized_folder_name("").is_err());
        assert!(build_atomic_remote_extraction_command("/t/a.tgz", "/t", "..").is_err());
    }

    #[test]
    fn posix_path_helpers_match_node() {
        assert_eq!(posix_join("/srv", "folder"), "/srv/folder");
        assert_eq!(posix_join("/srv/", "./x/../folder"), "/srv/folder");
        assert_eq!(posix_join("", "folder"), "folder");
        assert_eq!(posix_normalize("/../a"), "/a");
        assert_eq!(posix_normalize("a/../../b"), "../b");
    }

    #[test]
    fn replacement_uses_stable_stage_and_backup_across_operations() {
        let first = build_atomic_remote_extraction_command("/target/.one.tar.gz", "/target", "folder").unwrap();
        let second = build_atomic_remote_extraction_command("/target/.two.tar.gz", "/target", "folder").unwrap();
        let value = |cmd: &str, name: &str| {
            cmd.lines()
                .find(|l| l.starts_with(&format!("{name}=")))
                .map(str::to_string)
        };
        assert_eq!(value(&first, "backup"), value(&second, "backup"));
        assert_eq!(value(&first, "stage"), value(&second, "stage"));
        assert_ne!(value(&first, "archive"), value(&second, "archive"));
        assert!(value(&first, "stage").unwrap().contains("/target/.netcatty-compress-"));
    }

    #[test]
    fn quoting_keeps_hostile_names_inert() {
        let cmd =
            build_atomic_remote_extraction_command("/t/x'; rm -rf ~; '.tgz", "/t/it's", "f$(id)").unwrap();
        assert!(cmd.contains("archive='/t/x'\\''; rm -rf ~; '\\''.tgz'"));
        assert!(cmd.contains("final='/t/it'\\''s/f$(id)'"));
    }

    #[test]
    fn archive_paths_are_hidden_sanitized_and_unique_per_operation() {
        let a = build_remote_archive_path("/srv", "my folder", "op-1");
        let b = build_remote_archive_path("/srv", "my folder", "op-2");
        assert!(a.starts_with("/srv/.my_folder.netcatty-"));
        assert!(a.ends_with(".tar.gz"));
        assert_ne!(a, b);
        assert_eq!(a, build_remote_archive_path("/srv", "my folder", "op-1"));
    }

    #[test]
    fn target_keys_share_one_lock_per_endpoint_destination() {
        let a = compression_target_key("ep", "/srv/", "folder").unwrap();
        let b = compression_target_key("ep", "/srv/x/..", "folder").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, compression_target_key("other", "/srv", "folder").unwrap());
        assert!(compression_target_key("", "/srv", "folder").is_err());
    }

    #[test]
    fn extraction_timeout_scales_with_archive_size() {
        assert_eq!(extraction_timeout_ms(0), 60_000);
        assert_eq!(extraction_timeout_ms(1), 90_000);
        assert_eq!(extraction_timeout_ms(25 * 1024 * 1024), 150_000);
        assert_eq!(extraction_timeout_ms(u64::MAX / 2), 600_000);
    }

    #[test]
    fn local_tar_passes_paths_through_cwd_and_stdout() {
        let folder = Path::new("/home/u/下载目录/folder");
        let inv = local_tar_invocation(folder, Path::new("/tmp/1_1_folder.tar.gz")).unwrap();
        assert_eq!(inv.cwd, Path::new("/home/u/下载目录"));
        assert_eq!(&inv.args[..2], ["-czf", "-"]);
        assert!(!inv.args.iter().any(|a| a.contains("/home/u")));
        assert!(!inv.args.iter().any(|a| a == "-C"));
        assert_eq!(inv.args.last().unwrap(), "folder");
    }

    #[test]
    fn an_archive_inside_the_source_is_excluded() {
        let folder = Path::new("/p/folder");
        let inv = local_tar_invocation(folder, Path::new("/p/folder/tmp/1_1_folder.tar.gz")).unwrap();
        assert!(inv.args.contains(&"--exclude=folder/tmp/1_1_folder.tar.gz".to_string()));
    }

    #[test]
    fn progress_mapping_matches_electron() {
        assert_eq!(compressing_percent(5 * 1024 * 1024), 5.0);
        assert_eq!(compressing_percent(500 * 1024 * 1024), 30.0);
        assert_eq!(uploading_percent(50, 100), 60.0);
        assert_eq!(uploading_percent(0, 0), 30.0);
        assert_eq!(transferred_bytes(50.0, 100.0, 7), 3);
        assert_eq!(transferred_bytes(150.0, 100.0, 7), 7);
        assert_eq!(transferred_bytes(1.0, 0.0, 7), 0);
    }

    #[test]
    fn bounded_diagnostics_drop_a_cut_character() {
        let mut c = BoundedUtf8::new(4);
        c.append("ab中".as_bytes());
        assert_eq!(c.finish(), "ab");
        let mut c = BoundedUtf8::new(64);
        let bytes = "é!".as_bytes();
        c.append(&bytes[..1]);
        c.append(&bytes[1..]);
        assert_eq!(c.finish(), "é!");
    }

    #[cfg(unix)]
    mod shell {
        use super::super::*;
        use std::process::Command;

        fn tmp(name: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "netcatty-compress-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        fn no_artifacts(target: &Path) -> bool {
            !std::fs::read_dir(target)
                .unwrap()
                .any(|e| e.unwrap().file_name().to_string_lossy().contains(".netcatty-compress-"))
        }

        #[test]
        fn successful_extraction_merges_and_cleans_up() {
            let root = tmp("ok");
            let target = root.join("target");
            let final_dir = target.join("folder");
            let source = root.join("source/folder");
            std::fs::create_dir_all(&final_dir).unwrap();
            std::fs::create_dir_all(&source).unwrap();
            std::fs::write(final_dir.join("old.txt"), "old").unwrap();
            std::fs::write(source.join("new.txt"), "new").unwrap();
            let archive = target.join("folder.tar.gz");
            let status = Command::new("tar")
                .arg("-czf")
                .arg(&archive)
                .arg("-C")
                .arg(root.join("source"))
                .arg("folder")
                .status()
                .unwrap();
            assert!(status.success());
            let cmd = build_atomic_remote_extraction_command(
                archive.to_str().unwrap(),
                target.to_str().unwrap(),
                "folder",
            )
            .unwrap();
            assert!(Command::new("/bin/sh").args(["-c", &cmd]).status().unwrap().success());
            assert_eq!(std::fs::read_to_string(final_dir.join("old.txt")).unwrap(), "old");
            assert_eq!(std::fs::read_to_string(final_dir.join("new.txt")).unwrap(), "new");
            assert!(!archive.exists());
            assert!(no_artifacts(&target));
            let _ = std::fs::remove_dir_all(root);
        }

        #[test]
        fn failed_extraction_leaves_the_existing_folder_untouched() {
            let root = tmp("fail");
            let target = root.join("target");
            let final_dir = target.join("folder");
            std::fs::create_dir_all(&final_dir).unwrap();
            std::fs::write(final_dir.join("old.txt"), "old").unwrap();
            let archive = target.join("truncated.tar.gz");
            std::fs::write(&archive, [0x1f, 0x8b, 0x08, 0x00, 0x00]).unwrap();
            let cmd = build_atomic_remote_extraction_command(
                archive.to_str().unwrap(),
                target.to_str().unwrap(),
                "folder",
            )
            .unwrap();
            let status = Command::new("/bin/sh")
                .args(["-c", &cmd])
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(!status.success());
            assert_eq!(std::fs::read_to_string(final_dir.join("old.txt")).unwrap(), "old");
            assert!(no_artifacts(&target));
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

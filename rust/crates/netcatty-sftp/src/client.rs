//! SFTP browse operations.

use crate::error::{SftpError, SftpResult};
use crate::pipeline::{close_quietly, PipelinedReader, PipelinedWriter, PIPELINE_DEPTH};
use crate::wire::{from_wire, to_wire};
use futures::stream::{self, StreamExt};
use netcatty_core::format::{iso_from_ms, mode_to_permissions, parse_octal_mode, raw_bytes_string};
use netcatty_core::ids::now_ms;
use netcatty_core::models::{
    FileEntryType, LinkTargetType, RemoteFile, SftpFilenameEncoding, StatResult,
};
use netcatty_ssh::SshConnection;
use russh_sftp::client::rawsession::Limits;
use russh_sftp::client::{Config, RawSftpSession};
use russh_sftp::protocol::{File, FileAttributes, FileType, OpenFlags};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Largest single `READ`/`WRITE` request we issue. Keeps an inbound `DATA`
/// packet (payload + 13 header bytes) under russh-sftp's 256 KiB frame cap.
const MAX_REQUEST_LEN: u64 = 252 * 1024;
/// Defaults when the server does not advertise `limits@openssh.com`.
/// Many non-OpenSSH servers reject writes above 32 KiB.
const DEFAULT_READ_LEN: u32 = 64 * 1024;
const DEFAULT_WRITE_LEN: u32 = 32 * 1024;
/// Per-request timeout for the raw session (large chunks over slow links).
const REQUEST_TIMEOUT_SECS: u64 = 30;
/// Upper bound for a remote archive extraction.
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Concurrent `stat` calls while resolving symlink targets in a listing.
const SYMLINK_STAT_CONCURRENCY: usize = 16;

const RESOLVED_UTF8: u8 = 0;
const RESOLVED_GB18030: u8 = 1;

/// Request sizes negotiated with the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferLimits {
    pub read_len: u32,
    pub write_len: u32,
}

impl Default for TransferLimits {
    fn default() -> Self {
        Self {
            read_len: DEFAULT_READ_LEN,
            write_len: DEFAULT_WRITE_LEN,
        }
    }
}

/// One SFTP subsystem channel on an SSH connection.
///
/// The client keeps the owning [`SshConnection`] alive so a browser opened
/// from a terminal session survives the terminal closing (the Electron
/// bridge calls this "session lease").
///
/// Paths travel through `russh-sftp` as byte strings disguised as `String`
/// (see [`crate::wire`]); every public method takes and returns real,
/// decoded paths.
pub struct SftpClient {
    pub(crate) session: Arc<RawSftpSession>,
    pub connection: Arc<SshConnection>,
    pub encoding: SftpFilenameEncoding,
    /// Remote home directory discovered at open time (`realpath(".")`).
    pub home_dir: Option<String>,
    pub(crate) limits: TransferLimits,
    /// Concrete encoding `Auto` currently resolves to for *encoding* paths
    /// (mirrors the Electron per-session `resolved` state: starts as UTF-8
    /// and flips to GB18030 once a listing contains non-UTF-8 names).
    resolved: AtomicU8,
}

impl SftpClient {
    /// Open the `sftp` subsystem on `connection`.
    pub async fn open(
        connection: Arc<SshConnection>,
        encoding: SftpFilenameEncoding,
    ) -> SftpResult<Self> {
        let channel = connection
            .handle
            .channel_open_session()
            .await
            .map_err(|e| SftpError::Unavailable(format!("cannot open session channel: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| SftpError::Unavailable(format!("sftp subsystem request failed: {e}")))?;

        let stream = crate::wire::wrap(channel.into_stream());
        let cfg = Config {
            request_timeout_secs: REQUEST_TIMEOUT_SECS,
            ..Config::default()
        };
        let mut raw = RawSftpSession::new_with_config(stream, cfg);
        let version = raw
            .init()
            .await
            .map_err(|e| SftpError::Unavailable(format!("sftp init failed: {e}")))?;

        let mut limits = TransferLimits::default();
        let has_limits = version
            .extensions
            .get(russh_sftp::extensions::LIMITS)
            .is_some_and(|v| v == "1");
        if has_limits {
            match raw.limits().await {
                Ok(ext) => {
                    let server = Limits::from(ext);
                    raw.set_limits(server);
                    if let Some(read) = server.read_len {
                        limits.read_len = read.min(MAX_REQUEST_LEN) as u32;
                    }
                    if let Some(write) = server.write_len {
                        limits.write_len = write.min(MAX_REQUEST_LEN) as u32;
                    }
                }
                Err(err) => tracing::debug!(error = %err, "limits@openssh.com query failed"),
            }
        }

        let mut client = Self {
            session: Arc::new(raw),
            connection,
            encoding,
            home_dir: None,
            limits,
            resolved: AtomicU8::new(RESOLVED_UTF8),
        };
        client.home_dir = match client.realpath(".", None).await {
            Ok(path) => Some(path),
            Err(err) => {
                tracing::warn!(error = %err, "could not resolve sftp home directory");
                None
            }
        };
        Ok(client)
    }

    /// Negotiated request sizes.
    pub fn limits(&self) -> TransferLimits {
        self.limits
    }

    // --- encoding ---------------------------------------------------------

    /// The encoding to use for this call: explicit per-call value, else the
    /// client default. An explicit non-`Auto` value also pins the `Auto`
    /// resolution (as the Electron bridge does).
    fn effective(&self, requested: Option<SftpFilenameEncoding>) -> SftpFilenameEncoding {
        let encoding = requested.unwrap_or(self.encoding);
        match encoding {
            SftpFilenameEncoding::Utf8 => self.resolved.store(RESOLVED_UTF8, Ordering::Relaxed),
            SftpFilenameEncoding::Gb18030 => {
                self.resolved.store(RESOLVED_GB18030, Ordering::Relaxed)
            }
            SftpFilenameEncoding::Auto => {}
        }
        encoding
    }

    /// Concrete encoding used to *encode* outgoing paths.
    fn concrete(&self, encoding: SftpFilenameEncoding) -> SftpFilenameEncoding {
        match encoding {
            SftpFilenameEncoding::Auto => {
                if self.resolved.load(Ordering::Relaxed) == RESOLVED_GB18030 {
                    SftpFilenameEncoding::Gb18030
                } else {
                    SftpFilenameEncoding::Utf8
                }
            }
            other => other,
        }
    }

    /// Encode a user path for the wire (byte-preserving `String`).
    pub(crate) fn wire_path(&self, path: &str, encoding: SftpFilenameEncoding) -> String {
        to_wire(&encode_path(path, self.concrete(encoding)))
    }

    /// Encode with the client default encoding (used by transfers).
    pub(crate) fn wire_path_default(&self, path: &str) -> String {
        self.wire_path(path, self.encoding)
    }

    /// Decode a wire name with `encoding` (`Auto` tries UTF-8 then GB18030).
    fn decode(&self, wire: &str, encoding: SftpFilenameEncoding) -> String {
        decode_name(&from_wire(wire), encoding)
    }

    // --- browse -----------------------------------------------------------

    /// List a directory. Entries are returned unsorted; the renderer sorts.
    pub async fn list(
        &self,
        path: &str,
        encoding: Option<SftpFilenameEncoding>,
    ) -> SftpResult<Vec<RemoteFile>> {
        let encoding = self.effective(encoding);
        let base = self.wire_path(path, encoding);
        let files = self.read_dir_wire(&base).await?;

        // Auto-detect: any non-UTF-8 name flips the session to GB18030.
        let decode_with = if encoding == SftpFilenameEncoding::Auto {
            let non_utf8 = files
                .iter()
                .any(|f| std::str::from_utf8(&from_wire(&f.filename)).is_err());
            if non_utf8 {
                self.resolved.store(RESOLVED_GB18030, Ordering::Relaxed);
                SftpFilenameEncoding::Gb18030
            } else {
                self.concrete(SftpFilenameEncoding::Auto)
            }
        } else {
            encoding
        };

        let base = &base;
        let entries = stream::iter(files.into_iter().map(|file| async move {
            let name = self.decode(&file.filename, decode_with);
            let longname = self.decode(&file.longname, decode_with);
            let entry_type = entry_type_of(&file.attrs);
            let link_target = if entry_type == FileEntryType::Symlink {
                let full = join_wire(base, &file.filename);
                Some(match self.session.stat(full).await {
                    Ok(attrs) if attrs.attrs.is_dir() => Some(LinkTargetType::Directory),
                    Ok(_) => Some(LinkTargetType::File),
                    Err(_) => None,
                })
            } else {
                None
            };
            let (owner, group) = owner_group(&longname, &file.attrs);
            let permissions = file
                .attrs
                .permissions
                .map(|mode| mode_to_permissions(mode, false))
                .or_else(|| permissions_from_longname(&longname));
            let modified_ms = file
                .attrs
                .mtime
                .map(|m| m as i64 * 1000)
                .unwrap_or_else(now_ms);
            RemoteFile {
                name,
                entry_type,
                size: raw_bytes_string(file.attrs.size.unwrap_or(0)),
                last_modified: iso_from_ms(modified_ms),
                link_target,
                permissions,
                owner,
                group,
                hidden: None,
            }
        }))
        .buffered(SYMLINK_STAT_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
        Ok(entries)
    }

    pub async fn realpath(
        &self,
        path: &str,
        encoding: Option<SftpFilenameEncoding>,
    ) -> SftpResult<String> {
        let encoding = self.effective(encoding);
        let name = self
            .session
            .realpath(self.wire_path(path, encoding))
            .await?;
        let file = name
            .files
            .first()
            .ok_or_else(|| SftpError::Protocol("realpath returned no entry".into()))?;
        Ok(self.decode(&file.filename, encoding))
    }

    /// Stat following symlinks.
    pub async fn stat(
        &self,
        path: &str,
        encoding: Option<SftpFilenameEncoding>,
    ) -> SftpResult<StatResult> {
        let encoding = self.effective(encoding);
        let attrs = self.session.stat(self.wire_path(path, encoding)).await?;
        Ok(stat_result(path, &attrs.attrs))
    }

    /// Stat without following symlinks; `Ok(None)` when the path is missing.
    pub async fn lstat(
        &self,
        path: &str,
        encoding: Option<SftpFilenameEncoding>,
    ) -> SftpResult<Option<StatResult>> {
        let encoding = self.effective(encoding);
        match self.session.lstat(self.wire_path(path, encoding)).await {
            Ok(attrs) => Ok(Some(stat_result(path, &attrs.attrs))),
            Err(err) => match SftpError::from(err) {
                SftpError::NotFound(_) => Ok(None),
                other => Err(other),
            },
        }
    }

    /// Read a whole file (bounded by `max_bytes` when given — the renderer's
    /// text editor passes a cap so a huge log cannot exhaust memory).
    pub async fn read(
        &self,
        path: &str,
        max_bytes: Option<u64>,
        encoding: Option<SftpFilenameEncoding>,
    ) -> SftpResult<Vec<u8>> {
        let encoding = self.effective(encoding);
        let wire = self.wire_path(path, encoding);
        let handle = self
            .session
            .open(wire, OpenFlags::READ, FileAttributes::empty())
            .await?
            .handle;
        let size = match self.session.fstat(handle.as_str()).await {
            Ok(attrs) => attrs.attrs.size,
            Err(_) => None,
        };
        if let (Some(max), Some(size)) = (max_bytes, size) {
            if size > max {
                close_quietly(&self.session, &handle).await;
                return Err(too_large(size, max));
            }
        }
        let mut reader = PipelinedReader::new(
            self.session.clone(),
            handle.clone(),
            0,
            size,
            self.limits.read_len,
            PIPELINE_DEPTH,
        );
        let mut out = Vec::with_capacity(size.unwrap_or(0).min(16 * 1024 * 1024) as usize);
        let result = loop {
            match reader.next_chunk().await {
                Ok(Some(chunk)) => {
                    out.extend_from_slice(&chunk);
                    if let Some(max) = max_bytes {
                        if out.len() as u64 > max {
                            break Err(too_large(out.len() as u64, max));
                        }
                    }
                }
                Ok(None) => break Ok(()),
                Err(err) => break Err(err),
            }
        };
        drop(reader);
        close_quietly(&self.session, &handle).await;
        result.map(|_| out)
    }

    /// Read up to `max_bytes` starting at `offset` (to the end of the file
    /// when `max_bytes` is `None`). Returns the bytes and the file size when
    /// the server reports one. An offset at or past the end yields no bytes.
    pub async fn read_range(
        &self,
        path: &str,
        offset: u64,
        max_bytes: Option<u64>,
        encoding: Option<SftpFilenameEncoding>,
    ) -> SftpResult<(Vec<u8>, Option<u64>)> {
        let encoding = self.effective(encoding);
        let wire = self.wire_path(path, encoding);
        let handle = self
            .session
            .open(wire, OpenFlags::READ, FileAttributes::empty())
            .await?
            .handle;
        let size = match self.session.fstat(handle.as_str()).await {
            Ok(attrs) => attrs.attrs.size,
            Err(_) => None,
        };
        let end = match (max_bytes, size) {
            (Some(max), Some(size)) => Some(offset.saturating_add(max).min(size)),
            (Some(max), None) => Some(offset.saturating_add(max)),
            (None, size) => size,
        };
        if end.is_some_and(|end| offset >= end) {
            close_quietly(&self.session, &handle).await;
            return Ok((Vec::new(), size));
        }
        let mut reader = PipelinedReader::new(
            self.session.clone(),
            handle.clone(),
            offset,
            end,
            self.limits.read_len,
            PIPELINE_DEPTH,
        );
        let expected = end.map(|end| end - offset).unwrap_or(0);
        let mut out = Vec::with_capacity(expected.min(16 * 1024 * 1024) as usize);
        let result = loop {
            match reader.next_chunk().await {
                Ok(Some(chunk)) => out.extend_from_slice(&chunk),
                Ok(None) => break Ok(()),
                Err(err) => break Err(err),
            }
        };
        drop(reader);
        close_quietly(&self.session, &handle).await;
        result.map(|_| (out, size))
    }

    /// Write a whole file (create/truncate).
    pub async fn write(
        &self,
        path: &str,
        content: &[u8],
        encoding: Option<SftpFilenameEncoding>,
    ) -> SftpResult<()> {
        let encoding = self.effective(encoding);
        let wire = self.wire_path(path, encoding);
        let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE;
        let handle = self
            .session
            .open(wire, flags, FileAttributes::empty())
            .await?
            .handle;
        let mut writer = PipelinedWriter::new(
            self.session.clone(),
            handle.clone(),
            0,
            self.limits.write_len,
            PIPELINE_DEPTH,
        );
        let result = async {
            writer.write(content).await?;
            writer.flush().await
        }
        .await;
        drop(writer);
        match result {
            Ok(()) => {
                self.session.close(handle).await?;
                Ok(())
            }
            Err(err) => {
                close_quietly(&self.session, &handle).await;
                Err(err)
            }
        }
    }

    pub async fn mkdir(
        &self,
        path: &str,
        encoding: Option<SftpFilenameEncoding>,
    ) -> SftpResult<()> {
        let encoding = self.effective(encoding);
        self.session
            .mkdir(self.wire_path(path, encoding), FileAttributes::empty())
            .await?;
        Ok(())
    }

    /// Delete a file, symlink, or directory (recursively). When
    /// `expected_type` is given and the current type differs, fail with
    /// `SftpError::Stale` instead of deleting.
    pub async fn delete(
        &self,
        path: &str,
        expected_type: Option<FileEntryType>,
        encoding: Option<SftpFilenameEncoding>,
    ) -> SftpResult<()> {
        let encoding = self.effective(encoding);
        let wire = self.wire_path(path, encoding);
        let attrs = self.session.lstat(wire.clone()).await?.attrs;
        let actual = entry_type_of(&attrs);
        if let Some(expected) = expected_type {
            if expected != actual {
                return Err(SftpError::Stale {
                    expected: entry_type_name(expected).to_string(),
                    found: entry_type_name(actual).to_string(),
                });
            }
        }
        match actual {
            FileEntryType::Directory => self.remove_dir_recursive(wire).await,
            FileEntryType::Symlink | FileEntryType::File => {
                self.session.remove(wire).await?;
                Ok(())
            }
        }
    }

    pub async fn rename(
        &self,
        from: &str,
        to: &str,
        encoding: Option<SftpFilenameEncoding>,
    ) -> SftpResult<()> {
        let encoding = self.effective(encoding);
        self.session
            .rename(self.wire_path(from, encoding), self.wire_path(to, encoding))
            .await?;
        Ok(())
    }

    /// `mode` is an octal string such as `"755"`.
    pub async fn chmod(
        &self,
        path: &str,
        mode: &str,
        encoding: Option<SftpFilenameEncoding>,
    ) -> SftpResult<()> {
        let encoding = self.effective(encoding);
        let bits = parse_octal_mode(mode).ok_or_else(|| {
            SftpError::InvalidArgument(format!("invalid permission mode: {mode:?}"))
        })?;
        let attrs = FileAttributes {
            permissions: Some(bits & 0o7777),
            ..FileAttributes::empty()
        };
        self.session
            .setstat(self.wire_path(path, encoding), attrs)
            .await?;
        Ok(())
    }

    /// Extract an archive in place using remote `tar`/`unzip` via SSH exec.
    pub async fn extract_archive(
        &self,
        path: &str,
        encoding: Option<SftpFilenameEncoding>,
    ) -> SftpResult<()> {
        let encoding = self.effective(encoding);
        let raw_path = encode_path(path, self.concrete(encoding));
        let command = build_extract_command(&raw_path)?;
        let output = self
            .connection
            .exec(&command, Some(EXTRACT_TIMEOUT))
            .await?;
        match output.exit_code {
            Some(0) => Ok(()),
            code => {
                let stderr = output.stderr_lossy();
                let detail = stderr.trim();
                let detail = if detail.is_empty() {
                    format!(
                        "exit code {}",
                        code.map(|c| c.to_string())
                            .unwrap_or_else(|| "unknown".into())
                    )
                } else {
                    detail.chars().take(2000).collect()
                };
                Err(SftpError::Command(format!(
                    "archive extraction failed: {detail}"
                )))
            }
        }
    }

    pub async fn close(self) -> SftpResult<()> {
        self.session.close_session()?;
        Ok(())
    }

    // --- internals --------------------------------------------------------

    /// `readdir` loop on a wire path, skipping `.` and `..`.
    pub(crate) async fn read_dir_wire(&self, wire_path: &str) -> SftpResult<Vec<File>> {
        let handle = self.session.opendir(wire_path.to_string()).await?.handle;
        let mut files = Vec::new();
        let result = loop {
            match self.session.readdir(handle.as_str()).await {
                Ok(name) => files.extend(
                    name.files
                        .into_iter()
                        .filter(|f| f.filename != "." && f.filename != ".."),
                ),
                Err(russh_sftp::client::error::Error::Status(status))
                    if status.status_code == russh_sftp::protocol::StatusCode::Eof =>
                {
                    break Ok(())
                }
                Err(err) => break Err(SftpError::from(err)),
            }
        };
        close_quietly(&self.session, &handle).await;
        result.map(|_| files)
    }

    fn remove_dir_recursive(
        &self,
        wire_dir: String,
    ) -> Pin<Box<dyn Future<Output = SftpResult<()>> + Send + '_>> {
        Box::pin(async move {
            let entries = self.read_dir_wire(&wire_dir).await?;
            for entry in entries {
                let child = join_wire(&wire_dir, &entry.filename);
                if entry.attrs.is_dir() && !entry.attrs.is_symlink() {
                    self.remove_dir_recursive(child).await?;
                } else {
                    self.session.remove(child).await?;
                }
            }
            self.session.rmdir(wire_dir).await?;
            Ok(())
        })
    }
}

// --- pure helpers -----------------------------------------------------------

/// Encode a path for the wire according to `encoding`.
///
/// `Auto` encodes as UTF-8 here; [`SftpClient`] resolves `Auto` to a
/// concrete encoding first using its per-session detection state.
pub fn encode_path(path: &str, encoding: SftpFilenameEncoding) -> Vec<u8> {
    match encoding {
        SftpFilenameEncoding::Utf8 | SftpFilenameEncoding::Auto => path.as_bytes().to_vec(),
        SftpFilenameEncoding::Gb18030 => {
            if path.is_ascii() {
                path.as_bytes().to_vec()
            } else {
                encoding_rs::GB18030.encode(path).0.into_owned()
            }
        }
    }
}

/// Decode a wire filename according to `encoding`.
pub fn decode_name(bytes: &[u8], encoding: SftpFilenameEncoding) -> String {
    match encoding {
        SftpFilenameEncoding::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        SftpFilenameEncoding::Gb18030 => encoding_rs::GB18030
            .decode_without_bom_handling(bytes)
            .0
            .into_owned(),
        SftpFilenameEncoding::Auto => match std::str::from_utf8(bytes) {
            Ok(text) => text.to_owned(),
            Err(_) => encoding_rs::GB18030
                .decode_without_bom_handling(bytes)
                .0
                .into_owned(),
        },
    }
}

/// POSIX `join` on wire strings (`base/name`).
fn join_wire(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_string()
    } else if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Last path segment (POSIX), ignoring trailing slashes.
pub fn posix_basename(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return path.to_string();
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed).to_string()
}

/// Parent directory of a POSIX path; `None` for `/`, `.` and empty paths.
pub fn posix_parent(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "." {
        return None;
    }
    match trimmed.rfind('/') {
        None => Some(".".to_string()),
        Some(0) => Some("/".to_string()),
        Some(idx) => Some(trimmed[..idx].to_string()),
    }
}

fn entry_type_of(attrs: &FileAttributes) -> FileEntryType {
    match attrs.file_type() {
        FileType::Dir => FileEntryType::Directory,
        FileType::Symlink => FileEntryType::Symlink,
        FileType::File | FileType::Other => FileEntryType::File,
    }
}

pub(crate) fn entry_type_name(entry_type: FileEntryType) -> &'static str {
    match entry_type {
        FileEntryType::File => "file",
        FileEntryType::Directory => "directory",
        FileEntryType::Symlink => "symlink",
    }
}

/// Build a [`StatResult`] from SFTP attributes (`lastModified` in ms,
/// `permissions` as an octal string like the Electron bridge).
pub(crate) fn stat_result(path: &str, attrs: &FileAttributes) -> StatResult {
    StatResult {
        name: posix_basename(path),
        entry_type: entry_type_of(attrs),
        size: attrs.size.unwrap_or(0),
        size_known: Some(attrs.size.is_some()),
        last_modified: attrs.mtime.map(|m| m as i64 * 1000).unwrap_or(0),
        permissions: attrs.permissions.map(|mode| format!("{:o}", mode & 0o777)),
        owner: attrs.uid.map(|uid| uid.to_string()),
        group: attrs.gid.map(|gid| gid.to_string()),
        dev: None,
        ino: None,
    }
}

fn too_large(size: u64, max: u64) -> SftpError {
    SftpError::InvalidArgument(format!(
        "Remote file is too large to read into memory ({size} bytes; maximum {max} bytes). \
         Use SFTP download for large files, or open it with an external app."
    ))
}

fn is_mode_token(token: &str) -> bool {
    let mut chars = token.chars();
    let Some(kind) = chars.next() else {
        return false;
    };
    if !"dlbcps-".contains(kind) {
        return false;
    }
    let perms: Vec<char> = chars.collect();
    if perms.len() < 9 {
        return false;
    }
    perms[..9].iter().all(|c| "rwxsStT-".contains(*c))
        && perms[9..].iter().all(|c| "+.@".contains(*c))
}

/// Owner / group names from an `ls -l` style longname
/// (`-rwxr-xr-x 1 root wheel 4096 Jan 1 00:00 name`), falling back to
/// uid/gid strings.
pub(crate) fn owner_group(
    longname: &str,
    attrs: &FileAttributes,
) -> (Option<String>, Option<String>) {
    let tokens: Vec<&str> = longname.split_whitespace().collect();
    let from_longname = if tokens.len() >= 4
        && is_mode_token(tokens[0])
        && tokens[1].chars().all(|c| c.is_ascii_digit())
    {
        let clean = |t: &str| {
            let t = t.trim();
            (!t.is_empty() && t != "?" && t != "UNKNOWN").then(|| t.to_string())
        };
        (clean(tokens[2]), clean(tokens[3]))
    } else {
        (None, None)
    };
    (
        from_longname.0.or_else(|| attrs.uid.map(|u| u.to_string())),
        from_longname.1.or_else(|| attrs.gid.map(|g| g.to_string())),
    )
}

/// `rwxr-xr-x` from the first longname token, when the server sent no mode.
fn permissions_from_longname(longname: &str) -> Option<String> {
    let token = longname.split_whitespace().next()?;
    if !is_mode_token(token) {
        return None;
    }
    Some(token.chars().skip(1).take(9).collect())
}

/// Single-quote `text` for a POSIX shell.
pub fn shell_quote(text: &str) -> String {
    if text.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// Quote a raw path for a POSIX shell. Non-UTF-8 bytes (GB18030 names) are
/// reproduced with `printf` octal escapes so the remote shell receives the
/// exact bytes.
pub fn shell_quote_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => shell_quote(text),
        Err(_) => {
            let mut escaped = String::with_capacity(bytes.len() * 4);
            for b in bytes {
                escaped.push_str(&format!("\\{b:03o}"));
            }
            format!("\"$(printf '{escaped}')\"")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    TarZst,
    Zip,
    Gz,
    Bz2,
    Xz,
}

/// Detect the archive type from the file name (case-insensitive suffix).
pub fn archive_kind(name: &str) -> Option<ArchiveKind> {
    const TABLE: &[(ArchiveKind, &[&str])] = &[
        (ArchiveKind::TarGz, &[".tar.gz", ".tgz"]),
        (ArchiveKind::TarBz2, &[".tar.bz2", ".tbz2", ".tar.bzip2"]),
        (ArchiveKind::TarXz, &[".tar.xz", ".txz"]),
        (ArchiveKind::TarZst, &[".tar.zst", ".tzst"]),
        (ArchiveKind::Tar, &[".tar"]),
        (ArchiveKind::Zip, &[".zip"]),
        (ArchiveKind::Gz, &[".gz"]),
        (ArchiveKind::Bz2, &[".bz2"]),
        (ArchiveKind::Xz, &[".xz"]),
    ];
    let lower = posix_basename(name).to_lowercase();
    for (kind, suffixes) in TABLE {
        if suffixes
            .iter()
            .any(|s| lower.ends_with(s) && lower.len() > s.len())
        {
            return Some(*kind);
        }
    }
    None
}

/// Build the remote shell command that extracts `raw_path` (encoded path
/// bytes) next to itself.
pub fn build_extract_command(raw_path: &[u8]) -> SftpResult<String> {
    let display = String::from_utf8_lossy(raw_path).into_owned();
    let kind = archive_kind(&display).ok_or_else(|| {
        SftpError::InvalidArgument(format!(
            "Unsupported archive type: {}",
            posix_basename(&display)
        ))
    })?;
    let parent_len = {
        let trimmed_len = raw_path
            .iter()
            .rposition(|&b| b != b'/')
            .map(|i| i + 1)
            .unwrap_or(0);
        if trimmed_len == 0 {
            return Err(SftpError::InvalidArgument(
                "Archive path has no parent directory".into(),
            ));
        }
        raw_path[..trimmed_len].iter().rposition(|&b| b == b'/')
    };
    let parent: &[u8] = match parent_len {
        None => b".",
        Some(0) => b"/",
        Some(idx) => &raw_path[..idx],
    };
    let archive = shell_quote_bytes(raw_path);
    let dir = shell_quote_bytes(parent);
    let command = match kind {
        ArchiveKind::Tar => format!("tar -xf {archive} -C {dir}"),
        ArchiveKind::TarGz => format!("tar -xzf {archive} -C {dir}"),
        ArchiveKind::TarBz2 => format!("tar -xjf {archive} -C {dir}"),
        ArchiveKind::TarXz => format!("tar -xJf {archive} -C {dir}"),
        ArchiveKind::TarZst => format!("tar --zstd -xf {archive} -C {dir}"),
        ArchiveKind::Zip => [
            "if command -v unzip >/dev/null 2>&1; then".to_string(),
            format!("  unzip -qo {archive} -d {dir} >/dev/null"),
            format!("elif tar -tf {archive} >/dev/null 2>&1; then"),
            format!("  tar -xf {archive} -C {dir}"),
            "else".to_string(),
            "  echo 'unzip is not installed on the remote host' >&2".to_string(),
            "  exit 127".to_string(),
            "fi".to_string(),
        ]
        .join("\n"),
        ArchiveKind::Gz | ArchiveKind::Bz2 | ArchiveKind::Xz => {
            let (decoder, suffix) = match kind {
                ArchiveKind::Gz => ("gzip", ".gz"),
                ArchiveKind::Bz2 => ("bzip2", ".bz2"),
                _ => ("xz", ".xz"),
            };
            let base = posix_basename(&display);
            let stem_len = base.len() - suffix.len();
            // Output path: same directory, name without the suffix (byte-exact).
            let base_start = raw_path.len() - base.len();
            let output = shell_quote_bytes(&raw_path[..base_start + stem_len]);
            [
                "set -e".to_string(),
                format!("out={output}"),
                "if [ -e \"$out\" ]; then echo \"target already exists: $out\" >&2; exit 1; fi"
                    .to_string(),
                format!("{decoder} -dc {archive} > \"$out\""),
            ]
            .join("\n")
        }
    };
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trips() {
        assert_eq!(
            encode_path("中文", SftpFilenameEncoding::Gb18030),
            b"\xd6\xd0\xce\xc4"
        );
        assert_eq!(
            encode_path("中文", SftpFilenameEncoding::Utf8),
            "中文".as_bytes()
        );
        assert_eq!(
            encode_path("plain", SftpFilenameEncoding::Gb18030),
            b"plain"
        );
        assert_eq!(
            decode_name(b"\xd6\xd0\xce\xc4", SftpFilenameEncoding::Gb18030),
            "中文"
        );
        assert_eq!(
            decode_name(b"\xd6\xd0\xce\xc4", SftpFilenameEncoding::Auto),
            "中文"
        );
        assert_eq!(
            decode_name("中文".as_bytes(), SftpFilenameEncoding::Auto),
            "中文"
        );
        assert_eq!(
            decode_name("中文".as_bytes(), SftpFilenameEncoding::Utf8),
            "中文"
        );
        assert_eq!(
            decode_name(b"a\xffb", SftpFilenameEncoding::Utf8),
            "a\u{fffd}b"
        );
        for enc in [SftpFilenameEncoding::Utf8, SftpFilenameEncoding::Gb18030] {
            assert_eq!(
                decode_name(&encode_path("文件 (1).txt", enc), enc),
                "文件 (1).txt"
            );
        }
    }

    #[test]
    fn shell_quoting() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote_bytes(b"/tmp/x"), "'/tmp/x'");
        assert_eq!(shell_quote_bytes(b"\xd6\xd0"), "\"$(printf '\\326\\320')\"");
    }

    #[test]
    fn posix_helpers() {
        assert_eq!(posix_basename("/a/b/c.txt"), "c.txt");
        assert_eq!(posix_basename("/a/b/"), "b");
        assert_eq!(posix_basename("/"), "/");
        assert_eq!(posix_parent("/a/b/c"), Some("/a/b".into()));
        assert_eq!(posix_parent("/a"), Some("/".into()));
        assert_eq!(posix_parent("a"), Some(".".into()));
        assert_eq!(posix_parent("/"), None);
        assert_eq!(join_wire("/a/", "b"), "/a/b");
        assert_eq!(join_wire("/a", "b"), "/a/b");
    }

    #[test]
    fn archive_commands() {
        assert_eq!(archive_kind("x.tar.gz"), Some(ArchiveKind::TarGz));
        assert_eq!(archive_kind("X.TGZ"), Some(ArchiveKind::TarGz));
        assert_eq!(archive_kind("x.gz"), Some(ArchiveKind::Gz));
        assert_eq!(archive_kind(".gz"), None);
        assert_eq!(archive_kind("x.rar"), None);
        assert_eq!(
            build_extract_command(b"/srv/it's.tar").unwrap(),
            "tar -xf '/srv/it'\\''s.tar' -C '/srv'"
        );
        assert_eq!(
            build_extract_command(b"a.tar.xz").unwrap(),
            "tar -xJf 'a.tar.xz' -C '.'"
        );
        assert_eq!(
            build_extract_command(b"/a.tar.zst").unwrap(),
            "tar --zstd -xf '/a.tar.zst' -C '/'"
        );
        let zip = build_extract_command(b"/d/a.zip").unwrap();
        assert!(zip.contains("unzip -qo '/d/a.zip' -d '/d'"));
        let gz = build_extract_command(b"/d/log.txt.gz").unwrap();
        assert!(gz.contains("out='/d/log.txt'"));
        assert!(gz.contains("gzip -dc '/d/log.txt.gz'"));
        let gb = build_extract_command(b"/d/\xd6\xd0.tar").unwrap();
        assert!(gb.starts_with(
            "tar -xf \"$(printf '\\057\\144\\057\\326\\320\\056\\164\\141\\162')\" -C '/d'"
        ));
        assert!(matches!(
            build_extract_command(b"/"),
            Err(SftpError::InvalidArgument(_))
        ));
        assert!(matches!(
            build_extract_command(b"/x.bin"),
            Err(SftpError::InvalidArgument(_))
        ));
    }

    #[test]
    fn stat_and_listing_mappings() {
        let attrs = FileAttributes {
            size: Some(1234),
            uid: Some(1000),
            gid: Some(50),
            permissions: Some(0o100644),
            mtime: Some(1_700_000_000),
            ..FileAttributes::empty()
        };
        let st = stat_result("/home/u/file.txt", &attrs);
        assert_eq!(st.name, "file.txt");
        assert_eq!(st.entry_type, FileEntryType::File);
        assert_eq!(st.size, 1234);
        assert_eq!(st.size_known, Some(true));
        assert_eq!(st.last_modified, 1_700_000_000_000);
        assert_eq!(st.permissions.as_deref(), Some("644"));
        assert_eq!(st.owner.as_deref(), Some("1000"));

        let dir = FileAttributes {
            permissions: Some(0o040755),
            ..FileAttributes::empty()
        };
        assert_eq!(entry_type_of(&dir), FileEntryType::Directory);
        let link = FileAttributes {
            permissions: Some(0o120777),
            ..FileAttributes::empty()
        };
        assert_eq!(entry_type_of(&link), FileEntryType::Symlink);
        assert_eq!(stat_result("/x", &dir).size_known, Some(false));
        assert_eq!(mode_to_permissions(0o100644, false), "rw-r--r--");

        let (owner, group) = owner_group("-rw-r--r--    1 alice staff  12 Jan  1 00:00 f", &attrs);
        assert_eq!(owner.as_deref(), Some("alice"));
        assert_eq!(group.as_deref(), Some("staff"));
        let (owner, group) = owner_group("drwxr-xr-x+ 2 ? wheel 12 Jan 1 00:00 d", &attrs);
        assert_eq!(owner.as_deref(), Some("1000"));
        assert_eq!(group.as_deref(), Some("wheel"));
        let (owner, group) = owner_group("", &attrs);
        assert_eq!(
            (owner.as_deref(), group.as_deref()),
            (Some("1000"), Some("50"))
        );
        assert_eq!(
            permissions_from_longname("lrwxrwxrwx 1 a b 1 Jan 1 00:00 l").as_deref(),
            Some("rwxrwxrwx")
        );
        assert_eq!(permissions_from_longname("garbage"), None);
    }
}

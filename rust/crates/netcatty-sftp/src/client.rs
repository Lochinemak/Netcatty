//! SFTP browse operations.

use crate::error::SftpResult;
use netcatty_core::models::{FileEntryType, RemoteFile, SftpFilenameEncoding, StatResult};
use netcatty_ssh::SshConnection;
use russh_sftp::client::SftpSession;
use std::sync::Arc;

/// One SFTP subsystem channel on an SSH connection.
///
/// The client keeps the owning [`SshConnection`] alive so a browser opened
/// from a terminal session survives the terminal closing (the Electron
/// bridge calls this "session lease").
pub struct SftpClient {
    pub(crate) session: SftpSession,
    pub connection: Arc<SshConnection>,
    pub encoding: SftpFilenameEncoding,
    /// Remote home directory discovered at open time (`realpath(".")`).
    pub home_dir: Option<String>,
}

impl SftpClient {
    /// Open the `sftp` subsystem on `connection`.
    pub async fn open(connection: Arc<SshConnection>, encoding: SftpFilenameEncoding) -> SftpResult<Self> {
        let _ = (connection, encoding);
        todo!("channel_open_session + request_subsystem(\"sftp\") + SftpSession::new (sftp agent task)")
    }

    /// List a directory. Entries are returned unsorted; the renderer sorts.
    pub async fn list(&self, path: &str, encoding: Option<SftpFilenameEncoding>) -> SftpResult<Vec<RemoteFile>> {
        let _ = (path, encoding);
        todo!("readdir → RemoteFile (size as \"<n> bytes\", lastModified ISO, permissions, owner/group as uid/gid strings, linkTarget via stat) (sftp agent task)")
    }

    pub async fn realpath(&self, path: &str, encoding: Option<SftpFilenameEncoding>) -> SftpResult<String> {
        let _ = (path, encoding);
        todo!()
    }

    /// Stat following symlinks.
    pub async fn stat(&self, path: &str, encoding: Option<SftpFilenameEncoding>) -> SftpResult<StatResult> {
        let _ = (path, encoding);
        todo!()
    }

    /// Stat without following symlinks; `Ok(None)` when the path is missing.
    pub async fn lstat(&self, path: &str, encoding: Option<SftpFilenameEncoding>) -> SftpResult<Option<StatResult>> {
        let _ = (path, encoding);
        todo!()
    }

    /// Read a whole file (bounded by `max_bytes` when given — the renderer's
    /// text editor passes a cap so a huge log cannot exhaust memory).
    pub async fn read(&self, path: &str, max_bytes: Option<u64>, encoding: Option<SftpFilenameEncoding>) -> SftpResult<Vec<u8>> {
        let _ = (path, max_bytes, encoding);
        todo!()
    }

    /// Write a whole file (create/truncate).
    pub async fn write(&self, path: &str, content: &[u8], encoding: Option<SftpFilenameEncoding>) -> SftpResult<()> {
        let _ = (path, content, encoding);
        todo!()
    }

    pub async fn mkdir(&self, path: &str, encoding: Option<SftpFilenameEncoding>) -> SftpResult<()> {
        let _ = (path, encoding);
        todo!()
    }

    /// Delete a file, symlink, or directory (recursively). When
    /// `expected_type` is given and the current type differs, fail with
    /// `SftpError::Stale` instead of deleting.
    pub async fn delete(&self, path: &str, expected_type: Option<FileEntryType>, encoding: Option<SftpFilenameEncoding>) -> SftpResult<()> {
        let _ = (path, expected_type, encoding);
        todo!()
    }

    pub async fn rename(&self, from: &str, to: &str, encoding: Option<SftpFilenameEncoding>) -> SftpResult<()> {
        let _ = (from, to, encoding);
        todo!()
    }

    /// `mode` is an octal string such as `"755"`.
    pub async fn chmod(&self, path: &str, mode: &str, encoding: Option<SftpFilenameEncoding>) -> SftpResult<()> {
        let _ = (path, mode, encoding);
        todo!()
    }

    /// Extract an archive in place using remote `tar`/`unzip` via SSH exec.
    pub async fn extract_archive(&self, path: &str, encoding: Option<SftpFilenameEncoding>) -> SftpResult<()> {
        let _ = (path, encoding);
        todo!()
    }

    pub async fn close(self) -> SftpResult<()> {
        todo!()
    }
}

/// Encode a path for the wire according to `encoding`.
pub fn encode_path(path: &str, encoding: SftpFilenameEncoding) -> Vec<u8> {
    let _ = (path, encoding);
    todo!("utf-8 passthrough; gb18030 via encoding_rs (sftp agent task adds the dependency)")
}

/// Decode a wire filename according to `encoding`.
pub fn decode_name(bytes: &[u8], encoding: SftpFilenameEncoding) -> String {
    let _ = (bytes, encoding);
    todo!()
}

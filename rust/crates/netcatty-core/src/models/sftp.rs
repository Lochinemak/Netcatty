//! SFTP / transfer models (`domain/models/sftp.ts` and `global.d.ts`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SftpFilenameEncoding {
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "utf-8")]
    Utf8,
    #[serde(rename = "gb18030")]
    Gb18030,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileEntryType {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkTargetType {
    File,
    Directory,
}

/// Result of `statSftp` / `statLocal` (`SftpStatResult` in `global.d.ts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatResult {
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: FileEntryType,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_known: Option<bool>,
    /// Unix milliseconds.
    pub last_modified: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Local-only filesystem identity (omitted on Windows and for remotes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ino: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferStatus {
    Pending,
    Queued,
    Transferring,
    Pausing,
    Paused,
    Attention,
    Interrupted,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferDirection {
    #[serde(rename = "upload")]
    Upload,
    #[serde(rename = "download")]
    Download,
    #[serde(rename = "remote-to-remote")]
    RemoteToRemote,
    #[serde(rename = "local-copy")]
    LocalCopy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferPhase {
    Scanning,
    Compressing,
    Uploading,
    Transferring,
    Extracting,
    Verifying,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_names() {
        assert_eq!(
            serde_json::to_string(&SftpFilenameEncoding::Utf8).unwrap(),
            "\"utf-8\""
        );
        assert_eq!(
            serde_json::from_str::<SftpFilenameEncoding>("\"gb18030\"").unwrap(),
            SftpFilenameEncoding::Gb18030
        );
    }
}

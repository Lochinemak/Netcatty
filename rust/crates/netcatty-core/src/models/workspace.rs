//! Workspace models (`domain/models/workspace.ts`).

use super::sftp::{FileEntryType, LinkTargetType};
use serde::{Deserialize, Serialize};

/// A directory listing row as consumed by the SFTP / local file browser.
///
/// Note the Electron bridge's quirks that the renderer depends on:
/// `size` is the raw string `"<n> bytes"` and `lastModified` is an ISO-8601
/// string. Use [`crate::format::raw_bytes_string`] and
/// [`crate::format::iso_from_ms`] to build them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteFile {
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: FileEntryType,
    pub size: String,
    pub last_modified: String,
    /// For symlinks: target type, or `null` when the link is broken.
    /// Serialized as an explicit `null` for broken links (the renderer
    /// distinguishes `undefined` from `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_target: Option<Option<LinkTargetType>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broken_symlink_serializes_null() {
        let f = RemoteFile {
            name: "l".into(),
            entry_type: FileEntryType::Symlink,
            size: "0 bytes".into(),
            last_modified: "1970-01-01T00:00:00.000Z".into(),
            link_target: Some(None),
            permissions: None,
            owner: None,
            group: None,
            hidden: None,
        };
        let v = serde_json::to_value(&f).unwrap();
        assert!(v["linkTarget"].is_null());
        assert!(v.get("linkTarget").is_some());
        let plain = RemoteFile {
            link_target: None,
            ..f
        };
        let v = serde_json::to_value(&plain).unwrap();
        assert!(v.get("linkTarget").is_none());
    }
}

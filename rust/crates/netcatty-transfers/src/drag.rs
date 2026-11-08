//! Native file-drag request validation (Electron `localFileDragBridge.cjs`
//! `validateDragPayload`).
//!
//! Paths are kept exactly as spelled (no `..` collapsing: `link/../file`
//! can name a different file than its lexical simplification); only
//! identical strings are de-duplicated.

/// Maximum `requestId` length and number of paths per drag.
pub const MAX_REQUEST_ID_LEN: usize = 128;
pub const MAX_PATHS: usize = 4096;

/// Path syntax to validate against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFlavor {
    Posix,
    Windows,
}

impl PathFlavor {
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Posix
        }
    }
}

const INVALID_REQUEST: &str = "Invalid local file drag request";
const NOT_ABSOLUTE: &str = "Drag paths must be absolute filesystem paths";
const NOT_DRIVE_OR_SHARE: &str = "Drag paths must identify a drive or a network share";

fn is_sep(c: u8) -> bool {
    c == b'/' || c == b'\\'
}

/// `path.win32.isAbsolute`.
fn win_is_absolute(p: &[u8]) -> bool {
    match p {
        [first, ..] if is_sep(*first) => true,
        [drive, b':', sep, ..] if drive.is_ascii_alphabetic() && is_sep(*sep) => true,
        _ => false,
    }
}

/// `^(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/][^\\/]+)`.
fn win_drive_or_share(p: &[u8]) -> bool {
    if let [drive, b':', sep, ..] = p {
        if drive.is_ascii_alphabetic() && is_sep(*sep) {
            return true;
        }
    }
    if p.len() >= 2 && is_sep(p[0]) && is_sep(p[1]) {
        let rest = &p[2..];
        let server_len = rest.iter().take_while(|c| !is_sep(**c)).count();
        if server_len == 0 || server_len >= rest.len() {
            return false;
        }
        let share = &rest[server_len + 1..];
        return share.first().is_some_and(|c| !is_sep(*c));
    }
    false
}

/// `^[\\/]{2}[?.][\\/]` (device namespace).
fn win_device_path(p: &[u8]) -> bool {
    p.len() >= 4 && is_sep(p[0]) && is_sep(p[1]) && (p[2] == b'?' || p[2] == b'.') && is_sep(p[3])
}

/// Validate a drag request; returns the de-duplicated paths.
pub fn validate_drag_request(request_id: &str, paths: &[String], flavor: PathFlavor) -> Result<Vec<String>, String> {
    if request_id.is_empty()
        || request_id.len() > MAX_REQUEST_ID_LEN
        || paths.is_empty()
        || paths.len() > MAX_PATHS
    {
        return Err(INVALID_REQUEST.to_string());
    }
    let mut out: Vec<String> = Vec::with_capacity(paths.len());
    for value in paths {
        let bytes = value.as_bytes();
        let absolute = match flavor {
            PathFlavor::Posix => bytes.first() == Some(&b'/'),
            PathFlavor::Windows => win_is_absolute(bytes),
        };
        if value.contains('\0') || !absolute {
            return Err(NOT_ABSOLUTE.to_string());
        }
        if flavor == PathFlavor::Windows && (!win_drive_or_share(bytes) || win_device_path(bytes)) {
            return Err(NOT_DRIVE_OR_SHARE.to_string());
        }
        if !out.contains(value) {
            out.push(value.clone());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(paths: &[&str], flavor: PathFlavor) -> Result<Vec<String>, String> {
        let owned: Vec<String> = paths.iter().map(|s| s.to_string()).collect();
        validate_drag_request("x", &owned, flavor)
    }

    #[test]
    fn malformed_requests_are_rejected() {
        assert!(validate_drag_request("", &["/a".into()], PathFlavor::Posix).is_err());
        assert!(validate_drag_request(&"x".repeat(129), &["/a".into()], PathFlavor::Posix).is_err());
        assert!(v(&[], PathFlavor::Posix).is_err());
        assert!(v(&["relative"], PathFlavor::Posix).is_err());
        assert!(v(&["/bad\0file"], PathFlavor::Posix).is_err());
    }

    #[test]
    fn windows_drives_and_shares_keep_their_spelling() {
        assert_eq!(
            v(&["C:/a b/file ", "C:\\a b\\file ", "\\\\server\\share\\folder"], PathFlavor::Windows).unwrap(),
            vec!["C:/a b/file ", "C:\\a b\\file ", "\\\\server\\share\\folder"]
        );
        assert!(v(&["C:relative"], PathFlavor::Windows).is_err());
        assert!(v(&["/drive-relative"], PathFlavor::Windows).is_err());
        assert!(v(&["//./pipe/device"], PathFlavor::Windows).is_err());
        assert!(v(&["\\\\?\\C:\\x"], PathFlavor::Windows).is_err());
        assert!(v(&["\\\\server"], PathFlavor::Windows).is_err());
    }

    #[test]
    fn dot_segments_survive_and_only_identical_strings_dedupe() {
        assert_eq!(
            v(&["/a/../b", "/b", "/a/../b"], PathFlavor::Posix).unwrap(),
            vec!["/a/../b", "/b"]
        );
        let posix = ["/local/link/../file", "/local/./file", "/local//file"];
        let mut with_dup = posix.to_vec();
        with_dup.push(posix[0]);
        assert_eq!(v(&with_dup, PathFlavor::Posix).unwrap(), posix.to_vec());
        let win = ["C:\\local\\link\\..\\file", "C:/local/./file", "\\\\server\\share\\link\\..\\file"];
        let mut with_dup = win.to_vec();
        with_dup.push(win[0]);
        assert_eq!(v(&with_dup, PathFlavor::Windows).unwrap(), win.to_vec());
    }
}

//! Helpers for the encrypted `SyncedFile` body shared by the WebDAV and S3
//! transports.

use netcatty_core::{CoreError, CoreResult};
use serde_json::Value;

/// Compact JSON body (`JSON.stringify(syncedFile)`).
pub fn serialize_compact(synced_file: &Value) -> Vec<u8> {
    serde_json::to_vec(synced_file).unwrap_or_default()
}

/// Pretty JSON body (`JSON.stringify(syncedFile, null, 2)`), used by the
/// Google Drive and OneDrive uploads.
pub fn serialize_pretty(synced_file: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(synced_file).unwrap_or_default()
}

/// Parse a downloaded sync file. Empty text yields `None`.
///
/// Some WebDAV servers overwrite without truncating, leaving bytes of an
/// older, longer body after the JSON (Electron issue #2223). A complete JSON
/// value followed by anything is accepted and the tail dropped; text that does
/// not start with a complete value is still an error.
pub fn parse_recovering(text: &str) -> CoreResult<Option<Value>> {
    if text.is_empty() {
        return Ok(None);
    }
    let mut stream = serde_json::Deserializer::from_str(text).into_iter::<Value>();
    match stream.next() {
        Some(Ok(value)) => Ok(Some(value)),
        Some(Err(err)) => Err(CoreError::invalid(format!("Invalid sync file JSON: {err}"))),
        None => Ok(None),
    }
}

/// Strict JSON parse (S3 / Drive downloads).
pub fn parse_strict(text: &str) -> CoreResult<Value> {
    serde_json::from_str(text)
        .map_err(|err| CoreError::invalid(format!("Invalid sync file JSON: {err}")))
}

/// Pad `body` with spaces up to `min_len` so a non-truncating PUT cannot
/// leave trailing garbage. JSON parsers ignore trailing whitespace.
pub fn pad_to_at_least(body: &[u8], min_len: usize) -> Vec<u8> {
    let mut out = body.to_vec();
    if min_len > out.len() {
        out.resize(min_len, b' ');
    }
    out
}

/// True when `remote` is exactly `body` followed only by whitespace.
pub fn remote_matches_body(remote: &str, body: &[u8]) -> bool {
    let Ok(body) = std::str::from_utf8(body) else {
        return false;
    };
    match remote.strip_prefix(body) {
        Some(rest) => rest.chars().all(char::is_whitespace),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn recovers_from_trailing_garbage() {
        let text = r#"{"meta":{"v":1},"payload":"abc"}ld":"old"}"#;
        assert_eq!(
            parse_recovering(text).unwrap(),
            Some(json!({"meta":{"v":1},"payload":"abc"}))
        );
    }

    #[test]
    fn accepts_trailing_whitespace_and_rejects_broken_json() {
        assert_eq!(
            parse_recovering("{\"a\":1}   \n").unwrap(),
            Some(json!({"a":1}))
        );
        assert_eq!(parse_recovering("").unwrap(), None);
        assert!(parse_recovering("{\"a\":").is_err());
    }

    #[test]
    fn padding_and_matching() {
        let body = br#"{"a":1}"#;
        let padded = pad_to_at_least(body, 12);
        assert_eq!(padded.len(), 12);
        assert!(remote_matches_body(
            std::str::from_utf8(&padded).unwrap(),
            body
        ));
        assert!(!remote_matches_body(r#"{"a":1}x"#, body));
        assert!(!remote_matches_body(r#"{"b":1}"#, body));
        assert_eq!(pad_to_at_least(body, 2), body.to_vec());
    }
}

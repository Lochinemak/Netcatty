//! SSE `data:` line extraction (Electron: `electron/bridges/ai/sseDataLine.cjs`).

/// Extract the payload of an SSE `data:` field.
///
/// The WHATWG EventSource spec treats the space after the colon as optional
/// and strips at most one leading U+0020. Older AxonHub (0.9) and some
/// intranet OpenAI-compatible proxies emit `data:{json}` with no space,
/// which a `data: ` prefix check would silently drop (issue #3020).
pub fn extract_sse_data_payload(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let payload = trimmed.strip_prefix("data:")?;
    Some(payload.strip_prefix(' ').unwrap_or(payload).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_data_with_or_without_the_optional_space() {
        assert_eq!(extract_sse_data_payload("data: {\"a\":1}").as_deref(), Some("{\"a\":1}"));
        assert_eq!(extract_sse_data_payload("data:{\"a\":1}").as_deref(), Some("{\"a\":1}"));
        assert_eq!(extract_sse_data_payload("  data:{\"a\":1}  \r").as_deref(), Some("{\"a\":1}"));
        assert_eq!(extract_sse_data_payload("data: [DONE]").as_deref(), Some("[DONE]"));
        assert_eq!(extract_sse_data_payload("data:[DONE]").as_deref(), Some("[DONE]"));
    }

    #[test]
    fn strips_only_one_leading_space_after_the_colon() {
        assert_eq!(extract_sse_data_payload("data:  keep").as_deref(), Some(" keep"));
        assert_eq!(extract_sse_data_payload("data:").as_deref(), Some(""));
        assert_eq!(extract_sse_data_payload("data: ").as_deref(), Some(""));
    }

    #[test]
    fn ignores_non_data_sse_lines() {
        assert_eq!(extract_sse_data_payload(""), None);
        assert_eq!(extract_sse_data_payload(": comment"), None);
        assert_eq!(extract_sse_data_payload("event: message"), None);
        assert_eq!(extract_sse_data_payload("DATA: foo"), None);
    }
}

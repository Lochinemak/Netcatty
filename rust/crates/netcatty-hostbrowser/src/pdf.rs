//! PDF-to-download policy (Electron: `pdfDownloadHeaders`).
//!
//! Electron's page allowlist excluded Chromium's extension-based PDF viewer,
//! so PDF navigations were handed to the download manager by rewriting the
//! response's `Content-Disposition` to `attachment` at header time. The
//! policy is kept here as a pure function (with the original test cases) so
//! a runtime that can intercept response headers can apply it; see
//! `rust/docs/ipc-hostbrowser.md` for what each webview engine allows.

use regex::Regex;
use std::sync::OnceLock;

/// Header map as `(name, values)` pairs, order preserved.
pub type Headers = Vec<(String, Vec<String>)>;

fn attachment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^\s*attachment\s*(;|$)").unwrap())
}

/// Returns the rewritten response headers when a successful main / sub
/// frame navigation is a PDF that would otherwise be previewed inline.
/// `None` means "leave the response alone".
pub fn pdf_download_headers(
    resource_type: &str,
    status_code: u16,
    response_headers: Option<&Headers>,
) -> Option<Headers> {
    if !matches!(resource_type, "mainFrame" | "subFrame") || !(200..300).contains(&status_code) {
        return None;
    }
    let headers = response_headers?;
    let content_type = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
        .and_then(|(_, values)| values.first())?;
    let mime = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if mime != "application/pdf" {
        return None;
    }
    let disposition_key = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-disposition"))
        .map(|(key, _)| key.clone())
        .unwrap_or_else(|| "Content-Disposition".to_string());
    let disposition = headers
        .iter()
        .find(|(key, _)| *key == disposition_key)
        .and_then(|(_, values)| values.first())
        .cloned()
        .unwrap_or_default();
    if attachment_re().is_match(&disposition) {
        return None;
    }
    // Keep the site's filename / filename* parameters, including localized names.
    let parameters = disposition
        .find(';')
        .map(|index| disposition[index..].to_string())
        .unwrap_or_default();
    let rewritten = format!("attachment{parameters}");
    let mut result: Headers = headers
        .iter()
        .filter(|(key, _)| *key != disposition_key)
        .cloned()
        .collect();
    result.push((disposition_key, vec![rewritten]));
    Some(result)
}

/// Should a frame navigation's response be saved instead of shown? This is
/// the question for a runtime that decides per response rather than by
/// rewriting headers (WebKit's navigation response policy): the PDFs
/// [`pdf_download_headers`] would turn into attachments, and the responses
/// the site already marked `attachment`, which Chromium saves on its own but
/// WebKit shows whenever it can render the type.
pub fn navigation_response_downloads(
    resource_type: &str,
    status_code: u16,
    content_type: Option<&str>,
    content_disposition: Option<&str>,
) -> bool {
    if !matches!(resource_type, "mainFrame" | "subFrame") || !(200..300).contains(&status_code) {
        return false;
    }
    if content_disposition.is_some_and(|value| attachment_re().is_match(value)) {
        return true;
    }
    let mut headers: Headers = Vec::new();
    if let Some(value) = content_type {
        headers.push(("Content-Type".into(), vec![value.into()]));
    }
    if let Some(value) = content_disposition {
        headers.push(("Content-Disposition".into(), vec![value.into()]));
    }
    pdf_download_headers(resource_type, status_code, Some(&headers)).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Headers {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
            .collect()
    }

    fn value<'a>(headers: &'a Headers, key: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .and_then(|(_, v)| v.first().map(String::as_str))
    }

    #[test]
    fn pdf_navigations_download_before_the_preview_can_buffer_the_response() {
        let input = headers(&[
            ("Content-Type", "Application/PDF;charset=UTF-8"),
            ("Content-Length", "8933895"),
        ]);
        for resource_type in ["mainFrame", "subFrame"] {
            let out = pdf_download_headers(resource_type, 200, Some(&input)).unwrap();
            assert_eq!(value(&out, "Content-Disposition"), Some("attachment"));
            assert_eq!(value(&out, "Content-Length"), Some("8933895"));
            assert_eq!(value(&out, "Content-Type"), Some("Application/PDF;charset=UTF-8"));
        }
        assert!(value(&input, "Content-Disposition").is_none(), "input not mutated");
    }

    #[test]
    fn pdf_downloads_preserve_the_sites_localized_suggested_filename() {
        let filename = "; filename=report.pdf; filename*=UTF-8''%E6%8A%A5%E5%91%8A.pdf";
        let input = headers(&[
            ("content-type", "application/pdf"),
            ("content-disposition", &format!("inline{filename}")),
        ]);
        let out = pdf_download_headers("mainFrame", 200, Some(&input)).unwrap();
        assert_eq!(
            value(&out, "content-disposition"),
            Some(format!("attachment{filename}").as_str())
        );
        // The original header name (lower case) is kept.
        assert!(out.iter().any(|(k, _)| k == "content-disposition"));
    }

    #[test]
    fn pdf_policy_leaves_webpage_requests_failed_responses_and_explicit_downloads_alone() {
        let input = headers(&[("content-type", "application/pdf")]);
        for resource_type in ["xhr", "object", "other", "script", "image"] {
            assert!(pdf_download_headers(resource_type, 200, Some(&input)).is_none());
        }
        for status in [302u16, 404, 500] {
            assert!(pdf_download_headers("mainFrame", status, Some(&input)).is_none());
        }
        for mime in ["text/html", "image/png", "application/octet-stream"] {
            let other = headers(&[("content-type", mime)]);
            assert!(pdf_download_headers("mainFrame", 200, Some(&other)).is_none());
        }
        let explicit = headers(&[
            ("content-type", "application/pdf"),
            ("content-disposition", "attachment; filename=report.pdf"),
        ]);
        assert!(pdf_download_headers("mainFrame", 200, Some(&explicit)).is_none());
        assert!(pdf_download_headers("mainFrame", 200, None).is_none());
    }

    #[test]
    fn response_policy_saves_pdfs_and_attachments_and_shows_the_rest() {
        for frame in ["mainFrame", "subFrame"] {
            assert!(navigation_response_downloads(frame, 200, Some("application/pdf"), None));
            assert!(navigation_response_downloads(frame, 200, Some("Application/PDF; charset=UTF-8"), Some("inline; filename=a.pdf")));
            assert!(navigation_response_downloads(frame, 200, Some("application/pdf"), Some("attachment; filename=a.pdf")));
            assert!(navigation_response_downloads(frame, 200, Some("text/plain"), Some("Attachment")));
            assert!(navigation_response_downloads(frame, 206, Some("image/png"), Some(" attachment; filename=a.png")));
        }
        assert!(!navigation_response_downloads("mainFrame", 200, Some("text/html"), None));
        assert!(!navigation_response_downloads("mainFrame", 200, Some("image/png"), Some("inline")));
        assert!(!navigation_response_downloads("mainFrame", 200, None, None));
        // A header that only mentions the word is not an attachment.
        assert!(!navigation_response_downloads("mainFrame", 200, Some("text/html"), Some("inline; filename=attachment.html")));
        for status in [302u16, 404, 500] {
            assert!(!navigation_response_downloads("mainFrame", status, Some("application/pdf"), Some("attachment")));
        }
        for resource_type in ["xhr", "object", "image"] {
            assert!(!navigation_response_downloads(resource_type, 200, Some("application/pdf"), Some("attachment")));
        }
    }
}

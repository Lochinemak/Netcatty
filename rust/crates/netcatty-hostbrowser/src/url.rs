//! Address bar normalisation and page scheme policy (Electron:
//! `normalizeBrowserUrl`, `ALLOWED_PAGE_SCHEMES`, `iconOrigin`).

use regex::Regex;
use std::sync::OnceLock;
use url::Url;

/// Schemes a page tab may navigate to or request (everything else is
/// cancelled, including `file:` and `javascript:`).
pub const ALLOWED_PAGE_SCHEMES: &[&str] = &["http", "https", "ws", "wss", "blob", "data"];

/// Is `url` (as the webview reports it) allowed to load in a page tab?
pub fn is_allowed_page_url(url: &str) -> bool {
    Url::parse(url)
        .map(|parsed| ALLOWED_PAGE_SCHEMES.contains(&parsed.scheme()))
        .unwrap_or(false)
}

fn local_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(localhost|127\.\d+\.\d+\.\d+|\[[0-9a-f:]+\])(?::\d+)?(?:/|$)").unwrap()
    })
}

fn scheme_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^[a-z][a-z0-9+.-]*:").unwrap())
}

fn host_port_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[^/:]+:\d+(?:[/?#]|$)").unwrap())
}

/// Turn what the user typed into an `http(s)` URL, or explain why not.
/// Bare `localhost:3000` / loopback addresses get `http://`, everything
/// else `https://`; credentials and non-web schemes are refused.
pub fn normalize_browser_url(input: &str) -> Result<String, String> {
    let raw = input.trim();
    if raw.is_empty() || raw.len() > 2048 {
        return Err("Enter a valid web address".into());
    }
    let is_local = local_re().is_match(raw);
    let has_scheme = scheme_re().is_match(raw) && !host_port_re().is_match(raw);
    let candidate = if has_scheme {
        raw.to_string()
    } else {
        format!("{}://{raw}", if is_local { "http" } else { "https" })
    };
    let url = Url::parse(&candidate).map_err(|_| "Enter a valid web address".to_string())?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err("Only HTTP and HTTPS pages can open here".into());
    }
    if url.host_str().map(str::is_empty).unwrap_or(true)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("Enter a valid web address without credentials".into());
    }
    Ok(url.to_string())
}

/// Does `url` point at a loopback destination (`localhost`, `*.localhost`,
/// `127.0.0.0/8`, `::1`, `0.0.0.0`)? WebKit's proxy configuration (macOS)
/// never applies to these, so an SSH-routed browser must refuse them instead
/// of silently opening the local machine's services.
pub fn is_loopback_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Domain(domain)) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            domain == "localhost" || domain.ends_with(".localhost")
        }
        Some(url::Host::Ipv4(ip)) => ip.is_loopback() || ip.is_unspecified(),
        Some(url::Host::Ipv6(ip)) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        None => false,
    }
}

/// `scheme://host[:port]` of an `http(s)` URL (the key website icons are
/// stored under); `None` for anything else.
pub fn icon_origin(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_addresses_accept_bare_localhost_and_domain_ports() {
        assert_eq!(normalize_browser_url("localhost:3000").unwrap(), "http://localhost:3000/");
        assert_eq!(
            normalize_browser_url("localhost:3000/app").unwrap(),
            "http://localhost:3000/app"
        );
        assert_eq!(normalize_browser_url("127.0.0.1:8080").unwrap(), "http://127.0.0.1:8080/");
        assert_eq!(
            normalize_browser_url("example.com:8080").unwrap(),
            "https://example.com:8080/"
        );
        assert_eq!(
            normalize_browser_url("https://example.com/app").unwrap(),
            "https://example.com/app"
        );
        assert_eq!(normalize_browser_url(" example.com ").unwrap(), "https://example.com/");
        assert_eq!(normalize_browser_url("[::1]:5000").unwrap(), "http://[::1]:5000/");
    }

    #[test]
    fn browser_addresses_keep_rejecting_external_protocols_and_credentials() {
        for url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "mailto:test@example.com",
            "https://user:password@example.com/",
        ] {
            assert!(normalize_browser_url(url).is_err(), "{url}");
        }
        assert_eq!(normalize_browser_url("").unwrap_err(), "Enter a valid web address");
        assert_eq!(
            normalize_browser_url("ftp://example.com").unwrap_err(),
            "Only HTTP and HTTPS pages can open here"
        );
        assert_eq!(
            normalize_browser_url("https://user:pw@example.com").unwrap_err(),
            "Enter a valid web address without credentials"
        );
        assert!(normalize_browser_url(&"a".repeat(3000)).is_err());
    }

    #[test]
    fn page_scheme_allowlist() {
        assert!(is_allowed_page_url("https://example.com/"));
        assert!(is_allowed_page_url("http://10.0.0.1:8080/x"));
        assert!(is_allowed_page_url("wss://example.com/socket"));
        assert!(is_allowed_page_url("blob:https://example.com/uuid"));
        assert!(is_allowed_page_url("data:text/plain,hi"));
        assert!(!is_allowed_page_url("file:///etc/passwd"));
        assert!(!is_allowed_page_url("javascript:alert(1)"));
        assert!(!is_allowed_page_url("netcatty-hb://shortcut/new-tab"));
        assert!(!is_allowed_page_url("not a url"));
    }

    #[test]
    fn loopback_destinations_are_recognised() {
        for url in [
            "http://localhost:3000/",
            "http://LOCALHOST./",
            "http://app.localhost/",
            "http://127.0.0.1:8080/",
            "http://127.1.2.3/",
            "http://0.0.0.0:8000/",
            "http://[::1]:5000/",
            "http://[::ffff:127.0.0.1]/",
        ] {
            assert!(is_loopback_url(url), "{url}");
        }
        for url in [
            "http://10.0.0.1/",
            "https://example.com/",
            "http://localhost.example.com/",
            "http://[2001:db8::1]/",
            "data:text/plain,x",
            "garbage",
        ] {
            assert!(!is_loopback_url(url), "{url}");
        }
    }

    #[test]
    fn icon_origin_is_the_http_origin() {
        assert_eq!(
            icon_origin("https://example.com/page?x=1").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            icon_origin("http://10.0.0.1:8080/a").as_deref(),
            Some("http://10.0.0.1:8080")
        );
        assert_eq!(icon_origin("ftp://example.com/"), None);
        assert_eq!(icon_origin("garbage"), None);
    }
}

//! Outbound URL allowlist for the AI provider proxy (Electron:
//! `aiBridge/providerHandlers.cjs`, "URL allowlist" section).
//!
//! Only known AI provider hosts, hosts of the synced provider configs, the
//! web-search host and a few localhost ports (Ollama, LM Studio, common dev
//! ports) may be reached through `netcatty:ai:fetch` / `netcatty:ai:chat:stream`.
//! `aiAllowlistAddHost` adds a host for 30 seconds (the settings model
//! listing probes a URL before the provider is saved). Electron removes the
//! temporary entries with timers; here every entry carries an expiry instant
//! and expired entries are dropped lazily on the next access, which has the
//! same observable behaviour.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use url::Url;

/// Built-in provider and web-search hosts.
pub const BUILTIN_FETCH_HOSTS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "openrouter.ai",
    // Web search providers
    "api.tavily.com",
    "api.exa.ai",
    "api.bochaai.com",
    "open.bigmodel.cn",
];

/// Allowed localhost ports (SSRF guard, issue #9).
pub const BUILTIN_LOCALHOST_PORTS: &[u16] = &[
    11434, // Ollama default
    1234,  // LM Studio default
    3000, 3001, 5000, 5001, 8000, 8080, 8888, // Common local dev
];

/// Temporary allowlist entries live this long.
pub const TEMP_ALLOWLIST_TTL: Duration = Duration::from_millis(30_000);

/// `hostname === "localhost" || hostname === "127.0.0.1"`.
fn is_loopback_name(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1"
}

/// Port of a parsed URL: explicit port, else 443 for https and 80 otherwise
/// (`parsed.port ? Number(parsed.port) : (https ? 443 : 80)`).
fn url_port(url: &Url) -> u16 {
    url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 })
}

/// RFC1918 / link-local / loopback / CGNAT / IPv6 private ranges.
pub fn is_private_ip(ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    // Strip IPv6 brackets that URL.hostname may include.
    let cleaned = ip.trim_start_matches('[').trim_end_matches(']');
    if cleaned == "::1" || cleaned == "0.0.0.0" || cleaned == "::" {
        return true;
    }
    let lower = cleaned.to_ascii_lowercase();
    if lower.starts_with("fc") || lower.starts_with("fd") {
        return true; // fc00::/7
    }
    if lower.starts_with("fe8") || lower.starts_with("fe9") || lower.starts_with("fea") || lower.starts_with("feb") {
        return true; // fe80::/10
    }
    if let Some(v4) = lower.strip_prefix("::ffff:") {
        // IPv4-mapped IPv6 — check the IPv4 portion.
        return is_private_ip(v4);
    }
    // IPv4
    let parts: Vec<&str> = cleaned.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) {
        let a: u64 = parts[0].parse().unwrap_or(u64::MAX);
        let b: u64 = parts[1].parse().unwrap_or(u64::MAX);
        if a == 10 {
            return true; // 10.0.0.0/8
        }
        if a == 172 && (16..=31).contains(&b) {
            return true; // 172.16.0.0/12
        }
        if a == 192 && b == 168 {
            return true; // 192.168.0.0/16
        }
        if a == 127 {
            return true; // 127.0.0.0/8
        }
        if a == 169 && b == 254 {
            return true; // 169.254.0.0/16 link-local
        }
        if a == 100 && (64..=127).contains(&b) {
            return true; // 100.64.0.0/10 CGNAT (Tailscale etc.)
        }
        if a == 0 {
            return true; // 0.0.0.0/8
        }
    }
    false
}

/// `localhost`, cloud metadata endpoints and private IPs.
pub fn is_private_host(hostname: &str) -> bool {
    if hostname == "localhost" {
        return true;
    }
    // metadata endpoints (AWS, GCP, Azure)
    if hostname == "metadata.google.internal" {
        return true;
    }
    is_private_ip(hostname)
}

/// Lowercase host name of a URL, as `URL.hostname` would give it (IPv6 in brackets).
pub fn hostname_of(url: &Url) -> Option<String> {
    url.host_str().map(|h| h.to_ascii_lowercase())
}

/// The mutable allowlist.
#[derive(Debug, Default)]
pub struct FetchAllowlist {
    /// Hosts of the synced provider configs plus temporary entries.
    provider_hosts: HashSet<String>,
    /// Subset of `provider_hosts` whose provider base URL uses `http://`.
    provider_http_hosts: HashSet<String>,
    /// Allowed localhost ports (built-in + provider + temporary).
    localhost_ports: HashSet<u16>,
    /// Temporary hosts → expiry.
    temp_hosts: HashMap<String, Instant>,
    /// Temporary hosts added for an `http://` base URL.
    temp_http_hosts: HashSet<String>,
    /// Temporary localhost ports → expiry.
    temp_ports: HashMap<u16, Instant>,
    /// Base URLs of the synced provider configs.
    provider_base_urls: Vec<String>,
    /// Web search API host (`aiSyncWebSearch`).
    web_search_api_host: Option<String>,
}

impl FetchAllowlist {
    pub fn new() -> Self {
        let mut list = Self::default();
        list.rebuild_at(Instant::now());
        list
    }

    /// Replace the provider base URLs and rebuild (`aiSyncProviders`).
    pub fn set_provider_base_urls(&mut self, base_urls: Vec<String>) {
        self.provider_base_urls = base_urls;
        self.rebuild_at(Instant::now());
    }

    /// Replace the web-search host and rebuild (`aiSyncWebSearch`).
    pub fn set_web_search_api_host(&mut self, host: Option<String>) {
        self.web_search_api_host = host;
        self.rebuild_at(Instant::now());
    }

    pub fn web_search_api_host(&self) -> Option<&str> {
        self.web_search_api_host.as_deref()
    }

    fn web_search_hostname(&self) -> Option<String> {
        self.web_search_api_host
            .as_deref()
            .and_then(|h| Url::parse(h).ok())
            .and_then(|u| hostname_of(&u))
    }

    fn provider_urls(&self) -> impl Iterator<Item = Url> + '_ {
        self.provider_base_urls.iter().filter_map(|u| Url::parse(u).ok())
    }

    /// Is `host` owned by a currently synced provider config?
    fn is_host_in_provider_configs(&self, host: &str) -> bool {
        self.provider_urls().any(|u| hostname_of(&u).as_deref() == Some(host))
    }

    /// Is `host` owned by a provider config that uses `http://`?
    fn is_http_host_in_provider_configs(&self, host: &str) -> bool {
        self.provider_urls()
            .any(|u| hostname_of(&u).as_deref() == Some(host) && u.scheme() == "http")
    }

    /// Is a localhost `port` owned by a currently synced provider config?
    fn is_port_in_provider_configs(&self, port: u16) -> bool {
        self.provider_urls().any(|u| {
            hostname_of(&u).is_some_and(|h| is_loopback_name(&h)) && url_port(&u) == port
        })
    }

    /// Drop expired temporary entries (Electron: the `setTimeout` callbacks).
    fn expire(&mut self, now: Instant) {
        let expired_hosts: Vec<String> = self
            .temp_hosts
            .iter()
            .filter(|(_, expiry)| **expiry <= now)
            .map(|(host, _)| host.clone())
            .collect();
        for host in expired_hosts {
            self.temp_hosts.remove(&host);
            let is_web_search_host = self.web_search_hostname().as_deref() == Some(host.as_str());
            if !self.is_host_in_provider_configs(&host) && !is_web_search_host {
                self.provider_hosts.remove(&host);
                self.provider_http_hosts.remove(&host);
            } else if !self.is_http_host_in_provider_configs(&host) {
                self.provider_http_hosts.remove(&host);
            }
            self.temp_http_hosts.remove(&host);
        }
        let expired_ports: Vec<u16> = self
            .temp_ports
            .iter()
            .filter(|(_, expiry)| **expiry <= now)
            .map(|(port, _)| *port)
            .collect();
        for port in expired_ports {
            self.temp_ports.remove(&port);
            // Only remove if still temporary (not built-in and not synced by a provider).
            if !BUILTIN_LOCALHOST_PORTS.contains(&port) && !self.is_port_in_provider_configs(port) {
                self.localhost_ports.remove(&port);
            }
        }
    }

    /// Rebuild the dynamic allowlist from the provider configs and the
    /// web-search host, keeping still-active temporary entries.
    pub fn rebuild_at(&mut self, now: Instant) {
        self.expire(now);
        self.provider_hosts.clear();
        self.provider_http_hosts.clear();
        // Reset localhost ports to built-in defaults, then add provider-configured ones.
        self.localhost_ports.clear();
        self.localhost_ports.extend(BUILTIN_LOCALHOST_PORTS.iter().copied());
        // Re-add any still-active temporary entries so a sync doesn't wipe them.
        self.provider_hosts.extend(self.temp_hosts.keys().cloned());
        self.provider_http_hosts.extend(self.temp_http_hosts.iter().cloned());
        self.localhost_ports.extend(self.temp_ports.keys().copied());
        let provider_urls: Vec<Url> = self.provider_urls().collect();
        for parsed in provider_urls {
            let Some(host) = hostname_of(&parsed) else { continue };
            // Skip localhost — handled separately via the port allowlist.
            if is_loopback_name(&host) {
                self.localhost_ports.insert(url_port(&parsed));
            } else {
                if parsed.scheme() == "http" {
                    self.provider_http_hosts.insert(host.clone());
                }
                self.provider_hosts.insert(host);
            }
        }
        // Add the web search apiHost if configured (e.g. a self-hosted SearXNG).
        if let Some(parsed) = self.web_search_api_host.as_deref().and_then(|h| Url::parse(h).ok()) {
            if let Some(host) = hostname_of(&parsed) {
                if is_loopback_name(&host) {
                    self.localhost_ports.insert(url_port(&parsed));
                } else {
                    self.provider_hosts.insert(host);
                }
            }
        }
    }

    /// Temporarily allow the host (or localhost port) of `base_url`
    /// (`aiAllowlistAddHost`). Returns `Err("Invalid URL")` for unparsable input.
    pub fn add_host(&mut self, base_url: &str) -> Result<(), &'static str> {
        self.add_host_at(base_url, Instant::now())
    }

    pub fn add_host_at(&mut self, base_url: &str, now: Instant) -> Result<(), &'static str> {
        self.expire(now);
        let parsed = Url::parse(base_url).map_err(|_| "Invalid URL")?;
        let host = hostname_of(&parsed).ok_or("Invalid URL")?;
        let expiry = now + TEMP_ALLOWLIST_TTL;
        if is_loopback_name(&host) {
            let port = url_port(&parsed);
            if !self.localhost_ports.contains(&port) {
                self.localhost_ports.insert(port);
                self.temp_ports.insert(port, expiry);
            }
        } else {
            self.provider_hosts.insert(host.clone());
            // Always track so a rebuild can restore the host even if the
            // persistent source (e.g. an HTTPS provider) is removed mid-TTL.
            if parsed.scheme() == "http" {
                self.provider_http_hosts.insert(host.clone());
                if !self.is_http_host_in_provider_configs(&host) {
                    self.temp_http_hosts.insert(host.clone());
                }
            }
            // Always (re-)schedule the expiry.
            self.temp_hosts.insert(host, expiry);
        }
        Ok(())
    }

    /// May `url_string` be fetched? `skip_host_check` allows any public HTTPS
    /// host but still blocks private / internal hosts.
    pub fn is_allowed(&mut self, url_string: &str, skip_host_check: bool) -> bool {
        self.is_allowed_at(url_string, skip_host_check, Instant::now())
    }

    pub fn is_allowed_at(&mut self, url_string: &str, skip_host_check: bool, now: Instant) -> bool {
        self.expire(now);
        let Ok(parsed) = Url::parse(url_string) else { return false };
        let Some(host) = hostname_of(&parsed) else { return false };
        // Always block private/internal hosts when skipHostCheck is set (SSRF protection).
        if skip_host_check {
            if is_private_host(&host) {
                return false;
            }
            // Require HTTPS for skipHostCheck requests.
            return parsed.scheme() == "https";
        }
        // Allow localhost/127.0.0.1 only on known ports (e.g. Ollama).
        if is_loopback_name(&host) {
            return self.localhost_ports.contains(&url_port(&parsed));
        }
        // Only allow http: and https: schemes for remote hosts.
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return false;
        }
        // For HTTP, only allow providers explicitly configured with http:// or the web search apiHost.
        if parsed.scheme() == "http" {
            let is_provider_host = self.provider_http_hosts.contains(&host);
            let is_web_search_host = self.web_search_hostname().as_deref() == Some(host.as_str());
            if !is_provider_host && !is_web_search_host {
                return false;
            }
        }
        // Check built-in + provider-configured host allowlist.
        BUILTIN_FETCH_HOSTS.contains(&host.as_str()) || self.provider_hosts.contains(&host)
    }
}

/// `true` when `ip` parses as an IPv4 address (used by callers that need the
/// strict form rather than the lenient private-range test).
pub fn is_ipv4(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok()
}

/// `true` when `ip` parses as any IP address.
pub fn is_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ip_ranges() {
        for ip in [
            "10.1.2.3", "172.16.0.1", "172.31.9.9", "192.168.0.1", "127.0.0.1", "169.254.1.1",
            "100.64.0.1", "100.127.1.1", "0.0.0.0", "::1", "::", "[::1]", "fc00::1", "fd12::1",
            "fe80::1", "FE80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
        ] {
            assert!(is_private_ip(ip), "{ip}");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "100.128.0.1", "2001:db8::1", "example.com", ""] {
            assert!(!is_private_ip(ip), "{ip}");
        }
        assert!(is_private_host("localhost"));
        assert!(is_private_host("metadata.google.internal"));
        assert!(!is_private_host("api.openai.com"));
    }

    #[test]
    fn builtin_hosts_and_localhost_ports() {
        let mut list = FetchAllowlist::new();
        assert!(list.is_allowed("https://api.openai.com/v1/models", false));
        assert!(list.is_allowed("https://API.OpenAI.com/v1/models", false));
        assert!(!list.is_allowed("http://api.openai.com/v1/models", false));
        assert!(!list.is_allowed("https://evil.example/v1", false));
        assert!(list.is_allowed("http://localhost:11434/api/tags", false));
        assert!(list.is_allowed("http://127.0.0.1:1234/v1/models", false));
        assert!(!list.is_allowed("http://localhost:9999/x", false));
        assert!(!list.is_allowed("ftp://api.openai.com/", false));
        assert!(!list.is_allowed("not a url", false));
    }

    #[test]
    fn skip_host_check_allows_public_https_only() {
        let mut list = FetchAllowlist::new();
        assert!(list.is_allowed("https://any.example/path", true));
        assert!(!list.is_allowed("http://any.example/path", true));
        assert!(!list.is_allowed("https://localhost:8443/", true));
        assert!(!list.is_allowed("https://10.0.0.5/", true));
        assert!(!list.is_allowed("https://metadata.google.internal/", true));
        assert!(!list.is_allowed("https://[::1]/", true));
    }

    #[test]
    fn provider_configs_populate_hosts_ports_and_http_hosts() {
        let mut list = FetchAllowlist::new();
        list.set_provider_base_urls(vec![
            "https://llm.corp.example/v1".into(),
            "http://plain.corp.example/v1".into(),
            "http://localhost:4321/v1".into(),
            "garbage".into(),
        ]);
        assert!(list.is_allowed("https://llm.corp.example/v1/chat", false));
        assert!(!list.is_allowed("http://llm.corp.example/v1/chat", false));
        assert!(list.is_allowed("http://plain.corp.example/v1/chat", false));
        assert!(list.is_allowed("http://localhost:4321/v1/chat", false));
        list.set_provider_base_urls(vec![]);
        assert!(!list.is_allowed("https://llm.corp.example/v1/chat", false));
        assert!(!list.is_allowed("http://localhost:4321/v1/chat", false));
    }

    #[test]
    fn web_search_host_allows_http_and_localhost() {
        let mut list = FetchAllowlist::new();
        list.set_web_search_api_host(Some("http://searx.lan:8088".into()));
        assert!(list.is_allowed("http://searx.lan:8088/search?q=x", false));
        list.set_web_search_api_host(Some("http://127.0.0.1:7777".into()));
        assert!(list.is_allowed("http://127.0.0.1:7777/search", false));
        assert!(!list.is_allowed("http://searx.lan:8088/search?q=x", false));
    }

    #[test]
    fn temporary_hosts_expire_unless_synced() {
        let t0 = Instant::now();
        let mut list = FetchAllowlist::new();
        list.add_host_at("https://temp.example/v1", t0).unwrap();
        list.add_host_at("http://plain.example/v1", t0).unwrap();
        list.add_host_at("http://localhost:5555", t0).unwrap();
        assert!(list.is_allowed_at("https://temp.example/v1/models", false, t0 + Duration::from_secs(1)));
        assert!(list.is_allowed_at("http://plain.example/v1/models", false, t0 + Duration::from_secs(1)));
        assert!(list.is_allowed_at("http://localhost:5555/models", false, t0 + Duration::from_secs(1)));
        // A provider sync inside the TTL keeps the temporary entries.
        list.rebuild_at(t0 + Duration::from_secs(2));
        assert!(list.is_allowed_at("https://temp.example/v1/models", false, t0 + Duration::from_secs(3)));
        assert!(list.is_allowed_at("http://plain.example/v1/models", false, t0 + Duration::from_secs(3)));
        // After the TTL they are gone …
        let later = t0 + TEMP_ALLOWLIST_TTL + Duration::from_secs(1);
        assert!(!list.is_allowed_at("https://temp.example/v1/models", false, later));
        assert!(!list.is_allowed_at("http://plain.example/v1/models", false, later));
        assert!(!list.is_allowed_at("http://localhost:5555/models", false, later));
        // … unless a synced provider owns them.
        list.add_host_at("https://kept.example", later).unwrap();
        list.provider_base_urls = vec!["https://kept.example/v1".into()];
        let much_later = later + TEMP_ALLOWLIST_TTL + Duration::from_secs(1);
        assert!(list.is_allowed_at("https://kept.example/v1/models", false, much_later));
        assert_eq!(list.add_host_at("nope", much_later), Err("Invalid URL"));
    }

    #[test]
    fn temporary_http_host_loses_http_but_keeps_https_when_provider_is_https() {
        let t0 = Instant::now();
        let mut list = FetchAllowlist::new();
        list.provider_base_urls = vec!["https://mixed.example/v1".into()];
        list.rebuild_at(t0);
        list.add_host_at("http://mixed.example/v1", t0).unwrap();
        assert!(list.is_allowed_at("http://mixed.example/v1/models", false, t0 + Duration::from_secs(1)));
        let later = t0 + TEMP_ALLOWLIST_TTL + Duration::from_secs(1);
        assert!(!list.is_allowed_at("http://mixed.example/v1/models", false, later));
        assert!(list.is_allowed_at("https://mixed.example/v1/models", false, later));
    }
}

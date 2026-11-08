//! Host-owned source identity and plugin storage paths (ports of
//! `sourceIdentity.cjs` and `paths.cjs`).

use crate::error::{PluginError, PluginResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const OFFICIAL_ORIGIN: &str = "https://plugins.netcatty.app";

/// Curated first-party maintenance authority.
pub const FIRST_PARTY_PLUGINS: &[(&str, &str)] = &[
    ("com.netcatty.starter", "binaricat/Netcatty"),
    ("com.netcatty.hello", "binaricat/Netcatty"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub origin: Option<String>,
}

pub fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

impl Source {
    pub fn official() -> Self {
        Self {
            id: "official".into(),
            kind: "official".into(),
            name: "Netcatty marketplace".into(),
            origin: Some(OFFICIAL_ORIGIN.into()),
        }
    }
    pub fn local() -> Self {
        Self {
            id: "local".into(),
            kind: "local".into(),
            name: "Local import".into(),
            origin: None,
        }
    }
}

fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok() || host.trim_matches(['[', ']']).parse::<std::net::Ipv6Addr>().is_ok()
}

/// `canonicalSourceOrigin`.
pub fn canonical_source_origin(value: &str) -> PluginResult<String> {
    if value.len() > 2048 || value.chars().any(|c| c.is_whitespace() || matches!(c, '\\' | '%' | '?' | '#')) {
        return Err(PluginError::host("Use a public HTTPS origin without credentials, query or fragment"));
    }
    let url = url::Url::parse(value).map_err(|_| PluginError::host("Invalid market source address"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || !matches!(url.path(), "/" | "/v1/snapshot.json")
    {
        return Err(PluginError::host("Use an HTTPS origin or its /v1/snapshot.json endpoint"));
    }
    let hostname = url.host_str().unwrap_or("").to_ascii_lowercase();
    let reserved = ["localhost", "local", "internal", "invalid", "test"]
        .iter()
        .any(|suffix| hostname == *suffix || hostname.ends_with(&format!(".{suffix}")));
    if is_ip(&hostname) || hostname.contains(':') || !hostname.contains('.') || hostname.ends_with('.') || reserved {
        return Err(PluginError::host("Market sources must use a public DNS hostname"));
    }
    let lower = value.to_ascii_lowercase();
    let rest = lower.strip_prefix("https://").unwrap_or("");
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let path = &rest[authority_end..];
    if authority.is_empty() || authority.contains('@') || !(path.is_empty() || path == "/" || path == "/v1/snapshot.json") {
        return Err(PluginError::host("Invalid market source address"));
    }
    Ok(url.origin().ascii_serialization())
}

/// `thirdPartySource`.
pub fn third_party_source(name: &str, address: &str) -> PluginResult<Source> {
    let trimmed = name.trim();
    if trimmed.is_empty() || name.encode_utf16().count() > 100 || name.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f) {
        return Err(PluginError::host("Source name must contain 1-100 printable characters"));
    }
    let origin = canonical_source_origin(address)?;
    if origin == OFFICIAL_ORIGIN {
        return Err(PluginError::host("The official source is already built in"));
    }
    Ok(Source {
        id: format!("third-party:{}", sha256_hex(&origin)),
        kind: "third-party".into(),
        name: trimmed.to_string(),
        origin: Some(origin),
    })
}

/// `assertSource`: rebuild the trusted identity and compare.
pub fn assert_source(source: &Source) -> PluginResult<Source> {
    let trusted = match source.id.as_str() {
        "official" => Source::official(),
        "local" => Source::local(),
        _ => third_party_source(&source.name, source.origin.as_deref().unwrap_or(""))?,
    };
    if trusted.id != source.id || trusted.kind != source.kind || trusted.origin != source.origin {
        return Err(PluginError::host("Invalid host source identity"));
    }
    Ok(trusted)
}

pub fn is_plugin_id_like(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=128).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.' || *b == b'-')
}

/// `privateOwner`: `source:<sha256(source.id)>:<pluginId>`.
pub fn private_owner(source: &Source, plugin_id: &str) -> PluginResult<String> {
    if !is_plugin_id_like(plugin_id) {
        return Err(PluginError::host("Invalid plugin identity"));
    }
    let trusted = assert_source(source)?;
    Ok(format!("source:{}:{}", sha256_hex(&trusted.id), plugin_id))
}

/// Is `value` an opaque private owner (`source:<64 hex>:<id>`)?
pub fn is_private_owner(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("source:") else { return false };
    if rest.len() < 66 {
        return false;
    }
    let (hash, tail) = rest.split_at(64);
    hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && tail.starts_with(':')
        && is_plugin_id_like(&tail[1..])
}

/// `isOfficialMaintained`.
pub fn is_official_maintained(entry_id: &str, repository: Option<&str>, source: &Source) -> bool {
    assert_source(source).is_ok_and(|trusted| trusted == Source::official())
        && FIRST_PARTY_PLUGINS
            .iter()
            .any(|(id, repo)| *id == entry_id && Some(*repo) == repository)
}

/// `createPluginPaths`.
#[derive(Debug, Clone)]
pub struct PluginPaths {
    pub root: PathBuf,
    pub database: PathBuf,
    pub packages: PathBuf,
    pub staging: PathBuf,
    pub data: PathBuf,
    pub logs: PathBuf,
    pub dev: PathBuf,
}

impl PluginPaths {
    pub fn new(user_data: &Path) -> Self {
        let root = user_data.join("plugins");
        Self {
            database: root.join("plugins.sqlite"),
            packages: root.join("packages"),
            staging: root.join("staging"),
            data: root.join("data"),
            logs: root.join("logs"),
            dev: root.join("dev"),
            root,
        }
    }

    pub fn directories(&self) -> [&Path; 6] {
        [&self.root, &self.packages, &self.staging, &self.data, &self.logs, &self.dev]
    }
}

/// `assertPluginStorageSegment`.
pub fn assert_storage_segment(value: &str, kind: &str) -> PluginResult<String> {
    if value.is_empty() || value.encode_utf16().count() > 128 {
        return Err(PluginError::host(format!("Invalid plugin {kind}")));
    }
    if value == "." || value == ".." || value.contains(['/', '\\', '\0']) {
        return Err(PluginError::host(format!("Unsafe plugin {kind}")));
    }
    Ok(value.to_string())
}

pub fn installed_version_dir(paths: &PluginPaths, plugin_id: &str, version: &str) -> PluginResult<PathBuf> {
    Ok(paths
        .packages
        .join(assert_storage_segment(plugin_id, "ID")?)
        .join(assert_storage_segment(version, "version")?))
}

/// `isPathInside` (lexical).
pub fn is_path_inside(parent: &Path, candidate: &Path) -> bool {
    let normalize = |p: &Path| -> PathBuf {
        let mut out = PathBuf::new();
        for component in p.components() {
            match component {
                std::path::Component::ParentDir => {
                    out.pop();
                }
                std::path::Component::CurDir => {}
                other => out.push(other.as_os_str()),
            }
        }
        out
    };
    normalize(candidate).starts_with(normalize(parent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owners_and_sources() {
        let owner = private_owner(&Source::local(), "com.netcatty.hello").unwrap();
        assert!(is_private_owner(&owner));
        assert!(owner.ends_with(":com.netcatty.hello"));
        assert!(third_party_source("Mine", "https://plugins.example.com/").is_ok());
        assert!(third_party_source("Mine", "http://plugins.example.com/").is_err());
        assert!(third_party_source("Mine", "https://localhost/").is_err());
        assert!(third_party_source("Mine", "https://1.2.3.4/").is_err());
        let src = third_party_source("Mine", "https://plugins.example.com/v1/snapshot.json").unwrap();
        assert_eq!(src.origin.as_deref(), Some("https://plugins.example.com"));
        assert!(assert_source(&src).is_ok());
    }
}

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
    /// GitHub release pin (`kind: "github"` only): tag, its commit and the
    /// release asset the package came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, rename = "assetId", skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<u64>,
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
            tag: None,
            commit: None,
            asset_id: None,
        }
    }
    pub fn local() -> Self {
        Self {
            id: "local".into(),
            kind: "local".into(),
            name: "Local import".into(),
            origin: None,
            tag: None,
            commit: None,
            asset_id: None,
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
        tag: None,
        commit: None,
        asset_id: None,
    })
}

/// A GitHub release a package was installed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubReleasePin {
    pub tag: String,
    pub commit: String,
    pub asset_id: u64,
}

/// `githubSource`: the host-owned identity of a public GitHub repository,
/// optionally pinned to the release a package came from. The ID depends on
/// the repository only, so reinstalling a newer release keeps the binding.
pub fn github_source(address: &str, pin: Option<GitHubReleasePin>) -> PluginResult<Source> {
    let repository = crate::github::parse_github_repository(address)?;
    let mut source = Source {
        id: format!("github:{}", sha256_hex(&repository.origin)),
        kind: "github".into(),
        name: repository.repository,
        origin: Some(repository.origin),
        tag: None,
        commit: None,
        asset_id: None,
    };
    if let Some(pin) = pin {
        let commit_ok = pin.commit.len() == 40 && pin.commit.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if pin.tag.is_empty()
            || pin.tag.encode_utf16().count() > 256
            || pin.tag.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f)
            || !commit_ok
            || pin.asset_id < 1
            || pin.asset_id > crate::github::MAX_SAFE_INTEGER
        {
            return Err(PluginError::host("Invalid GitHub release identity"));
        }
        source.tag = Some(pin.tag);
        source.commit = Some(pin.commit);
        source.asset_id = Some(pin.asset_id);
    }
    Ok(source)
}

/// `assertSource`: rebuild the trusted identity and compare.
pub fn assert_source(source: &Source) -> PluginResult<Source> {
    let trusted = if source.kind == "github" {
        let pin = match (&source.tag, &source.commit, source.asset_id) {
            (None, None, None) => None,
            (Some(tag), Some(commit), Some(asset_id)) => Some(GitHubReleasePin { tag: tag.clone(), commit: commit.clone(), asset_id }),
            _ => return Err(PluginError::host("Invalid GitHub release identity")),
        };
        github_source(source.origin.as_deref().unwrap_or(""), pin)?
    } else {
        match source.id.as_str() {
            "official" => Source::official(),
            "local" => Source::local(),
            _ => third_party_source(&source.name, source.origin.as_deref().unwrap_or(""))?,
        }
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

    #[test]
    fn github_sources_share_one_identity_per_repository() {
        let a = github_source("https://github.com/Owner/Repo.git", None).unwrap();
        let b = github_source("owner/repo", None).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.kind, "github");
        assert_eq!(a.name, "owner/repo");
        assert_eq!(a.origin.as_deref(), Some("https://github.com/owner/repo"));
        assert_eq!(a.id, format!("github:{}", sha256_hex("https://github.com/owner/repo")));

        let pin = GitHubReleasePin { tag: "v1.0.0".into(), commit: "a".repeat(40), asset_id: 7 };
        let pinned = github_source("owner/repo", Some(pin.clone())).unwrap();
        assert_eq!(pinned.id, a.id, "the release pin does not change the binding");
        assert_eq!(assert_source(&pinned).unwrap(), pinned);
        let json = serde_json::to_value(&pinned).unwrap();
        assert_eq!(json["assetId"], 7);
        assert_eq!(serde_json::from_value::<Source>(json).unwrap(), pinned);
        assert!(serde_json::to_value(Source::local()).unwrap().get("tag").is_none());

        for bad in [
            GitHubReleasePin { commit: "A".repeat(40), ..pin.clone() },
            GitHubReleasePin { commit: "a".repeat(39), ..pin.clone() },
            GitHubReleasePin { tag: String::new(), ..pin.clone() },
            GitHubReleasePin { tag: "v1\n".into(), ..pin.clone() },
            GitHubReleasePin { asset_id: 0, ..pin.clone() },
        ] {
            assert!(github_source("owner/repo", Some(bad)).is_err());
        }
        // Forged or partial identities are rejected.
        assert!(assert_source(&Source { id: "official".into(), ..a.clone() }).is_err());
        assert!(assert_source(&Source { tag: Some("v1".into()), ..a.clone() }).is_err());
        assert!(assert_source(&Source { origin: Some("https://github.com/other/repo".into()), ..a }).is_err());
    }
}

//! npm-compatible semver helpers (`valid`, `validRange`, `satisfies` of
//! node-semver, which the Electron host uses through `@netcatty/plugin-cli`).

use nodejs_semver::{Range, Version};

pub fn valid_version(version: &str) -> bool {
    // node-semver `valid` is strict: no leading `v`/`=`, no surrounding spaces.
    let trimmed = version.trim();
    trimmed == version
        && !version.starts_with('v')
        && !version.starts_with('=')
        && Version::parse(version).is_ok()
}

pub fn valid_range(range: &str) -> bool {
    Range::parse(range).is_ok()
}

/// `satisfies(version, range)`; prerelease versions only match comparators
/// with the same `[major, minor, patch]` tuple (node-semver default).
pub fn satisfies(version: &str, range: &str) -> bool {
    match (Version::parse(version), Range::parse(range)) {
        (Ok(version), Ok(range)) => version.satisfies(&range),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_semver_semantics() {
        assert!(satisfies("0.1.0-internal.1", ">=0.1.0-internal <0.2.0"));
        assert!(satisfies("0.1.0-internal.1", ">=0.1.0-internal.1 <0.2.0"));
        assert!(!satisfies("0.1.0-internal", ">=0.1.0-internal.1 <0.2.0"));
        assert!(satisfies("1.2.1", ">=0.0.0"));
        assert!(valid_version("0.1.3"));
        assert!(!valid_version("v1.0.0"));
        assert!(valid_range(">=0.1.0-internal <0.2.0"));
    }
}

//! Portable package paths (port of `packages/plugin-cli/src/packagePath.ts`).

use super::limits;
use crate::error::{PluginError, PluginResult};
use std::collections::HashSet;
use unicode_normalization::UnicodeNormalization;

fn is_windows_reserved(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    let stem = lower.split('.').next().unwrap_or("");
    matches!(stem, "con" | "prn" | "aux" | "nul")
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn portable_syntax(value: &str, original: &str) -> PluginResult<Vec<String>> {
    let bytes = value.as_bytes();
    if value.starts_with('/')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        || value.contains('\\')
    {
        return Err(PluginError::host(format!(
            "Package path must be relative POSIX syntax: {original}"
        )));
    }
    let segments: Vec<String> = value.split('/').map(str::to_string).collect();
    if segments.iter().any(|s| s.is_empty() || s == "." || s == "..") {
        return Err(PluginError::host(format!(
            "Package path contains an unsafe segment: {original}"
        )));
    }
    for segment in &segments {
        if segment.ends_with('.')
            || segment.ends_with(' ')
            || is_windows_reserved(segment)
            || segment.chars().any(|c| "<>:\"|?*".contains(c))
            || segment.chars().any(|c| (c as u32) <= 0x1f)
        {
            return Err(PluginError::host(format!(
                "Package path is not portable across supported platforms: {original}"
            )));
        }
    }
    Ok(segments)
}

/// `assertSafePackagePath`.
pub fn assert_safe_package_path(input: &str) -> PluginResult<String> {
    if input.is_empty() || input.nfc().collect::<String>() != input {
        return Err(PluginError::host(format!(
            "Package path must be non-empty NFC text: {input:?}"
        )));
    }
    if input.chars().count() > limits::PATH_CHARACTERS {
        return Err(PluginError::host(format!(
            "Package path exceeds {} Unicode characters: {input}",
            limits::PATH_CHARACTERS
        )));
    }
    if input.len() > limits::PATH_BYTES {
        return Err(PluginError::host(format!(
            "Package path exceeds {} UTF-8 bytes: {input}",
            limits::PATH_BYTES
        )));
    }
    let raw = portable_syntax(input, input)?;
    let compat: String = input.nfkc().collect();
    let compat_segments = portable_syntax(&compat, input)?;
    if compat_segments.len() != raw.len() {
        return Err(PluginError::host(format!(
            "Package path changes directory structure after Unicode compatibility normalization: {input}"
        )));
    }
    Ok(input.to_string())
}

fn portable_key(value: &str) -> String {
    let nfkc: String = value.nfkc().collect();
    nfkc.to_uppercase().to_lowercase().nfkc().collect()
}

/// `PackagePathRegistry`: rejects duplicate, case-colliding and
/// file/directory-colliding paths.
#[derive(Default)]
pub struct PackagePathRegistry {
    files_exact: HashSet<String>,
    files_portable: HashSet<String>,
    dirs_exact: HashSet<String>,
    dirs_portable: HashSet<String>,
}

impl PackagePathRegistry {
    pub fn add(&mut self, input: &str) -> PluginResult<String> {
        let safe = assert_safe_package_path(input)?;
        let key = portable_key(&safe);
        if self.files_exact.contains(&safe) || self.files_portable.contains(&key) {
            return Err(PluginError::host(format!(
                "Duplicate or case-colliding package path: {safe}"
            )));
        }
        if self.dirs_exact.contains(&safe) || self.dirs_portable.contains(&key) {
            return Err(PluginError::host(format!(
                "File/directory package path collision: {safe}"
            )));
        }
        let segments: Vec<&str> = safe.split('/').collect();
        let mut ancestors = Vec::new();
        for index in 1..segments.len() {
            let ancestor = segments[..index].join("/");
            if self.files_exact.contains(&ancestor)
                || self.files_portable.contains(&portable_key(&ancestor))
            {
                return Err(PluginError::host(format!(
                    "File/directory package path collision: {safe}"
                )));
            }
            ancestors.push(ancestor);
        }
        self.files_exact.insert(safe.clone());
        self.files_portable.insert(key);
        for ancestor in ancestors {
            self.dirs_portable.insert(portable_key(&ancestor));
            self.dirs_exact.insert(ancestor);
        }
        Ok(safe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_paths() {
        for bad in ["", "/abs", "C:/x", "a\\b", "a/../b", "a//b", "con.txt", "x/aux", "a.", "a ", "a?b", "a\u{1}b"] {
            assert!(assert_safe_package_path(bad).is_err(), "{bad:?}");
        }
        assert!(assert_safe_package_path("dist/index.js").is_ok());
        assert!(assert_safe_package_path("com10/x").is_ok());
    }

    #[test]
    fn registry_detects_collisions() {
        let mut registry = PackagePathRegistry::default();
        registry.add("a/b.js").unwrap();
        assert!(registry.add("A/B.js").is_err());
        assert!(registry.add("a").is_err());
        assert!(registry.add("a/b.js/c").is_err());
        registry.add("a/c.js").unwrap();
    }
}

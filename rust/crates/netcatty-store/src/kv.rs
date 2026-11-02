//! JSON document store keyed by storage key.

use netcatty_core::{CoreError, CoreResult};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const FILE_EXT: &str = ".json";
const TMP_EXT: &str = ".tmp";
/// Sidecar holding the original key of a hashed (over-long) file name.
const KEY_SIDECAR_EXT: &str = ".key";
const MAX_KEY_CHARS: usize = 512;
/// Encoded stems longer than this are hashed so the final file name stays
/// well under the 255-byte limit every mainstream filesystem imposes.
const MAX_PLAIN_STEM_BYTES: usize = 200;
const HASHED_STEM_PREFIX_BYTES: usize = 120;
const HASH_SEPARATOR: &str = "~";

/// File-backed key/value store. Keys are sanitized to safe file names
/// (`netcatty.vault.hosts` → `netcatty.vault.hosts.json`). Writes are atomic
/// (write to `.tmp`, fsync, rename).
pub struct KvStore {
    pub root: PathBuf,
}

impl KvStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub async fn get(&self, key: &str) -> CoreResult<Option<String>> {
        let path = self.path_for(key)?;
        match tokio::fs::read_to_string(&path).await {
            Ok(value) => Ok(Some(value)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(io_error("read", &path, err)),
        }
    }

    pub async fn set(&self, key: &str, value: &str) -> CoreResult<()> {
        let path = self.path_for(key)?;
        tokio::fs::create_dir_all(&self.root)
            .await
            .map_err(|err| io_error("create", &self.root, err))?;

        let tmp_path = tmp_path_for(&path);
        let write_result = write_durably(&tmp_path, value.as_bytes()).await;
        if let Err(err) = write_result {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(io_error("write", &tmp_path, err));
        }
        if let Err(err) = tokio::fs::rename(&tmp_path, &path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(io_error("rename", &path, err));
        }
        if Self::is_hashed_file_name(&file_name_of(&path)) {
            // Over-long keys cannot be decoded from the file name; keep the
            // original next to the document so `keys()` can list it.
            let sidecar = sidecar_path_for(&path);
            if let Err(err) = write_durably(&sidecar, key.as_bytes()).await {
                return Err(io_error("write", &sidecar, err));
            }
        }
        Ok(())
    }

    pub async fn remove(&self, key: &str) -> CoreResult<()> {
        let path = self.path_for(key)?;
        let _ = tokio::fs::remove_file(sidecar_path_for(&path)).await;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(io_error("remove", &path, err)),
        }
    }

    pub async fn keys(&self) -> CoreResult<Vec<String>> {
        let mut dir = match tokio::fs::read_dir(&self.root).await {
            Ok(dir) => dir,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(io_error("list", &self.root, err)),
        };
        let mut keys = Vec::new();
        while let Some(entry) = dir
            .next_entry()
            .await
            .map_err(|err| io_error("list", &self.root, err))?
        {
            let is_file = entry
                .file_type()
                .await
                .map(|t| t.is_file())
                .unwrap_or(false);
            if !is_file {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if Self::is_hashed_file_name(name) {
                let sidecar = sidecar_path_for(&entry.path());
                match tokio::fs::read_to_string(&sidecar).await {
                    Ok(key) if validate_key(&key).is_ok() && Self::file_name_for(&key) == name => {
                        keys.push(key)
                    }
                    Ok(_) => tracing::warn!(
                        file = name,
                        "ignoring store document with a mismatched key sidecar"
                    ),
                    Err(err) => {
                        tracing::warn!(file = name, error = %err, "ignoring store document without a key sidecar")
                    }
                }
            } else if let Some(key) = Self::key_for_file_name(name) {
                keys.push(key);
            }
        }
        keys.sort();
        Ok(keys)
    }

    /// Map a storage key to a safe file name: every byte outside
    /// `[A-Za-z0-9._-]` is percent-encoded (`%XX`, uppercase hex) and
    /// `.json` is appended. Keys whose encoding would exceed the
    /// filesystem name limit are shortened to
    /// `<prefix>~<sha256-hex>.json` (see [`KvStore::is_hashed_file_name`]).
    pub fn file_name_for(key: &str) -> String {
        let mut stem = String::with_capacity(key.len());
        for byte in key.bytes() {
            if is_safe_byte(byte) {
                stem.push(byte as char);
            } else {
                stem.push_str(&format!("%{byte:02X}"));
            }
        }
        if stem.len() > MAX_PLAIN_STEM_BYTES {
            let digest = Sha256::digest(key.as_bytes());
            let mut hex = String::with_capacity(64);
            for b in digest {
                hex.push_str(&format!("{b:02x}"));
            }
            // Cut on an ASCII boundary (the stem is pure ASCII) and never
            // inside a `%XX` escape so the prefix stays readable.
            let mut cut = HASHED_STEM_PREFIX_BYTES;
            if let Some(pct) = stem[..cut].rfind('%') {
                if pct + 3 > cut {
                    cut = pct;
                }
            }
            stem.truncate(cut);
            stem.push_str(HASH_SEPARATOR);
            stem.push_str(&hex);
        }
        stem.push_str(FILE_EXT);
        stem
    }

    /// Whether a file name was produced by the over-long-key path of
    /// [`KvStore::file_name_for`].
    pub fn is_hashed_file_name(file_name: &str) -> bool {
        file_name
            .strip_suffix(FILE_EXT)
            .and_then(|stem| stem.rsplit_once(HASH_SEPARATOR))
            .map(|(_, hash)| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or(false)
    }

    /// Inverse of [`KvStore::file_name_for`] for plain (non-hashed) names.
    /// Returns `None` for files that do not belong to the store (wrong
    /// extension, temp files, sidecars, malformed escapes) and for hashed
    /// names, whose key lives in the `.key` sidecar.
    pub fn key_for_file_name(file_name: &str) -> Option<String> {
        let stem = file_name.strip_suffix(FILE_EXT)?;
        if stem.is_empty() || Self::is_hashed_file_name(file_name) {
            return None;
        }
        let bytes = stem.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'%' {
                let hi = *bytes.get(i + 1)?;
                let lo = *bytes.get(i + 2)?;
                let value = (hex_value(hi)? << 4) | hex_value(lo)?;
                decoded.push(value);
                i += 3;
            } else if is_safe_byte(b) {
                decoded.push(b);
                i += 1;
            } else {
                return None;
            }
        }
        String::from_utf8(decoded).ok()
    }

    fn path_for(&self, key: &str) -> CoreResult<PathBuf> {
        validate_key(key)?;
        Ok(self.root.join(Self::file_name_for(key)))
    }
}

fn validate_key(key: &str) -> CoreResult<()> {
    if key.is_empty() {
        return Err(CoreError::invalid("storage key must not be empty"));
    }
    let chars = key.chars().count();
    if chars > MAX_KEY_CHARS {
        return Err(CoreError::invalid(format!(
            "storage key too long ({chars} > {MAX_KEY_CHARS} characters)"
        )));
    }
    Ok(())
}

fn is_safe_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

fn hex_value(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|v| v as u8)
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(TMP_EXT);
    path.with_file_name(name)
}

fn sidecar_path_for(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(KEY_SIDECAR_EXT);
    path.with_file_name(name)
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

async fn write_durably(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::File::create(path).await?;
    file.write_all(bytes).await?;
    file.flush().await?;
    file.sync_all().await?;
    Ok(())
}

fn io_error(action: &str, path: &Path, err: std::io::Error) -> CoreError {
    let mut core = CoreError::from(err);
    core.message = format!("failed to {action} {}: {}", path.display(), core.message);
    core
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_name_round_trips_unicode_and_specials() {
        for key in [
            "netcatty.vault.hosts",
            "hello world",
            "ключ/с/слэшами",
            "日本語キー",
            "100%sure",
            "..",
            "a%20b",
        ] {
            let name = KvStore::file_name_for(key);
            assert!(name.ends_with(FILE_EXT));
            assert!(
                name[..name.len() - FILE_EXT.len()]
                    .bytes()
                    .all(|b| is_safe_byte(b) || b == b'%'),
                "unsafe byte in {name}"
            );
            assert!(!name.contains('/') && !name.contains('\\'));
            assert_eq!(
                KvStore::key_for_file_name(&name).as_deref(),
                Some(key),
                "key {key}"
            );
        }
        assert_eq!(
            KvStore::file_name_for("netcatty.vault.hosts"),
            "netcatty.vault.hosts.json"
        );
        assert_eq!(KvStore::file_name_for("a b"), "a%20b.json");
    }

    #[test]
    fn foreign_files_are_not_keys() {
        assert_eq!(KvStore::key_for_file_name("notes.txt"), None);
        assert_eq!(KvStore::key_for_file_name("foo.json.tmp"), None);
        assert_eq!(KvStore::key_for_file_name(".json"), None);
        assert_eq!(KvStore::key_for_file_name("bad%zz.json"), None);
        assert_eq!(KvStore::key_for_file_name("bad%2.json"), None);
    }

    #[tokio::test]
    async fn set_get_remove_keys() {
        let dir = tempfile::tempdir().unwrap();
        let store = KvStore::new(dir.path().join("store"));

        assert_eq!(store.get("missing").await.unwrap(), None);
        assert!(store.keys().await.unwrap().is_empty());

        store.set("netcatty.vault.hosts", "[1,2]").await.unwrap();
        store.set("ключ", "{\"a\":1}").await.unwrap();
        assert_eq!(
            store.get("netcatty.vault.hosts").await.unwrap().as_deref(),
            Some("[1,2]")
        );
        assert_eq!(
            store.get("ключ").await.unwrap().as_deref(),
            Some("{\"a\":1}")
        );

        store.set("netcatty.vault.hosts", "[3]").await.unwrap();
        assert_eq!(
            store.get("netcatty.vault.hosts").await.unwrap().as_deref(),
            Some("[3]")
        );

        let mut keys = store.keys().await.unwrap();
        keys.sort();
        assert_eq!(
            keys,
            vec!["netcatty.vault.hosts".to_string(), "ключ".to_string()]
        );

        store.remove("ключ").await.unwrap();
        store.remove("ключ").await.unwrap();
        assert_eq!(store.get("ключ").await.unwrap(), None);
        assert_eq!(
            store.keys().await.unwrap(),
            vec!["netcatty.vault.hosts".to_string()]
        );
    }

    #[tokio::test]
    async fn atomic_write_leaves_no_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = KvStore::new(dir.path().to_path_buf());
        store.set("k", "v").await.unwrap();
        store.set("k", "v2").await.unwrap();
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["k.json".to_string()]);
    }

    #[tokio::test]
    async fn rejects_invalid_keys() {
        let dir = tempfile::tempdir().unwrap();
        let store = KvStore::new(dir.path().to_path_buf());
        let err = store.set("", "v").await.unwrap_err();
        assert_eq!(err.code, netcatty_core::ErrorCode::InvalidArgument);
        let long = "k".repeat(MAX_KEY_CHARS + 1);
        let err = store.get(&long).await.unwrap_err();
        assert_eq!(err.code, netcatty_core::ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn over_long_keys_are_hashed_and_still_listed() {
        let dir = tempfile::tempdir().unwrap();
        let store = KvStore::new(dir.path().to_path_buf());

        let long_ascii = "k".repeat(MAX_KEY_CHARS);
        let long_unicode = "ключ-".repeat(60); // 300 chars, ~900 bytes encoded
        let name = KvStore::file_name_for(&long_ascii);
        assert!(name.len() < 255, "{}", name.len());
        assert!(KvStore::is_hashed_file_name(&name));
        assert_eq!(KvStore::key_for_file_name(&name), None);
        assert_ne!(
            KvStore::file_name_for(&long_ascii),
            KvStore::file_name_for(&long_unicode)
        );
        assert!(!KvStore::is_hashed_file_name("short.json"));
        assert!(!KvStore::is_hashed_file_name("a~b.json"));

        store.set(&long_ascii, "1").await.unwrap();
        store.set(&long_unicode, "2").await.unwrap();
        store.set("short", "3").await.unwrap();
        assert_eq!(store.get(&long_ascii).await.unwrap().as_deref(), Some("1"));
        assert_eq!(
            store.get(&long_unicode).await.unwrap().as_deref(),
            Some("2")
        );

        let mut keys = store.keys().await.unwrap();
        keys.sort();
        let mut expected = vec![
            long_ascii.clone(),
            long_unicode.clone(),
            "short".to_string(),
        ];
        expected.sort();
        assert_eq!(keys, expected);

        store.remove(&long_ascii).await.unwrap();
        assert_eq!(store.get(&long_ascii).await.unwrap(), None);
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 3, "{names:?}"); // long_unicode.json + .key, short.json
        assert!(names.iter().all(|n| !n.contains(TMP_EXT)));
    }
}

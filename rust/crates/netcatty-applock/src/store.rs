//! `app-lock-settings.json` persistence (Electron `createAppLockSettingsStore`).
//!
//! The file lives in the app data directory under the Electron name, holds
//! the normalised settings as pretty JSON with a trailing newline, and is
//! replaced atomically (unique temp file + rename, mode 0600) so a crash
//! mid-write cannot leave a truncated file that would load as "disabled".

use crate::settings::{normalize_settings, normalize_typed, AppLockSettings};
use parking_lot::Mutex;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const APP_LOCK_SETTINGS_FILE: &str = "app-lock-settings.json";

pub struct SettingsStore {
    path: PathBuf,
    snapshot: Mutex<AppLockSettings>,
    /// Serialises writes so two saves never race on the temp file.
    write_lock: Mutex<()>,
}

impl SettingsStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            snapshot: Mutex::new(AppLockSettings::default()),
            write_lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the file. Missing → defaults; unparsable JSON → defaults; other
    /// I/O errors are returned (the snapshot keeps its previous value).
    pub fn load(&self) -> std::io::Result<AppLockSettings> {
        let loaded = match std::fs::read_to_string(&self.path) {
            Ok(raw) => serde_json::from_str::<serde_json::Value>(&raw)
                .map(|v| normalize_settings(&v))
                .unwrap_or_default(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => AppLockSettings::default(),
            Err(e) => return Err(e),
        };
        *self.snapshot.lock() = loaded.clone();
        Ok(loaded)
    }

    pub fn snapshot(&self) -> AppLockSettings {
        self.snapshot.lock().clone()
    }

    /// Normalise, write atomically, update the snapshot.
    pub fn save(&self, next: &AppLockSettings) -> std::io::Result<AppLockSettings> {
        let _guard = self.write_lock.lock();
        let normalized = normalize_typed(next);
        let mut payload = serde_json::to_string_pretty(&normalized)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        payload.push('\n');
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_file_name(format!(
            "{}.{}.{}.tmp",
            self.path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| APP_LOCK_SETTINGS_FILE.into()),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        let write = || -> std::io::Result<()> {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp)?;
            file.write_all(payload.as_bytes())?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&tmp, &self.path)
        };
        if let Err(e) = write() {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        *self.snapshot.lock() = normalized.clone();
        Ok(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::create_password_verifier_with;

    #[test]
    fn missing_file_loads_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let store = SettingsStore::new(dir.path().join(APP_LOCK_SETTINGS_FILE));
        assert_eq!(store.load().unwrap(), AppLockSettings::default());
    }

    #[test]
    fn corrupt_file_loads_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(APP_LOCK_SETTINGS_FILE);
        std::fs::write(&path, "{ not json").unwrap();
        let store = SettingsStore::new(&path);
        assert_eq!(store.load().unwrap(), AppLockSettings::default());
    }

    #[test]
    fn save_round_trips_in_electron_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(APP_LOCK_SETTINGS_FILE);
        let store = SettingsStore::new(&path);
        let settings = AppLockSettings {
            enabled: true,
            timeout_minutes: 5,
            system_unlock_enabled: true,
            system_unlock_auto_prompt_enabled: false,
            password_verifier: Some(create_password_verifier_with("pw", 100_000).unwrap()),
        };
        let saved = store.save(&settings).unwrap();
        assert_eq!(saved, settings);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.starts_with("{\n  \"enabled\": true,\n  \"timeoutMinutes\": 5,"));
        assert!(raw.ends_with("}\n"));
        assert!(raw.contains("\"algorithm\": \"PBKDF2-SHA256\""));
        let reloaded = SettingsStore::new(&path).load().unwrap();
        assert_eq!(reloaded, settings);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // No temp files are left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn save_normalises_enabled_without_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let store = SettingsStore::new(dir.path().join(APP_LOCK_SETTINGS_FILE));
        let saved = store
            .save(&AppLockSettings {
                enabled: true,
                timeout_minutes: 7,
                ..AppLockSettings::default()
            })
            .unwrap();
        assert!(!saved.enabled);
        assert_eq!(saved.timeout_minutes, 15);
    }
}

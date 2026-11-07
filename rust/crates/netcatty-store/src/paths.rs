//! Application directories.

use std::path::PathBuf;

/// Environment variable that switches the app into portable mode: every
/// persistent file lives under this directory (mirrors the Windows
/// portable build of the Electron app, `electron/portableData.cjs`).
pub const PORTABLE_DATA_DIR_ENV: &str = "NETCATTY_PORTABLE_DATA_DIR";

const APP_DIR_NAME: &str = "netcatty";

/// Resolved application directories. Honors `NETCATTY_PORTABLE_DATA_DIR`
/// (portable mode) before the platform defaults.
#[derive(Debug, Clone)]
pub struct AppPaths {
    /// `<data>/netcatty` — vault store, known hosts, backups.
    pub data_dir: PathBuf,
    /// `<cache>/netcatty` — temp downloads, staged uploads.
    pub cache_dir: PathBuf,
    /// `<data>/netcatty/logs`.
    pub logs_dir: PathBuf,
}

impl AppPaths {
    /// Resolve the directories. Nothing is created here; `KvStore` and
    /// `BackupStore` create what they need lazily.
    pub fn resolve() -> Self {
        Self::resolve_with(std::env::var_os(PORTABLE_DATA_DIR_ENV).map(PathBuf::from))
    }

    /// Resolve with an explicit portable override (tests / embedding).
    pub fn resolve_with(portable_dir: Option<PathBuf>) -> Self {
        if let Some(dir) = portable_dir.filter(|d| !d.as_os_str().is_empty()) {
            return Self::from_data_and_cache(dir.clone(), dir.join("cache"));
        }

        let data_dir = dirs::data_dir()
            .map(|d| d.join(APP_DIR_NAME))
            .or_else(|| dirs::home_dir().map(|h| h.join(format!(".{APP_DIR_NAME}"))))
            .unwrap_or_else(|| std::env::temp_dir().join(APP_DIR_NAME));
        let cache_dir = dirs::cache_dir()
            .map(|d| d.join(APP_DIR_NAME))
            .unwrap_or_else(|| data_dir.join("cache"));
        Self::from_data_and_cache(data_dir, cache_dir)
    }

    fn from_data_and_cache(data_dir: PathBuf, cache_dir: PathBuf) -> Self {
        let logs_dir = data_dir.join("logs");
        Self {
            data_dir,
            cache_dir,
            logs_dir,
        }
    }

    pub fn store_dir(&self) -> PathBuf {
        self.data_dir.join("store")
    }
    pub fn backups_dir(&self) -> PathBuf {
        self.data_dir.join("backups")
    }
    /// `<data>/netcatty/crash-logs` (Electron: `{userData}/crash-logs`).
    pub fn crash_logs_dir(&self) -> PathBuf {
        self.data_dir.join("crash-logs")
    }
    pub fn temp_dir(&self) -> PathBuf {
        self.cache_dir.join("tmp")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_override_wins() {
        let paths = AppPaths::resolve_with(Some(PathBuf::from("/portable/data")));
        assert_eq!(paths.data_dir, PathBuf::from("/portable/data"));
        assert_eq!(paths.cache_dir, PathBuf::from("/portable/data/cache"));
        assert_eq!(paths.logs_dir, PathBuf::from("/portable/data/logs"));
        assert_eq!(paths.store_dir(), PathBuf::from("/portable/data/store"));
        assert_eq!(paths.backups_dir(), PathBuf::from("/portable/data/backups"));
        assert_eq!(paths.temp_dir(), PathBuf::from("/portable/data/cache/tmp"));
    }

    #[test]
    fn platform_defaults_end_with_app_name() {
        let paths = AppPaths::resolve_with(None);
        assert!(
            paths.data_dir.ends_with(APP_DIR_NAME),
            "{:?}",
            paths.data_dir
        );
        assert!(paths.cache_dir.to_string_lossy().contains(APP_DIR_NAME));
        assert_eq!(paths.logs_dir, paths.data_dir.join("logs"));
    }
}

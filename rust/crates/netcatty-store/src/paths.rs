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
        Self::resolve_with(
            std::env::var_os(PORTABLE_DATA_DIR_ENV)
                .map(PathBuf::from)
                .or_else(portable_data_dir_beside_executable),
        )
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

/// Windows ZIP / portable builds (Electron: `electron/portableData.cjs`): a
/// `data` directory beside the executable (or beside the portable launcher,
/// `PORTABLE_EXECUTABLE_DIR`) holds all app data. Release builds on Windows
/// only, like Electron's `app.isPackaged` gate.
fn portable_data_dir_beside_executable() -> Option<PathBuf> {
    if !cfg!(windows) || cfg!(debug_assertions) {
        return None;
    }
    let launcher = std::env::var("PORTABLE_EXECUTABLE_DIR").ok();
    let exe = std::env::current_exe().ok();
    portable_data_dir(launcher.as_deref(), exe.as_deref())
}

/// `<launcher dir or exe dir>/data` when it is an existing directory.
pub fn portable_data_dir(
    portable_launcher_dir: Option<&str>,
    executable: Option<&std::path::Path>,
) -> Option<PathBuf> {
    let base = match portable_launcher_dir.map(str::trim).filter(|d| !d.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => executable?.parent()?.to_path_buf(),
    };
    let data = base.join("data");
    data.is_dir().then_some(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_data_beside_the_executable_or_launcher() {
        let root = std::env::temp_dir().join(format!("netcatty-portable-{}", std::process::id()));
        let exe_dir = root.join("app");
        let launcher_dir = root.join("usb-drive");
        std::fs::create_dir_all(exe_dir.join("data")).unwrap();
        std::fs::create_dir_all(&launcher_dir).unwrap();
        let exe = exe_dir.join("Netcatty.exe");
        assert_eq!(portable_data_dir(None, Some(&exe)), Some(exe_dir.join("data")));
        // A launcher directory without `data` disables portable mode even if
        // the unpacked runtime has one.
        assert_eq!(portable_data_dir(Some(launcher_dir.to_str().unwrap()), Some(&exe)), None);
        std::fs::create_dir_all(launcher_dir.join("data")).unwrap();
        assert_eq!(
            portable_data_dir(Some(launcher_dir.to_str().unwrap()), Some(&exe)),
            Some(launcher_dir.join("data"))
        );
        // A `data` file is not a data directory.
        let file_dir = root.join("file");
        std::fs::create_dir_all(&file_dir).unwrap();
        std::fs::write(file_dir.join("data"), "x").unwrap();
        assert_eq!(portable_data_dir(None, Some(&file_dir.join("Netcatty.exe"))), None);
        let _ = std::fs::remove_dir_all(&root);
    }

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

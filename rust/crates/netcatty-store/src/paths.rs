//! Application directories.

use std::path::PathBuf;

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
    pub fn resolve() -> Self {
        todo!("dirs::data_dir / cache_dir with portable override (store agent task)")
    }

    pub fn store_dir(&self) -> PathBuf {
        self.data_dir.join("store")
    }
    pub fn backups_dir(&self) -> PathBuf {
        self.data_dir.join("backups")
    }
    pub fn temp_dir(&self) -> PathBuf {
        self.cache_dir.join("tmp")
    }
}

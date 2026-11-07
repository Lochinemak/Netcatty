//! Atomic JSON file writes shared by the stores (Electron: write a
//! `<file>.<pid>.tmp` with mode 0600, then rename over the target).

use std::io;
use std::path::Path;

pub(crate) fn atomic_write(file: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = file.with_extension(format!("{}.tmp", std::process::id()));
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut handle = options.open(&temporary)?;
        io::Write::write_all(&mut handle, bytes)?;
    }
    std::fs::rename(&temporary, file)
}

/// Read a JSON file; `Ok(None)` when it does not exist.
pub(crate) fn read_json(file: &Path) -> io::Result<Option<serde_json::Value>> {
    match std::fs::read(file) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Milliseconds since the Unix epoch (`Date.now()`).
pub(crate) fn now_ms() -> i64 {
    netcatty_core::ids::now_ms()
}

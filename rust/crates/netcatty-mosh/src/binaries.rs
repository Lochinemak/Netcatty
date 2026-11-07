//! Locating the external client binaries.
//!
//! Electron bundles `mosh-client` (MoshCatty) and `et` through
//! electron-builder `extraResources` at `<Resources>/mosh/` and
//! `<Resources>/et/`, with a development fallback under
//! `resources/<tool>/<platform-arch>/`. The Tauri build ships them the same
//! way (`bundle.resources`, see `build-tauri.yml`); when neither is present
//! the client found on `PATH` is used.

use std::path::{Path, PathBuf};

/// Which bundled client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    Mosh,
    Et,
}

impl Client {
    /// Resource sub-directory (`mosh` / `et`).
    pub fn dir(self) -> &'static str {
        match self {
            Client::Mosh => "mosh",
            Client::Et => "et",
        }
    }

    /// Executable name on this platform.
    pub fn exe(self) -> &'static str {
        match (self, cfg!(windows)) {
            (Client::Mosh, false) => "mosh-client",
            (Client::Mosh, true) => "mosh-client.exe",
            (Client::Et, false) => "et",
            (Client::Et, true) => "et.exe",
        }
    }

    /// Program name looked up on `PATH`.
    pub fn path_name(self) -> &'static str {
        match self {
            Client::Mosh => "mosh-client",
            Client::Et => "et",
        }
    }
}

/// `<platform>-<arch>` directory of the development layout.
pub fn dev_platform_dir() -> String {
    if cfg!(target_os = "macos") {
        return "darwin-universal".into();
    }
    let platform = if cfg!(windows) { "win32" } else { "linux" };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{platform}-{arch}")
}

/// Is `path` an executable regular file?
pub fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Candidate locations of a bundled client, in lookup order.
pub fn bundled_candidates(
    client: Client,
    resource_dir: Option<&Path>,
    project_root: Option<&Path>,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(dir) = resource_dir {
        out.push(dir.join(client.dir()).join(client.exe()));
    }
    if let Some(root) = project_root {
        out.push(
            root.join("resources")
                .join(client.dir())
                .join(dev_platform_dir())
                .join(client.exe()),
        );
    }
    out
}

/// Search `PATH` (or `path_override`) for `name`. On Windows `PATHEXT`
/// extensions are tried.
pub fn find_on_path(name: &str, path_override: Option<&str>) -> Option<PathBuf> {
    let path_var = match path_override {
        Some(p) => p.to_string(),
        None => std::env::var("PATH").ok()?,
    };
    let exts: Vec<String> = if cfg!(windows) {
        let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".into());
        std::iter::once(String::new())
            .chain(pathext.split(';').filter(|e| !e.is_empty()).map(str::to_string))
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        for ext in &exts {
            let candidate = dir.join(format!("{name}{ext}"));
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Resolve a client: bundled first, then `PATH`.
pub fn resolve_client(
    client: Client,
    resource_dir: Option<&Path>,
    project_root: Option<&Path>,
    path_override: Option<&str>,
) -> Option<PathBuf> {
    bundled_candidates(client, resource_dir, project_root)
        .into_iter()
        .find(|c| is_executable_file(c))
        .or_else(|| find_on_path(client.path_name(), path_override))
}

/// The system OpenSSH client (`resolveSshExecutable`): `PATH`, then the
/// in-box `%SystemRoot%\System32\OpenSSH\ssh.exe` on Windows.
pub fn resolve_ssh(path_override: Option<&str>) -> Option<PathBuf> {
    if let Some(found) = find_on_path("ssh", path_override) {
        return Some(found);
    }
    if cfg!(windows) {
        let root = std::env::var("SystemRoot")
            .or_else(|_| std::env::var("SYSTEMROOT"))
            .unwrap_or_else(|_| "C:\\Windows".into());
        let inbox = PathBuf::from(root)
            .join("System32")
            .join("OpenSSH")
            .join("ssh.exe");
        if inbox.is_file() {
            return Some(inbox);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_follow_electron_layout() {
        let c = bundled_candidates(
            Client::Mosh,
            Some(Path::new("/App/Resources")),
            Some(Path::new("/src/netcatty")),
        );
        assert_eq!(c[0], Path::new("/App/Resources/mosh").join(Client::Mosh.exe()));
        assert!(c[1].starts_with("/src/netcatty/resources/mosh"));
        assert!(c[1].to_string_lossy().contains(&dev_platform_dir()));
        let c = bundled_candidates(Client::Et, Some(Path::new("/R")), None);
        assert_eq!(c, vec![Path::new("/R/et").join(Client::Et.exe())]);
    }

    #[cfg(unix)]
    #[test]
    fn path_lookup_and_bundled_preference() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nc-bin-{}", std::process::id()));
        let bin = dir.join("bin");
        let res = dir.join("res/mosh");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&res).unwrap();
        for p in [bin.join("mosh-client"), res.join("mosh-client")] {
            std::fs::write(&p, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = bin.to_string_lossy().into_owned();
        assert_eq!(find_on_path("mosh-client", Some(&path)), Some(bin.join("mosh-client")));
        assert_eq!(
            resolve_client(Client::Mosh, Some(&dir.join("res")), None, Some(&path)),
            Some(res.join("mosh-client"))
        );
        assert_eq!(
            resolve_client(Client::Mosh, None, None, Some(&path)),
            Some(bin.join("mosh-client"))
        );
        assert_eq!(resolve_client(Client::Et, None, None, Some(&path)), None);
        // Not executable → ignored.
        std::fs::set_permissions(bin.join("mosh-client"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert_eq!(find_on_path("mosh-client", Some(&path)), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

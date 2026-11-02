//! Working-directory discovery for a running process (mirrors
//! `localSessionCwd.cjs`).
//!
//! `cd` is a shell builtin, so the process cwd changes even when the shell
//! never prints OSC 7. Linux reads `/proc/<pid>/cwd`; macOS asks the kernel
//! via `proc_pidinfo(PROC_PIDVNODEPATHINFO)` and falls back to `lsof`.
//! Windows is not probed.

use std::time::Duration;

#[allow(dead_code)]
const LSOF_TIMEOUT: Duration = Duration::from_secs(2);

/// Current working directory of `pid`, when the platform supports it.
pub async fn process_cwd(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(cwd) = proc_cwd(pid).await {
            return Some(cwd);
        }
        lsof_cwd(pid, &["lsof"]).await
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(cwd) = tokio::task::spawn_blocking(move || macos::pidinfo_cwd(pid))
            .await
            .ok()
            .flatten()
        {
            return Some(cwd);
        }
        lsof_cwd(pid, &["/usr/sbin/lsof", "lsof"]).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

fn is_absolute_posix_path(value: &str) -> bool {
    value.starts_with('/') && !value.contains('\0')
}

#[cfg(target_os = "linux")]
async fn proc_cwd(pid: u32) -> Option<String> {
    let target = tokio::fs::read_link(format!("/proc/{pid}/cwd"))
        .await
        .ok()?;
    let text = target.to_string_lossy().into_owned();
    // A deleted directory shows up as "/path (deleted)"; nothing to cd into.
    if text.ends_with(" (deleted)") || !is_absolute_posix_path(&text) {
        return None;
    }
    Some(text)
}

/// lsof appends "(readlink: Permission denied)" style notes to names it
/// could not resolve. Those are not directories the shell can `cd` into.
fn is_annotated_lsof_name(name: &str) -> bool {
    let Some(open) = name.rfind(" (") else {
        return false;
    };
    let note = &name[open + 2..];
    let Some(note) = note.strip_suffix(')') else {
        return false;
    };
    let Some((kind, _)) = note.split_once(": ") else {
        return false;
    };
    let mut chars = kind.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric())
}

/// Parse `lsof -F n` (optionally with `t` type records) and return the cwd
/// name when lsof reports a directory.
pub fn parse_lsof_cwd_output(stdout: &str) -> Option<String> {
    if stdout.is_empty() {
        return None;
    }
    let mut name: Option<&str> = None;
    let mut is_dir = true;
    let mut saw_type = false;
    for line in stdout.split('\n') {
        if let Some(rest) = line.strip_prefix('f') {
            let _ = rest;
            saw_type = false;
            is_dir = true;
            continue;
        }
        if line.starts_with('t') {
            saw_type = true;
            is_dir = line == "tDIR" || line == "tVDIR";
            continue;
        }
        if let Some(rest) = line.strip_prefix('n') {
            if !saw_type || is_dir {
                name = Some(rest);
            }
        }
    }
    let name = name?;
    if !is_absolute_posix_path(name) || is_annotated_lsof_name(name) {
        return None;
    }
    Some(name.to_string())
}

#[allow(dead_code)]
async fn lsof_cwd(pid: u32, binaries: &[&str]) -> Option<String> {
    let pid_arg = pid.to_string();
    for bin in binaries {
        let mut cmd = tokio::process::Command::new(bin);
        cmd.args(["-a", "-p", &pid_arg, "-d", "cwd", "-Fn"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        let output = match tokio::time::timeout(LSOF_TIMEOUT, child.wait_with_output()).await {
            Ok(Ok(output)) => output,
            _ => return None,
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(cwd) = parse_lsof_cwd_output(&stdout) {
            return Some(cwd);
        }
    }
    None
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{c_char, c_int, c_void, CStr};

    /// `proc_pidinfo(PROC_PIDVNODEPATHINFO)` — the kernel's view of the
    /// process cwd, no subprocess required.
    pub fn pidinfo_cwd(pid: u32) -> Option<String> {
        // SAFETY: proc_vnodepathinfo is plain-old-data; zeroed is a valid
        // initial state and the kernel fills it in.
        let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_vnodepathinfo>() as c_int;
        // SAFETY: the buffer pointer and size describe `info` exactly.
        let written = unsafe {
            libc::proc_pidinfo(
                pid as c_int,
                libc::PROC_PIDVNODEPATHINFO,
                0,
                &mut info as *mut libc::proc_vnodepathinfo as *mut c_void,
                size,
            )
        };
        if written <= 0 || written as usize > std::mem::size_of::<libc::proc_vnodepathinfo>() {
            return None;
        }
        let path_ptr = info.pvi_cdir.vip_path.as_ptr() as *const c_char;
        let path_len = std::mem::size_of_val(&info.pvi_cdir.vip_path);
        // SAFETY: vip_path is an inline buffer of `path_len` bytes that the
        // kernel NUL-terminates; we never read past it.
        let bytes = unsafe { std::slice::from_raw_parts(path_ptr as *const u8, path_len) };
        let end = bytes.iter().position(|b| *b == 0)?;
        let cstr = CStr::from_bytes_with_nul(&bytes[..=end]).ok()?;
        let path = cstr.to_string_lossy().into_owned();
        if super::is_absolute_posix_path(&path) {
            Some(path)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_lsof_output() {
        assert_eq!(
            parse_lsof_cwd_output("p123\nfcwd\nn/Users/me/src\n").as_deref(),
            Some("/Users/me/src")
        );
        assert_eq!(
            parse_lsof_cwd_output("p123\nfcwd\ntDIR\nn/tmp\n").as_deref(),
            Some("/tmp")
        );
        assert_eq!(
            parse_lsof_cwd_output("p123\nfcwd\ntVDIR\nn/private/tmp\n").as_deref(),
            Some("/private/tmp")
        );
    }

    #[test]
    fn rejects_non_directories_and_annotations() {
        assert_eq!(
            parse_lsof_cwd_output("p1\nfcwd\ntREG\nn/etc/passwd\n"),
            None
        );
        assert_eq!(
            parse_lsof_cwd_output("p1\nfcwd\nn/root (readlink: Permission denied)\n"),
            None
        );
        assert_eq!(parse_lsof_cwd_output("p1\nfcwd\nnrelative/path\n"), None);
        assert_eq!(parse_lsof_cwd_output(""), None);
        assert_eq!(parse_lsof_cwd_output("p1\n"), None);
    }

    #[test]
    fn keeps_parenthesised_directory_names() {
        assert_eq!(
            parse_lsof_cwd_output("p1\nfcwd\nn/Users/me/Projects (old)\n").as_deref(),
            Some("/Users/me/Projects (old)")
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn own_cwd_is_discoverable() {
        let expected = std::env::current_dir().unwrap().canonicalize().unwrap();
        let cwd = process_cwd(std::process::id()).await.expect("cwd of self");
        let got = std::path::Path::new(&cwd).canonicalize().unwrap();
        assert_eq!(got, expected);
    }
}

//! Owner (uid → user name) resolution for directory listings.

#[cfg(unix)]
mod imp {
    use std::collections::HashMap;
    use std::ffi::CStr;
    use std::os::unix::fs::MetadataExt;
    use std::sync::{Mutex, OnceLock};

    static NAME_CACHE: OnceLock<Mutex<HashMap<u32, Option<String>>>> = OnceLock::new();

    /// Owner of a directory entry: the user name when the uid resolves,
    /// otherwise the numeric uid as a string (what `ls` does too).
    pub fn owner_name(meta: &std::fs::Metadata) -> Option<String> {
        let uid = meta.uid();
        Some(user_name_for_uid(uid).unwrap_or_else(|| uid.to_string()))
    }

    /// Name of the user running this process (`getpwuid(getuid())`).
    pub fn current_user_name() -> Option<String> {
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        user_name_for_uid(uid)
    }

    fn user_name_for_uid(uid: u32) -> Option<String> {
        let cache = NAME_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Some(cached) = cache.lock().ok().and_then(|c| c.get(&uid).cloned()) {
            return cached;
        }
        let resolved = lookup(uid);
        if let Ok(mut c) = cache.lock() {
            if c.len() > 4096 {
                c.clear();
            }
            c.insert(uid, resolved.clone());
        }
        resolved
    }

    fn lookup(uid: u32) -> Option<String> {
        let mut buf = vec![0u8; 16 * 1024];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: all pointers reference live, correctly sized buffers;
        // getpwuid_r writes only within `buf` and `pwd`.
        let rc = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
            return None;
        }
        // SAFETY: pw_name points into `buf`, which is still alive, and is
        // NUL-terminated by getpwuid_r.
        let name = unsafe { CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }
}

#[cfg(not(unix))]
mod imp {
    /// The Electron bridge omits `owner` on Windows.
    pub fn owner_name(_meta: &std::fs::Metadata) -> Option<String> {
        None
    }

    pub fn current_user_name() -> Option<String> {
        None
    }
}

pub use imp::{current_user_name, owner_name};

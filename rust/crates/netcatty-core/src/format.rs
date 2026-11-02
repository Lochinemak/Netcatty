//! Pure formatting helpers shared by SFTP / local-fs listings.

/// Format a byte count the way the Electron bridge did for `RemoteFile.size`
/// (a raw `"<n> bytes"` string; the renderer formats for display).
pub fn raw_bytes_string(size: u64) -> String {
    format!("{size} bytes")
}

/// Human readable size (`1.5 MB`), used by diagnostics and logs.
pub fn human_bytes(size: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if size < 1024 {
        return format!("{size} B");
    }
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Render a POSIX mode (`0o755`) as `rwxr-xr-x`, including the type prefix
/// character when `with_type` is set (`drwxr-xr-x`).
pub fn mode_to_permissions(mode: u32, with_type: bool) -> String {
    let mut out = String::with_capacity(10);
    if with_type {
        out.push(match mode & 0o170000 {
            0o040000 => 'd',
            0o120000 => 'l',
            0o020000 => 'c',
            0o060000 => 'b',
            0o010000 => 'p',
            0o140000 => 's',
            _ => '-',
        });
    }
    let bits = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    for (i, (mask, ch)) in bits.iter().enumerate() {
        let mut c = if mode & mask != 0 { *ch } else { '-' };
        // setuid / setgid / sticky
        if i == 2 && mode & 0o4000 != 0 {
            c = if mode & mask != 0 { 's' } else { 'S' };
        }
        if i == 5 && mode & 0o2000 != 0 {
            c = if mode & mask != 0 { 's' } else { 'S' };
        }
        if i == 8 && mode & 0o1000 != 0 {
            c = if mode & mask != 0 { 't' } else { 'T' };
        }
        out.push(c);
    }
    out
}

/// Parse an octal permission string such as `"755"` or `"0644"` into a mode.
pub fn parse_octal_mode(text: &str) -> Option<u32> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.len() > 5 {
        return None;
    }
    u32::from_str_radix(trimmed, 8).ok()
}

/// ISO-8601 timestamp (UTC, millisecond precision) from unix milliseconds —
/// the format the Electron bridge used for `RemoteFile.lastModified`.
pub fn iso_from_ms(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_render() {
        assert_eq!(mode_to_permissions(0o755, false), "rwxr-xr-x");
        assert_eq!(mode_to_permissions(0o100644, true), "-rw-r--r--");
        assert_eq!(mode_to_permissions(0o040755, true), "drwxr-xr-x");
        assert_eq!(mode_to_permissions(0o4755, false), "rwsr-xr-x");
    }

    #[test]
    fn octal_parse() {
        assert_eq!(parse_octal_mode("755"), Some(0o755));
        assert_eq!(parse_octal_mode("0644"), Some(0o644));
        assert_eq!(parse_octal_mode("abc"), None);
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KB");
    }

    #[test]
    fn iso_timestamps() {
        assert_eq!(iso_from_ms(0), "1970-01-01T00:00:00.000Z");
    }
}

//! Create a `.tar.gz` / `.zip` archive on the remote host from files in one
//! directory, without transferring their bytes.
//!
//! Mirrors `electron/bridges/sftpBridge/archiveCreate.cjs`: the archive is
//! written into a private staging directory next to the target and then
//! published with `ln` (atomic, never replaces) or, with `overwrite`, `mv -f`.
//! A remote marker line on stdout tells "created" from "name already taken".

use std::time::Duration;

use netcatty_core::ipc::{SftpArchiveCreateOptions, SftpArchiveFormat};
use netcatty_core::models::SftpFilenameEncoding;

use crate::client::{encode_path, shell_quote_bytes, SftpClient};
use crate::error::{SftpError, SftpResult};

/// Upper bound for the remote archiver run.
const CREATE_ARCHIVE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_ARCHIVE_ITEMS: usize = 1000;
const MAX_COMMAND_BYTES: usize = 256 * 1024;
const RESULT_OK: &str = "NETCATTY_ARCHIVE_RESULT:OK";
const RESULT_EXISTS: &str = "NETCATTY_ARCHIVE_RESULT:EEXIST";

/// What the remote host reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveCreateOutcome {
    Created,
    /// The target name is taken and `overwrite` was not set.
    AlreadyExists,
}

/// Options after validation: selection roots normalised, deduplicated and
/// with descendants of other selected folders dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedArchiveCreate {
    pub directory: String,
    pub archive_name: String,
    pub format: SftpArchiveFormat,
    pub overwrite: bool,
    pub paths: Vec<String>,
}

fn invalid(message: &str) -> SftpError {
    SftpError::InvalidArgument(message.to_string())
}

fn safe_remote_path(value: &str) -> SftpResult<&str> {
    if value.is_empty() {
        return Err(invalid("Remote path is required"));
    }
    if value.contains('\0') || value.contains('\r') || value.contains('\n') {
        return Err(invalid("Remote path must not contain NUL or newlines"));
    }
    Ok(value)
}

/// `path.posix.normalize` for a relative path with no `..`, minus any
/// trailing slash: drops empty and `.` segments.
fn normalize_relative(value: &str) -> String {
    value
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/")
}

pub fn validate_archive_create_options(
    options: &SftpArchiveCreateOptions,
) -> SftpResult<ValidatedArchiveCreate> {
    let directory = safe_remote_path(&options.directory)?;
    if !directory.starts_with('/') || directory.contains('\\') {
        return Err(invalid("Archive directory must be an absolute POSIX path"));
    }

    let archive_name = safe_remote_path(&options.archive_name)?;
    if archive_name == "." || archive_name == ".." || archive_name.contains(['/', '\\']) {
        return Err(invalid(
            "Archive name must be a file name without a directory",
        ));
    }
    let extension = options.format.extension();
    let suffix = format!(".{extension}");
    if !archive_name.to_lowercase().ends_with(&suffix) || archive_name.len() <= suffix.len() {
        return Err(SftpError::InvalidArgument(format!(
            "Archive name must end with {suffix}"
        )));
    }

    if options.paths.is_empty() || options.paths.len() > MAX_ARCHIVE_ITEMS {
        return Err(invalid("Choose between 1 and 1000 items to archive"));
    }
    let mut paths: Vec<String> = Vec::with_capacity(options.paths.len());
    for entry in &options.paths {
        let value = safe_remote_path(entry)?;
        if value.starts_with('/') || value.contains('\\') || value.split('/').any(|p| p == "..") {
            return Err(invalid(
                "Archive source must stay inside the current directory",
            ));
        }
        let normalized = normalize_relative(value);
        if normalized.is_empty() {
            return Err(invalid("Cannot archive the current directory itself"));
        }
        if normalized == archive_name || normalized.starts_with(&format!("{archive_name}/")) {
            return Err(invalid(
                "Archive output cannot be one of the selected sources",
            ));
        }
        if !paths.contains(&normalized) {
            paths.push(normalized);
        }
    }
    // Selecting a folder already includes its descendants.
    let roots = paths
        .iter()
        .filter(|entry| {
            !paths
                .iter()
                .any(|parent| entry.starts_with(&format!("{parent}/")))
        })
        .cloned()
        .collect();

    Ok(ValidatedArchiveCreate {
        directory: directory.to_string(),
        archive_name: archive_name.to_string(),
        format: options.format,
        overwrite: options.overwrite == Some(true),
        paths: roots,
    })
}

/// Build the POSIX script that creates and publishes the archive. Paths are
/// encoded with `encoding` (a concrete one: UTF-8 or GB18030) so non-UTF-8
/// names reach the remote shell byte-exact.
pub fn build_create_archive_command(
    options: &ValidatedArchiveCreate,
    encoding: SftpFilenameEncoding,
) -> SftpResult<String> {
    let quote = |value: &str| shell_quote_bytes(&encode_path(value, encoding));
    let tool = match options.format {
        SftpArchiveFormat::TarGz => "tar",
        SftpArchiveFormat::Zip => "zip",
    };
    let source_args = options
        .paths
        .iter()
        .map(|entry| quote(&format!("./{entry}")))
        .collect::<Vec<_>>()
        .join(" ");
    let mut parent_paths: Vec<String> = Vec::new();
    for entry in &options.paths {
        let parts: Vec<&str> = entry.split('/').collect();
        for depth in 1..parts.len() {
            let parent = format!("./{}", parts[..depth].join("/"));
            if !parent_paths.contains(&parent) {
                parent_paths.push(parent);
            }
        }
    }

    let mut lines: Vec<String> = vec![
        "set -e".into(),
        "umask 077".into(),
        format!("cd {}", quote(&options.directory)),
        format!("name={}", quote(&options.archive_name)),
        "out=\"./$name\"".into(),
        "check_target() {".into(),
        "  if [ -L \"$out\" ] || { [ -e \"$out\" ] && [ ! -f \"$out\" ]; }; then".into(),
        "    echo 'Archive target must be a regular file, not a directory or symbolic link' >&2"
            .into(),
        "    exit 1".into(),
        "  fi".into(),
    ];
    // Case-insensitive filesystems and hard links can alias a selected source
    // even when the input and output names are different strings.
    for entry in &options.paths {
        lines.push(format!(
            "  if [ -e \"$out\" ] && [ \"$out\" -ef {} ]; then echo 'Archive output refers to a selected source' >&2; exit 1; fi",
            quote(&format!("./{entry}"))
        ));
    }
    if !options.overwrite {
        lines.extend([
            "  if [ -e \"$out\" ]; then".into(),
            format!("    printf '%s\\n' '{RESULT_EXISTS}'"),
            "    exit 0".into(),
            "  fi".into(),
        ]);
    }
    lines.push("}".into());
    lines.push("check_target".into());
    // An intermediate symlink can resolve a tree selection outside directory,
    // including back into the directory holding the newly written archive.
    for parent in &parent_paths {
        lines.push(format!(
            "if [ -L {} ]; then echo 'Archive source traverses a symbolic link' >&2; exit 1; fi",
            quote(parent)
        ));
    }
    for entry in &options.paths {
        let source = quote(&format!("./{entry}"));
        lines.push(format!(
            "if [ ! -e {source} ] && [ ! -L {source} ]; then echo 'Archive source no longer exists' >&2; exit 1; fi"
        ));
    }
    lines.push(format!(
        "command -v {tool} >/dev/null 2>&1 || {{ echo '{tool} is not installed on the remote host' >&2; exit 127; }}"
    ));
    lines.extend([
        "stage=$(mktemp -d \"./.netcatty-archive.XXXXXXXXXX\")".into(),
        "trap 'rm -rf -- \"$stage\"' EXIT".into(),
        "trap 'exit 1' HUP INT TERM".into(),
    ]);
    lines.push(match options.format {
        SftpArchiveFormat::Zip => {
            format!("zip -q -r -y -nw -MM \"$stage/$name\" -- {source_args} >/dev/null")
        }
        SftpArchiveFormat::TarGz => {
            format!("tar -czf \"$stage/$name\" -- {source_args} >/dev/null")
        }
    });
    lines.push("check_target".into());
    if options.overwrite {
        lines.push("mv -f -- \"$stage/$name\" .".into());
    } else {
        lines.extend([
            "if ! ln -- \"$stage/$name\" .; then".into(),
            // ln is an atomic no-replace operation. A concurrent regular-file
            // publication is a conflict, never permission to overwrite it.
            "  if [ -f \"$out\" ] && [ ! -L \"$out\" ]; then".into(),
            format!("    printf '%s\\n' '{RESULT_EXISTS}'"),
            "    exit 0".into(),
            "  fi".into(),
            "  echo 'Could not publish archive without replacing an existing target' >&2".into(),
            "  exit 1".into(),
            "fi".into(),
        ]);
    }
    lines.push(format!("printf '%s\\n' '{RESULT_OK}'"));

    let command = lines.join("\n");
    if command.len() > MAX_COMMAND_BYTES {
        return Err(invalid("Archive selection is too large"));
    }
    Ok(command)
}

/// Read the marker the script prints last.
pub fn parse_create_archive_result(stdout: &str) -> SftpResult<ArchiveCreateOutcome> {
    match stdout.trim().lines().last().map(str::trim_end) {
        Some(RESULT_OK) => Ok(ArchiveCreateOutcome::Created),
        Some(RESULT_EXISTS) => Ok(ArchiveCreateOutcome::AlreadyExists),
        _ => Err(SftpError::Command(
            "Remote host did not confirm that the archive was created".into(),
        )),
    }
}

impl SftpClient {
    /// Create an archive of `options.paths` inside `options.directory` via
    /// SSH exec.
    pub async fn create_archive(
        &self,
        options: &SftpArchiveCreateOptions,
        encoding: Option<SftpFilenameEncoding>,
    ) -> SftpResult<ArchiveCreateOutcome> {
        let validated = validate_archive_create_options(options)?;
        let encoding = self.concrete(self.effective(encoding));
        let command = build_create_archive_command(&validated, encoding)?;
        let output = self
            .connection
            .exec(&command, Some(CREATE_ARCHIVE_TIMEOUT))
            .await?;
        if output.exit_code != Some(0) {
            let stderr = output.stderr_lossy();
            let detail = stderr.trim();
            let detail = if detail.is_empty() {
                format!(
                    "exit code {}",
                    output
                        .exit_code
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "unknown".into())
                )
            } else {
                detail.chars().take(2000).collect()
            };
            return Err(SftpError::Command(format!(
                "archive creation failed: {detail}"
            )));
        }
        parse_create_archive_result(&output.stdout_lossy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(paths: &[&str]) -> SftpArchiveCreateOptions {
        SftpArchiveCreateOptions {
            directory: "/home/alice".into(),
            paths: paths.iter().map(|p| p.to_string()).collect(),
            archive_name: "out.tar.gz".into(),
            format: SftpArchiveFormat::TarGz,
            overwrite: None,
        }
    }

    fn rejects(opts: SftpArchiveCreateOptions, needle: &str) {
        let err = validate_archive_create_options(&opts)
            .unwrap_err()
            .to_string();
        assert!(err.contains(needle), "{err:?} should mention {needle:?}");
    }

    #[test]
    fn options_deserialize_from_the_renderer_shape() {
        let opts: SftpArchiveCreateOptions = serde_json::from_value(serde_json::json!({
            "directory": "/srv",
            "paths": ["a", "b/c"],
            "archiveName": "x.zip",
            "format": "zip",
            "overwrite": true,
        }))
        .unwrap();
        assert_eq!(opts.format, SftpArchiveFormat::Zip);
        assert_eq!(opts.overwrite, Some(true));
        assert!(
            serde_json::from_value::<SftpArchiveCreateOptions>(serde_json::json!({
                "directory": "/srv", "paths": ["a"], "archiveName": "x.rar", "format": "rar",
            }))
            .is_err()
        );
    }

    #[test]
    fn selection_is_normalised_deduplicated_and_reduced_to_roots() {
        let v = validate_archive_create_options(&options(&[
            "./logs/",
            "logs/app.log",
            "b//c",
            "b/c",
            "notes.txt",
        ]))
        .unwrap();
        assert_eq!(v.paths, vec!["logs", "b/c", "notes.txt"]);
        assert!(!v.overwrite);
    }

    #[test]
    fn unsafe_options_are_rejected() {
        rejects(
            SftpArchiveCreateOptions {
                directory: "relative".into(),
                ..options(&["a"])
            },
            "absolute",
        );
        rejects(
            SftpArchiveCreateOptions {
                directory: "/a\nb".into(),
                ..options(&["a"])
            },
            "newlines",
        );
        rejects(
            SftpArchiveCreateOptions {
                archive_name: "sub/out.tar.gz".into(),
                ..options(&["a"])
            },
            "without a directory",
        );
        rejects(
            SftpArchiveCreateOptions {
                archive_name: "out.zip".into(),
                ..options(&["a"])
            },
            "must end with .tar.gz",
        );
        rejects(
            SftpArchiveCreateOptions {
                archive_name: ".tar.gz".into(),
                ..options(&["a"])
            },
            "must end with",
        );
        rejects(options(&[]), "between 1 and 1000");
        rejects(options(&["../etc"]), "inside the current directory");
        rejects(options(&["/etc"]), "inside the current directory");
        rejects(options(&["./"]), "current directory itself");
        rejects(
            options(&["out.tar.gz"]),
            "cannot be one of the selected sources",
        );
        let many: Vec<String> = (0..1001).map(|i| format!("f{i}")).collect();
        rejects(
            SftpArchiveCreateOptions {
                paths: many,
                ..options(&[])
            },
            "between 1 and 1000",
        );
    }

    #[test]
    fn upper_case_extension_is_accepted() {
        let opts = SftpArchiveCreateOptions {
            archive_name: "Backup.TAR.GZ".into(),
            ..options(&["a"])
        };
        assert!(validate_archive_create_options(&opts).is_ok());
    }

    #[test]
    fn tar_command_publishes_without_replacing() {
        let v = validate_archive_create_options(&options(&["it's/x", "b"])).unwrap();
        let cmd = build_create_archive_command(&v, SftpFilenameEncoding::Utf8).unwrap();
        assert!(cmd.starts_with("set -e\numask 077\ncd '/home/alice'\nname='out.tar.gz'\n"));
        assert!(cmd.contains("tar -czf \"$stage/$name\" -- './it'\\''s/x' './b' >/dev/null"));
        assert!(
            cmd.contains("if [ -L './it'\\''s' ]; then"),
            "parent symlink guard"
        );
        assert!(cmd.contains("if ! ln -- \"$stage/$name\" .; then"));
        assert!(!cmd.contains("mv -f"));
        assert!(cmd.contains(&format!("printf '%s\\n' '{RESULT_EXISTS}'")));
        assert!(cmd.ends_with(&format!("printf '%s\\n' '{RESULT_OK}'")));
    }

    #[test]
    fn zip_overwrite_command_replaces_with_mv() {
        let opts = SftpArchiveCreateOptions {
            archive_name: "out.zip".into(),
            format: SftpArchiveFormat::Zip,
            overwrite: Some(true),
            ..options(&["a"])
        };
        let v = validate_archive_create_options(&opts).unwrap();
        let cmd = build_create_archive_command(&v, SftpFilenameEncoding::Utf8).unwrap();
        assert!(cmd.contains("command -v zip >/dev/null 2>&1"));
        assert!(cmd.contains("zip -q -r -y -nw -MM \"$stage/$name\" -- './a' >/dev/null"));
        assert!(cmd.contains("mv -f -- \"$stage/$name\" ."));
        assert!(!cmd.contains("ln --"));
        assert!(
            !cmd.contains(RESULT_EXISTS),
            "overwrite never reports a conflict"
        );
    }

    #[test]
    fn gb18030_names_are_sent_as_raw_bytes() {
        let v = validate_archive_create_options(&options(&["日志"])).unwrap();
        let cmd = build_create_archive_command(&v, SftpFilenameEncoding::Gb18030).unwrap();
        // "./日志" in GB18030 is not UTF-8, so it goes through printf octal escapes.
        let expected = shell_quote_bytes(&encode_path("./日志", SftpFilenameEncoding::Gb18030));
        assert!(expected.starts_with("\"$(printf '"));
        assert!(cmd.contains(&expected));
    }

    #[test]
    fn result_marker_is_read_from_the_last_line() {
        assert_eq!(
            parse_create_archive_result("noise\nNETCATTY_ARCHIVE_RESULT:OK\n").unwrap(),
            ArchiveCreateOutcome::Created
        );
        assert_eq!(
            parse_create_archive_result("NETCATTY_ARCHIVE_RESULT:EEXIST\r\n").unwrap(),
            ArchiveCreateOutcome::AlreadyExists
        );
        assert!(parse_create_archive_result("").is_err());
        assert!(parse_create_archive_result("NETCATTY_ARCHIVE_RESULT:OK\nlater").is_err());
    }

    /// Run the generated script with the local `sh`, the same way the remote
    /// shell would, and read its marker.
    #[cfg(unix)]
    fn run_script(opts: &SftpArchiveCreateOptions) -> (Option<i32>, String, String) {
        let v = validate_archive_create_options(opts).unwrap();
        let cmd = build_create_archive_command(&v, SftpFilenameEncoding::Utf8).unwrap();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    #[cfg(unix)]
    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netcatty-archive-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("logs")).unwrap();
        std::fs::write(dir.join("logs/app.log"), b"hello").unwrap();
        std::fs::write(dir.join("it's here.txt"), b"quoted").unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn script_creates_refuses_to_replace_and_overwrites_with_local_tar() {
        let dir = scratch_dir("tar");
        let base = SftpArchiveCreateOptions {
            directory: dir.to_string_lossy().into_owned(),
            paths: vec!["logs".into(), "it's here.txt".into()],
            archive_name: "out.tar.gz".into(),
            format: SftpArchiveFormat::TarGz,
            overwrite: None,
        };

        let (code, stdout, stderr) = run_script(&base);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert_eq!(
            parse_create_archive_result(&stdout).unwrap(),
            ArchiveCreateOutcome::Created
        );
        let listing = std::process::Command::new("tar")
            .arg("-tzf")
            .arg(dir.join("out.tar.gz"))
            .output()
            .unwrap();
        let listing = String::from_utf8_lossy(&listing.stdout);
        assert!(listing.contains("./logs/app.log"), "{listing}");
        assert!(listing.contains("./it's here.txt"), "{listing}");

        // The name is taken now: reported, file left alone.
        let before = std::fs::metadata(dir.join("out.tar.gz")).unwrap().len();
        let (code, stdout, _) = run_script(&base);
        assert_eq!(code, Some(0));
        assert_eq!(
            parse_create_archive_result(&stdout).unwrap(),
            ArchiveCreateOutcome::AlreadyExists
        );
        assert_eq!(
            std::fs::metadata(dir.join("out.tar.gz")).unwrap().len(),
            before
        );

        // overwrite replaces it.
        let (code, stdout, stderr) = run_script(&SftpArchiveCreateOptions {
            paths: vec!["logs".into()],
            overwrite: Some(true),
            ..base.clone()
        });
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert_eq!(
            parse_create_archive_result(&stdout).unwrap(),
            ArchiveCreateOutcome::Created
        );

        // No staging directory is left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".netcatty-archive.")
            })
            .collect();
        assert!(leftovers.is_empty());

        // A missing source fails the script without publishing anything.
        let (code, _, stderr) = run_script(&SftpArchiveCreateOptions {
            paths: vec!["gone".into()],
            archive_name: "other.tar.gz".into(),
            ..base.clone()
        });
        assert_ne!(code, Some(0));
        assert!(stderr.contains("no longer exists"), "{stderr}");
        assert!(!dir.join("other.tar.gz").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn script_refuses_a_directory_or_symlink_as_the_target() {
        let dir = scratch_dir("target");
        std::fs::create_dir(dir.join("taken.tar.gz")).unwrap();
        let (code, _, stderr) = run_script(&SftpArchiveCreateOptions {
            directory: dir.to_string_lossy().into_owned(),
            paths: vec!["logs".into()],
            archive_name: "taken.tar.gz".into(),
            format: SftpArchiveFormat::TarGz,
            overwrite: Some(true),
        });
        assert_ne!(code, Some(0));
        assert!(stderr.contains("must be a regular file"), "{stderr}");
        assert!(dir.join("taken.tar.gz").is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

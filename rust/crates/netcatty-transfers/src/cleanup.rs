//! `cleanupTransferArtifacts` rules (Electron `transferBridge.cjs`).
//!
//! The renderer calls this on dismiss / clear / fresh-id retry of a task.
//! Only Netcatty's own artifacts are removed:
//!
//! * the local temp stage `<temp>/.transfer_<id>_<name>.part` for the target
//!   and source basenames (computed by the caller);
//! * the transfer engine's `.<name>.netcatty-part` stage next to the target;
//! * a directory-replace stage, but only when its path is exactly the
//!   renderer's `<targetPath>.netcatty-<sanitized id>.part` name (so a
//!   tampered payload can never turn this into an arbitrary recursive
//!   delete).

/// The renderer's directory-replace stage name for `transfer_id`
/// (`useSftpTransfers.ts`: `${targetPath}.netcatty-${id.replace(/[^A-Za-z0-9_-]/g, "_")}.part`).
pub fn expected_replace_stage(target_path: &str, transfer_id: &str) -> String {
    let safe: String = transfer_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{target_path}.netcatty-{safe}.part")
}

/// May `staged_target_path` be removed recursively for this task?
pub fn replace_stage_is_owned(
    staged_target_path: &str,
    target_path: &str,
    transfer_id: &str,
) -> bool {
    !target_path.is_empty()
        && !transfer_id.is_empty()
        && staged_target_path == expected_replace_stage(target_path, transfer_id)
}

/// File name used for temp stages (`path.basename` with `transfer` default).
pub fn stage_file_name(path: &str) -> String {
    let trimmed = path.trim_end_matches(['/', '\\']);
    let name = trimmed.rsplit(['/', '\\']).next().unwrap_or("");
    if name.is_empty() {
        "transfer".to_string()
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_renderer_stage_name_is_owned() {
        assert_eq!(
            expected_replace_stage("/srv/site", "task:1/x"),
            "/srv/site.netcatty-task_1_x.part"
        );
        assert!(replace_stage_is_owned(
            "/srv/site.netcatty-t1.part",
            "/srv/site",
            "t1"
        ));
        assert!(!replace_stage_is_owned("/srv/site", "/srv/site", "t1"));
        assert!(!replace_stage_is_owned("/", "/srv/site", "t1"));
        assert!(!replace_stage_is_owned(
            "/srv/site.netcatty-t2.part",
            "/srv/site",
            "t1"
        ));
        assert!(!replace_stage_is_owned("x.netcatty-t1.part", "", "t1"));
    }

    #[test]
    fn stage_file_names_are_basenames() {
        assert_eq!(stage_file_name("/a/b/c.txt"), "c.txt");
        assert_eq!(stage_file_name("C:\\a\\d.bin"), "d.bin");
        assert_eq!(stage_file_name("/a/dir/"), "dir");
        assert_eq!(stage_file_name(""), "transfer");
    }
}

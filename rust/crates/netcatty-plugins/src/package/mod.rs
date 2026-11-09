//! Package format: portable paths, manifest validation, `.ncpkg` archives,
//! compatibility and runtime placement policy.

pub mod archive;
pub mod brand_icon;
pub mod compat;
pub mod manifest;
pub mod path;
pub mod semver_util;

/// `PACKAGE_LIMITS` of `@netcatty/plugin-cli`.
pub mod limits {
    pub const ARCHIVE_BYTES: usize = 100 * 1024 * 1024;
    pub const UNCOMPRESSED_BYTES: usize = 250 * 1024 * 1024;
    pub const SINGLE_FILE_BYTES: usize = 50 * 1024 * 1024;
    pub const MANIFEST_BYTES: usize = 1024 * 1024;
    pub const FILE_COUNT: usize = 5_000;
    pub const PATH_CHARACTERS: usize = 128;
    pub const PATH_BYTES: usize = 512;
}

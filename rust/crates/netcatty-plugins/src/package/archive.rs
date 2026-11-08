//! `.ncpkg` archives (port of `packages/plugin-cli/src/archive.ts`).
//!
//! A strict ZIP reader validates every entry (UTF-8 names, no data
//! descriptors, local/central header agreement, stored or deflate only, CRC,
//! size limits, portable unique paths, regular files) before extraction.
//! Integrity uses the representation-independent logical content digest
//! (`netcatty-plugin-content-v1`), so a retained snapshot and the installed
//! tree compare equal regardless of ZIP encoder choices.

use super::brand_icon::{inspect_brand_icon, PLUGIN_BRAND_ICON_MAX_BYTES};
use super::limits;
use super::manifest::{companion_variants, package_icon_paths, parse_and_validate_manifest, referenced_paths};
use super::path::{assert_safe_package_path, PackagePathRegistry};
use crate::error::{PluginError, PluginResult};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const EXECUTABLE_EXTENSIONS: &[&str] = &[".bat", ".cmd", ".com", ".exe", ".ps1"];
pub const IGNORED_ROOT_ENTRIES: &[&str] = &[".DS_Store", ".git", "node_modules"];
pub const MANIFEST_FILE: &str = "netcatty.plugin.json";

/// Result of validating a package archive or an installed directory.
#[derive(Debug, Clone)]
pub struct PackageValidation {
    pub manifest: Value,
    pub file_count: usize,
    pub uncompressed_bytes: u64,
    pub content_sha256: String,
}

#[derive(Debug, Clone)]
pub struct ContentEntry {
    pub package_path: String,
    pub size: u64,
    pub sha256: String,
    pub executable: bool,
}

fn host(message: impl Into<String>) -> PluginError {
    PluginError::host(message)
}

/// `computePackageContentSha256`.
pub fn compute_content_sha256(entries: &[ContentEntry]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"netcatty-plugin-content-v1\0");
    let mut ordered: Vec<&ContentEntry> = entries.iter().collect();
    ordered.sort_by(|a, b| a.package_path.as_bytes().cmp(b.package_path.as_bytes()));
    for entry in ordered {
        let path = entry.package_path.as_bytes();
        hasher.update((path.len() as u32).to_be_bytes());
        hasher.update(entry.size.to_be_bytes());
        hasher.update([u8::from(entry.executable)]);
        hasher.update(path);
        hasher.update(hex::decode(&entry.sha256).unwrap_or_default());
    }
    hex::encode(hasher.finalize())
}

fn extension_lower(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rfind('.') {
        Some(0) | None => String::new(),
        Some(index) => name[index..].to_ascii_lowercase(),
    }
}

fn is_executable_package_file(path: &str, mode: u32) -> bool {
    mode & 0o111 != 0 || EXECUTABLE_EXTENSIONS.contains(&extension_lower(path).as_str())
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[derive(Debug, Clone)]
struct CentralEntry {
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    name_raw: Vec<u8>,
    external_attributes: u32,
    local_offset: u32,
}

fn parse_central_directory(data: &[u8]) -> PluginResult<Vec<CentralEntry>> {
    if data.len() < 22 {
        return Err(host("Plugin archive is not a ZIP file"));
    }
    let search_start = data.len().saturating_sub(22 + 65_535);
    let mut eocd = None;
    let mut index = data.len() - 22;
    loop {
        if le32(data, index) == 0x0605_4b50 && index + 22 + le16(data, index + 20) as usize == data.len() {
            eocd = Some(index);
            break;
        }
        if index == search_start {
            break;
        }
        index -= 1;
    }
    let eocd = eocd.ok_or_else(|| host("Plugin archive end of central directory was not found"))?;
    if le16(data, eocd + 4) != 0 || le16(data, eocd + 6) != 0 {
        return Err(host("Multi-disk ZIP archives are not supported"));
    }
    let count = le16(data, eocd + 10) as usize;
    if count != le16(data, eocd + 8) as usize {
        return Err(host("Invalid ZIP entry count"));
    }
    let cd_size = le32(data, eocd + 12) as usize;
    let cd_offset = le32(data, eocd + 16) as usize;
    if count == 0xffff || cd_size == 0xffff_ffff || cd_offset == 0xffff_ffff {
        return Err(host("ZIP64 plugin archives are not supported"));
    }
    if cd_offset.checked_add(cd_size).is_none_or(|end| end > eocd) {
        return Err(host("Invalid ZIP central directory bounds"));
    }
    let mut entries = Vec::with_capacity(count);
    let mut offset = cd_offset;
    for _ in 0..count {
        if offset + 46 > cd_offset + cd_size || le32(data, offset) != 0x0201_4b50 {
            return Err(host("Invalid ZIP central directory entry"));
        }
        let name_len = le16(data, offset + 28) as usize;
        let extra_len = le16(data, offset + 30) as usize;
        let comment_len = le16(data, offset + 32) as usize;
        let end = offset + 46 + name_len + extra_len + comment_len;
        if end > cd_offset + cd_size {
            return Err(host("Invalid ZIP central directory entry"));
        }
        let entry = CentralEntry {
            flags: le16(data, offset + 8),
            method: le16(data, offset + 10),
            crc32: le32(data, offset + 16),
            compressed_size: le32(data, offset + 20),
            uncompressed_size: le32(data, offset + 24),
            name_raw: data[offset + 46..offset + 46 + name_len].to_vec(),
            external_attributes: le32(data, offset + 38),
            local_offset: le32(data, offset + 42),
        };
        if entry.compressed_size == 0xffff_ffff || entry.uncompressed_size == 0xffff_ffff || entry.local_offset == 0xffff_ffff {
            return Err(host("ZIP64 plugin archives are not supported"));
        }
        entries.push(entry);
        offset = end;
    }
    Ok(entries)
}

/// Validate the local header against the central entry; returns the offset
/// of the entry data.
fn validate_local_header(data: &[u8], entry: &CentralEntry, package_path: &str) -> PluginResult<usize> {
    if entry.flags & 0x0800 == 0 {
        return Err(host(format!("ZIP entry name must use UTF-8 encoding: {package_path}")));
    }
    if entry.flags & 0x0008 != 0 {
        return Err(host(format!("ZIP data descriptors are not allowed: {package_path}")));
    }
    let offset = entry.local_offset as usize;
    if offset + 30 > data.len() || le32(data, offset) != 0x0403_4b50 {
        return Err(host(format!("Unable to read local ZIP header: {package_path}")));
    }
    let name_len = le16(data, offset + 26) as usize;
    let extra_len = le16(data, offset + 28) as usize;
    if offset + 30 + name_len + extra_len > data.len() {
        return Err(host(format!("Unable to read local ZIP header: {package_path}")));
    }
    if data[offset + 30..offset + 30 + name_len] != entry.name_raw[..] {
        return Err(host(format!("ZIP local and central entry names differ: {package_path}")));
    }
    if le16(data, offset + 6) != entry.flags {
        return Err(host(format!("ZIP local and central entry flags differ: {package_path}")));
    }
    if le16(data, offset + 8) != entry.method {
        return Err(host(format!("ZIP local and central compression methods differ: {package_path}")));
    }
    if le32(data, offset + 14) != entry.crc32
        || le32(data, offset + 18) != entry.compressed_size
        || le32(data, offset + 22) != entry.uncompressed_size
    {
        return Err(host(format!("ZIP local and central integrity metadata differ: {package_path}")));
    }
    let start = offset + 30 + name_len + extra_len;
    if start + entry.compressed_size as usize > data.len() {
        return Err(host(format!("ZIP entry data exceeds the archive: {package_path}")));
    }
    Ok(start)
}

struct ReadEntry {
    bytes: Vec<u8>,
    crc32: u32,
    sha256: String,
}

fn read_entry(data: &[u8], start: usize, entry: &CentralEntry, package_path: &str) -> PluginResult<ReadEntry> {
    let raw = &data[start..start + entry.compressed_size as usize];
    let limit = limits::SINGLE_FILE_BYTES as u64;
    let bytes = if entry.method == 0 {
        if raw.len() as u64 > limit {
            return Err(host(format!("Plugin file exceeds size limit: {package_path}")));
        }
        raw.to_vec()
    } else {
        let mut out = Vec::new();
        let mut decoder = flate2::read::DeflateDecoder::new(raw).take(limit + 1);
        decoder
            .read_to_end(&mut out)
            .map_err(|e| host(format!("Unable to read archive entry: {package_path}: {e}")))?;
        if out.len() as u64 > limit {
            return Err(host(format!("Plugin file exceeds size limit: {package_path}")));
        }
        out
    };
    let crc32 = crc32fast::hash(&bytes);
    let sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(ReadEntry { bytes, crc32, sha256 })
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> PluginResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> PluginResult<()> {
    Ok(())
}

#[cfg(unix)]
fn create_dir_private(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
}
#[cfg(not(unix))]
fn create_dir_private(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

pub(crate) fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    create_dir_private(path)
}

fn create_new_private_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn inspect_package(archive_path: &Path, extraction: Option<&Path>) -> PluginResult<PackageValidation> {
    let meta = fs::metadata(archive_path)?;
    if meta.len() > limits::ARCHIVE_BYTES as u64 {
        return Err(host(format!("Plugin archive exceeds {} bytes", limits::ARCHIVE_BYTES)));
    }
    let data = fs::read(archive_path)?;
    let central = parse_central_directory(&data)?;
    let mut registry = PackagePathRegistry::default();
    struct Record {
        mode: u32,
        sha256: String,
        size: u64,
        contents: Option<Vec<u8>>,
    }
    let mut entries: BTreeMap<String, Record> = BTreeMap::new();
    let mut total = 0u64;
    for entry in &central {
        let name = String::from_utf8(entry.name_raw.clone())
            .map_err(|_| host("ZIP central entry name is not canonical UTF-8"))?;
        if name.contains('\\') {
            return Err(host(format!("invalid characters in fileName: {name}")));
        }
        let package_path = registry.add(&name)?;
        if entries.len() + 1 > limits::FILE_COUNT {
            return Err(host(format!("Plugin package exceeds {} files", limits::FILE_COUNT)));
        }
        if entry.flags & 1 != 0 {
            return Err(host(format!("Encrypted ZIP entries are not allowed: {package_path}")));
        }
        if entry.method != 0 && entry.method != 8 {
            return Err(host(format!("Unsupported ZIP compression method: {package_path}")));
        }
        let start = validate_local_header(&data, entry, &package_path)?;
        let mode = (entry.external_attributes >> 16) & 0xffff;
        let file_type = mode & 0o170000;
        if file_type != 0 && file_type != 0o100000 {
            return Err(host(format!("Only regular files are allowed: {package_path}")));
        }
        if entry.uncompressed_size as usize > limits::SINGLE_FILE_BYTES {
            return Err(host(format!("Plugin file exceeds size limit: {package_path}")));
        }
        if package_path == MANIFEST_FILE && entry.uncompressed_size as usize > limits::MANIFEST_BYTES {
            return Err(host(format!("Plugin manifest exceeds {} bytes", limits::MANIFEST_BYTES)));
        }
        total += entry.uncompressed_size as u64;
        if total > limits::UNCOMPRESSED_BYTES as u64 {
            return Err(host("Plugin package exceeds the uncompressed size limit"));
        }
        let read = read_entry(&data, start, entry, &package_path)?;
        if read.bytes.len() as u64 != entry.uncompressed_size as u64 || read.crc32 != entry.crc32 {
            return Err(host(format!("ZIP entry integrity check failed: {package_path}")));
        }
        if let Some(root) = extraction {
            let target = package_path.split('/').fold(root.to_path_buf(), |p, s| p.join(s));
            if let Some(parent) = target.parent() {
                create_dir_private(parent)?;
            }
            let mut file = create_new_private_file(&target)?;
            file.write_all(&read.bytes)?;
            file.sync_all()?;
        }
        let keep = package_path == MANIFEST_FILE || read.bytes.len() <= PLUGIN_BRAND_ICON_MAX_BYTES;
        entries.insert(
            package_path,
            Record {
                mode,
                sha256: read.sha256,
                size: read.bytes.len() as u64,
                contents: keep.then_some(read.bytes),
            },
        );
    }
    let manifest_record = entries
        .get(MANIFEST_FILE)
        .and_then(|r| r.contents.as_ref())
        .ok_or_else(|| host("Plugin package is missing netcatty.plugin.json"))?;
    let manifest = parse_and_validate_manifest(manifest_record)?;
    let declared: HashMap<String, String> = companion_variants(&manifest).into_iter().collect();
    for (path, record) in &entries {
        if is_executable_package_file(path, record.mode) && !declared.contains_key(path) {
            return Err(host(format!("Executable file is not declared as a companion: {path}")));
        }
    }
    for required in referenced_paths(&manifest) {
        if !entries.contains_key(&required) {
            return Err(host(format!("Manifest references a missing package file: {required}")));
        }
    }
    for icon in package_icon_paths(manifest.get("icon")) {
        let record = entries
            .get(&icon)
            .filter(|r| r.size as usize <= PLUGIN_BRAND_ICON_MAX_BYTES)
            .ok_or_else(|| host("Brand icon is missing or exceeds size limit"))?;
        inspect_brand_icon(record.contents.as_deref().unwrap_or_default(), &icon)?;
    }
    for (path, sha) in &declared {
        let record = entries
            .get(path)
            .ok_or_else(|| host(format!("Manifest references a missing companion: {path}")))?;
        if &record.sha256 != sha {
            return Err(host(format!("Companion SHA-256 mismatch: {path}")));
        }
    }
    if let Some(root) = extraction {
        for path in entries.keys() {
            let target = path.split('/').fold(root.to_path_buf(), |p, s| p.join(s));
            set_mode(&target, if declared.contains_key(path) { 0o700 } else { 0o600 })?;
        }
    }
    let content: Vec<ContentEntry> = entries
        .iter()
        .map(|(path, record)| ContentEntry {
            package_path: path.clone(),
            size: record.size,
            sha256: record.sha256.clone(),
            executable: declared.contains_key(path),
        })
        .collect();
    Ok(PackageValidation {
        manifest,
        file_count: entries.len(),
        uncompressed_bytes: total,
        content_sha256: compute_content_sha256(&content),
    })
}

/// `validatePluginPackage`.
pub fn validate_package(archive_path: &Path) -> PluginResult<PackageValidation> {
    inspect_package(archive_path, None)
}

/// `extractPluginPackage`: validates while extracting into a new directory;
/// a failed extraction removes the destination.
pub fn extract_package(archive_path: &Path, destination: &Path) -> PluginResult<PackageValidation> {
    fs::create_dir(destination)?;
    set_mode(destination, 0o700)?;
    match inspect_package(archive_path, Some(destination)) {
        Ok(result) => Ok(result),
        Err(err) => {
            let _ = fs::remove_dir_all(destination);
            Err(err)
        }
    }
}

struct ScannedFile {
    absolute: PathBuf,
    package_path: String,
    size: u64,
    crc32: u32,
    sha256: String,
    executable: bool,
}

fn file_mode(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0o100644
    }
}

/// Read the manifest of a directory (`readValidatedManifestSource`).
fn read_manifest_source(dir: &Path) -> PluginResult<(Value, u64, String)> {
    let path = dir.join(MANIFEST_FILE);
    let meta = fs::symlink_metadata(&path)?;
    if !meta.is_file() {
        return Err(host("Plugin manifest must be a regular file"));
    }
    if meta.len() > limits::MANIFEST_BYTES as u64 {
        return Err(host(format!("Plugin manifest exceeds {} bytes", limits::MANIFEST_BYTES)));
    }
    let mut contents = Vec::new();
    File::open(&path)?
        .take(limits::MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut contents)?;
    if contents.len() > limits::MANIFEST_BYTES {
        return Err(host(format!("Plugin manifest exceeds {} bytes", limits::MANIFEST_BYTES)));
    }
    let manifest = parse_and_validate_manifest(&contents)?;
    Ok((manifest, contents.len() as u64, hex::encode(Sha256::digest(&contents))))
}

fn scan_directory(dir: &Path, allow_ignored_root_entries: bool) -> PluginResult<(Value, Vec<ScannedFile>)> {
    let (manifest, manifest_size, manifest_sha) = read_manifest_source(dir)?;
    let companions: HashMap<String, String> = companion_variants(&manifest).into_iter().collect();
    let mut registry = PackagePathRegistry::default();
    let mut files = Vec::new();
    let mut total = 0u64;
    let mut stack = vec![(dir.to_path_buf(), String::new())];
    while let Some((directory, relative)) = stack.pop() {
        let mut names: Vec<std::ffi::OsString> = fs::read_dir(&directory)?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<Result<_, _>>()?;
        names.sort_by(|a, b| a.as_encoded_bytes().cmp(b.as_encoded_bytes()));
        let mut subdirs = Vec::new();
        for name in names {
            let name = name
                .into_string()
                .map_err(|_| host("Plugin package path is not valid UTF-8"))?;
            if relative.is_empty() && (IGNORED_ROOT_ENTRIES.contains(&name.as_str()) || name.ends_with(".ncpkg")) {
                if !allow_ignored_root_entries {
                    return Err(host(format!("Installed plugin contains an unpackaged root entry: {name}")));
                }
                continue;
            }
            let rel = if relative.is_empty() { name.clone() } else { format!("{relative}/{name}") };
            let package_path = assert_safe_package_path(&rel)?;
            let absolute = directory.join(&name);
            let meta = fs::symlink_metadata(&absolute)?;
            if meta.file_type().is_symlink() {
                return Err(host(format!("Symbolic links are not allowed in plugin packages: {package_path}")));
            }
            if meta.is_dir() {
                subdirs.push((absolute, package_path));
                continue;
            }
            if !meta.is_file() {
                return Err(host(format!("Only regular files are allowed in plugin packages: {package_path}")));
            }
            registry.add(&package_path)?;
            if files.len() + 1 > limits::FILE_COUNT {
                return Err(host(format!("Plugin package exceeds {} files", limits::FILE_COUNT)));
            }
            if meta.len() > limits::SINGLE_FILE_BYTES as u64 {
                return Err(host(format!("Plugin file exceeds {} bytes: {package_path}", limits::SINGLE_FILE_BYTES)));
            }
            total += meta.len();
            if total > limits::UNCOMPRESSED_BYTES as u64 {
                return Err(host(format!("Plugin package exceeds {} uncompressed bytes", limits::UNCOMPRESSED_BYTES)));
            }
            let bytes = fs::read(&absolute)?;
            if bytes.len() as u64 != meta.len() {
                return Err(host(format!("Package source changed while it was being scanned: {package_path}")));
            }
            let sha256 = hex::encode(Sha256::digest(&bytes));
            let executable = is_executable_package_file(&package_path, file_mode(&meta));
            let companion = companions.get(&package_path);
            if executable && companion.is_none() {
                return Err(host(format!("Executable file is not declared as a companion: {package_path}")));
            }
            if let Some(expected) = companion {
                if expected != &sha256 {
                    return Err(host(format!("Companion SHA-256 mismatch: {package_path}")));
                }
            }
            files.push(ScannedFile {
                absolute,
                package_path,
                size: meta.len(),
                crc32: crc32fast::hash(&bytes),
                sha256,
                executable: companion.is_some(),
            });
        }
        // Depth-first in sorted order: push in reverse.
        for sub in subdirs.into_iter().rev() {
            stack.push(sub);
        }
    }
    let manifest_file = files.iter().find(|f| f.package_path == MANIFEST_FILE);
    if !manifest_file.is_some_and(|f| f.size == manifest_size && f.sha256 == manifest_sha) {
        return Err(host("Plugin manifest changed after validation"));
    }
    let present: std::collections::HashSet<&str> = files.iter().map(|f| f.package_path.as_str()).collect();
    let mut required = vec![MANIFEST_FILE.to_string()];
    required.extend(referenced_paths(&manifest));
    required.extend(companions.keys().cloned());
    for path in required {
        if !present.contains(path.as_str()) {
            return Err(host(format!("Manifest references a missing package file: {path}")));
        }
    }
    for icon in package_icon_paths(manifest.get("icon")) {
        let file = files.iter().find(|f| f.package_path == icon).expect("checked above");
        if file.size as usize > PLUGIN_BRAND_ICON_MAX_BYTES {
            return Err(host("Plugin brand icon exceeds size limit"));
        }
        let bytes = fs::read(&file.absolute)?;
        if hex::encode(Sha256::digest(&bytes)) != file.sha256 {
            return Err(host("Brand icon changed during packaging"));
        }
        inspect_brand_icon(&bytes, &icon)?;
    }
    files.sort_by(|a, b| a.package_path.as_bytes().cmp(b.package_path.as_bytes()));
    Ok((manifest, files))
}

/// `validatePluginDirectory`.
pub fn validate_directory(dir: &Path, allow_ignored_root_entries: bool) -> PluginResult<PackageValidation> {
    let (manifest, files) = scan_directory(dir, allow_ignored_root_entries)?;
    let content: Vec<ContentEntry> = files
        .iter()
        .map(|f| ContentEntry {
            package_path: f.package_path.clone(),
            size: f.size,
            sha256: f.sha256.clone(),
            executable: f.executable,
        })
        .collect();
    Ok(PackageValidation {
        manifest,
        file_count: files.len(),
        uncompressed_bytes: files.iter().map(|f| f.size).sum(),
        content_sha256: compute_content_sha256(&content),
    })
}

/// `buildPluginPackage`: deterministic stored ZIP of a plugin directory.
/// Returns the archive SHA-256.
pub fn build_package(dir: &Path, output: &Path) -> PluginResult<String> {
    if output.extension().and_then(|e| e.to_str()) != Some("ncpkg") {
        return Err(host("Plugin package output must use the .ncpkg extension"));
    }
    let canonical_dir = fs::canonicalize(dir)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
        if fs::canonicalize(parent)?.starts_with(&canonical_dir) {
            return Err(host("Plugin package output must be outside the plugin source directory"));
        }
    }
    let (_, files) = scan_directory(dir, true)?;
    let mut archive = Vec::new();
    let mut central = Vec::new();
    for file in &files {
        let name = file.package_path.as_bytes();
        let offset = archive.len() as u32;
        let size = file.size as u32;
        // Local header.
        archive.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        archive.extend_from_slice(&20u16.to_le_bytes());
        archive.extend_from_slice(&0x0800u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&33u16.to_le_bytes());
        archive.extend_from_slice(&file.crc32.to_le_bytes());
        archive.extend_from_slice(&size.to_le_bytes());
        archive.extend_from_slice(&size.to_le_bytes());
        archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(name);
        let bytes = fs::read(&file.absolute)?;
        if hex::encode(Sha256::digest(&bytes)) != file.sha256 {
            return Err(host(format!("Package source changed while it was being written: {}", file.package_path)));
        }
        archive.extend_from_slice(&bytes);
        // Central header.
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&0x0314u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0x0800u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&33u16.to_le_bytes());
        central.extend_from_slice(&file.crc32.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0u8; 8]);
        let mode: u32 = if file.executable { 0o100755 } else { 0o100644 };
        central.extend_from_slice(&(mode << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let cd_offset = archive.len() as u32;
    let cd_size = central.len() as u32;
    archive.extend_from_slice(&central);
    archive.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    archive.extend_from_slice(&[0u8; 4]);
    archive.extend_from_slice(&(files.len() as u16).to_le_bytes());
    archive.extend_from_slice(&(files.len() as u16).to_le_bytes());
    archive.extend_from_slice(&cd_size.to_le_bytes());
    archive.extend_from_slice(&cd_offset.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    if archive.len() > limits::ARCHIVE_BYTES {
        return Err(host(format!("Plugin archive exceeds {} bytes", limits::ARCHIVE_BYTES)));
    }
    let tmp = output.with_extension(format!("ncpkg.tmp-{}", uuid::Uuid::new_v4()));
    fs::write(&tmp, &archive)?;
    fs::rename(&tmp, output)?;
    Ok(hex::encode(Sha256::digest(&archive)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples/plugins").join(name)
    }

    /// The Rust builder produces the same bytes as `netcatty-plugin pack`
    /// (when a JS-built archive is supplied) and validates the examples.
    #[test]
    fn example_packages_round_trip() {
        for (name, env) in [("hello-netcatty", "NETCATTY_TEST_HELLO_NCPKG"), ("starter-netcatty", "NETCATTY_TEST_STARTER_NCPKG")] {
            let dir = example(name);
            if !dir.join("dist").exists() {
                eprintln!("skipping {name}: run `npm run build:plugin-packages` first");
                continue;
            }
            let out = tempfile::tempdir().unwrap();
            let archive = out.path().join(format!("{name}.ncpkg"));
            let sha = build_package(&dir, &archive).unwrap();
            let validation = validate_package(&archive).unwrap();
            let directory = validate_directory(&dir, true).unwrap();
            assert_eq!(validation.content_sha256, directory.content_sha256);
            if let Ok(js) = std::env::var(env) {
                let js_validation = validate_package(Path::new(&js)).unwrap();
                assert_eq!(js_validation.content_sha256, validation.content_sha256);
                assert_eq!(hex::encode(Sha256::digest(fs::read(&js).unwrap())), sha);
            }
        }
    }
}

//! Clipboard files and images (Electron: `clipboardFiles.cjs`), used for
//! pasting copied files into SFTP and images into terminal TUIs.
//!
//! Text goes through `tauri-plugin-clipboard-manager`; files and images use
//! `arboard` directly (the plugin exposes neither file lists nor PNG export).

use crate::state::Ctx;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClipboardFile {
    pub path: String,
    pub name: String,
    pub is_directory: bool,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClipboardImage {
    path: String,
    name: String,
    media_type: &'static str,
    size: u64,
}

/// Existing regular files / directories, de-duplicated, in order.
pub fn collect_existing_files(paths: impl IntoIterator<Item = PathBuf>) -> Vec<ClipboardFile> {
    let mut seen = std::collections::HashSet::new();
    paths
        .into_iter()
        .filter(|p| !p.as_os_str().is_empty() && seen.insert(p.clone()))
        .filter_map(|path| {
            let meta = std::fs::metadata(&path).ok()?;
            if !meta.is_dir() && !meta.is_file() {
                return None;
            }
            Some(ClipboardFile {
                name: path.file_name()?.to_string_lossy().into_owned(),
                path: path.to_string_lossy().into_owned(),
                is_directory: meta.is_dir(),
                size: if meta.is_dir() { 0 } else { meta.len() },
            })
        })
        .collect()
}

/// `file://` lines of a `text/uri-list` style text (comments skipped).
pub fn parse_file_uri_lines(text: &str) -> Vec<PathBuf> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && line.starts_with("file://"))
        .filter_map(|line| url::Url::parse(line).ok()?.to_file_path().ok())
        .collect()
}

/// `netcatty-paste-YYYYMMDD-HHMMSS-mmm.png` (Electron naming).
fn image_file_name() -> String {
    format!(
        "netcatty-paste-{}.png",
        chrono::Local::now().format("%Y%m%d-%H%M%S-%3f")
    )
}

fn encode_png(width: usize, height: usize, rgba: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width as u32, height as u32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().ok()?;
        writer.write_image_data(rgba).ok()?;
    }
    Some(out)
}

fn read_files() -> Vec<ClipboardFile> {
    let Ok(mut clipboard) = arboard::Clipboard::new() else {
        return Vec::new();
    };
    if let Ok(files) = clipboard.get().file_list() {
        let files = collect_existing_files(files);
        if !files.is_empty() {
            return files;
        }
    }
    // Some file managers only publish a `text/uri-list` as text.
    clipboard
        .get_text()
        .map(|text| collect_existing_files(parse_file_uri_lines(&text)))
        .unwrap_or_default()
}

fn write_image(temp_dir: &Path) -> Option<ClipboardImage> {
    let image = arboard::Clipboard::new().ok()?.get_image().ok()?;
    if image.width == 0 || image.height == 0 {
        return None;
    }
    let png = encode_png(image.width, image.height, &image.bytes)?;
    std::fs::create_dir_all(temp_dir).ok()?;
    let name = image_file_name();
    let path = temp_dir.join(&name);
    std::fs::write(&path, &png).ok()?;
    Some(ClipboardImage {
        path: path.to_string_lossy().into_owned(),
        name,
        media_type: "image/png",
        size: png.len() as u64,
    })
}

#[tauri::command]
pub async fn clipboard_read_files() -> Vec<ClipboardFile> {
    tauri::async_runtime::spawn_blocking(read_files)
        .await
        .unwrap_or_default()
}

/// Save the clipboard image as a PNG in the temp dir; `null` when there is none.
#[tauri::command]
pub async fn clipboard_read_image<R: tauri::Runtime>(
    state: Ctx<'_, R>,
) -> super::CmdResult<Option<ClipboardImage>> {
    let temp_dir = super::tempdir::current(&state.app);
    Ok(
        tauri::async_runtime::spawn_blocking(move || write_image(&temp_dir))
            .await
            .ok()
            .flatten(),
    )
}

#[tauri::command]
pub async fn clipboard_has_image() -> bool {
    tauri::async_runtime::spawn_blocking(|| {
        arboard::Clipboard::new()
            .and_then(|mut c| c.get_image())
            .map(|image| image.width > 0 && image.height > 0)
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_existing_files_once() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, "hello").unwrap();
        let files = collect_existing_files(vec![
            file.clone(),
            file.clone(),
            dir.path().to_path_buf(),
            dir.path().join("missing"),
            PathBuf::new(),
        ]);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name, "a.txt");
        assert_eq!(files[0].size, 5);
        assert!(!files[0].is_directory);
        assert!(files[1].is_directory);
        assert_eq!(files[1].size, 0);
    }

    #[test]
    fn parses_uri_lists() {
        let dir = tempfile::tempdir().unwrap();
        let url = url::Url::from_file_path(dir.path().join("x y.txt")).unwrap();
        let text = format!("# comment\r\n{url}\r\nnot-a-uri\n");
        assert_eq!(
            parse_file_uri_lines(&text),
            vec![dir.path().join("x y.txt")]
        );
    }

    #[test]
    fn encodes_png_and_names_like_electron() {
        let png = encode_png(1, 1, &[255, 0, 0, 255]).unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        let name = image_file_name();
        assert!(name.starts_with("netcatty-paste-") && name.ends_with(".png"));
        assert_eq!(name.len(), "netcatty-paste-20260101-120000-000.png".len());
    }
}

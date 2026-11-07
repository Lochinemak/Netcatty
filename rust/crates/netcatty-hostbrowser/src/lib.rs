//! Host browser support crate (Electron: `electron/hostBrowser/*Store.cjs`,
//! `downloadFile.cjs` and the pure parts of `hostBrowserManager.cjs`).
//!
//! Everything here is independent of the webview runtime so it can be unit
//! tested: the three JSON stores (bookmarks, downloads, website icons), the
//! address / page-scheme policy, the PDF-to-download header policy, theme
//! token validation and the download file reservation. The Tauri side
//! (`apps/netcatty-desktop/src/commands/hostbrowser.rs`) owns the webviews.

pub mod bookmarks;
pub mod downloads;
mod fs;
pub mod icons;
pub mod pdf;
pub mod theme;
pub mod url;

pub use bookmarks::{normalize_bookmark, Bookmark, BookmarkStore, MAX_BOOKMARKS};
pub use downloads::{
    reserve_download_file, Download, DownloadListed, DownloadStatus, DownloadStore, ReservedFile,
    MAX_DOWNLOADS,
};
pub use icons::{
    image_mime, valid_image_data_url, IconMode, SiteIcon, SiteIconInput, SiteIconStore,
    MAX_ICONS, MAX_ICON_BYTES,
};
pub use pdf::pdf_download_headers;
pub use theme::{valid_theme_tokens, THEME_TOKEN_NAMES};
pub use url::{icon_origin, is_allowed_page_url, normalize_browser_url, ALLOWED_PAGE_SCHEMES};

/// Maximum number of tabs per browser (Electron `MAX_TABS`).
pub const MAX_TABS: usize = 32;
/// Height of the tab strip + navigation bar of the standalone browser window.
pub const CHROME_HEIGHT: f64 = 80.0;
/// Width of the downloads panel of the standalone browser window.
pub const DOWNLOAD_PANEL_WIDTH: f64 = 372.0;
/// Default icon colour used by every store.
pub const DEFAULT_ICON_COLOR: &str = "#247969";

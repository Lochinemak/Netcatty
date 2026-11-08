"use strict";

// Tauri replacement for electron/hostBrowser/{browser,downloads}Preload.cjs:
// exposes the same `window.hostBrowser` / `window.hostBrowserDownloads`
// objects on top of the `hostbrowser_*` commands and events
// (rust/docs/ipc-hostbrowser.md). Loaded before browser.js / downloads.js.
(function () {
  const tauri = window.__TAURI__;
  const internals = window.__TAURI_INTERNALS__;
  const label = internals && internals.metadata && internals.metadata.currentWindow
    ? internals.metadata.currentWindow.label : "";

  const invoke = (command, args) => tauri.core.invoke(command, args || {}).catch((error) => {
    throw new Error(error && typeof error.message === "string" ? error.message : String(error));
  });

  // Chrome events arrive as { labels, payload }; keep ours. Global events
  // (bookmarks-changed) carry no labels.
  const on = (event, callback) => {
    let unlisten = null;
    let disposed = false;
    tauri.event.listen(event, ({ payload }) => {
      if (payload && Array.isArray(payload.labels)) {
        if (!payload.labels.includes(label)) return;
        callback(payload.payload);
      } else callback(payload);
    }).then((fn) => { if (disposed) fn(); else unlisten = fn; }).catch(() => {});
    return () => { disposed = true; if (unlisten) unlisten(); };
  };

  if (label.startsWith("host-browser-dl-")) {
    window.hostBrowserDownloads = Object.freeze({
      list: () => invoke("hostbrowser_downloads_list"),
      theme: () => invoke("hostbrowser_downloads_theme"),
      command: (type, id) => invoke("hostbrowser_downloads_command", { command: { type, id } }),
      onChanged: (callback) => on("netcatty:host-browser:downloads-changed", callback),
      onTheme: (callback) => on("netcatty:host-browser:theme", callback),
    });
    return;
  }

  window.hostBrowser = Object.freeze({
    snapshot: () => invoke("hostbrowser_snapshot"),
    command: (command) => invoke("hostbrowser_command", { command }),
    listBookmarks: () => invoke("hostbrowser_bookmarks_list"),
    saveBookmark: (bookmark) => invoke("hostbrowser_bookmarks_upsert", { bookmark }),
    removeBookmark: (id) => invoke("hostbrowser_bookmarks_remove", { id }),
    listDownloads: () => invoke("hostbrowser_downloads_list"),
    onDownloadsChanged: (callback) => on("netcatty:host-browser:downloads-changed", callback),
    onBookmarksChanged: (callback) => on("netcatty:host-browser:bookmarks-changed", () => callback()),
    onSiteIconsChanged: (callback) => on("netcatty:host-browser:site-icons-changed", () => callback()),
    onShortcut: (callback) => on("netcatty:host-browser:shortcut", callback),
    onState: (callback) => on("netcatty:host-browser:state", callback),
  });

  // `-webkit-app-region: drag` is an Electron feature: drag the frameless
  // window from the tab strip's empty space ourselves.
  document.addEventListener("mousedown", (event) => {
    if (event.button !== 0 || event.detail > 1) return;
    const target = event.target;
    if (!target || !target.closest || !target.closest("#window-drag-region")) return;
    if (target.closest("button, input, .tab, .tabs")) return;
    invoke("hostbrowser_command", { command: { type: "window-drag" } }).catch(() => {});
  });
})();

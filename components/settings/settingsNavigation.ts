/** Top-level settings tabs another window may open the settings window on. */
const NAVIGABLE_SETTINGS_TABS = new Set([
  "application",
  "plugins",
  "appearance",
  "terminal",
  "shortcuts",
  "file-associations",
  "ai",
  "sync",
  "system",
]);

export function normalizeSettingsTab(tab: unknown): string | null {
  return typeof tab === "string" && NAVIGABLE_SETTINGS_TABS.has(tab) ? tab : null;
}

/** `#/settings?tab=sync` → `sync` (set by Rust when the window is created). */
export function settingsTabFromHash(hash: string): string | null {
  const query = hash.indexOf("?");
  if (query < 0) return null;
  return normalizeSettingsTab(new URLSearchParams(hash.slice(query + 1)).get("tab"));
}

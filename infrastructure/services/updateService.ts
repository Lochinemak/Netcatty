/**
 * Update Service
 *
 * Combines two update mechanisms:
 * 1. GitHub API-based version comparison (used by useUpdateCheck for notification banner)
 * 2. electron-updater bridge (used by SettingsSystemTab for download/install)
 */

import { netcattyBridge } from "./netcattyBridge";

// ================================
// Part 1: GitHub API Version Check
// ================================

// Fork: check the fork's own releases. `releases/latest` ignores pre-releases,
// and fork builds are tagged `vX.Y.Z-<suffix>.N` (pre-release), so list the
// most recent releases and take the first published, non-draft one instead.
const GITHUB_API_URL = 'https://api.github.com/repos/Lochinemak/Netcatty/releases?per_page=5';
const RELEASES_PAGE_URL = 'https://github.com/Lochinemak/Netcatty/releases';

export interface ReleaseInfo {
  version: string;       // e.g. "1.0.0" (without 'v' prefix)
  tagName: string;       // e.g. "v1.0.0"
  name: string;          // Release title
  body: string;          // Release notes (markdown)
  htmlUrl: string;       // URL to the release page
  publishedAt: string;   // ISO date string
  assets: ReleaseAsset[];
}

export interface ReleaseAsset {
  name: string;
  browserDownloadUrl: string;
  size: number;
}

export interface UpdateCheckResult {
  hasUpdate: boolean;
  currentVersion: string;
  latestRelease: ReleaseInfo | null;
  error?: string;
}

interface ParsedVersion {
  numbers: number[];
  prerelease: string[];
}

/**
 * Parse version string into numeric parts and prerelease identifiers
 * e.g. "1.2.3" -> { numbers: [1, 2, 3], prerelease: [] }
 *      "1.2.3-loch.2" -> { numbers: [1, 2, 3], prerelease: ["loch", "2"] }
 */
function parseVersion(version: string): ParsedVersion {
  // Remove 'v' prefix and any build metadata (+sha) if present
  const clean = version.replace(/^v/i, '').split('+')[0];
  const dash = clean.indexOf('-');
  const core = dash === -1 ? clean : clean.slice(0, dash);
  const prerelease = dash === -1 ? [] : clean.slice(dash + 1).split('.').filter(Boolean);
  const numbers = core.split('.').map((part) => {
    const num = parseInt(part, 10);
    return isNaN(num) ? 0 : num;
  });
  return { numbers, prerelease };
}

/**
 * Compare prerelease identifier lists per semver: a version without a
 * prerelease is newer than one with; numeric identifiers compare as numbers
 * and sort before alphanumeric ones; a longer list wins when all shared
 * identifiers are equal.
 */
function comparePrerelease(a: string[], b: string[]): number {
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;

  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const idA = a[i];
    const idB = b[i];
    if (idA === idB) continue;
    const numA = /^\d+$/.test(idA) ? Number(idA) : null;
    const numB = /^\d+$/.test(idB) ? Number(idB) : null;
    if (numA !== null && numB !== null) return numA > numB ? 1 : -1;
    if (numA !== null) return -1;
    if (numB !== null) return 1;
    return idA > idB ? 1 : -1;
  }
  if (a.length === b.length) return 0;
  return a.length > b.length ? 1 : -1;
}

/**
 * Compare two version strings (semver-aware, including prerelease suffixes)
 * Returns: 1 if a > b, -1 if a < b, 0 if equal
 */
export function compareVersions(a: string, b: string): number {
  const parsedA = parseVersion(a);
  const parsedB = parseVersion(b);
  const maxLen = Math.max(parsedA.numbers.length, parsedB.numbers.length);

  for (let i = 0; i < maxLen; i++) {
    const numA = parsedA.numbers[i] ?? 0;
    const numB = parsedB.numbers[i] ?? 0;
    if (numA > numB) return 1;
    if (numA < numB) return -1;
  }
  return comparePrerelease(parsedA.prerelease, parsedB.prerelease);
}

/**
 * Check for updates via GitHub API (compares version strings).
 * Used by useUpdateCheck for the notification banner.
 */
export async function checkForUpdates(currentVersion: string): Promise<UpdateCheckResult> {
  try {
    const response = await fetch(GITHUB_API_URL, {
      headers: { Accept: 'application/vnd.github.v3+json' },
    });

    if (!response.ok) {
      throw new Error(`GitHub API returned ${response.status}`);
    }

    const releases = await response.json();
    const data = Array.isArray(releases)
      ? releases.find((r: { draft?: boolean; tag_name?: string }) => !r.draft && r.tag_name)
      : releases;
    if (!data) {
      throw new Error('No published releases found');
    }
    const latestVersion = (data.tag_name as string).replace(/^v/i, '');

    const latestRelease: ReleaseInfo = {
      version: latestVersion,
      tagName: data.tag_name,
      name: data.name || data.tag_name,
      body: data.body || '',
      htmlUrl: data.html_url,
      publishedAt: data.published_at,
      assets: (data.assets || []).map((a: { name: string; browser_download_url: string; size: number }) => ({
        name: a.name,
        browserDownloadUrl: a.browser_download_url,
        size: a.size,
      })),
    };

    const hasUpdate = compareVersions(latestVersion, currentVersion) > 0;

    return { hasUpdate, currentVersion, latestRelease };
  } catch (error) {
    return {
      hasUpdate: false,
      currentVersion,
      latestRelease: null,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Get release page URL for a specific version
 */
export function getReleaseUrl(version?: string): string {
  if (version) {
    return `${RELEASES_PAGE_URL}/tag/v${version.replace(/^v/i, '')}`;
  }
  return RELEASES_PAGE_URL;
}

/**
 * Get download URL for current platform
 */
export function getDownloadUrlForPlatform(
  release: ReleaseInfo,
  platform: string
): string | null {
  const assets = release.assets;

  // Platform-specific file patterns
  const patterns: Record<string, RegExp[]> = {
    win32: [/\.exe$/i, /win.*\.zip$/i, /windows/i],
    darwin: [/\.dmg$/i, /mac.*\.zip$/i, /darwin/i],
    linux: [/\.AppImage$/i, /\.deb$/i, /linux/i],
  };

  const platformPatterns = patterns[platform] || [];

  for (const pattern of platformPatterns) {
    const asset = assets.find((a) => pattern.test(a.name));
    if (asset) {
      return asset.browserDownloadUrl;
    }
  }

  // Fallback to release page
  return null;
}

// =============================================
// Part 2: electron-updater Bridge (IPC-based)
// =============================================

export interface ElectronUpdateCheckResult {
  available: boolean;
  supported?: boolean;
  version?: string;
  releaseNotes?: string;
  releaseDate?: string | null;
  error?: string;
}

export interface UpdateDownloadProgress {
  percent: number;
  bytesPerSecond: number;
  transferred: number;
  total: number;
}

export async function checkForUpdate(): Promise<ElectronUpdateCheckResult> {
  const bridge = netcattyBridge.get();
  if (!bridge?.checkForUpdate) {
    return { available: false, supported: false, error: "Bridge unavailable" };
  }
  try {
    return await bridge.checkForUpdate();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return { available: false, error: message };
  }
}

export async function downloadUpdate(): Promise<{ success: boolean; error?: string }> {
  const bridge = netcattyBridge.get();
  if (!bridge?.downloadUpdate) {
    return { success: false, error: "Bridge unavailable" };
  }
  return bridge.downloadUpdate();
}

export function installUpdate(): void {
  const bridge = netcattyBridge.get();
  bridge?.installUpdate?.();
}

export function onDownloadProgress(
  cb: (progress: UpdateDownloadProgress) => void,
): (() => void) | undefined {
  return netcattyBridge.get()?.onUpdateDownloadProgress?.(cb);
}

export function onDownloaded(cb: () => void): (() => void) | undefined {
  return netcattyBridge.get()?.onUpdateDownloaded?.(cb);
}

export function onError(
  cb: (payload: { error: string }) => void,
): (() => void) | undefined {
  return netcattyBridge.get()?.onUpdateError?.(cb);
}

/** Returns the GitHub Releases page URL, optionally for a specific version tag. */
export function getReleasesUrl(version?: string): string {
  if (version) {
    return `${RELEASES_PAGE_URL}/tag/v${version}`;
  }
  return `${RELEASES_PAGE_URL}/latest`;
}

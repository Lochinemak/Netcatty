import { createTauriBridge } from './createTauriBridge';
import { isTauri } from './tauriApi';

/**
 * Installs the Tauri-backed `window.netcatty` bridge when the page runs inside
 * a Tauri webview and nothing else (the Electron preload) has provided one.
 *
 * Returns `true` when the bridge was installed by this call. No extra platform
 * flags are published: the renderer derives OS information from `navigator`.
 */
export function installTauriBridge(): boolean {
  if (typeof window === 'undefined' || !isTauri()) return false;
  // This module *provides* window.netcatty (the Tauri counterpart of the
  // Electron preload), so it is the one legitimate direct access.
  // eslint-disable-next-line no-restricted-properties
  if (window.netcatty) return false;
  // eslint-disable-next-line no-restricted-properties
  window.netcatty = createTauriBridge();
  return true;
}

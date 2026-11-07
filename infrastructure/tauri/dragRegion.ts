/**
 * Title-bar drag regions for frameless Tauri windows.
 *
 * The renderer marks its custom title bars with `.app-drag` / `.app-no-drag`
 * (`-webkit-app-region` in `index.css`), which only Electron honours. This
 * reproduces it on top of Tauri's window commands, the same way Tauri's own
 * `data-tauri-drag-region` script does:
 *  - primary-button press inside a drag region → native window drag;
 *  - double click → toggle maximize (`internal_toggle_maximize` follows the
 *    macOS "double-click a window's title bar" preference).
 * The innermost `.app-drag` / `.app-no-drag` ancestor decides, like
 * `app-region`; interactive controls never start a drag.
 */

import { invoke, isTauri } from './tauriApi';

const REGION_SELECTOR = '.app-drag, .app-no-drag';
const INTERACTIVE_SELECTOR = [
  'button',
  'a[href]',
  'input',
  'select',
  'textarea',
  'summary',
  '[role="button"]',
  '[role="tab"]',
  '[role="menuitem"]',
  '[contenteditable]:not([contenteditable="false"])',
].join(', ');

/** Whether a press on `target` should drag the window. */
export function isDragRegionTarget(target: EventTarget | null): boolean {
  if (typeof Element === 'undefined' || !(target instanceof Element)) return false;
  const region = target.closest(REGION_SELECTOR);
  if (!region || !region.classList.contains('app-drag')) return false;
  const interactive = target.closest(INTERACTIVE_SELECTOR);
  return !interactive || !region.contains(interactive);
}

let installed = false;

export function installDragRegions(): void {
  if (installed || typeof document === 'undefined' || !isTauri()) return;
  installed = true;
  document.addEventListener('mousedown', (event) => {
    if (event.button !== 0 || !isDragRegionTarget(event.target)) return;
    event.preventDefault();
    const command = event.detail === 2 ? 'plugin:window|internal_toggle_maximize' : 'plugin:window|start_dragging';
    invoke<void>(command).catch((error: unknown) => {
      console.warn('[tauri-bridge] window drag failed', error);
    });
  });
}

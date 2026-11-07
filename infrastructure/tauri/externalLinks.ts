/**
 * External links for Tauri windows.
 *
 * Electron routed `window.open(...)` and `<a target="_blank">` to the system
 * browser through `setWindowOpenHandler`. A Tauri webview silently drops both,
 * so buttons such as "Open GitHub" did nothing. This sends web / mail URLs to
 * the opener plugin instead; anything else keeps the webview's behaviour.
 */

import { isTauri } from './tauriApi';
import { pluginOpener } from './plugins';

const EXTERNAL_PROTOCOLS = new Set(['http:', 'https:', 'mailto:']);

/** The absolute URL to hand to the system, or `null` to leave it alone. */
export function externalUrl(raw: string | URL | undefined | null, base?: string): string | null {
  if (raw === undefined || raw === null) return null;
  const text = String(raw).trim();
  if (!text) return null;
  let parsed: URL;
  try {
    parsed = base ? new URL(text, base) : new URL(text);
  } catch {
    return null;
  }
  if (!EXTERNAL_PROTOCOLS.has(parsed.protocol)) return null;
  // Same-origin pages (the app's own routes) are not external.
  // (`mailto:` and custom schemes have an opaque "null" origin.)
  if (base && parsed.origin !== 'null') {
    try {
      if (parsed.origin === new URL(base).origin) return null;
    } catch {
      // Unparseable base: treat the URL as external.
    }
  }
  return parsed.toString();
}

function openExternally(url: string, open: (url: string) => Promise<void>): void {
  open(url).catch((err: unknown) => {
    console.warn('[netcatty] failed to open external URL', url, err);
  });
}

let installed = false;

export function installExternalLinks(
  open: (url: string) => Promise<void> = (url) => pluginOpener.openUrl(url),
): void {
  if (installed || typeof window === 'undefined' || !isTauri()) return;
  installed = true;

  const nativeOpen = window.open.bind(window);
  window.open = ((url?: string | URL, target?: string, features?: string) => {
    const external = externalUrl(url, window.location.href);
    if (external) {
      openExternally(external, open);
      return null;
    }
    return nativeOpen(url, target, features);
  }) as typeof window.open;

  document.addEventListener(
    'click',
    (event) => {
      if (event.defaultPrevented || event.button !== 0) return;
      const target = event.target;
      if (!(target instanceof Element)) return;
      const anchor = target.closest('a[href]');
      if (!(anchor instanceof HTMLAnchorElement)) return;
      const external = externalUrl(anchor.getAttribute('href'), window.location.href);
      if (!external) return;
      event.preventDefault();
      openExternally(external, open);
    },
    // Bubble phase: React (delegated at its root, inside `document`) handles
    // the click first and may already have prevented it.
    false,
  );
}

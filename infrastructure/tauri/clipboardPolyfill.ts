/**
 * Routes `navigator.clipboard.writeText/readText` through the Tauri
 * clipboard-manager plugin.
 *
 * The renderer (xterm copy-on-select, context menus, "copy path" actions)
 * uses the Web Clipboard API directly. Inside WKWebView that API is either
 * missing or rejects with `NotAllowedError` outside a trusted user gesture,
 * so copying from the terminal silently did nothing. The plugin talks to the
 * system pasteboard without those restrictions. The plugin is reached via
 * `invoke("plugin:clipboard-manager|…")` (see plugins.ts).
 */
import { pluginClipboard } from './plugins';
import { isTauri } from './tauriApi';

let installed = false;

export function installClipboardPolyfill(): boolean {
  if (installed || typeof window === 'undefined' || !isTauri()) return false;
  installed = true;

  const writeText = (text: string): Promise<void> => pluginClipboard.writeText(String(text ?? ''));
  const readText = (): Promise<string> => pluginClipboard.readText();

  const existing = navigator.clipboard as Clipboard | undefined;
  if (existing) {
    // Patch the instance (and the prototype, which is what xterm reaches
    // through `navigator.clipboard`) so every caller gets the plugin.
    const proto = Object.getPrototypeOf(existing) as Record<string, unknown> | null;
    for (const target of [existing as unknown as Record<string, unknown>, proto]) {
      if (!target) continue;
      try {
        Object.defineProperty(target, 'writeText', { value: writeText, configurable: true, writable: true });
        Object.defineProperty(target, 'readText', { value: readText, configurable: true, writable: true });
      } catch {
        // Non-configurable in this engine: fall through to replacing the getter.
      }
    }
    if (existing.writeText === writeText) return true;
  }

  try {
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText, readText },
      configurable: true,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Direct bindings to the Tauri plugins the bridge needs.
 *
 * The plugins' own JS globals (`window.__TAURI__.clipboardManager`, `.dialog`,
 * `.opener`) are not injected in this app (their init scripts run before the
 * core global exists and bail out), so every call goes through
 * `core.invoke("plugin:<name>|<command>")` with the same argument shapes the
 * official JS packages use. Permissions live in
 * `rust/apps/netcatty-desktop/capabilities/default.json`.
 */
import { invoke } from './tauriApi';

export interface DialogFilter {
  name: string;
  extensions: string[];
}

export interface OpenDialogOptions {
  title?: string;
  defaultPath?: string;
  directory?: boolean;
  multiple?: boolean;
  filters?: DialogFilter[];
}

export interface SaveDialogOptions {
  title?: string;
  defaultPath?: string;
  filters?: DialogFilter[];
}

export const pluginClipboard = {
  writeText: (text: string, label?: string): Promise<void> =>
    invoke<void>('plugin:clipboard-manager|write_text', { text, label }),
  readText: (): Promise<string> => invoke<string>('plugin:clipboard-manager|read_text'),
};

export const pluginDialog = {
  open: (options: OpenDialogOptions): Promise<string | string[] | null> =>
    invoke<string | string[] | null>('plugin:dialog|open', { options }),
  save: (options: SaveDialogOptions): Promise<string | null> =>
    invoke<string | null>('plugin:dialog|save', { options }),
};

export const pluginOpener = {
  openUrl: (url: string, openWith?: string): Promise<void> =>
    invoke<void>('plugin:opener|open_url', { url, with: openWith }),
  openPath: (path: string, openWith?: string): Promise<void> =>
    invoke<void>('plugin:opener|open_path', { path, with: openWith }),
  revealItemInDir: (path: string): Promise<void> =>
    invoke<void>('plugin:opener|reveal_item_in_dir', { paths: [path] }),
};

/**
 * Minimal, hand-written surface of the global Tauri 2 API that the renderer
 * adapter (`infrastructure/tauri/`) relies on. Tauri injects `window.__TAURI__`
 * because `app.withGlobalTauri` is enabled in `rust/apps/netcatty-desktop/
 * tauri.conf.json`; we deliberately avoid the `@tauri-apps/api` npm packages so
 * the Electron build stays dependency-free.
 *
 * Everything is optional: the Electron renderer never has these globals, and a
 * plugin that is not registered on the Rust side leaves its namespace absent.
 */
declare global {
  interface NetcattyTauriInvokeOptions {
    /** Request headers for raw-body (`ArrayBuffer`) commands. */
    headers?: Record<string, string>;
  }

  /** `invoke` accepts a JSON object or a raw binary body. */
  type NetcattyTauriInvokeArgs = Record<string, unknown> | ArrayBuffer | Uint8Array | number[];

  interface NetcattyTauriEvent<T> {
    event: string;
    id: number;
    payload: T;
  }

  interface NetcattyTauriDialogFilter {
    name: string;
    extensions: string[];
  }

  interface NetcattyTauriOpenDialogOptions {
    title?: string;
    defaultPath?: string;
    directory?: boolean;
    multiple?: boolean;
    filters?: NetcattyTauriDialogFilter[];
  }

  interface NetcattyTauriSaveDialogOptions {
    title?: string;
    defaultPath?: string;
    filters?: NetcattyTauriDialogFilter[];
  }

  interface NetcattyTauriGlobal {
    core?: {
      invoke?<T>(
        cmd: string,
        args?: NetcattyTauriInvokeArgs,
        options?: NetcattyTauriInvokeOptions,
      ): Promise<T>;
    };
    event?: {
      listen?<T>(
        event: string,
        handler: (event: NetcattyTauriEvent<T>) => void,
      ): Promise<() => void>;
    };
    dialog?: {
      open?(options?: NetcattyTauriOpenDialogOptions): Promise<string | string[] | null>;
      save?(options?: NetcattyTauriSaveDialogOptions): Promise<string | null>;
    };
    clipboardManager?: {
      readText?(): Promise<string>;
      writeText?(text: string): Promise<void>;
    };
    opener?: {
      openUrl?(url: string, openWith?: string): Promise<void>;
      openPath?(path: string, openWith?: string): Promise<void>;
      revealItemInDir?(path: string): Promise<void>;
    };
  }

  interface Window {
    __TAURI__?: NetcattyTauriGlobal;
    /** Present whenever the page runs inside a Tauri webview. */
    __TAURI_INTERNALS__?: unknown;
  }
}

export {};

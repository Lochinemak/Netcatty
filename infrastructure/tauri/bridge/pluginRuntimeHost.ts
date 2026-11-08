/**
 * Renderer relay for browser plugin runtimes (Tauri host).
 *
 * Electron runs each browser plugin in a hidden sandboxed BrowserWindow and
 * hands it a MessagePort. Under Tauri the plugin document lives in a hidden
 * `<iframe sandbox="allow-scripts">` (opaque origin: no Tauri IPC, no
 * storage, no access to this document) served by the Rust
 * `netcatty-plugin` scheme. This relay only moves JSON-RPC messages:
 *
 *   iframe port  ──(ordered batches)──▶ `plugin_runtime_messages`  (Rust router)
 *   Rust Channel ──────────────────────▶ iframe port
 *
 * Stream chunks transferred as ArrayBuffers travel as `transferBase64`.
 * All capability checks run in Rust; nothing here interprets messages.
 */

import { createChannel as tauriCreateChannel, invoke as tauriInvoke } from '../tauriApi';

export const PLUGIN_RUNTIME_EVENTS = {
  launch: 'netcatty:plugins:runtime-launch',
  stop: 'netcatty:plugins:runtime-stop',
} as const;

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

export interface PluginRuntimeHostDeps {
  subscribe: <T>(event: string, cb: (payload: T) => void) => () => void;
  invoke?: Invoke;
  createChannel?: <T>(onMessage: (message: T) => void) => NetcattyTauriChannel<T>;
  document?: Document;
  window?: Window;
}

interface RuntimeEntry {
  iframe: HTMLIFrameElement;
  port: MessagePort | null;
  queue: unknown[];
  flushing: boolean;
  closed: boolean;
  onWindowMessage: (event: MessageEvent) => void;
}

export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function fromBase64(text: string): Uint8Array {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Port → Rust: replace an ArrayBuffer stream transfer by base64. */
export function encodeRuntimeMessage(message: unknown): unknown {
  if (message && typeof message === 'object' && 'frame' in message && 'transfer' in message) {
    const { transfer, ...rest } = message as { transfer: unknown };
    if (transfer instanceof ArrayBuffer) {
      return { ...rest, transferBase64: toBase64(new Uint8Array(transfer)) };
    }
  }
  return message;
}

export function createPluginRuntimeHost(deps: PluginRuntimeHostDeps): { dispose: () => void } {
  const invoke = deps.invoke ?? tauriInvoke;
  const createChannel = deps.createChannel ?? tauriCreateChannel;
  const doc = deps.document ?? (typeof document === 'undefined' ? undefined : document);
  const win = deps.window ?? (typeof window === 'undefined' ? undefined : window);
  const runtimes = new Map<string, RuntimeEntry>();

  const flush = async (runtimeId: string, entry: RuntimeEntry) => {
    if (entry.flushing) return;
    entry.flushing = true;
    try {
      while (entry.queue.length > 0 && !entry.closed) {
        const messages = entry.queue.splice(0, entry.queue.length);
        await invoke('plugin_runtime_messages', { runtimeId, messages });
      }
    } catch {
      close(runtimeId, 'Plugin runtime relay failed', true);
    } finally {
      entry.flushing = false;
    }
  };

  const close = (runtimeId: string, reason: string, notify: boolean) => {
    const entry = runtimes.get(runtimeId);
    if (!entry) return;
    runtimes.delete(runtimeId);
    entry.closed = true;
    entry.port?.close();
    win?.removeEventListener('message', entry.onWindowMessage);
    entry.iframe.remove();
    if (notify) void invoke('plugin_runtime_exited', { runtimeId, reason }).catch(() => undefined);
  };

  const launch = ({ runtimeId, url }: { runtimeId: string; url: string }) => {
    if (!doc || !win || runtimes.has(runtimeId)) return;
    const iframe = doc.createElement('iframe');
    iframe.setAttribute('sandbox', 'allow-scripts');
    iframe.setAttribute('aria-hidden', 'true');
    iframe.setAttribute('tabindex', '-1');
    iframe.style.cssText = 'position:fixed;width:0;height:0;border:0;visibility:hidden;pointer-events:none;';
    const entry: RuntimeEntry = {
      iframe,
      port: null,
      queue: [],
      flushing: false,
      closed: false,
      onWindowMessage: () => undefined,
    };
    entry.onWindowMessage = (event: MessageEvent) => {
      if (event.source !== iframe.contentWindow) return;
      const type = (event.data as { type?: unknown } | null)?.type;
      if (type === 'netcatty-plugin:preload-ready' && !entry.port) {
        const channel = new MessageChannel();
        entry.port = channel.port1;
        channel.port1.onmessage = (message) => {
          entry.queue.push(encodeRuntimeMessage(message.data));
          void flush(runtimeId, entry);
        };
        iframe.contentWindow?.postMessage({ type: 'netcatty-plugin:port' }, '*', [channel.port2]);
      } else if (type === 'netcatty-plugin:runtime-connected' && entry.port) {
        const port = entry.port;
        const outbound = createChannel<Record<string, unknown>>((message) => {
          if (entry.closed) return;
          if (message && typeof message.transferBase64 === 'string') {
            const { transferBase64, ...rest } = message;
            const bytes = fromBase64(transferBase64 as string);
            port.postMessage({ ...rest, transfer: bytes.buffer }, [bytes.buffer]);
          } else {
            port.postMessage(message);
          }
        });
        void invoke<boolean>('plugin_runtime_attach', { runtimeId, channel: outbound })
          .then((attached) => { if (!attached) close(runtimeId, 'Plugin runtime was not registered', false); })
          .catch(() => close(runtimeId, 'Plugin runtime attach failed', true));
      }
    };
    win.addEventListener('message', entry.onWindowMessage);
    runtimes.set(runtimeId, entry);
    iframe.src = url;
    doc.body.appendChild(iframe);
  };

  const unsubscribeLaunch = deps.subscribe(PLUGIN_RUNTIME_EVENTS.launch, launch);
  const unsubscribeStop = deps.subscribe<{ runtimeId: string }>(PLUGIN_RUNTIME_EVENTS.stop, ({ runtimeId }) => {
    close(runtimeId, 'Plugin runtime stopped', false);
  });
  // A reloaded renderer lost every iframe of the previous document.
  void invoke('plugin_runtime_reset').catch(() => undefined);

  return {
    dispose: () => {
      unsubscribeLaunch();
      unsubscribeStop();
      for (const runtimeId of Array.from(runtimes.keys())) close(runtimeId, 'Plugin renderer closed', true);
    },
  };
}

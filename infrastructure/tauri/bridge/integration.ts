/**
 * OS shell integration part of the Tauri `NetcattyBridge` adapter
 * (Electron: `deepLink.cjs`, `openTerminalPath.cjs`, `explorerContextMenu.cjs`,
 * `appIconManager.cjs` and the launch-intent queues in `main.cjs`; Rust:
 * `commands/integration.rs`, `rust/docs/ipc-integration.md`).
 *
 * Launch intents (ssh / telnet / jms deep links, PuTTY / SecureCRT command
 * lines, open-terminal-at-path requests) only ever reach the main window.
 * Tauri drops events nobody listens to, so the main window's adapter:
 *
 * 1. on the first `on*` subscription, listens to the four intent channels;
 * 2. then calls `integration_renderer_attach`, which returns the intents
 *    queued before the renderer existed and settles cold start
 *    (`onColdStartIntentsSettled`); later intents arrive as live events;
 * 3. buffers an intent until a callback for its channel subscribes, so
 *    React effect order (and StrictMode re-subscription) cannot lose one.
 */
import { EventHub, currentWindowLabel, invoke as invokeCommand } from '../tauriApi';

export const INTEGRATION_EVENTS = {
  sshDeepLink: 'netcatty:deepLink:ssh',
  telnetDeepLink: 'netcatty:deepLink:telnet',
  jmsDeepLink: 'netcatty:deepLink:jms',
  openTerminalPath: 'netcatty:openTerminalPath',
} as const;

type IntentChannel = (typeof INTEGRATION_EVENTS)[keyof typeof INTEGRATION_EVENTS];

const INTENT_CHANNELS: readonly IntentChannel[] = Object.values(INTEGRATION_EVENTS);

type IntegrationBridgeKeys =
  | 'onSshDeepLink'
  | 'onTelnetDeepLink'
  | 'onJmsDeepLink'
  | 'onOpenTerminalPath'
  | 'onColdStartIntentsSettled'
  | 'getSshDeepLinkEnabled'
  | 'setSshDeepLinkEnabled'
  | 'getJmsDeepLinkEnabled'
  | 'setJmsDeepLinkEnabled'
  | 'getExplorerContextMenuEnabled'
  | 'setExplorerContextMenuEnabled'
  | 'setAppIconVariant';

export type IntegrationBridge = Required<Pick<NetcattyBridge, IntegrationBridgeKeys>>;

type Result<K extends IntegrationBridgeKeys> = Awaited<ReturnType<IntegrationBridge[K]>>;

export interface IntegrationBridgeDeps {
  hub: EventHub;
  /** Injected for tests; defaults to the Tauri `invoke` wrapper. */
  invoke?: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
  /** Injected for tests; defaults to the label Tauri reports. */
  windowLabel?: () => string;
  /** Where failures are reported; defaults to `console.warn`. */
  warn?: (label: string, error: unknown) => void;
  /** Deferral for buffered deliveries; defaults to `queueMicrotask`. */
  defer?: (task: () => void) => void;
}

interface AttachResult {
  intents?: Array<{ channel?: string; payload?: unknown }>;
  coldStartSettled?: boolean;
}

const MAIN_WINDOW_LABEL = 'main';

const isIntentChannel = (value: unknown): value is IntentChannel =>
  typeof value === 'string' && (INTENT_CHANNELS as readonly string[]).includes(value);

export function createIntegrationBridge(deps: IntegrationBridgeDeps): IntegrationBridge {
  const { hub } = deps;
  const invoke = deps.invoke ?? invokeCommand;
  const windowLabel = deps.windowLabel ?? currentWindowLabel;
  const warn = deps.warn ?? ((label, error) => console.warn(`[tauri] ${label} failed`, error));
  const defer = deps.defer ?? ((task) => queueMicrotask(task));

  const listeners = new Map<IntentChannel, Set<(payload: unknown) => void>>(
    INTENT_CHANNELS.map((channel) => [channel, new Set()]),
  );
  const buffered = new Map<IntentChannel, unknown[]>(INTENT_CHANNELS.map((channel) => [channel, []]));
  const settledListeners = new Set<() => void>();
  let settled = false;
  let started = false;

  const deliver = (channel: IntentChannel, payload: unknown): void => {
    const current = listeners.get(channel)!;
    if (current.size === 0) {
      buffered.get(channel)!.push(payload);
      return;
    }
    for (const cb of Array.from(current)) {
      try {
        cb(payload);
      } catch (error) {
        warn(`${channel} listener`, error);
      }
    }
  };

  const settle = (): void => {
    if (settled) return;
    settled = true;
    for (const cb of Array.from(settledListeners)) {
      try {
        cb();
      } catch (error) {
        warn('coldStartIntentsSettled listener', error);
      }
    }
    settledListeners.clear();
  };

  const start = (): void => {
    if (started) return;
    started = true;
    for (const channel of INTENT_CHANNELS) {
      hub.subscribe<unknown>(channel, (payload) => deliver(channel, payload));
    }
    void Promise.all(INTENT_CHANNELS.map((channel) => hub.ensure(channel)))
      .then(() => invoke<AttachResult>('integration_renderer_attach'))
      .then((result) => {
        for (const intent of result?.intents ?? []) {
          if (isIntentChannel(intent?.channel)) deliver(intent.channel, intent.payload);
        }
      })
      .catch((error: unknown) => warn('integration_renderer_attach', error))
      // Never leave cold start pending: the startup terminal waits for it.
      .finally(settle);
  };

  const isMainWindow = (): boolean => windowLabel() === MAIN_WINDOW_LABEL;

  const subscribeIntent = <T>(channel: IntentChannel, cb: (payload: T) => void): (() => void) => {
    if (!isMainWindow()) return () => {};
    const listener = cb as (payload: unknown) => void;
    listeners.get(channel)!.add(listener);
    const pending = buffered.get(channel)!.splice(0);
    if (pending.length > 0) {
      defer(() => {
        for (const payload of pending) {
          try {
            listener(payload);
          } catch (error) {
            warn(`${channel} listener`, error);
          }
        }
      });
    }
    start();
    return () => {
      listeners.get(channel)!.delete(listener);
    };
  };

  return {
    onSshDeepLink: (cb) => subscribeIntent(INTEGRATION_EVENTS.sshDeepLink, cb),
    onTelnetDeepLink: (cb) => subscribeIntent(INTEGRATION_EVENTS.telnetDeepLink, cb),
    onJmsDeepLink: (cb) => subscribeIntent(INTEGRATION_EVENTS.jmsDeepLink, cb),
    onOpenTerminalPath: (cb) => subscribeIntent(INTEGRATION_EVENTS.openTerminalPath, cb),
    onColdStartIntentsSettled: (cb) => {
      // Only the main window has launch intents; elsewhere cold start is
      // trivially settled.
      if (!isMainWindow() || settled) {
        defer(cb);
        return () => {};
      }
      settledListeners.add(cb);
      start();
      return () => {
        settledListeners.delete(cb);
      };
    },
    getSshDeepLinkEnabled: () => invoke<Result<'getSshDeepLinkEnabled'>>('integration_get_ssh_deep_link_enabled'),
    setSshDeepLinkEnabled: (enabled) =>
      invoke<Result<'setSshDeepLinkEnabled'>>('integration_set_ssh_deep_link_enabled', { enabled: enabled !== false }),
    getJmsDeepLinkEnabled: () => invoke<Result<'getJmsDeepLinkEnabled'>>('integration_get_jms_deep_link_enabled'),
    setJmsDeepLinkEnabled: (enabled) =>
      invoke<Result<'setJmsDeepLinkEnabled'>>('integration_set_jms_deep_link_enabled', { enabled: enabled !== false }),
    getExplorerContextMenuEnabled: () =>
      invoke<Result<'getExplorerContextMenuEnabled'>>('integration_get_explorer_context_menu_enabled'),
    setExplorerContextMenuEnabled: (enabled) =>
      invoke<Result<'setExplorerContextMenuEnabled'>>('integration_set_explorer_context_menu_enabled', {
        enabled: enabled !== false,
      }),
    setAppIconVariant: (variant) =>
      invoke<Result<'setAppIconVariant'>>('integration_set_app_icon_variant', { variant }),
  };
}

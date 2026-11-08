/**
 * Plugin bridge methods (`global.d.ts` `NetcattyBridge` plugin surface) on
 * top of the Rust plugin host (`rust/docs/ipc-plugins.md`).
 *
 * Every Electron `netcatty:plugins:<method>` IPC call maps onto one command,
 * `plugin_call { method, payload }`, with the Electron payload unchanged.
 * Binary fields cross the IPC boundary as base64 (`*Base64` keys) and are
 * converted back to `Uint8Array` here, so renderer code sees the Electron
 * shapes. Events keep the Electron channel names.
 */

import type { EventHub } from '../tauriApi';
import { currentWindowLabel, invoke as tauriInvoke } from '../tauriApi';
import { createPluginRuntimeHost, fromBase64, toBase64 } from './pluginRuntimeHost';

export const PLUGIN_EVENTS = {
  catalogChanged: 'netcatty:plugins:catalog-changed',
  agentHostRequest: 'netcatty:plugins:agent-host-request',
  aiHostRequest: 'netcatty:plugins:ai-host-request',
  interaction: 'netcatty:plugins:host-interaction',
  permissionPrompt: 'netcatty:plugins:permission-prompt',
  themesChanged: 'netcatty:plugins:themes-changed',
  importerProgress: 'netcatty:plugins:importer-progress',
  authenticationChallenge: 'netcatty:plugins:authentication-challenge',
  connectionData: 'netcatty:plugins:connection-data',
  connectionClosed: 'netcatty:plugins:connection-closed',
  viewUpdate: 'netcatty:plugins:host-ui-update',
  contributionsChanged: 'netcatty:plugins:contributions-changed',
  viewClosed: 'netcatty:plugins:view-closed',
  scopeCatalogChanged: 'netcatty:plugins:scope-catalog-changed',
} as const;

type Bridge = NetcattyBridge;
type AnyFn = (...args: never[]) => unknown;
type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

export interface PluginsBridgeDeps {
  hub: EventHub;
  invoke?: Invoke;
  /** Start the iframe runtime relay (main window only by default). */
  runtimeHost?: boolean;
}

const newRequestId = (): string =>
  typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `req-${Date.now()}-${Math.random().toString(36).slice(2)}`;

const asBytes = (value: unknown): Uint8Array => {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (Array.isArray(value)) return Uint8Array.from(value as number[]);
  throw new TypeError('Expected binary bytes');
};

/** Replace `key` (bytes) by `<key>Base64`. */
const encodeField = (payload: Record<string, unknown>, key: string): Record<string, unknown> => {
  if (payload[key] === undefined || payload[key] === null) return payload;
  const { [key]: value, ...rest } = payload;
  return { ...rest, [`${key}Base64`]: toBase64(asBytes(value)) };
};

/** Replace `<key>Base64` by `key` (Uint8Array). */
const decodeField = <T>(result: T, key: string): T => {
  if (!result || typeof result !== 'object') return result;
  const record = result as Record<string, unknown>;
  const encoded = record[`${key}Base64`];
  if (typeof encoded !== 'string') return result;
  const { [`${key}Base64`]: _drop, ...rest } = record;
  return { ...rest, [key]: fromBase64(encoded) } as T;
};

export function createPluginsBridge(deps: PluginsBridgeDeps): Partial<Bridge> {
  const { hub } = deps;
  const invoke = deps.invoke ?? tauriInvoke;
  const call = <T = unknown>(method: string, payload?: unknown): Promise<T> =>
    invoke<T>('plugin_call', { method, payload: payload ?? null });

  for (const event of Object.values(PLUGIN_EVENTS)) void hub.ensure(event);
  const on = (event: string) => (cb: (payload: never) => void): (() => void) => hub.subscribe(event, cb as (p: unknown) => void);

  if (deps.runtimeHost ?? currentWindowLabel() === 'main') {
    createPluginRuntimeHost({ subscribe: (event, cb) => hub.subscribe(event, cb) });
  }

  // `pluginHostReady` is synchronous in Electron (sendSync); cache it.
  let hostReady = false;
  void call<boolean>('host-available-sync').then((ready) => { hostReady = ready === true; }).catch(() => undefined);

  const withRequestId = (request: unknown): Record<string, unknown> => {
    const record = (request ?? {}) as Record<string, unknown>;
    return { ...record, requestId: typeof record.requestId === 'string' && record.requestId ? record.requestId : newRequestId() };
  };

  const bridge: Record<string, AnyFn> = {
    getPluginRuntimeStatus: () => call('status'),
    getPluginSourceBinding: (pluginId: string) => call('source-binding', { pluginId }),
    resetPluginSource: (pluginId: string, expectedSourceId: string) => call('reset-source', { pluginId, expectedSourceId }),
    listPluginSources: () => call('sources'),
    addPluginSource: (source: unknown) => call('add-source', source),
    updatePluginSource: (source: unknown) => call('update-source', source),
    removePluginSource: (id: string, disablePlugins: boolean) => call('remove-source', { id, disablePlugins }),
    listPluginCatalog: (sourceId?: string) => call('catalog', { sourceId }),
    getPluginAuthorPresentation: (request: unknown) => call('author', request),
    onPluginCatalogChanged: on(PLUGIN_EVENTS.catalogChanged),
    getPluginCatalogReadme: (id: string, selectionToken?: string, sourceId?: string) => call('catalog-readme', { id, selectionToken, sourceId }),
    getPluginCatalogReadmeImages: (id: string, selectionToken?: string, sourceId?: string) => call('catalog-readme-images', { id, selectionToken, sourceId }),
    installCatalogPlugin: (id: string, selectionToken?: string, sourceId?: string, acceptedSourceId?: string) =>
      call('catalog-install', { id, selectionToken, sourceId, acceptedSourceId }),
    setPluginAIHostReady: (ready: boolean) => call('ai-host-ready', ready),
    setPluginAgentHostReady: (ready: boolean) => call('agent-host-ready', ready),
    respondPluginAgentHost: (response: unknown) => call('agent-host-response', response),
    onPluginAgentHostRequest: on(PLUGIN_EVENTS.agentHostRequest),
    respondPluginAIHost: (response: unknown) => call('ai-host-response', response),
    onPluginAIHostRequest: on(PLUGIN_EVENTS.aiHostRequest),
    setPluginInteractionReady: (ready: boolean) => call('interaction-ready', { ready }),
    respondPluginInteraction: (response: unknown) => call('interaction-response', response),
    onPluginInteraction: on(PLUGIN_EVENTS.interaction),
    listPlugins: () => call('list'),
    setPluginPermissionMode: (pluginId: string, permission: string, mode: string, policyRevision: string) =>
      call('set-permission-mode', { pluginId, permission, mode, policyRevision }),
    setPluginPermissionReady: (ready: boolean) => call('permission-ready', { ready }),
    respondPluginPermission: (response: unknown) => call('permission-response', response),
    onPluginPermission: on(PLUGIN_EVENTS.permissionPrompt),
    getPluginPermissions: (pluginId: string) => call('permissions', { pluginId }),
    revokePluginPermissions: (pluginId: string) => call('revoke-permissions', { pluginId }),
    installPluginPackage: (archivePath: string, options?: { enable?: boolean }) =>
      call('install', { archivePath, enable: options?.enable === true }),
    setPluginEnabled: (pluginId: string, enabled: boolean) => call('set-enabled', { pluginId, enabled: enabled === true }),
    restartPlugin: (pluginId: string) => call('restart', { pluginId }),
    uninstallPlugin: (pluginId: string) => call('uninstall', { pluginId }),
    getPluginLogStatus: () => call('log-status'),
    configurePluginLogs: (settings: unknown) => call('log-configure', settings),
    openPluginLogFolder: () => call('log-open'),
    exportPluginLogs: () => call('log-export'),
    clearPluginLogs: () => call('log-clear'),
    setPluginTerminalTarget: (target: unknown) => call('terminal-target', target),
    getPluginThemes: () => call('theme-catalog'),
    applyPluginTheme: (request: unknown) => call('theme-apply', request),
    onPluginThemesChanged: (cb: () => void) => hub.subscribe(PLUGIN_EVENTS.themesChanged, () => cb()),
    getPluginContributions: (options?: unknown) => call('contributions', options ?? {}),
    getPluginBrandIcon: (pluginId: string) => call('brand-icon', { pluginId }),
    getPluginContributionIcon: (pluginId: string, icon: unknown) => call('contribution-icon', { pluginId, icon }),
    executePluginCommand: (command: string, args?: unknown, context?: unknown) =>
      call('execute-command', { command, ...(args === undefined ? {} : { args }), ...(context === undefined ? {} : { context }) }),
    updatePluginSetting: (pluginId: string, settingId: string, value: unknown, scopeId?: string) =>
      call('update-setting', { pluginId, settingId, value, ...(scopeId === undefined ? {} : { scopeId }) }),
    resetPluginSetting: (pluginId: string, settingId: string, scopeId?: string) =>
      call('reset-setting', { pluginId, settingId, ...(scopeId === undefined ? {} : { scopeId }) }),
    setPluginEnvironment: (environment: unknown) => call('set-environment', environment),
    listPluginTerminalProviders: (options?: unknown) => call('terminal-providers', options ?? {}),
    providePluginTerminal: (request: unknown) => call('terminal-provide', request),
    cancelPluginTerminalRequest: (requestId: string) => call('terminal-cancel', { requestId }),
    publishPluginTerminalSessionEvent: (event: unknown) => call('terminal-session-event', event),
    listPluginExtensionProviders: (options?: unknown) => call('extension-providers', options ?? {}),
    updatePluginCredentialCatalog: (entries: unknown) => call('credential-catalog-update', { entries }),
    invokePluginExtensionProvider: (request: unknown) => call('extension-invoke', withRequestId(request)),
    cancelPluginExtensionRequest: (requestId: string) => call('extension-cancel', { requestId }),
    pluginSyncConnect: (request: unknown) => call('sync-connect', withRequestId(request)),
    pluginSyncDisconnect: (request: unknown) => call('sync-disconnect', withRequestId(request)),
    pluginSyncGetAccount: (request: unknown) => call('sync-get-account', withRequestId(request)),
    pluginSyncGetCapabilities: (request: unknown) => call('sync-get-capabilities', withRequestId(request)),
    pluginSyncReadObject: async (request: unknown) => decodeField(await call('sync-read-object', withRequestId(request)), 'data'),
    pluginSyncReadChunk: async (request: unknown) => decodeField(await call('sync-read-chunk', request), 'chunk'),
    pluginSyncWriteObject: (request: unknown) => {
      const record = withRequestId(request);
      return call('sync-write-object', encodeField(encodeField(record, 'data'), 'bytes'));
    },
    pluginSyncWriteBegin: (request: unknown) => call('sync-write-begin', withRequestId(request)),
    pluginSyncWriteChunk: (request: unknown) => call('sync-write-chunk', encodeField((request ?? {}) as Record<string, unknown>, 'chunk')),
    pluginSyncWriteCommit: (request: unknown) => call('sync-write-commit', request),
    pluginSyncDeleteObject: (request: unknown) => call('sync-delete-object', withRequestId(request)),
    pluginSyncPutSecret: (request: unknown) => call('sync-put-secret', request ?? {}),
    pluginSyncDeleteSecrets: (request: unknown) => call('sync-delete-secrets', request ?? {}),
    pluginSyncRestoreSecrets: (request: unknown) => call('sync-restore-secrets', request ?? {}),
    collectPluginSyncSidecars: () => call('sync-sidecars-collect', {}),
    applyPluginSyncSidecars: (bundle: unknown) => call('sync-sidecars-apply', bundle ?? { version: 1, entries: [] }),
    pluginHostReady: () => hostReady,
    startPluginConnection: (request: unknown) => call('connection-start', withRequestId(request)),
    writePluginConnection: (sessionId: string, data: Uint8Array) =>
      call('connection-write', { sessionId, dataBase64: toBase64(asBytes(data)) }),
    controlPluginConnection: (sessionId: string, operation: string, payload?: unknown) =>
      call('connection-control', { sessionId, operation, payload: payload ?? {} }),
    detectPluginImporter: (request: unknown) => call('importer-detect', encodeField(withRequestId(request), 'sample')),
    selectPluginImporterFile: async () => decodeField(await call('importer-select-file', {}), 'sample'),
    releasePluginImporterFile: (selectionToken: string) => call('importer-release-file', { selectionToken }),
    parsePluginImporterFile: (request: unknown) => call('importer-parse-file', withRequestId(request)),
    onPluginImporterProgress: on(PLUGIN_EVENTS.importerProgress),
    respondPluginAuthenticationChallenge: (response: unknown) => call('authentication-respond', response),
    onPluginAuthenticationChallenge: on(PLUGIN_EVENTS.authenticationChallenge),
    onPluginConnectionData: (cb: (event: { sessionId: string; data: Uint8Array }) => void) =>
      hub.subscribe<{ sessionId: string; dataBase64: string }>(PLUGIN_EVENTS.connectionData, (event) =>
        cb({ sessionId: event.sessionId, data: fromBase64(event.dataBase64) })),
    onPluginConnectionClosed: on(PLUGIN_EVENTS.connectionClosed),
    getPluginViewResource: (payload: unknown) => call('host-ui-resource', payload),
    openHostDrawnPluginView: (payload: unknown) => call('host-ui-open', payload),
    closeHostDrawnPluginView: (instanceId: string) => call('host-ui-close', { instanceId }),
    sendHostDrawnPluginViewEvent: (instanceId: string, event: unknown) => call('host-ui-event', { instanceId, event }),
    onHostDrawnPluginViewUpdate: on(PLUGIN_EVENTS.viewUpdate),
    onPluginContributionsChanged: on(PLUGIN_EVENTS.contributionsChanged),
    onPluginViewClosed: on(PLUGIN_EVENTS.viewClosed),
    getPluginScopeCatalog: () => call('get-scope-catalog'),
    setPluginScopeCatalog: (catalog: unknown) => call('set-scope-catalog', catalog),
    onPluginScopeCatalogChanged: on(PLUGIN_EVENTS.scopeCatalogChanged),
  };
  return bridge as unknown as Partial<Bridge>;
}

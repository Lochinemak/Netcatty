/**
 * AI core part of the Tauri bridge: provider proxy (`aiFetch`), chat
 * streaming (`aiChatStream` + `netcatty:ai:stream:*` events), privacy,
 * user skills, the skills CLI invocation and the AI sessions backup.
 * Commands and events are specified in `rust/docs/ipc-ai.md`; every
 * command takes the Electron IPC argument as `payload` and answers with the
 * Electron result object, so this module is a thin mapping.
 */

import { EventHub, invoke } from '../tauriApi';
import { localStorageAdapter } from '../../persistence/localStorageAdapter';
import { STORAGE_KEY_AI_EXTERNAL_MCP_REDACTION, STORAGE_KEY_AI_PRIVACY } from '../../config/storageKeys';

export const AI_STREAM_EVENTS = {
  data: 'netcatty:ai:stream:data',
  end: 'netcatty:ai:stream:end',
  error: 'netcatty:ai:stream:error',
} as const;

type BridgeMethod<K extends keyof NetcattyBridge> = NonNullable<NetcattyBridge[K]>;
type BridgeResult<K extends keyof NetcattyBridge> = Awaited<ReturnType<BridgeMethod<K>>>;

interface StreamDataEvent { requestId: string; data: string }
interface StreamEndEvent { requestId: string }
interface StreamErrorEvent { requestId: string; error: string }

/**
 * Bridge members the renderer reads dynamically but that are not declared on
 * `NetcattyBridge` (see `application/state/aiSessionsBackup.ts` and
 * `components/AIChatSidePanel.tsx`).
 */
export interface AiBridgeExtras {
  aiSyncWebSearch: (apiHost: string | null, apiKey: string | null) => Promise<{ ok: boolean }>;
  aiSessionsBackupWrite: (payload: { json: string }) => Promise<{ ok: boolean; file?: string; error?: string }>;
  aiSessionsBackupReadLatest: () => Promise<{ ok: boolean; json?: string; file?: string }>;
  aiSessionsBackupExport: (payload: { json: string }) => Promise<{ success: boolean; filePath?: string; canceled?: boolean; error?: string }>;
  aiSessionsBackupImport: () => Promise<{ success: boolean; json?: string; canceled?: boolean; error?: string }>;
}

export interface AiBridgeDeps {
  hub: EventHub;
  /**
   * Persisted AI privacy policy, read once before the first privacy call:
   * `undefined` when nothing is stored (defaults), `null` when the stored
   * value is corrupt (fails closed). Injected for tests.
   */
  readStoredPrivacyPolicy?: () => Record<string, unknown> | null | undefined;
}

const PRIVACY_KEYS = ['enabled', 'redactPrivateIps', 'cidrs', 'patterns'];

/**
 * Mirrors `readAIPrivacySettings` (application/state/useExternalMcpToggleState):
 * the shared key wins over the legacy External MCP key, and corrupt data is
 * never treated as "privacy off".
 */
export function readStoredPrivacyPolicy(): Record<string, unknown> | null | undefined {
  let stored: string | null;
  try {
    stored = localStorageAdapter.readString(STORAGE_KEY_AI_PRIVACY)
      ?? localStorageAdapter.readString(STORAGE_KEY_AI_EXTERNAL_MCP_REDACTION);
  } catch {
    return null;
  }
  if (stored === null) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(stored);
  } catch {
    return null;
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const settings = value as Record<string, unknown>;
  const stringArray = (entry: unknown) => Array.isArray(entry) && entry.every((item) => typeof item === 'string');
  if (
    Object.keys(settings).some((key) => !PRIVACY_KEYS.includes(key))
    || typeof settings.enabled !== 'boolean'
    || typeof settings.redactPrivateIps !== 'boolean'
    || !stringArray(settings.cidrs)
    || !stringArray(settings.patterns)
  ) {
    return null;
  }
  return {
    enabled: settings.enabled,
    redactPrivateIps: settings.redactPrivateIps,
    cidrs: [...(settings.cidrs as string[])],
    patterns: [...(settings.patterns as string[])],
  };
}

export function createAiBridge(deps: AiBridgeDeps): Partial<NetcattyBridge> & AiBridgeExtras {
  const { hub } = deps;
  const readPolicy = deps.readStoredPrivacyPolicy ?? readStoredPrivacyPolicy;

  // Subscribe once, lazily, before the first stream starts: Tauri delivers
  // events only to listeners that exist when they are emitted.
  let streamEventsReady: Promise<unknown> | null = null;
  const ensureStreamEvents = () => {
    streamEventsReady ??= Promise.all([
      hub.ensure(AI_STREAM_EVENTS.data),
      hub.ensure(AI_STREAM_EVENTS.end),
      hub.ensure(AI_STREAM_EVENTS.error),
    ]);
    return streamEventsReady;
  };

  // Electron's main process receives the persisted privacy policy through
  // `externalMcpSetConfig` at startup. Until that command exists in the Tauri
  // build (and before the startup sync runs), push the stored policy once;
  // the backend applies it only while it is still waiting for a policy.
  let privacyInitialized: Promise<void> | null = null;
  const ensurePrivacyInitialized = () => {
    privacyInitialized ??= (async () => {
      const policy = readPolicy();
      try {
        await invoke('ai_privacy_initialize', { payload: { redaction: policy === undefined ? {} : policy } });
      } catch {
        // The backend keeps failing closed ("still loading") on error.
        privacyInitialized = null;
      }
    })();
    return privacyInitialized;
  };

  return {
    // ── Provider / web-search config (keys stay encrypted) ──
    aiSyncProviders: (providers) =>
      invoke<BridgeResult<'aiSyncProviders'>>('ai_sync_providers', { payload: { providers } }),
    aiSyncWebSearch: (apiHost, apiKey) =>
      invoke<{ ok: boolean }>('ai_sync_web_search', { payload: { apiHost, apiKey } }),
    aiAllowlistAddHost: (baseURL) =>
      invoke<BridgeResult<'aiAllowlistAddHost'>>('ai_allowlist_add_host', { payload: { baseURL } }),

    // ── Provider HTTP proxy ──
    aiFetch: (url, method, headers, body, providerId, skipHostCheck, followRedirects, skipTLSVerify, ...rest: unknown[]) => {
      const requestId = rest[0];
      return invoke<BridgeResult<'aiFetch'>>('ai_fetch', {
        payload: {
          url, method, headers, body, providerId, skipHostCheck, followRedirects, skipTLSVerify,
          ...(requestId ? { requestId } : {}),
        },
      });
    },

    // ── Chat streaming ──
    aiChatStream: async (requestId, url, headers, body, providerId, idleTimeoutMs) => {
      await ensureStreamEvents();
      return invoke<BridgeResult<'aiChatStream'>>('ai_chat_stream', {
        payload: { requestId, url, headers, body, providerId, idleTimeoutMs },
      });
    },
    aiChatCancel: (requestId) => invoke<boolean>('ai_chat_cancel', { payload: { requestId } }),
    aiSetChatSessionCancelled: (chatSessionId, cancelled = true) =>
      invoke<BridgeResult<'aiSetChatSessionCancelled'>>('ai_set_chat_session_cancelled', {
        payload: { chatSessionId, cancelled },
      }),
    onAiStreamData: (requestId, cb) =>
      hub.subscribe<StreamDataEvent>(AI_STREAM_EVENTS.data, (event) => {
        if (event?.requestId === requestId) cb(event.data);
      }),
    onAiStreamEnd: (requestId, cb) =>
      hub.subscribe<StreamEndEvent>(AI_STREAM_EVENTS.end, (event) => {
        if (event?.requestId === requestId) cb();
      }),
    onAiStreamError: (requestId, cb) =>
      hub.subscribe<StreamErrorEvent>(AI_STREAM_EVENTS.error, (event) => {
        if (event?.requestId === requestId) cb(event.error);
      }),

    // ── Privacy ──
    aiPrivacyStatus: async () => {
      await ensurePrivacyInitialized();
      return invoke<BridgeResult<'aiPrivacyStatus'>>('ai_privacy_status');
    },
    aiPrivacyTransform: async (request) => {
      await ensurePrivacyInitialized();
      return invoke<BridgeResult<'aiPrivacyTransform'>>('ai_privacy_transform', { payload: request ?? {} });
    },
    aiPrivacyClearSession: (chatSessionId) =>
      invoke<BridgeResult<'aiPrivacyClearSession'>>('ai_privacy_clear', { chatSessionId }),

    // ── User skills / skills CLI ──
    aiUserSkillsGetStatus: () => invoke<BridgeResult<'aiUserSkillsGetStatus'>>('ai_user_skills_status'),
    aiUserSkillsOpenFolder: () => invoke<BridgeResult<'aiUserSkillsOpenFolder'>>('ai_user_skills_open'),
    aiUserSkillsBuildContext: (prompt, selectedSkillSlugs) =>
      invoke<BridgeResult<'aiUserSkillsBuildContext'>>('ai_user_skills_build_context', {
        payload: { prompt, selectedSkillSlugs },
      }),
    aiSkillsCliGetInvocation: () => invoke<BridgeResult<'aiSkillsCliGetInvocation'>>('ai_skills_cli_invocation'),

    // ── AI sessions backup ──
    aiSessionsBackupWrite: (payload) => invoke('ai_sessions_backup_write', { payload: payload ?? {} }),
    aiSessionsBackupReadLatest: () => invoke('ai_sessions_backup_read_latest'),
    aiSessionsBackupExport: (payload) => invoke('ai_sessions_backup_export', { payload: payload ?? {} }),
    aiSessionsBackupImport: () => invoke('ai_sessions_backup_import'),
  };
}

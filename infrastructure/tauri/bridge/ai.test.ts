import assert from 'node:assert/strict';
import test from 'node:test';

import { AI_STREAM_EVENTS, createAiBridge, readStoredPrivacyPolicy } from './ai';
import { createTauriBridge } from '../createTauriBridge';
import { EventHub } from '../tauriApi';

type Listener = (event: { event: string; id: number; payload: unknown }) => void;

interface InvokeRecord { cmd: string; args: unknown }

/** Minimal `window.__TAURI__`: records invokes, emits events to listeners. */
const setup = (storage: Record<string, string> = {}) => {
  const invokes: InvokeRecord[] = [];
  const order: string[] = [];
  const responses = new Map<string, (args: unknown) => unknown>();
  const listeners = new Map<string, Set<Listener>>();
  const tauri: NetcattyTauriGlobal = {
    core: {
      invoke: async <T>(cmd: string, args?: unknown): Promise<T> => {
        invokes.push({ cmd, args });
        order.push(`invoke:${cmd}`);
        const responder = responses.get(cmd);
        return (responder ? responder(args) : undefined) as T;
      },
    },
    event: {
      listen: async <T>(event: string, handler: (event: { event: string; id: number; payload: T }) => void) => {
        order.push(`listen:${event}`);
        let set = listeners.get(event);
        if (!set) {
          set = new Set();
          listeners.set(event, set);
        }
        set.add(handler as Listener);
        return () => set?.delete(handler as Listener);
      },
    },
  };
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: { __TAURI__: tauri, __TAURI_INTERNALS__: {} },
  });
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem: (key: string) => (key in storage ? storage[key] : null),
      setItem: (key: string, value: string) => { storage[key] = value; },
      removeItem: (key: string) => { delete storage[key]; },
    },
  });
  const emit = (event: string, payload: unknown) => {
    for (const listener of Array.from(listeners.get(event) ?? [])) listener({ event, id: 1, payload });
  };
  return {
    invokes,
    order,
    emit,
    respond: (cmd: string, fn: (args: unknown) => unknown) => responses.set(cmd, fn),
  };
};

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

test('aiChatStream subscribes to the stream events before invoking and filters by requestId', async () => {
  const fake = setup();
  fake.respond('ai_chat_stream', () => ({ ok: true, statusCode: 200, statusText: 'OK' }));
  const bridge = createAiBridge({ hub: new EventHub() });
  const data: string[] = [];
  let ended = 0;
  const errors: string[] = [];
  const offData = bridge.onAiStreamData!('req-1', (chunk) => data.push(chunk));
  bridge.onAiStreamEnd!('req-1', () => { ended += 1; });
  bridge.onAiStreamError!('req-1', (error) => errors.push(error));

  const result = await bridge.aiChatStream!('req-1', 'https://api.openai.com/v1/chat', { a: 'b' }, '{}', 'p1', 1000);
  assert.deepEqual(result, { ok: true, statusCode: 200, statusText: 'OK' });
  const invokeIndex = fake.order.indexOf('invoke:ai_chat_stream');
  for (const event of Object.values(AI_STREAM_EVENTS)) {
    const listenIndex = fake.order.indexOf(`listen:${event}`);
    assert.ok(listenIndex >= 0 && listenIndex < invokeIndex, `${event} subscribed before invoke`);
  }
  assert.deepEqual(fake.invokes.at(-1), {
    cmd: 'ai_chat_stream',
    args: { payload: { requestId: 'req-1', url: 'https://api.openai.com/v1/chat', headers: { a: 'b' }, body: '{}', providerId: 'p1', idleTimeoutMs: 1000 } },
  });

  fake.emit(AI_STREAM_EVENTS.data, { requestId: 'other', data: 'x' });
  fake.emit(AI_STREAM_EVENTS.data, { requestId: 'req-1', data: '{"a":1}' });
  fake.emit(AI_STREAM_EVENTS.error, { requestId: 'other', error: 'nope' });
  fake.emit(AI_STREAM_EVENTS.end, { requestId: 'req-1' });
  assert.deepEqual(data, ['{"a":1}']);
  assert.equal(ended, 1);
  assert.deepEqual(errors, []);
  offData();
  fake.emit(AI_STREAM_EVENTS.data, { requestId: 'req-1', data: 'late' });
  assert.deepEqual(data, ['{"a":1}']);
});

test('aiFetch and the other commands send the Electron IPC argument as payload', async () => {
  const fake = setup();
  const bridge = createAiBridge({ hub: new EventHub() });
  await bridge.aiFetch!('https://x', 'GET', { h: '1' }, undefined, 'p', true, false, true);
  assert.deepEqual(fake.invokes.at(-1), {
    cmd: 'ai_fetch',
    args: { payload: { url: 'https://x', method: 'GET', headers: { h: '1' }, body: undefined, providerId: 'p', skipHostCheck: true, followRedirects: false, skipTLSVerify: true } },
  });
  const withId = bridge.aiFetch as unknown as (...args: unknown[]) => Promise<unknown>;
  await withId('https://x', 'POST', {}, 'b', 'p', false, false, false, 'agent-model_x');
  assert.equal((fake.invokes.at(-1)!.args as { payload: { requestId?: string } }).payload.requestId, 'agent-model_x');

  await bridge.aiChatCancel!('req');
  await bridge.aiSetChatSessionCancelled!('chat');
  await bridge.aiSyncProviders!([{ id: 'p', providerId: 'openai', enabled: true }]);
  await bridge.aiSyncWebSearch('https://api.tavily.com', 'enc:v2:x');
  await bridge.aiAllowlistAddHost!('https://h');
  await bridge.aiUserSkillsBuildContext!('prompt', ['a']);
  await bridge.aiPrivacyClearSession!('chat');
  await bridge.aiSessionsBackupWrite({ json: '[]' });
  await bridge.aiSessionsBackupExport({ json: '[]' });
  await bridge.aiSessionsBackupImport();
  await bridge.aiSessionsBackupReadLatest();
  await bridge.aiUserSkillsGetStatus!();
  await bridge.aiUserSkillsOpenFolder!();
  await bridge.aiSkillsCliGetInvocation!();
  assert.deepEqual(fake.invokes.slice(2).map(({ cmd, args }) => [cmd, args]), [
    ['ai_chat_cancel', { payload: { requestId: 'req' } }],
    ['ai_set_chat_session_cancelled', { payload: { chatSessionId: 'chat', cancelled: true } }],
    ['ai_sync_providers', { payload: { providers: [{ id: 'p', providerId: 'openai', enabled: true }] } }],
    ['ai_sync_web_search', { payload: { apiHost: 'https://api.tavily.com', apiKey: 'enc:v2:x' } }],
    ['ai_allowlist_add_host', { payload: { baseURL: 'https://h' } }],
    ['ai_user_skills_build_context', { payload: { prompt: 'prompt', selectedSkillSlugs: ['a'] } }],
    ['ai_privacy_clear', { chatSessionId: 'chat' }],
    ['ai_sessions_backup_write', { payload: { json: '[]' } }],
    ['ai_sessions_backup_export', { payload: { json: '[]' } }],
    ['ai_sessions_backup_import', undefined],
    ['ai_sessions_backup_read_latest', undefined],
    ['ai_user_skills_status', undefined],
    ['ai_user_skills_open', undefined],
    ['ai_skills_cli_invocation', undefined],
  ]);
});

test('privacy calls push the stored policy once before the first status / transform', async () => {
  const fake = setup();
  fake.respond('ai_privacy_status', () => ({ ok: true, enabled: true }));
  fake.respond('ai_privacy_transform', (args) => ({ ok: true, value: (args as { payload: { value: unknown } }).payload.value }));
  const policy = { enabled: true, redactPrivateIps: false, cidrs: [], patterns: [] };
  const bridge = createAiBridge({ hub: new EventHub(), readStoredPrivacyPolicy: () => policy });
  assert.deepEqual(await bridge.aiPrivacyStatus!(), { ok: true, enabled: true });
  await bridge.aiPrivacyTransform!({ chatSessionId: 'c', operation: 'redact', value: [] });
  await bridge.aiPrivacyStatus!();
  assert.deepEqual(fake.invokes.map(({ cmd }) => cmd), [
    'ai_privacy_initialize', 'ai_privacy_status', 'ai_privacy_transform', 'ai_privacy_status',
  ]);
  assert.deepEqual(fake.invokes[0].args, { payload: { redaction: policy } });
  assert.deepEqual(fake.invokes[2].args, { payload: { chatSessionId: 'c', operation: 'redact', value: [] } });

  // Missing policy → defaults; corrupt policy → null (fails closed).
  const missing = setup();
  await createAiBridge({ hub: new EventHub(), readStoredPrivacyPolicy: () => undefined }).aiPrivacyStatus!();
  assert.deepEqual(missing.invokes[0].args, { payload: { redaction: {} } });
  const corrupt = setup();
  await createAiBridge({ hub: new EventHub(), readStoredPrivacyPolicy: () => null }).aiPrivacyStatus!();
  assert.deepEqual(corrupt.invokes[0].args, { payload: { redaction: null } });
});

test('a failed privacy initialization is retried on the next call', async () => {
  const fake = setup();
  let failures = 1;
  fake.respond('ai_privacy_initialize', () => {
    if (failures-- > 0) throw { code: 'INTERNAL', message: 'boom' };
    return { ok: true, applied: true };
  });
  const bridge = createAiBridge({ hub: new EventHub(), readStoredPrivacyPolicy: () => undefined });
  await bridge.aiPrivacyStatus!();
  await bridge.aiPrivacyStatus!();
  await bridge.aiPrivacyStatus!();
  assert.equal(fake.invokes.filter(({ cmd }) => cmd === 'ai_privacy_initialize').length, 2);
});

test('readStoredPrivacyPolicy mirrors the renderer validation', () => {
  setup({});
  assert.equal(readStoredPrivacyPolicy(), undefined);
  const valid = { enabled: true, redactPrivateIps: true, cidrs: ['10.0.0.0/8'], patterns: ['X-[0-9]+'] };
  setup({ netcatty_ai_privacy_v1: JSON.stringify(valid) });
  assert.deepEqual(readStoredPrivacyPolicy(), valid);
  // The shared key wins over the legacy External MCP key, even when corrupt.
  setup({ netcatty_ai_privacy_v1: '{oops', netcatty_ai_external_mcp_redaction_v1: JSON.stringify(valid) });
  assert.equal(readStoredPrivacyPolicy(), null);
  setup({ netcatty_ai_external_mcp_redaction_v1: JSON.stringify(valid) });
  assert.deepEqual(readStoredPrivacyPolicy(), valid);
  for (const bad of [[], 'x', { ...valid, extra: 1 }, { ...valid, enabled: 'yes' }, { ...valid, cidrs: [1] }]) {
    setup({ netcatty_ai_privacy_v1: JSON.stringify(bad) });
    assert.equal(readStoredPrivacyPolicy(), null, JSON.stringify(bad));
  }
});

test('createTauriBridge exposes the AI methods', async () => {
  setup();
  const bridge = createTauriBridge({ hub: new EventHub() }) as NetcattyBridge & Record<string, unknown>;
  for (const key of [
    'aiFetch', 'aiChatStream', 'aiChatCancel', 'aiSetChatSessionCancelled', 'aiAllowlistAddHost', 'aiSyncProviders',
    'aiSyncWebSearch', 'aiPrivacyStatus', 'aiPrivacyTransform', 'aiPrivacyClearSession', 'aiUserSkillsGetStatus',
    'aiUserSkillsOpenFolder', 'aiUserSkillsBuildContext', 'aiSkillsCliGetInvocation', 'onAiStreamData',
    'onAiStreamEnd', 'onAiStreamError', 'aiSessionsBackupWrite', 'aiSessionsBackupReadLatest',
    'aiSessionsBackupExport', 'aiSessionsBackupImport',
  ]) {
    assert.equal(typeof bridge[key], 'function', key);
  }
  await flush();
});

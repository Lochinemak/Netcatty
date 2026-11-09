import assert from 'node:assert/strict';
import test from 'node:test';

import { EventHub } from '../tauriApi';
import { AGENT_EVENTS, createAgentsBridge } from './agents';

type Listener = (event: { event: string; id: number; payload: unknown }) => void;

interface InvokeRecord {
  cmd: string;
  args: unknown;
}

const setup = () => {
  const invokes: InvokeRecord[] = [];
  const responses = new Map<string, (args: unknown) => unknown>();
  const listeners = new Map<string, Set<Listener>>();
  const tauri: NetcattyTauriGlobal = {
    core: {
      invoke: async <T>(cmd: string, args?: unknown): Promise<T> => {
        invokes.push({ cmd, args });
        return (responses.get(cmd)?.(args) ?? undefined) as T;
      },
    },
    event: {
      listen: async <T>(event: string, handler: (event: { event: string; id: number; payload: T }) => void) => {
        const set = listeners.get(event) ?? new Set<Listener>();
        listeners.set(event, set);
        set.add(handler as Listener);
        return () => set.delete(handler as Listener);
      },
    },
  };
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { __TAURI__: tauri, __TAURI_INTERNALS__: {} } });
  const emit = (event: string, payload: unknown) => {
    for (const listener of Array.from(listeners.get(event) ?? [])) listener({ event, id: 1, payload });
  };
  const bridge = createAgentsBridge({ hub: new EventHub() });
  return { bridge, invokes, responses, emit, listeners };
};

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

test('aiSdkAgentStream subscribes first and sends the Electron payload shape', async () => {
  const { bridge, invokes, responses, listeners } = setup();
  responses.set('ai_sdk_agent_stream', () => ({ ok: true }));
  const result = await bridge.aiSdkAgentStream?.(
    'req-1', 'chat-1', 'codebuddy', 'hi', undefined, 'prov', 'glm/high', 'sess', [{ role: 'user', content: 'x' }],
    undefined, 'skills', undefined, 'skills ctx', { A: '1' }, '/bin/codebuddy', undefined, 'auto',
    { effort: 'high', maxTurns: 3, persistSession: false },
  );
  assert.deepEqual(result, { ok: true });
  for (const event of [AGENT_EVENTS.sdkEvent, AGENT_EVENTS.sdkDone, AGENT_EVENTS.sdkError]) {
    assert.equal(listeners.get(event)?.size, 1, `${event} subscribed`);
  }
  const record = invokes.find((entry) => entry.cmd === 'ai_sdk_agent_stream');
  const payload = (record?.args as { payload: Record<string, unknown> }).payload;
  assert.equal(payload.requestId, 'req-1');
  assert.equal(payload.sdkBackend, 'codebuddy');
  assert.equal(payload.toolIntegrationMode, 'skills');
  assert.equal(payload.permissionMode, 'auto');
  assert.equal(payload.effort, 'high');
  assert.equal(payload.maxTurns, 3);
  assert.equal(payload.persistSession, false);
  assert.ok(!('codebuddyOptions' in payload));
});

test('request-scoped listeners only see their own request', async () => {
  const { bridge, emit } = setup();
  const events: unknown[] = [];
  const errors: string[] = [];
  let done = 0;
  const offEvent = bridge.onAiSdkAgentEvent?.('req-1', (event) => events.push(event));
  bridge.onAiSdkAgentDone?.('req-1', () => { done += 1; });
  bridge.onAiSdkAgentError?.('req-1', (error) => errors.push(error));
  await flush();
  emit(AGENT_EVENTS.sdkEvent, { requestId: 'req-1', event: { type: 'text-delta', textDelta: 'a' } });
  emit(AGENT_EVENTS.sdkEvent, { requestId: 'other', event: { type: 'text-delta', textDelta: 'b' } });
  emit(AGENT_EVENTS.sdkDone, { requestId: 'req-1' });
  emit(AGENT_EVENTS.sdkError, { requestId: 'req-1', error: 'boom' });
  assert.deepEqual(events, [{ type: 'text-delta', textDelta: 'a' }]);
  assert.equal(done, 1);
  assert.deepEqual(errors, ['boom']);
  offEvent?.();
  emit(AGENT_EVENTS.sdkEvent, { requestId: 'req-1', event: { type: 'status' } });
  assert.equal(events.length, 1);
});

test('commands map to the agents IPC names and argument shapes', async () => {
  const { bridge, invokes } = setup();
  await bridge.aiSdkAgentCancel?.('req', 'chat');
  await bridge.aiSdkAgentCleanup?.('chat');
  await bridge.aiSdkAgentSteer?.('req', 'chat', 'more', undefined, 'msg-1');
  await bridge.aiSdkAgentListModels?.('grok', undefined, undefined, 'chat', { A: 'b' }, 'grok', undefined, true);
  await bridge.aiDiscoverAgents?.({ refreshShellEnv: true });
  await bridge.aiResolveCli({ command: 'codex', customPath: '/x/codex' });
  await bridge.aiCodexGetLoginSession?.('login-1');
  await bridge.codexAppServerGetStatus?.('/x/codex', { CODEX_HOME: '/h' });
  await bridge.respondCodexAppServerInteraction?.({ interactionId: 'i', decision: 'once' });
  await bridge.cancelCodexAppServerInteractionTimeout?.('i');
  await bridge.aiSdkAgentElicitationResponse?.('e', 'accept', { a: 1 });
  await bridge.aiSdkAgentPluginEnable?.('p', 'm');
  await bridge.aiSdkAgentMarketplaceInstall?.({ name: 'm', repo: 'o/r' });
  assert.deepEqual(invokes.map((entry) => [entry.cmd, entry.args]), [
    ['ai_sdk_agent_cancel', { requestId: 'req', chatSessionId: 'chat' }],
    ['ai_sdk_agent_cleanup', { chatSessionId: 'chat' }],
    ['ai_sdk_agent_steer', { payload: { requestId: 'req', chatSessionId: 'chat', prompt: 'more', images: undefined, clientUserMessageId: 'msg-1' } }],
    ['ai_sdk_agent_list_models', { payload: { sdkBackend: 'grok', cwd: undefined, providerId: undefined, chatSessionId: 'chat', agentEnv: { A: 'b' }, agentCommand: 'grok', codexRuntime: undefined, force: true } }],
    ['ai_agents_discover', { options: { refreshShellEnv: true } }],
    ['ai_resolve_cli', { payload: { command: 'codex', customPath: '/x/codex' } }],
    ['ai_codex_get_login_session', { sessionId: 'login-1' }],
    ['codex_app_server_status', { payload: { agentCommand: '/x/codex', agentEnv: { CODEX_HOME: '/h' } } }],
    ['codex_app_server_respond', { payload: { interactionId: 'i', decision: 'once' } }],
    ['codex_app_server_cancel_timeout', { interactionId: 'i' }],
    ['ai_sdk_agent_elicitation_response', { payload: { elicitationId: 'e', action: 'accept', content: { a: 1 } } }],
    ['ai_sdk_agent_plugin_enable', { payload: { name: 'p', marketplace: 'm' } }],
    ['ai_sdk_agent_marketplace_install', { payload: { options: { name: 'm', repo: 'o/r' } } }],
  ]);
});

test('codex interaction events fan out to every subscriber', async () => {
  const { bridge, emit } = setup();
  const requests: unknown[] = [];
  const cleared: unknown[] = [];
  bridge.onCodexAppServerInteractionRequest?.((payload) => requests.push(payload));
  bridge.onCodexAppServerInteractionCleared?.((payload) => cleared.push(payload));
  await flush();
  emit(AGENT_EVENTS.codexInteractionRequest, { interactionId: 'i', kind: 'command' });
  emit(AGENT_EVENTS.codexInteractionCleared, { interactionIds: ['i'], chatSessionId: 'c' });
  assert.deepEqual(requests, [{ interactionId: 'i', kind: 'command' }]);
  assert.deepEqual(cleared, [{ interactionIds: ['i'], chatSessionId: 'c' }]);
});

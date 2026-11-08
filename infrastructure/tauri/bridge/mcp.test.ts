import assert from 'node:assert/strict';
import test from 'node:test';

import { EventHub } from '../tauriApi';
import { MCP_EVENTS, createMcpBridge } from './mcp';
import { McpMarkerFilter, endsWithMarkerPrefix } from './mcpMarkerFilter';

interface InvokeRecord { cmd: string; args: unknown }

const setup = () => {
  const invokes: InvokeRecord[] = [];
  const listeners = new Map<string, Array<(e: { payload: unknown }) => void>>();
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: {
      __TAURI_INTERNALS__: {},
      __TAURI__: {
        core: {
          invoke: async (cmd: string, args?: unknown) => {
            invokes.push({ cmd, args });
            return { ok: true };
          },
        },
        event: {
          listen: async (event: string, handler: (e: { payload: unknown }) => void) => {
            listeners.set(event, [...(listeners.get(event) ?? []), handler]);
            return () => undefined;
          },
        },
      },
    },
  });
  const hub = new EventHub();
  const bridge = createMcpBridge({ hub });
  const emit = (event: string, payload: unknown) => {
    for (const l of listeners.get(event) ?? []) l({ payload });
  };
  return { invokes, bridge, emit };
};

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

test('commands map to snake_case invokes with Electron argument names', async () => {
  const { invokes, bridge } = setup();
  await bridge.aiExec?.('s1', 'uptime', 'chat-1');
  await bridge.aiCattyCancelExec?.('chat-1');
  await bridge.aiCapability('vault.hosts.list', { q: 1 }, 'chat-1');
  await bridge.aiMcpUpdateSessions?.([], 'chat-1');
  await bridge.respondMcpApproval('a1', true, 'session');
  await bridge.readToolOutputTemp?.('/tmp/x', { mode: 'head' });
  await bridge.deleteTerminalToolOutputsTemp?.('chat-1', 't1');
  await bridge.externalMcpSetEnabled?.(true);
  await bridge.externalMcpClaudeAdd?.();
  await bridge.externalMcpGrokGetStatus?.();
  await bridge.setExternalMcpApprovalAlertMode?.({ mode: 'always' });
  assert.deepEqual(invokes, [
    { cmd: 'ai_exec', args: { sessionId: 's1', command: 'uptime', chatSessionId: 'chat-1' } },
    { cmd: 'ai_catty_cancel_exec', args: { chatSessionId: 'chat-1' } },
    { cmd: 'ai_capability', args: { rpcMethod: 'vault.hosts.list', params: { q: 1 }, chatSessionId: 'chat-1' } },
    { cmd: 'ai_mcp_update_sessions', args: { sessions: [], chatSessionId: 'chat-1' } },
    { cmd: 'ai_mcp_approval_respond', args: { approvalId: 'a1', approved: true, scope: 'session' } },
    { cmd: 'tool_output_read', args: { path: '/tmp/x', request: { mode: 'head' } } },
    { cmd: 'tool_output_delete_terminal_session', args: { chatSessionId: 'chat-1', terminalSessionId: 't1' } },
    { cmd: 'external_mcp_set_enabled', args: { enabled: true } },
    { cmd: 'external_mcp_client_add', args: { client: 'claude' } },
    { cmd: 'external_mcp_client_status', args: { client: 'grok' } },
    { cmd: 'mcp_set_approval_alert_mode', args: { payload: { mode: 'always' } } },
  ]);
});

test('approval and vault-agent events fan out to subscribers', async () => {
  const { bridge, emit } = setup();
  const seen: unknown[] = [];
  const off = bridge.onMcpApprovalRequest((p) => seen.push(p));
  bridge.onVaultAgentRequest?.((p) => seen.push(p));
  await flush();
  emit(MCP_EVENTS.approvalRequest, { approvalId: 'a1' });
  emit(MCP_EVENTS.vaultAgentRequest, { requestId: 'r1', op: 'list', params: {} });
  off();
  emit(MCP_EVENTS.approvalRequest, { approvalId: 'a2' });
  assert.deepEqual(seen, [{ approvalId: 'a1' }, { requestId: 'r1', op: 'list', params: {} }]);
});

const filterHarness = () => {
  const out: string[] = [];
  const timers: Array<() => void> = [];
  const f = new McpMarkerFilter<undefined>({
    deliver: (_id, data) => out.push(data),
    setTimer: (cb) => {
      timers.push(cb);
      return timers.length;
    },
    clearTimer: () => undefined,
  });
  return { f, out, fire: () => timers.splice(0).forEach((cb) => cb()) };
};

test('marker lines are hidden, including markers split across chunks', () => {
  const { f, out } = filterHarness();
  f.push('s', 'hello\n');
  f.push('s', '__NCMCP_abc_S\r\noutput\n__NC');
  f.push('s', 'MCP_abc_E:0\r\n$ ');
  assert.equal(out.join(''), 'hello\noutput\n$ ');
});

test('held fragments are released by the delayed flush; synthetic echo bypasses', () => {
  const { f, out, fire } = filterHarness();
  f.push('s', 'prompt __NC');
  assert.equal(out.join(''), '');
  fire();
  assert.equal(out.join(''), 'prompt __NC');
  f.push('s', 'echo __NCMCP_x', undefined, true);
  assert.equal(out.at(-1), 'echo __NCMCP_x');
  assert.ok(endsWithMarkerPrefix('x __NCMC'));
  assert.ok(!endsWithMarkerPrefix('plain'));
});

test('probe prompts are suppressed until the command start marker', () => {
  const { f, out } = filterHarness();
  f.push('s', '__NCMCP_p1_Q\r\n');
  f.push('s', 'user@host:~$ \r\n');
  f.push('s', '__NCMCP_p1_S\r\nresult\n');
  assert.equal(out.join(''), 'result\n');
});

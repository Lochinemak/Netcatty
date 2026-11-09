import assert from 'node:assert/strict';
import test from 'node:test';

import { EventHub } from '../tauriApi';
import { INTEGRATION_EVENTS, createIntegrationBridge } from './integration';

interface InvokeRecord {
  cmd: string;
  args: unknown;
}

const setup = (options: { label?: string; attach?: () => unknown; attachFails?: boolean } = {}) => {
  const invokes: InvokeRecord[] = [];
  const listeners = new Map<string, Set<(payload: unknown) => void>>();
  const warnings: string[] = [];
  const hub = new EventHub({
    listen: async <T>(event: string, cb: (payload: T) => void) => {
      let set = listeners.get(event);
      if (!set) {
        set = new Set();
        listeners.set(event, set);
      }
      const listener = cb as (payload: unknown) => void;
      set.add(listener);
      return () => {
        set?.delete(listener);
      };
    },
  });
  const emit = (event: string, payload?: unknown) => {
    for (const listener of Array.from(listeners.get(event) ?? [])) listener(payload);
  };
  const bridge = createIntegrationBridge({
    hub,
    windowLabel: () => options.label ?? 'main',
    invoke: async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
      invokes.push({ cmd, args });
      if (cmd === 'integration_renderer_attach') {
        if (options.attachFails) throw new Error('attach failed');
        return (options.attach?.() ?? { intents: [], coldStartSettled: true }) as T;
      }
      return true as T;
    },
    warn: (label) => {
      warnings.push(label);
    },
  });
  const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
  return { bridge, invokes, emit, warnings, flush, listeners };
};

test('cold-start intents are handed to their subscribers, then cold start settles', async () => {
  const h = setup({
    attach: () => ({
      intents: [
        { channel: INTEGRATION_EVENTS.sshDeepLink, payload: { url: 'ssh://a@h', tabName: 'Prod' } },
        { channel: INTEGRATION_EVENTS.openTerminalPath, payload: { path: '/tmp' } },
        { channel: 'netcatty:unknown', payload: {} },
      ],
      coldStartSettled: true,
    }),
  });
  const ssh: unknown[] = [];
  const order: string[] = [];
  h.bridge.onColdStartIntentsSettled(() => order.push('settled'));
  h.bridge.onSshDeepLink((payload) => {
    ssh.push(payload);
    order.push('ssh');
  });
  await h.flush();
  assert.deepEqual(ssh, [{ url: 'ssh://a@h', tabName: 'Prod' }]);
  assert.equal(h.invokes.filter((i) => i.cmd === 'integration_renderer_attach').length, 1);
  assert.deepEqual(order, ['ssh', 'settled']);

  // The open-terminal intent waits in the buffer for its subscriber.
  const opened: unknown[] = [];
  h.bridge.onOpenTerminalPath((payload) => opened.push(payload));
  await h.flush();
  assert.deepEqual(opened, [{ path: '/tmp' }]);
});

test('the bridge listens before attaching, so live intents are never lost', async () => {
  const h = setup({
    attach: () => {
      // Rust may emit right after attach returns.
      assert.ok(h.listeners.get(INTEGRATION_EVENTS.telnetDeepLink)?.size, 'listener exists before attach');
      return { intents: [], coldStartSettled: true };
    },
  });
  const telnet: unknown[] = [];
  h.bridge.onTelnetDeepLink((payload) => telnet.push(payload));
  await h.flush();
  h.emit(INTEGRATION_EVENTS.telnetDeepLink, { url: 'telnet://router' });
  assert.deepEqual(telnet, [{ url: 'telnet://router' }]);
});

test('live intents without a subscriber are buffered for the next one', async () => {
  const h = setup();
  h.bridge.onColdStartIntentsSettled(() => {});
  await h.flush();
  h.emit(INTEGRATION_EVENTS.jmsDeepLink, { url: 'jms://payload' });
  const jms: unknown[] = [];
  const off = h.bridge.onJmsDeepLink((payload) => jms.push(payload));
  await h.flush();
  assert.deepEqual(jms, [{ url: 'jms://payload' }]);
  off();
  h.emit(INTEGRATION_EVENTS.jmsDeepLink, { url: 'jms://second' });
  const again: unknown[] = [];
  h.bridge.onJmsDeepLink((payload) => again.push(payload));
  await h.flush();
  assert.deepEqual(again, [{ url: 'jms://second' }]);
  assert.deepEqual(jms, [{ url: 'jms://payload' }]);
});

test('a failed attach still settles cold start', async () => {
  const h = setup({ attachFails: true });
  let settled = 0;
  h.bridge.onColdStartIntentsSettled(() => {
    settled += 1;
  });
  await h.flush();
  assert.equal(settled, 1);
  assert.deepEqual(h.warnings, ['integration_renderer_attach']);
  // Late subscribers see the settled state immediately.
  h.bridge.onColdStartIntentsSettled(() => {
    settled += 1;
  });
  await h.flush();
  assert.equal(settled, 2);
});

test('other windows never attach and are settled immediately', async () => {
  const h = setup({ label: 'settings' });
  let settled = false;
  h.bridge.onColdStartIntentsSettled(() => {
    settled = true;
  });
  const off = h.bridge.onSshDeepLink(() => assert.fail('settings never receives deep links'));
  await h.flush();
  assert.equal(settled, true);
  assert.equal(h.invokes.length, 0);
  off();
});

test('preference and icon commands use the Electron payload semantics', async () => {
  const h = setup();
  await h.bridge.getSshDeepLinkEnabled();
  await h.bridge.setSshDeepLinkEnabled(false);
  await h.bridge.setJmsDeepLinkEnabled(true);
  await h.bridge.getJmsDeepLinkEnabled();
  await h.bridge.getExplorerContextMenuEnabled();
  await h.bridge.setExplorerContextMenuEnabled(true);
  await h.bridge.setAppIconVariant('bright');
  assert.deepEqual(h.invokes, [
    { cmd: 'integration_get_ssh_deep_link_enabled', args: undefined },
    { cmd: 'integration_set_ssh_deep_link_enabled', args: { enabled: false } },
    { cmd: 'integration_set_jms_deep_link_enabled', args: { enabled: true } },
    { cmd: 'integration_get_jms_deep_link_enabled', args: undefined },
    { cmd: 'integration_get_explorer_context_menu_enabled', args: undefined },
    { cmd: 'integration_set_explorer_context_menu_enabled', args: { enabled: true } },
    { cmd: 'integration_set_app_icon_variant', args: { variant: 'bright' } },
  ]);
});

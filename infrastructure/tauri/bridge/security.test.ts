import assert from 'node:assert/strict';
import test from 'node:test';

import { EventHub } from '../tauriApi';
import { SECURITY_EVENTS, createSecurityBridge } from './security';

interface InvokeRecord {
  cmd: string;
  args: unknown;
}

const setup = () => {
  const invokes: InvokeRecord[] = [];
  const responses = new Map<string, (args: unknown) => unknown>();
  const listeners = new Map<string, Set<(payload: unknown) => void>>();
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
  const bridge = createSecurityBridge({
    hub,
    invoke: async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
      invokes.push({ cmd, args });
      const responder = responses.get(cmd);
      return (responder ? responder(args) : undefined) as T;
    },
  });
  const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
  return {
    bridge,
    invokes,
    emit,
    flush,
    respond: (cmd: string, fn: (args: unknown) => unknown) => responses.set(cmd, fn),
    last: (cmd: string) => {
      const record = [...invokes].reverse().find((entry) => entry.cmd === cmd);
      assert.ok(record, `expected an invoke of ${cmd}`);
      return record;
    },
  };
};

test('app lock methods map to app_lock_* commands with Electron argument shapes', async () => {
  const { bridge, last, respond } = setup();
  const state = {
    initialized: true,
    locked: true,
    reason: 'startup' as const,
    version: 1,
    lastLockedAt: 1,
    lastUnlockedAt: null,
    lastActivityAt: 1,
  };
  respond('app_lock_get_runtime_state', () => state);
  assert.deepEqual(await bridge.getAppLockRuntimeState(), state);

  await bridge.getAppLockSettings();
  last('app_lock_get_settings');
  await bridge.setAppLockTimeoutMinutes(5);
  assert.deepEqual(last('app_lock_set_timeout_minutes').args, { timeoutMinutes: 5 });
  await bridge.requestAppLockEnable();
  last('app_lock_request_enable');
  await bridge.requestAppLockDisable('pw');
  assert.deepEqual(last('app_lock_request_disable').args, { currentPassword: 'pw' });
  await bridge.requestAppLockReset('pw');
  assert.deepEqual(last('app_lock_request_reset').args, { currentPassword: 'pw' });
  await bridge.requestAppLockPasswordChange({ currentPassword: 'a', nextPassword: 'b' });
  assert.deepEqual(last('app_lock_request_password_change').args, {
    input: { currentPassword: 'a', nextPassword: 'b' },
  });
  await bridge.setAppLockRuntimeLocked('manual');
  assert.deepEqual(last('app_lock_set_locked').args, { reason: 'manual' });
  respond('app_lock_request_unlock', () => ({ ok: false, error: 'incorrect' }));
  assert.deepEqual(await bridge.requestAppLockUnlock('x'), { ok: false, error: 'incorrect' });
  assert.deepEqual(last('app_lock_request_unlock').args, { password: 'x' });
  await bridge.getAppLockSystemUnlockStatus();
  last('app_lock_get_system_unlock_status');
  await bridge.setAppLockSystemUnlockEnabled({ enabled: true, autoPromptEnabled: false });
  assert.deepEqual(last('app_lock_set_system_unlock_enabled').args, {
    input: { enabled: true, autoPromptEnabled: false },
  });
  await bridge.requestAppLockSystemUnlock();
  last('app_lock_request_system_unlock');
  assert.equal(await bridge.reportAppLockActivity(), undefined);
  last('app_lock_report_activity');
});

test('app lock events keep the Electron channels and payloads', async () => {
  const { bridge, emit, flush } = setup();
  const states: unknown[] = [];
  const settings: unknown[] = [];
  let reopened = 0;
  const offState = bridge.onAppLockRuntimeStateChanged((s) => states.push(s));
  bridge.onAppLockSettingsChanged((s) => settings.push(s));
  const offReopen = bridge.onAppLockReopen(() => {
    reopened += 1;
  });
  await flush();
  emit(SECURITY_EVENTS.appLockRuntimeStateChanged, { locked: true, reason: 'idle' });
  emit(SECURITY_EVENTS.appLockSettingsChanged, { enabled: true });
  emit(SECURITY_EVENTS.appLockReopen, null);
  assert.deepEqual(states, [{ locked: true, reason: 'idle' }]);
  assert.deepEqual(settings, [{ enabled: true }]);
  assert.equal(reopened, 1);
  offState();
  offReopen();
  emit(SECURITY_EVENTS.appLockRuntimeStateChanged, { locked: false });
  emit(SECURITY_EVENTS.appLockReopen, null);
  assert.equal(states.length, 1);
  assert.equal(reopened, 1);
});

test('FIDO prompts: events and respond', async () => {
  const { bridge, emit, flush, last } = setup();
  const requests: unknown[] = [];
  const timeouts: unknown[] = [];
  const cancelled: unknown[] = [];
  bridge.onFidoPromptRequest((r) => requests.push(r));
  bridge.onFidoPromptTimeout((r) => timeouts.push(r));
  bridge.onFidoPromptCancelled((r) => cancelled.push(r));
  await flush();
  const request = {
    requestId: 'pin-1',
    kind: 'pin',
    message: 'Enter PIN',
    title: '',
    keyName: 'YubiKey',
    notificationOnly: false,
    allowPasswordFallback: false,
  };
  emit(SECURITY_EVENTS.fidoPromptRequest, request);
  emit(SECURITY_EVENTS.fidoPromptTimeout, { requestId: 'pin-1' });
  emit(SECURITY_EVENTS.fidoPromptCancelled, { requestId: 'touch-2', reason: 'helper-exited' });
  assert.deepEqual(requests, [request]);
  assert.deepEqual(timeouts, [{ requestId: 'pin-1' }]);
  assert.deepEqual(cancelled, [{ requestId: 'touch-2', reason: 'helper-exited' }]);

  await bridge.respondFidoPrompt('pin-1', '123456');
  assert.deepEqual(last('fido_prompt_respond').args, { requestId: 'pin-1', response: '123456', cancelled: false });
  await bridge.respondFidoPrompt('pin-1', '', true);
  assert.deepEqual(last('fido_prompt_respond').args, { requestId: 'pin-1', response: '', cancelled: true });
});

test('generateKeyPair routes security-key types to the FIDO command', async () => {
  const { bridge, invokes } = setup();
  await bridge.generateKeyPair({ type: 'ED25519-SK', comment: 'c', resident: true, verifyRequired: true });
  await bridge.generateKeyPair({ type: 'ECDSA-SK' });
  await bridge.generateKeyPair({ type: 'ED25519', comment: 'c' });
  assert.deepEqual(invokes.map((i) => i.cmd), ['fido_generate_key_pair', 'fido_generate_key_pair', 'ssh_generate_key_pair']);
  assert.deepEqual(invokes[0].args, {
    payload: { type: 'ED25519-SK', comment: 'c', resident: true, verifyRequired: true },
  });
  assert.deepEqual(invokes[2].args, { payload: { type: 'ED25519', comment: 'c' } });
});

test('TOTP screen scan and SSH debug log commands', async () => {
  const { bridge, respond, last } = setup();
  respond('totp_scan_screen', () => ({ ok: false, error: 'screen-permission-denied' }));
  assert.deepEqual(await bridge.scanTotpQrFromScreen(), { ok: false, error: 'screen-permission-denied' });
  respond('ssh_debug_log_info', () => ({ enabled: false, path: '/tmp/netcatty-ssh.log', exists: false, size: 0 }));
  assert.deepEqual(await bridge.getSshDebugLogInfo(), {
    enabled: false,
    path: '/tmp/netcatty-ssh.log',
    exists: false,
    size: 0,
  });
  await bridge.openSshDebugLogDir();
  last('ssh_debug_log_open_dir');
});

import assert from 'node:assert/strict';
import test from 'node:test';

import { FlowPauseCoordinator, createTauriBridge, encodeByteStringBase64, knownHostsToText } from './createTauriBridge';
import { EventHub, SessionDataBacklog, TauriBridgeError, normalizeTauriError } from './tauriApi';

type Listener = (event: { event: string; id: number; payload: unknown }) => void;

interface InvokeRecord {
  cmd: string;
  args: unknown;
  options: unknown;
}

/**
 * Minimal `window.__TAURI__` stand-in: records every invoke, lets a test
 * choose the response per command and emit events to registered listeners.
 */
const createFakeTauri = () => {
  const invokes: InvokeRecord[] = [];
  const responses = new Map<string, (args: unknown, options: unknown) => unknown>();
  const listeners = new Map<string, Set<Listener>>();
  let listenCalls = 0;

  const tauri: NetcattyTauriGlobal = {
    core: {
      invoke: async <T>(cmd: string, args?: unknown, options?: unknown): Promise<T> => {
        invokes.push({ cmd, args, options });
        const responder = responses.get(cmd);
        if (!responder) return undefined as T;
        return responder(args, options) as T;
      },
    },
    event: {
      listen: async <T>(event: string, handler: (event: { event: string; id: number; payload: T }) => void) => {
        listenCalls += 1;
        let set = listeners.get(event);
        if (!set) {
          set = new Set();
          listeners.set(event, set);
        }
        const listener = handler as Listener;
        set.add(listener);
        return () => {
          set?.delete(listener);
        };
      },
    },
  };

  const emit = (event: string, payload: unknown) => {
    for (const listener of Array.from(listeners.get(event) ?? [])) {
      listener({ event, id: 1, payload });
    }
  };

  return {
    tauri,
    invokes,
    emit,
    respond: (cmd: string, fn: (args: unknown, options: unknown) => unknown) => responses.set(cmd, fn),
    listenerCount: (event: string) => listeners.get(event)?.size ?? 0,
    get listenCalls() {
      return listenCalls;
    },
  };
};

const installWindow = (tauri: NetcattyTauriGlobal) => {
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: { __TAURI__: tauri, __TAURI_INTERNALS__: {} },
  });
};

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const setup = () => {
  const fake = createFakeTauri();
  installWindow(fake.tauri);
  const bridge = createTauriBridge();
  return { fake, bridge };
};

const lastInvoke = (fake: ReturnType<typeof createFakeTauri>, cmd: string): InvokeRecord => {
  const record = [...fake.invokes].reverse().find((entry) => entry.cmd === cmd);
  assert.ok(record, `expected an invoke of ${cmd}`);
  return record;
};

test('startSSHSession sends the options as payload and unwraps sessionId', async () => {
  const { fake, bridge } = setup();
  fake.respond('session_start_ssh', () => ({ sessionId: 'sess-42' }));

  const sessionId = await bridge.startSSHSession({ hostname: 'example.com', username: 'root', port: 2222 });

  assert.equal(sessionId, 'sess-42');
  const record = lastInvoke(fake, 'session_start_ssh');
  assert.deepEqual(record.args, { payload: { hostname: 'example.com', username: 'root', port: 2222 } });
  // Session events were subscribed eagerly before the start command ran.
  assert.equal(fake.listenerCount('netcatty:data'), 1);
  assert.equal(fake.listenerCount('netcatty:exit'), 1);
});

test('writeToSession base64-encodes binary writes and forwards the write flags', async () => {
  const { fake, bridge } = setup();
  const bytes = String.fromCharCode(0x1b, 0x5b, 0xff, 0x00);

  bridge.writeToSession('s1', bytes, { binary: true, automated: true, sensitive: true, pasteRequestId: 'p1', lineDelayMs: 25 });
  bridge.writeToSession('s1', 'ls\n');
  await flush();

  const writes = fake.invokes.filter((entry) => entry.cmd === 'session_write');
  assert.equal(writes.length, 2);
  assert.deepEqual(writes[0].args, {
    payload: {
      sessionId: 's1',
      data: Buffer.from([0x1b, 0x5b, 0xff, 0x00]).toString('base64'),
      binary: true,
      automated: true,
      sensitive: true,
      pasteRequestId: 'p1',
      lineDelayMs: 25,
    },
  });
  assert.deepEqual(writes[1].args, {
    payload: {
      sessionId: 's1',
      data: 'ls\n',
      binary: false,
      automated: false,
      sensitive: false,
      pasteRequestId: undefined,
      lineDelayMs: undefined,
    },
  });
  assert.equal(encodeByteStringBase64(bytes), Buffer.from([0x1b, 0x5b, 0xff, 0x00]).toString('base64'));
});

test('onSessionData filters by session, replays the backlog once and stops after unsubscribe', async () => {
  const { fake, bridge } = setup();
  await flush();

  // Output before any listener is parked in the backlog.
  fake.emit('netcatty:data', { sessionId: 'a', data: 'early-a ' });
  fake.emit('netcatty:data', { sessionId: 'b', data: 'early-b ' });

  const receivedA: string[] = [];
  const receivedPlain: string[] = [];
  const unsubscribeA = bridge.onSessionData('a', (data) => receivedA.push(data), { replayBacklog: true });
  const unsubscribePlain = bridge.onSessionData('a', (data) => receivedPlain.push(data));

  assert.deepEqual(receivedA, ['early-a ']);
  assert.deepEqual(receivedPlain, [], 'non-replay listeners do not get the backlog');

  fake.emit('netcatty:data', { sessionId: 'a', data: 'live-a' });
  fake.emit('netcatty:data', { sessionId: 'b', data: 'live-b' });
  assert.deepEqual(receivedA, ['early-a ', 'live-a']);
  assert.deepEqual(receivedPlain, ['live-a']);

  // A second replay subscriber does not see data that was already delivered.
  const late: string[] = [];
  const unsubscribeLate = bridge.onSessionData('a', (data) => late.push(data), { replayBacklog: true });
  assert.deepEqual(late, []);

  unsubscribeA();
  unsubscribePlain();
  unsubscribeLate();
  fake.emit('netcatty:data', { sessionId: 'a', data: 'after-unsubscribe' });
  assert.deepEqual(receivedA, ['early-a ', 'live-a']);
  assert.deepEqual(receivedPlain, ['live-a']);

  // Session b's backlog is still waiting for its first display listener.
  const receivedB: string[] = [];
  bridge.onSessionData('b', (data) => receivedB.push(data), { replayBacklog: true });
  assert.deepEqual(receivedB, ['early-b live-b']);
});

test('onSessionExit delivers the exit payload for its session only and clears the backlog', async () => {
  const { fake, bridge } = setup();
  await flush();

  const exits: unknown[] = [];
  const unsubscribe = bridge.onSessionExit('a', (evt) => exits.push(evt));
  fake.emit('netcatty:data', { sessionId: 'a', data: 'pending' });
  fake.emit('netcatty:exit', { sessionId: 'b', reason: 'closed', exitCode: 0 });
  fake.emit('netcatty:exit', { sessionId: 'a', reason: 'exited', exitCode: 1, remoteClosedWithoutExitStatus: false });

  assert.deepEqual(exits, [{
    exitCode: 1,
    signal: undefined,
    exitSignal: undefined,
    error: undefined,
    reason: 'exited',
    remoteClosedWithoutExitStatus: false,
  }]);

  const replayed: string[] = [];
  bridge.onSessionData('a', (data) => replayed.push(data), { replayBacklog: true });
  assert.deepEqual(replayed, [], 'backlog is dropped on exit');

  unsubscribe();
  fake.emit('netcatty:exit', { sessionId: 'a', reason: 'closed' });
  assert.equal(exits.length, 1);
});

test('readSftpBinary passes the ArrayBuffer through untouched', async () => {
  const { fake, bridge } = setup();
  const buffer = new Uint8Array([1, 2, 3, 4]).buffer;
  fake.respond('sftp_read_binary', () => buffer);

  const result = await bridge.readSftpBinary!('sftp-1', '/tmp/é.bin', 'utf-8');

  assert.equal(result, buffer);
  assert.deepEqual(lastInvoke(fake, 'sftp_read_binary').args, { sftpId: 'sftp-1', path: '/tmp/é.bin', encoding: 'utf-8' });
});

test('writeLocalFile sends the raw bytes with a percent-encoded path header', async () => {
  const { fake, bridge } = setup();
  const bytes = new Uint8Array([104, 105]).buffer;

  await bridge.writeLocalFile!('/tmp/ünï code/file.txt', bytes);

  const record = lastInvoke(fake, 'local_write_file');
  assert.equal(record.args, bytes);
  assert.deepEqual(record.options, { headers: { path: encodeURIComponent('/tmp/ünï code/file.txt') } });
});

test('writeSftpBinary sends sftpId/path/encoding headers and omits undefined ones', async () => {
  const { fake, bridge } = setup();
  const bytes = new Uint8Array([1]).buffer;

  await bridge.writeSftpBinary!('sftp-9', '/remote/日本.txt', bytes);

  const record = lastInvoke(fake, 'sftp_write_binary');
  assert.equal(record.args, bytes);
  assert.deepEqual(record.options, {
    headers: { sftpId: 'sftp-9', path: encodeURIComponent('/remote/日本.txt') },
  });
});

test('respondHostKeyVerification sends { requestId, accept, addToKnownHosts }', async () => {
  const { fake, bridge } = setup();
  fake.respond('ssh_respond_host_key', () => ({ success: true }));

  const result = await bridge.respondHostKeyVerification!('req-1', true, true);
  assert.deepEqual(result, { success: true });
  assert.deepEqual(lastInvoke(fake, 'ssh_respond_host_key').args, {
    payload: { requestId: 'req-1', accept: true, addToKnownHosts: true },
  });

  await bridge.respondHostKeyVerification!('req-2', false);
  assert.deepEqual(lastInvoke(fake, 'ssh_respond_host_key').args, {
    payload: { requestId: 'req-2', accept: false, addToKnownHosts: false },
  });
});

test('passphrase responses distinguish answer, cancel and skip', async () => {
  const { fake, bridge } = setup();

  await bridge.respondPassphrase!('r1', 'secret');
  assert.deepEqual(lastInvoke(fake, 'ssh_respond_passphrase').args, {
    payload: { requestId: 'r1', passphrase: 'secret', cancelled: false, skip: false },
  });
  await bridge.respondPassphrase!('r2', '', true);
  assert.deepEqual(lastInvoke(fake, 'ssh_respond_passphrase').args, {
    payload: { requestId: 'r2', passphrase: undefined, cancelled: true, skip: false },
  });
  await bridge.respondPassphraseSkip!('r3');
  assert.deepEqual(lastInvoke(fake, 'ssh_respond_passphrase').args, {
    payload: { requestId: 'r3', cancelled: false, skip: true },
  });
});

test('global prompt events are delivered once per subscriber and unsubscribe stops delivery', async () => {
  const { fake, bridge } = setup();
  const seen: unknown[] = [];
  const unsubscribe = bridge.onHostKeyVerification!((request) => seen.push(request));
  bridge.onKeyboardInteractive!(() => undefined);
  await flush();

  const request = { requestId: 'hk-1', sessionId: 's', hostname: 'h', port: 22, status: 'unknown', keyType: 'ssh-ed25519', fingerprint: 'abc' };
  fake.emit('netcatty:host-key:verify', request);
  assert.deepEqual(seen, [request]);
  // One Tauri listener per event name, regardless of subscriber count.
  assert.equal(fake.listenerCount('netcatty:host-key:verify'), 1);

  unsubscribe();
  fake.emit('netcatty:host-key:verify', { ...request, requestId: 'hk-2' });
  assert.equal(seen.length, 1);
});

test('port forwarding maps wire shapes to the renderer contract', async () => {
  const { fake, bridge } = setup();
  fake.respond('portforward_snapshot', () => ({
    epoch: 7,
    revision: 3,
    tunnels: [{ tunnelId: 't1', ruleId: 'r1', type: 'local', status: 'active', localPort: 8080, bindAddress: '127.0.0.1', hostname: 'h', updatedAt: 1000 }],
  }));
  fake.respond('portforward_status', () => ({ status: 'unknown' }));
  fake.respond('portforward_stop', () => ({ success: true }));

  assert.deepEqual(await bridge.getPortForwardSnapshot!(), {
    epoch: '7',
    revision: 3,
    records: [{ ruleId: 'r1', tunnelId: 't1', phase: 'active', error: undefined, revision: 3, updatedAt: 1000 }],
  });
  assert.deepEqual(await bridge.getPortForwardStatus!('t1'), { tunnelId: 't1', status: 'inactive', error: undefined });
  assert.deepEqual(await bridge.stopPortForward!('t1'), { tunnelId: 't1', success: true, error: undefined });

  const statuses: Array<[string, string | undefined]> = [];
  const runtime: unknown[] = [];
  bridge.onPortForwardStatus!('t1', (status, error) => statuses.push([status, error]));
  bridge.onPortForwardRuntime!((event) => runtime.push(event));
  await flush();
  fake.emit('netcatty:portforward:status', { tunnelId: 't2', status: 'active', epoch: 1, revision: 1 });
  fake.emit('netcatty:portforward:status', { tunnelId: 't1', status: 'error', error: 'boom', epoch: 1, revision: 2 });
  fake.emit('netcatty:portforward:runtime', { kind: 'remove', epoch: 1, revision: 3, tunnelId: 't1' });
  assert.deepEqual(statuses, [['error', 'boom']]);
  assert.deepEqual(runtime, [{ epoch: '1', revision: 3, kind: 'remove', tunnelId: 't1' }]);
});

test('listLocalTree streams progress and entries for its own scanId only', async () => {
  const { fake, bridge } = setup();
  const entries = [{ localPath: '/a/x', relativePath: 'x', type: 'file', size: 1, lastModified: 1 }];
  fake.respond('local_list_tree', (args) => {
    const scanId = (args as { scanId: string }).scanId;
    fake.emit('netcatty:local:tree-progress', { scanId: 'other', fileCount: 99, directoryCount: 0, entryCount: 99, entries });
    fake.emit('netcatty:local:tree-progress', { scanId, fileCount: 1, directoryCount: 0, entryCount: 1, entries });
    fake.emit('netcatty:local:tree-progress', { scanId, fileCount: 1, directoryCount: 0, entryCount: 1, entries: [], done: true });
    return entries;
  });

  const progress: unknown[] = [];
  const streamed: unknown[] = [];
  const result = await bridge.listLocalTree!('/a', {
    scanId: 'scan-1',
    onProgress: (stats) => progress.push(stats),
    onEntries: (batch) => streamed.push(batch),
    limits: { maxEntries: 10 },
  });

  assert.deepEqual(result, entries);
  assert.deepEqual(lastInvoke(fake, 'local_list_tree').args, { scanId: 'scan-1', path: '/a', limits: { maxEntries: 10 } });
  assert.deepEqual(progress, [
    { fileCount: 1, directoryCount: 0, entryCount: 1 },
    { fileCount: 1, directoryCount: 0, entryCount: 1 },
  ]);
  assert.deepEqual(streamed, [entries]);
});

test('rejected invokes surface as TauriBridgeError carrying the backend code', async () => {
  const { fake, bridge } = setup();
  fake.respond('sftp_list', () => {
    throw { code: 'NOT_FOUND', message: 'no such directory' };
  });

  await assert.rejects(bridge.listSftp('s', '/missing'), (error: unknown) => {
    assert.ok(error instanceof TauriBridgeError);
    assert.equal(error.code, 'NOT_FOUND');
    assert.equal(error.message, 'no such directory');
    return true;
  });
  assert.equal(normalizeTauriError('plain string').code, 'INTERNAL');
  assert.equal(normalizeTauriError(new Error('x')).message, 'x');
});

test('plugin-backed methods go through invoke("plugin:…") when no plugin global exists', async () => {
  const fake = createFakeTauri();
  installWindow(fake.tauri);
  const bridge = createTauriBridge();
  fake.respond('plugin:dialog|open', (args) => ((args as { options: { directory?: boolean } }).options.directory ? '/picked/dir' : ['/picked/file']));
  fake.respond('plugin:clipboard-manager|read_text', () => 'from-pasteboard');

  assert.equal(await bridge.selectDirectory!('Pick', '/start'), '/picked/dir');
  assert.deepEqual(lastInvoke(fake, 'plugin:dialog|open').args, {
    options: { directory: true, multiple: false, title: 'Pick', defaultPath: '/start' },
  });
  assert.equal(await bridge.selectFile!(), '/picked/file');
  assert.equal(await bridge.readClipboardText!(), 'from-pasteboard');
  assert.equal(await bridge.writeClipboardText!('copied'), true);
  assert.deepEqual(lastInvoke(fake, 'plugin:clipboard-manager|write_text').args, { text: 'copied', label: undefined });
  await bridge.openExternal!('https://example.com');
  assert.deepEqual(lastInvoke(fake, 'plugin:opener|open_url').args, { url: 'https://example.com', with: undefined });
  // No Rust counterpart: stays undefined rather than faking success.
  assert.equal(bridge.startMoshSession, undefined);
  assert.equal(bridge.checkForUpdate, undefined);
});

test('dialog, clipboard and opener plugins are wired through the global API', async () => {
  const fake = createFakeTauri();
  const calls: unknown[] = [];
  fake.tauri.dialog = {
    open: async (opts) => {
      calls.push(['open', opts]);
      return opts?.directory ? '/picked/dir' : ['/picked/file'];
    },
    save: async (opts) => {
      calls.push(['save', opts]);
      return null;
    },
  };
  fake.tauri.clipboardManager = {
    readText: async () => 'clip',
    writeText: async (text) => {
      calls.push(['write', text]);
    },
  };
  fake.tauri.opener = {
    openUrl: async (url) => {
      calls.push(['url', url]);
    },
    openPath: async () => {
      throw new Error('no handler');
    },
  };
  installWindow(fake.tauri);
  const bridge = createTauriBridge();

  assert.equal(await bridge.selectDirectory!('Pick', '/home'), '/picked/dir');
  assert.equal(await bridge.selectFile!('Pick file'), '/picked/file');
  assert.equal(await bridge.showSaveDialog!('/home/out.txt', [{ name: 'Text', extensions: ['txt'] }]), null);
  assert.equal(await bridge.readClipboardText!(), 'clip');
  assert.equal(await bridge.writeClipboardText!('hello'), true);
  await bridge.openExternal!('https://example.com');
  assert.deepEqual(await bridge.openWithSystemDefault!('/x'), { success: false, error: 'no handler' });
  assert.deepEqual(calls, [
    ['open', { directory: true, multiple: false, title: 'Pick', defaultPath: '/home' }],
    ['open', { multiple: false, title: 'Pick file', defaultPath: undefined, filters: undefined }],
    ['save', { defaultPath: '/home/out.txt', filters: [{ name: 'Text', extensions: ['txt'] }] }],
    ['write', 'hello'],
    ['url', 'https://example.com'],
  ]);
});

test('readKnownHosts rebuilds known_hosts text from parsed entries', async () => {
  const { fake, bridge } = setup();
  fake.respond('ssh_read_known_hosts', () => [
    { id: '1', hostname: 'example.com', port: 22, keyType: 'ssh-ed25519', publicKey: 'AAAA1' },
    { id: '2', hostname: '10.0.0.1', port: 2222, keyType: 'ssh-rsa', publicKey: 'ssh-rsa AAAA2' },
  ]);
  assert.equal(await bridge.readKnownHosts!(), 'example.com ssh-ed25519 AAAA1\n[10.0.0.1]:2222 ssh-rsa AAAA2');
  assert.equal(knownHostsToText([]), '');

  fake.respond('ssh_read_known_hosts', () => []);
  assert.equal(await bridge.readKnownHosts!(), null);
});

test('SessionDataBacklog keeps only the newest bytes up to its limit', () => {
  const backlog = new SessionDataBacklog(5);
  backlog.append('s', 'abc');
  backlog.append('s', 'defg');
  assert.equal(backlog.size('s'), 5);
  assert.equal(backlog.take('s'), 'cdefg');
  assert.equal(backlog.take('s'), '');
});

test('EventHub subscribes once per event and keeps delivering after a throwing listener', async () => {
  const fake = createFakeTauri();
  const errors: unknown[] = [];
  const hub = new EventHub({
    listen: (event, cb) => fake.tauri.event!.listen!(event, (evt) => cb(evt.payload as never)),
    onError: (_message, error) => errors.push(error),
  });
  const seen: unknown[] = [];
  hub.subscribe('x', () => {
    throw new Error('listener failed');
  });
  const off = hub.subscribe('x', (payload) => seen.push(payload));
  await hub.ensure('x');
  assert.equal(fake.listenCalls, 1);

  fake.emit('x', 1);
  assert.deepEqual(seen, [1]);
  assert.equal(errors.length, 1);
  off();
  fake.emit('x', 2);
  assert.deepEqual(seen, [1]);
});

test('stageUploadFile streams the file into the temp dir in chunks and returns the staged path', async () => {
  const { fake, bridge } = setup();
  const chunks: Array<{ bytes: Uint8Array; headers: Record<string, string> }> = [];
  fake.respond('temp_upload_begin', (args) => {
    const { transferId, fileName } = args as { transferId: string; fileName: string };
    assert.ok(transferId.startsWith('xfer-1-'));
    assert.equal(fileName, 'photo.png');
    return '/tmp/netcatty/.transfer_xfer-1_photo.png.part';
  });
  fake.respond('temp_upload_chunk', (args, options) => {
    const bytes = args as Uint8Array;
    chunks.push({ bytes: new Uint8Array(bytes), headers: (options as { headers: Record<string, string> }).headers });
    return chunks.reduce((n, c) => n + c.bytes.byteLength, 0);
  });

  const file = new File([new Uint8Array([1, 2, 3, 4, 5])], 'photo.png');
  const path = await bridge.stageUploadFile!(file, 'xfer-1');

  assert.equal(path, '/tmp/netcatty/.transfer_xfer-1_photo.png.part');
  assert.equal(chunks.length, 1);
  assert.deepEqual(Array.from(chunks[0].bytes), [1, 2, 3, 4, 5]);
  assert.equal(chunks[0].headers.path, encodeURIComponent(path));
  assert.equal(fake.invokes.some((i) => i.cmd === 'temp_delete_file'), false);
});

test('stageUploadFile deletes the staged file when a chunk fails', async () => {
  const { fake, bridge } = setup();
  fake.respond('temp_upload_begin', () => '/tmp/netcatty/.transfer_x_f.part');
  fake.respond('temp_upload_chunk', () => {
    throw new Error('disk full');
  });

  await assert.rejects(bridge.stageUploadFile!(new File(['abc'], 'f'), 'x'), /disk full/);
  const del = lastInvoke(fake, 'temp_delete_file');
  assert.deepEqual(del.args, { filePath: '/tmp/netcatty/.transfer_x_f.part' });
  assert.deepEqual(await bridge.cancelStagedUploadFile!('x'), { success: false });
});

test('cloud sync methods map to the netcatty-sync commands with Electron-shaped arguments', async () => {
  const { fake, bridge } = setup();
  const webdav = { endpoint: 'https://dav.example.com', authType: 'basic' as const, username: 'u', password: 'p' };
  const s3 = { endpoint: 'https://s3.example.com', region: 'us-east-1', bucket: 'b', accessKeyId: 'a', secretAccessKey: 's' };
  const syncedFile = { meta: { version: 1 }, payload: 'cipher' } as unknown as Parameters<NonNullable<NetcattyBridge['cloudSyncWebdavUpload']>>[1];

  fake.respond('webdav_download', () => ({ syncedFile }));
  assert.deepEqual(await bridge.cloudSyncWebdavDownload!(webdav), { syncedFile });
  await bridge.cloudSyncWebdavUpload!(webdav, syncedFile);
  assert.deepEqual(lastInvoke(fake, 'webdav_upload').args, { config: webdav, syncedFile });
  await bridge.cloudSyncS3Delete!(s3);
  assert.deepEqual(lastInvoke(fake, 's3_delete').args, { config: s3 });

  fake.respond('oauth_prepare_callback', () => ({ sessionId: 'oauth-1', port: 45678, redirectUri: 'http://127.0.0.1:45678/oauth/callback' }));
  assert.equal((await bridge.prepareOAuthCallback!()).sessionId, 'oauth-1');
  await bridge.awaitOAuthCallback!('state-1', 'oauth-1');
  assert.deepEqual(lastInvoke(fake, 'oauth_await_callback').args, { expectedState: 'state-1', sessionId: 'oauth-1' });
  await bridge.cancelOAuthCallback!('oauth-1');
  assert.deepEqual(lastInvoke(fake, 'oauth_cancel_callback').args, { sessionId: 'oauth-1' });

  await bridge.githubStartDeviceFlow!();
  assert.deepEqual(lastInvoke(fake, 'github_device_flow_start').args, { payload: {} });
  await bridge.githubPollDeviceFlowToken!({ deviceCode: 'dc', pollId: 'p1' });
  assert.deepEqual(lastInvoke(fake, 'github_device_flow_poll').args, { payload: { deviceCode: 'dc', pollId: 'p1' } });
  await bridge.githubCancelDeviceFlowPoll!('p1');
  assert.deepEqual(lastInvoke(fake, 'github_device_flow_cancel').args, { pollId: 'p1' });

  const exchange = { clientId: 'c', code: 'x', codeVerifier: 'v', redirectUri: 'http://127.0.0.1:45678/oauth/callback' };
  await bridge.googleExchangeCodeForTokens!(exchange);
  assert.deepEqual(lastInvoke(fake, 'google_oauth_exchange').args, { payload: exchange });
  await bridge.onedriveDownloadSyncFile!({ accessToken: 't', fileId: 'f' });
  assert.deepEqual(lastInvoke(fake, 'onedrive_download_sync_file').args, { payload: { accessToken: 't', fileId: 'f' } });
});

test('cloud sync session password round-trips and announces availability', async () => {
  const { fake, bridge } = setup();
  fake.respond('cloudsync_password_get', () => 'hunter2');

  let notified = 0;
  const off = bridge.onCloudSyncSessionPasswordAvailable!(() => {
    notified += 1;
  });
  await flush();

  await bridge.cloudSyncSetSessionPassword!('hunter2');
  assert.deepEqual(lastInvoke(fake, 'cloudsync_password_set').args, { password: 'hunter2' });
  assert.equal(await bridge.cloudSyncGetSessionPassword!(), 'hunter2');

  fake.emit('netcatty:cloudsync:password-available', null);
  assert.equal(notified, 1);
  off();
  fake.emit('netcatty:cloudsync:password-available', null);
  assert.equal(notified, 1);

  await bridge.cloudSyncClearSessionPassword!();
  assert.ok(fake.invokes.some((entry) => entry.cmd === 'cloudsync_password_clear'));
});

// ---------------------------------------------------------------------------
// Remote desktop (VNC / RDP)
// ---------------------------------------------------------------------------

/** `window.__TAURI__.core.Channel` stand-in that remembers its instances. */
const installFakeChannel = (fake: ReturnType<typeof createFakeTauri>) => {
  const channels: Array<{ onmessage: (message: unknown) => void }> = [];
  class FakeChannel {
    onmessage: (message: unknown) => void = () => {};
    constructor() {
      channels.push(this);
    }
  }
  fake.tauri.core!.Channel = FakeChannel as unknown as NonNullable<NetcattyTauriGlobal['core']>['Channel'];
  return channels;
};

test('startRemoteDesktopSession passes a channel and decodes its JSON and binary messages', async () => {
  const { fake, bridge } = setup();
  const channels = installFakeChannel(fake);
  fake.respond('rdesktop_connect', () => ({ sessionId: 'rd-1' }));
  const events: unknown[] = [];

  const sessionId = await bridge.startRemoteDesktopSession!(
    { protocol: 'vnc', hostname: 'desk.example.test', port: 5901, password: 'pw' },
    (event) => events.push(event),
  );

  assert.equal(sessionId, 'rd-1');
  assert.equal(channels.length, 1);
  const record = lastInvoke(fake, 'rdesktop_connect');
  const args = record.args as { payload: unknown; onEvent: unknown };
  assert.deepEqual(args.payload, { protocol: 'vnc', hostname: 'desk.example.test', port: 5901, password: 'pw' });
  assert.equal(args.onEvent, channels[0], 'the channel travels as the top-level onEvent argument');

  channels[0].onmessage({ type: 'connected', width: 2, height: 1 });
  // [1][x=3][y=4][w=2][h=1] + two RGBA pixels.
  const frame = new Uint8Array([1, 3, 0, 4, 0, 2, 0, 1, 0, 10, 20, 30, 255, 40, 50, 60, 255]);
  channels[0].onmessage(frame.buffer);
  // [2][srcX=1][srcY=2][dstX=3][dstY=4][w=5][h=6]
  channels[0].onmessage(new Uint8Array([2, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0]).buffer);
  // Malformed and unknown messages are dropped instead of reaching the view.
  channels[0].onmessage(new Uint8Array([1, 0, 0]).buffer);
  channels[0].onmessage({ type: 'mystery' });
  channels[0].onmessage({ type: 'closed', error: 'gone' });

  assert.equal(events.length, 4);
  assert.deepEqual(events[0], { type: 'connected', width: 2, height: 1 });
  const decoded = events[1] as { type: string; x: number; y: number; width: number; height: number; rgba: Uint8ClampedArray };
  assert.deepEqual(
    { type: decoded.type, x: decoded.x, y: decoded.y, width: decoded.width, height: decoded.height },
    { type: 'frame', x: 3, y: 4, width: 2, height: 1 },
  );
  assert.deepEqual(Array.from(decoded.rgba), [10, 20, 30, 255, 40, 50, 60, 255]);
  assert.deepEqual(events[2], { type: 'copyRect', srcX: 1, srcY: 2, dstX: 3, dstY: 4, width: 5, height: 6 });
  assert.deepEqual(events[3], { type: 'closed', error: 'gone' });
});

test('remote desktop input is batched into one invoke and close is forwarded', async () => {
  const { fake, bridge } = setup();

  bridge.sendRemoteDesktopInput!('rd-1', []);
  assert.equal(fake.invokes.some((entry) => entry.cmd === 'rdesktop_input'), false, 'an empty batch is not sent');

  bridge.sendRemoteDesktopInput!('rd-1', [
    { type: 'pointer', x: 5, y: 6, buttons: 1 },
    { type: 'key', down: true, keysym: 0x61, scancode: 0x1e },
  ]);
  assert.deepEqual(lastInvoke(fake, 'rdesktop_input').args, {
    payload: {
      sessionId: 'rd-1',
      events: [
        { type: 'pointer', x: 5, y: 6, buttons: 1 },
        { type: 'key', down: true, keysym: 0x61, scancode: 0x1e },
      ],
    },
  });

  await bridge.closeRemoteDesktopSession!('rd-1');
  assert.deepEqual(lastInvoke(fake, 'rdesktop_close').args, { sessionId: 'rd-1' });
});

test('startRemoteDesktopSession reports an unsupported runtime when channels are missing', async () => {
  const { bridge } = setup();
  await assert.rejects(
    bridge.startRemoteDesktopSession!({ protocol: 'rdp', hostname: 'h' }, () => {}),
    (error: unknown) => error instanceof TauriBridgeError && error.code === 'UNSUPPORTED',
  );
});

// ---------------------------------------------------------------------------
// Output flow pause leases
// ---------------------------------------------------------------------------

const flowPauseCalls = (fake: ReturnType<typeof createFakeTauri>) => fake.invokes
  .filter((entry) => entry.cmd === 'session_set_flow_paused')
  .map((entry) => (entry.args as { sessionId: string; paused: boolean }).paused);

test('a flow pause lease pauses the output pump and resumes it on release', async () => {
  const { fake, bridge } = setup();

  const acquired = await bridge.acquireSessionFlowPauseLease!('s1');
  assert.equal(acquired.success, true);
  assert.ok(acquired.leaseId);
  assert.deepEqual(flowPauseCalls(fake), [true]);
  assert.deepEqual(await bridge.waitSessionFlowPauseLease!('s1', acquired.leaseId!), { success: true });
  assert.equal((await bridge.waitSessionFlowPauseLease!('s1', 'nope')).success, false);

  // A second lease does not pause again, and the pump stays paused until the last one is back.
  const second = await bridge.acquireSessionFlowPauseLease!('s1');
  await bridge.releaseSessionFlowPauseLease!('s1', acquired.leaseId!);
  assert.deepEqual(flowPauseCalls(fake), [true]);
  await bridge.releaseSessionFlowPauseLease!('s1', second.leaseId!);
  assert.deepEqual(flowPauseCalls(fake), [true, false]);

  // Releasing twice is harmless.
  assert.deepEqual(await bridge.releaseSessionFlowPauseLease!('s1', second.leaseId!), { success: true });
  assert.deepEqual(flowPauseCalls(fake), [true, false]);
});

test('a lease never resumes output the renderer paused itself, and keepPaused leaves the pump alone', async () => {
  const { fake, bridge } = setup();

  // Renderer backpressure pauses first; the lease on top changes nothing on the backend.
  bridge.setSessionFlowPaused('s1', true);
  const lease = await bridge.acquireSessionFlowPauseLease!('s1');
  await bridge.releaseSessionFlowPauseLease!('s1', lease.leaseId!);
  assert.deepEqual(flowPauseCalls(fake), [true], 'still paused: backpressure has not cleared');
  bridge.setSessionFlowPaused('s1', false);
  assert.deepEqual(flowPauseCalls(fake), [true, false]);

  // keepPaused: the session is being replaced, so its pump must not be resumed.
  const kept = await bridge.acquireSessionFlowPauseLease!('s2');
  await bridge.releaseSessionFlowPauseLease!('s2', kept.leaseId!, { keepPaused: true });
  assert.deepEqual(
    fake.invokes
      .filter((entry) => entry.cmd === 'session_set_flow_paused' && (entry.args as { sessionId: string }).sessionId === 's2')
      .map((entry) => (entry.args as { paused: boolean }).paused),
    [true],
  );
});

test('a failed pause reports the error and leaves no lease behind', async () => {
  let fail = true;
  const calls: boolean[] = [];
  const coordinator = new FlowPauseCoordinator(async (_sessionId, paused) => {
    calls.push(paused);
    if (fail) throw new Error('session gone');
  });

  await assert.rejects(coordinator.acquire('s1'), /session gone/);
  // The failed attempt must not make the next one think the pump is already paused.
  fail = false;
  const leaseId = await coordinator.acquire('s1');
  assert.equal(coordinator.holds('s1', leaseId), true);
  assert.deepEqual(calls, [true, true]);
  await coordinator.release('s1', leaseId, false);
  assert.deepEqual(calls, [true, true, false]);
});

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

test('window controls and the settings window map to the window commands', async () => {
  const { fake, bridge } = setup();
  fake.respond('window_open_settings', () => true);
  fake.respond('window_maximize', () => true);
  fake.respond('window_open_main', () => true);

  assert.equal(await bridge.openSettingsWindow!(), true);
  await bridge.closeSettingsWindow!();
  assert.ok(fake.invokes.some((entry) => entry.cmd === 'window_close_settings'));
  assert.equal(await bridge.windowMaximize!(), true);
  await bridge.windowMinimize!();
  assert.ok(fake.invokes.some((entry) => entry.cmd === 'window_minimize'));
  await bridge.setWindowTitle!('prod-db');
  assert.deepEqual(lastInvoke(fake, 'window_set_title').args, { title: 'prod-db' });
  assert.deepEqual(await bridge.openMainWindow!(), { success: true });

  await bridge.setTheme!('dark');
  assert.deepEqual(lastInvoke(fake, 'app_set_theme').args, { theme: 'dark' });
  await bridge.setBackgroundColor!('216 33% 96%');
  assert.deepEqual(lastInvoke(fake, 'app_set_background_color').args, { color: '216 33% 96%' });
  await bridge.setLanguage!('zh-CN');
  assert.deepEqual(lastInvoke(fake, 'app_set_language').args, { language: 'zh-CN' });

  bridge.rendererReady!();
  await flush();
  assert.ok(fake.invokes.some((entry) => entry.cmd === 'window_renderer_ready'));
});

test('settings changes are relayed to other windows but not echoed back', async () => {
  const { fake, bridge } = setup();
  const received: Array<{ key: string; value: unknown }> = [];
  const off = bridge.onSettingsChanged!((payload) => received.push(payload));
  await flush();

  bridge.notifySettingsChanged!({ key: 'netcatty_theme_v1', value: 'dark' });
  await flush();
  assert.deepEqual(lastInvoke(fake, 'app_broadcast_settings_changed').args, {
    payload: { key: 'netcatty_theme_v1', value: 'dark' },
  });

  // Outside a real webview the current window label is "main".
  fake.emit('netcatty:settings:changed', { source: 'main', payload: { key: 'own', value: 1 } });
  fake.emit('netcatty:settings:changed', { source: 'settings', payload: { key: 'other', value: 2 } });
  assert.deepEqual(received, [{ key: 'other', value: 2 }]);
  off();
});

test('language and fullscreen events reach the right listeners', async () => {
  const { fake, bridge } = setup();
  const languages: string[] = [];
  const fullscreen: boolean[] = [];
  bridge.onLanguageChanged!((language) => languages.push(language));
  bridge.onWindowFullScreenChanged!((value) => fullscreen.push(value));
  await flush();

  fake.emit('netcatty:language-changed', 'ja');
  fake.emit('netcatty:window:fullscreen-changed', { label: 'settings', fullscreen: true });
  fake.emit('netcatty:window:fullscreen-changed', { label: 'main', fullscreen: true });
  assert.deepEqual(languages, ['ja']);
  assert.deepEqual(fullscreen, [true]);
});

// ---------------------------------------------------------------------------
// Tray, tray panel, global hotkey, auto launch, system notifications
// ---------------------------------------------------------------------------

/** Pretend the bridge runs in the window labelled `label`. */
const setWindowLabel = (label: string) => {
  const win = (globalThis as unknown as { window: Record<string, unknown> }).window;
  win.__TAURI_INTERNALS__ = { metadata: { currentWindow: { label } } };
};

test('hotkey, tray, auto-launch and notification methods map to their commands', async () => {
  const { fake, bridge } = setup();
  fake.respond('hotkey_register', () => ({ success: true, enabled: true, accelerator: 'Control+`' }));
  fake.respond('hotkey_status', () => ({ enabled: true, hotkey: 'Ctrl + `' }));
  fake.respond('tray_set_close_to_tray', (args) => ({ success: true, enabled: (args as { enabled: boolean }).enabled }));
  fake.respond('autostart_get', () => ({ success: true, enabled: false, supported: true }));
  fake.respond('notification_show', () => ({ shown: false, reason: 'focused' }));

  assert.deepEqual(await bridge.registerGlobalHotkey!('Ctrl + `'), { success: true, enabled: true, accelerator: 'Control+`' });
  assert.deepEqual(lastInvoke(fake, 'hotkey_register').args, { hotkey: 'Ctrl + `' });
  assert.deepEqual(await bridge.getGlobalHotkeyStatus!(), { enabled: true, hotkey: 'Ctrl + `' });
  await bridge.unregisterGlobalHotkey!();
  assert.ok(fake.invokes.some((entry) => entry.cmd === 'hotkey_unregister'));

  assert.deepEqual(await bridge.setCloseToTray!(true), { success: true, enabled: true });
  await bridge.setShowTrayIcon!(false);
  assert.deepEqual(lastInvoke(fake, 'tray_set_show_icon').args, { enabled: false });
  await bridge.isCloseToTray!();
  await bridge.isShowTrayIcon!();
  assert.ok(fake.invokes.some((entry) => entry.cmd === 'tray_is_close_to_tray'));
  assert.ok(fake.invokes.some((entry) => entry.cmd === 'tray_is_show_icon'));

  assert.deepEqual(await bridge.getAutoLaunch!(), { success: true, enabled: false, supported: true });
  await bridge.setAutoLaunch!(true);
  assert.deepEqual(lastInvoke(fake, 'autostart_set').args, { enabled: true });

  const data = { sessions: [{ id: 's1', label: 'web', hostLabel: 'Web', status: 'connected' as const }] };
  await bridge.updateTrayMenuData!(data);
  assert.deepEqual(lastInvoke(fake, 'tray_update_menu_data').args, { payload: data });

  const notification = { title: 'Approval needed', body: 'Run ls?', sessionId: 's1', dedupeKey: 'k', whenUnfocused: true };
  assert.deepEqual(await bridge.showSystemNotification!(notification), { shown: false, reason: 'focused' });
  assert.deepEqual(lastInvoke(fake, 'notification_show').args, { payload: notification });
});

test('tray panel actions invoke the tray_panel commands', async () => {
  const { fake, bridge } = setup();
  fake.respond('tray_panel_start_port_forward', () => ({ success: false, error: 'Main window is not ready' }));

  await bridge.hideTrayPanel!();
  assert.ok(fake.invokes.some((entry) => entry.cmd === 'tray_panel_hide'));
  await bridge.jumpToSessionFromTrayPanel!('s1');
  assert.deepEqual(lastInvoke(fake, 'tray_panel_jump_to_session').args, { sessionId: 's1' });
  await bridge.connectToHostFromTrayPanel!('h1');
  assert.deepEqual(lastInvoke(fake, 'tray_panel_connect_to_host').args, { hostId: 'h1' });
  await bridge.closeSessionFromTrayPanel!('s2');
  assert.deepEqual(lastInvoke(fake, 'tray_panel_close_session').args, { sessionId: 's2' });
  assert.deepEqual(await bridge.startPortForwardFromTrayPanel!('r1'), { success: false, error: 'Main window is not ready' });
  assert.deepEqual(lastInvoke(fake, 'tray_panel_start_port_forward').args, { ruleId: 'r1' });
});

test('tray actions reach the main window only; focusSession follows its label', async () => {
  const { fake, bridge } = setup();
  const focused: string[] = [];
  const toggles: Array<[string, boolean]> = [];
  const jumps: string[] = [];
  const connects: string[] = [];
  const closes: string[] = [];
  const offFocus = bridge.onTrayFocusSession!((id) => focused.push(id));
  const offToggle = bridge.onTrayTogglePortForward!((id, start) => toggles.push([id, start]));
  bridge.onTrayPanelJumpToSession!((id) => jumps.push(id));
  bridge.onTrayPanelConnectToHost!((id) => connects.push(id));
  bridge.onTrayPanelCloseSession!((id) => closes.push(id));
  await flush();

  fake.emit('netcatty:tray:focusSession', { sessionId: 's1', label: 'main' });
  fake.emit('netcatty:tray:focusSession', { sessionId: 's2', label: 'settings' });
  fake.emit('netcatty:tray:togglePortForward', { ruleId: 'r1', start: false });
  fake.emit('netcatty:trayPanel:startPortForward', 'r2');
  fake.emit('netcatty:trayPanel:jumpToSession', 's3');
  fake.emit('netcatty:trayPanel:connectToHost', 'h1');
  fake.emit('netcatty:trayPanel:closeSession', 's4');
  assert.deepEqual(focused, ['s1']);
  assert.deepEqual(toggles, [['r1', false], ['r2', true]]);
  assert.deepEqual(jumps, ['s3']);
  assert.deepEqual(connects, ['h1']);
  assert.deepEqual(closes, ['s4']);

  offToggle();
  fake.emit('netcatty:trayPanel:startPortForward', 'r3');
  assert.equal(toggles.length, 2);
  offFocus();

  // The tray panel window does not act on main-window actions.
  setWindowLabel('tray-panel');
  const panelJumps: string[] = [];
  bridge.onTrayPanelJumpToSession!((id) => panelJumps.push(id));
  bridge.onTrayTogglePortForward!(() => panelJumps.push('toggle'));
  await flush();
  fake.emit('netcatty:trayPanel:jumpToSession', 's5');
  fake.emit('netcatty:trayPanel:startPortForward', 'r4');
  assert.deepEqual(panelJumps, []);
});

test('tray panel menu data is read once on subscribe and then follows pushes', async () => {
  const { fake, bridge } = setup();
  setWindowLabel('tray-panel');
  const current = { sessions: [], portForwardRules: [], hosts: [{ id: 'h1' }] };
  fake.respond('tray_get_menu_data', () => current);
  const received: unknown[] = [];
  let refreshes = 0;
  bridge.onTrayPanelMenuData!((data) => received.push(data));
  bridge.onTrayPanelRefresh!(() => {
    refreshes += 1;
  });
  await flush();
  assert.deepEqual(received, [current]);

  const pushed = { sessions: [{ id: 's1', label: 'a', hostLabel: 'A', status: 'connected' }], portForwardRules: [], hosts: [] };
  fake.emit('netcatty:trayPanel:setMenuData', pushed);
  fake.emit('netcatty:trayPanel:refresh', null);
  assert.deepEqual(received, [current, pushed]);
  assert.equal(refreshes, 1);
});

test('tray panel menu data skips the initial read when a push arrived first', async () => {
  const { fake, bridge } = setup();
  let release: (value: unknown) => void = () => {};
  fake.respond('tray_get_menu_data', () => new Promise((resolve) => {
    release = resolve;
  }));
  const received: unknown[] = [];
  bridge.onTrayPanelMenuData!((data) => received.push(data));
  await flush();
  const pushed = { sessions: [], portForwardRules: [], hosts: [] };
  fake.emit('netcatty:trayPanel:setMenuData', pushed);
  release({ sessions: [], portForwardRules: [], hosts: [{ id: 'stale' }] });
  await flush();
  assert.deepEqual(received, [pushed]);
});

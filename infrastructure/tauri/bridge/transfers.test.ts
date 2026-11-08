import assert from 'node:assert/strict';
import test from 'node:test';

import { createTransfersBridge } from './transfers';

interface InvokeRecord {
  cmd: string;
  args: Record<string, unknown> | undefined;
}

const setup = (responses: Record<string, unknown> = {}, fail: string[] = []) => {
  const invokes: InvokeRecord[] = [];
  const bridge = createTransfersBridge({
    invoke: async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
      invokes.push({ cmd, args });
      if (fail.includes(cmd)) throw new Error(`${cmd} failed`);
      return responses[cmd] as T;
    },
  });
  return { bridge, invokes };
};

test('queue controls map to transfer_* commands', async () => {
  const { bridge, invokes } = setup({
    transfer_prioritize: { success: true },
    transfer_set_concurrency: { success: true, limit: 4 },
    transfer_cleanup: { success: true },
  });
  assert.deepEqual(await bridge.prioritizeTransfer!('t1'), { success: true });
  assert.deepEqual(await bridge.setGlobalTransferConcurrency!(4), { success: true, limit: 4 });
  const payload = { transferId: 't1', sourcePath: '/a', targetPath: '/b', targetSftpId: 's1' };
  assert.deepEqual(await bridge.cleanupTransferArtifacts!(payload), { success: true });
  assert.deepEqual(invokes, [
    { cmd: 'transfer_prioritize', args: { transferId: 't1' } },
    { cmd: 'transfer_set_concurrency', args: { limit: 4 } },
    { cmd: 'transfer_cleanup', args: { payload } },
  ]);
  assert.notEqual(invokes[2].args?.payload, payload, 'payload is copied');
});

test('compressed upload methods map to compress_* commands', async () => {
  const { bridge, invokes } = setup({
    compress_start: { compressionId: 'c1', success: true },
    compress_check_support: { supported: true, localTar: true, remoteTar: true },
  });
  const options = {
    compressionId: 'c1',
    folderPath: '/local/folder',
    targetPath: '/srv',
    sftpId: 's1',
    folderName: 'folder',
    totalBytes: 10,
  };
  assert.deepEqual(await bridge.startCompressedUpload!(options), { compressionId: 'c1', success: true });
  await bridge.cancelCompressedUpload!('c1');
  await bridge.pauseCompressedUpload!('c1');
  await bridge.resumeCompressedUpload!('c1');
  assert.equal((await bridge.checkCompressedUploadSupport!('s1')).supported, true);
  assert.deepEqual(
    invokes.map((i) => [i.cmd, i.args]),
    [
      ['compress_start', { payload: options }],
      ['compress_cancel', { compressionId: 'c1' }],
      ['compress_pause', { compressionId: 'c1' }],
      ['compress_resume', { compressionId: 'c1' }],
      ['compress_check_support', { sftpId: 's1' }],
    ],
  );
});

test('local file drag forwards only requestId and paths; cancel never throws', async () => {
  const { bridge, invokes } = setup({ local_drag_start: { started: true } }, ['local_drag_cancel']);
  const result = await bridge.startLocalFileDrag!({
    requestId: 'r1',
    paths: ['/a', '/b'],
    extra: 'ignored',
  } as unknown as { requestId: string; paths: string[] });
  assert.deepEqual(result, { started: true });
  assert.equal(bridge.cancelLocalFileDrag!('r1'), undefined);
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(invokes, [
    { cmd: 'local_drag_start', args: { payload: { requestId: 'r1', paths: ['/a', '/b'] } } },
    { cmd: 'local_drag_cancel', args: { requestId: 'r1' } },
  ]);
});

test('getSessionPwd forwards the cwd probe options', async () => {
  const { bridge, invokes } = setup({ session_pwd: { success: true, cwd: '/srv/app' } });
  assert.deepEqual(
    await bridge.getSessionPwd!('s1', { allowHomeFallback: false, allowLoginShellFallback: true, timeoutMs: 800 }),
    { success: true, cwd: '/srv/app' },
  );
  await bridge.getSessionPwd!('s2');
  assert.deepEqual(invokes, [
    {
      cmd: 'session_pwd',
      args: { sessionId: 's1', allowHomeFallback: false, allowLoginShellFallback: true, timeoutMs: 800 },
    },
    {
      cmd: 'session_pwd',
      args: { sessionId: 's2', allowHomeFallback: undefined, allowLoginShellFallback: undefined, timeoutMs: undefined },
    },
  ]);
});

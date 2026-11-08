/**
 * Transfer features of the Tauri `NetcattyBridge` (Electron preload:
 * `electron/preload/api.cjs` transfer, compressed-upload, local-file-drag and
 * `getSessionPwd` entries). Commands are specified in
 * `rust/docs/ipc-transfers.md`.
 *
 * Progress and terminal states of queued transfers and compressed uploads
 * arrive on `netcatty:sftp:global-transfer`, which the main adapter already
 * exposes as `onGlobalSftpTransferEvent`.
 */

import { EventHub, invoke as tauriInvoke } from '../tauriApi';

type Method<K extends keyof NetcattyBridge> = NonNullable<NetcattyBridge[K]>;
type Result<K extends keyof NetcattyBridge> = Awaited<ReturnType<Method<K>>>;

export interface TransfersBridgeDeps {
  /** Unused today; kept for the shared `create<Module>Bridge({ hub })` shape. */
  hub?: EventHub;
  /** Defaults to the real `invoke`; injected by tests. */
  invoke?: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
}

export function createTransfersBridge(deps: TransfersBridgeDeps = {}): Partial<NetcattyBridge> {
  const invoke = deps.invoke ?? tauriInvoke;

  return {
    // Global transfer queue.
    prioritizeTransfer: (transferId) =>
      invoke<Result<'prioritizeTransfer'>>('transfer_prioritize', { transferId }),
    setGlobalTransferConcurrency: (limit) =>
      invoke<Result<'setGlobalTransferConcurrency'>>('transfer_set_concurrency', { limit }),
    cleanupTransferArtifacts: (payload) =>
      invoke<Result<'cleanupTransferArtifacts'>>('transfer_cleanup', { payload: { ...payload } }),

    // Compressed folder upload.
    startCompressedUpload: (options) =>
      invoke<Result<'startCompressedUpload'>>('compress_start', { payload: { ...options } }),
    cancelCompressedUpload: (compressionId) =>
      invoke<Result<'cancelCompressedUpload'>>('compress_cancel', { compressionId }),
    pauseCompressedUpload: (compressionId) =>
      invoke<Result<'pauseCompressedUpload'>>('compress_pause', { compressionId }),
    resumeCompressedUpload: (compressionId) =>
      invoke<Result<'resumeCompressedUpload'>>('compress_resume', { compressionId }),
    checkCompressedUploadSupport: (sftpId) =>
      invoke<Result<'checkCompressedUploadSupport'>>('compress_check_support', { sftpId }),

    // Native drag of local files out of the app (fire-and-forget cancel,
    // like Electron's `ipcRenderer.send`).
    startLocalFileDrag: (payload) =>
      invoke<Result<'startLocalFileDrag'>>('local_drag_start', {
        payload: { requestId: payload?.requestId, paths: payload?.paths },
      }),
    cancelLocalFileDrag: (requestId) => {
      void invoke<void>('local_drag_cancel', { requestId }).catch(() => undefined);
    },

    // Real cwd of SSH terminals (the options were dropped before).
    getSessionPwd: (sessionId, options) =>
      invoke<Result<'getSessionPwd'>>('session_pwd', {
        sessionId,
        allowHomeFallback: options?.allowHomeFallback,
        allowLoginShellFallback: options?.allowLoginShellFallback,
        timeoutMs: options?.timeoutMs,
      }),
  };
}

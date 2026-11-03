/**
 * Streams a renderer `File` into the Rust temp directory so it can be
 * uploaded like a local file (mirrors `stageUploadFile` in the Electron
 * preload, which used `webUtils.getPathForFile` / a temp copy).
 *
 * Protocol: `temp_upload_begin` creates an empty `.part` file and returns
 * its path; `temp_upload_chunk` appends raw bodies (CHUNK_BYTES each);
 * `temp_delete_file` removes it on failure or cancellation.
 */
import { invoke, invokeBinary } from './tauriApi';

export const CHUNK_BYTES = 4 * 1024 * 1024;

const controllers = new Map<string, AbortController>();

const generateSuffix = (): string => {
  const webCrypto = typeof crypto !== 'undefined' ? crypto : undefined;
  if (webCrypto?.randomUUID) return webCrypto.randomUUID();
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
};

const cancellationError = (signal: AbortSignal): Error =>
  signal.reason instanceof Error ? signal.reason : new Error('Upload staging cancelled');

async function pumpFile(file: File, path: string, signal: AbortSignal): Promise<void> {
  if (typeof file.stream !== 'function') {
    throw new Error('Upload file streaming is unavailable');
  }
  const reader = file.stream().getReader();
  let pending: Uint8Array[] = [];
  let pendingBytes = 0;
  const flush = async (): Promise<void> => {
    if (pendingBytes === 0) return;
    const merged = new Uint8Array(pendingBytes);
    let offset = 0;
    for (const part of pending) {
      merged.set(part, offset);
      offset += part.byteLength;
    }
    pending = [];
    pendingBytes = 0;
    if (signal.aborted) throw cancellationError(signal);
    await invokeBinary('temp_upload_chunk', merged, { path });
  };
  try {
    while (true) {
      if (signal.aborted) throw cancellationError(signal);
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      pending.push(value);
      pendingBytes += value.byteLength;
      if (pendingBytes >= CHUNK_BYTES) await flush();
    }
    await flush();
  } finally {
    reader.releaseLock();
  }
}

/** Stage `file` and resolve with the temp path. Rejects on cancellation. */
export async function stageUploadFile(file: File, transferId: string): Promise<string> {
  controllers.get(transferId)?.abort(new Error('Upload staging superseded'));
  const controller = new AbortController();
  controllers.set(transferId, controller);
  let path: string | null = null;
  try {
    path = await invoke<string>('temp_upload_begin', {
      transferId: `${transferId}-${generateSuffix()}`,
      fileName: file?.name || 'upload.bin',
    });
    await pumpFile(file, path, controller.signal);
    return path;
  } catch (error) {
    if (path) {
      await invoke('temp_delete_file', { filePath: path }).catch(() => undefined);
    }
    throw error;
  } finally {
    if (controllers.get(transferId) === controller) controllers.delete(transferId);
  }
}

export function cancelStagedUpload(transferId: string): { success: boolean } {
  const controller = controllers.get(transferId);
  if (!controller) return { success: false };
  controller.abort(new Error('Upload staging cancelled'));
  return { success: true };
}

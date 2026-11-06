import { GripVertical, Monitor, RefreshCcw, X } from 'lucide-react';
import React, { useCallback, useEffect, useRef, useState } from 'react';

import { useI18n } from '../../application/i18n/I18nProvider';
import { useRemoteDesktopBackend } from '../../application/state/useRemoteDesktopBackend';
import { isEncryptedCredentialPlaceholder } from '../../domain/credentials';
import {
  accumulateWheelNotches,
  domButtonsToRemoteMask,
  mapPointerToRemote,
  resolveRemoteDesktopPort,
  resolveRemoteKeyEvent,
  type RemoteDesktopEvent,
  type RemoteDesktopInputEvent,
  type RemoteDesktopProtocol,
} from '../../domain/remoteDesktop';
import { resolveHostAuth } from '../../domain/sshAuth';
import { cn } from '../../lib/utils';
import type { Host, Identity, SSHKey, TerminalSession } from '../../types';
import { Button } from '../ui/button';

const DEFAULT_DESKTOP_SIZE = { width: 1280, height: 800 };
const MIN_REQUEST_SIZE = { width: 800, height: 600 };
const MAX_REQUEST_SIZE = 4096;

export interface RemoteDesktopPaneProps {
  host: Host;
  protocol: RemoteDesktopProtocol;
  sessionId: string;
  keys: SSHKey[];
  identities: Identity[];
  isVisible: boolean;
  isFocused: boolean;
  inWorkspace: boolean;
  sessionDisplayName?: string;
  onStatusChange?: (sessionId: string, status: TerminalSession['status']) => void;
  onCloseSession?: (sessionId: string) => void;
  /** Starts dragging this pane out of / between workspace tabs. */
  onDetachPointerDown?: (event: React.PointerEvent<HTMLElement>) => void;
}

type ConnectionState =
  | { status: 'connecting' }
  | { status: 'connected' }
  | { status: 'disconnected'; error?: string };

/** RDP desktop size to request: the pane size, clamped and made even. */
export function resolveRequestedDesktopSize(box: { width: number; height: number } | null): {
  width: number;
  height: number;
} {
  if (!box || box.width < 1 || box.height < 1) return DEFAULT_DESKTOP_SIZE;
  const even = (value: number, min: number) => {
    const clamped = Math.min(Math.max(Math.round(value), min), MAX_REQUEST_SIZE);
    return clamped - (clamped % 2);
  };
  return {
    width: even(box.width, MIN_REQUEST_SIZE.width),
    height: even(box.height, MIN_REQUEST_SIZE.height),
  };
}

/**
 * A VNC / RDP session rendered in a terminal pane slot. The backend decodes
 * the remote framebuffer and streams RGBA rectangles; this view paints them
 * on a canvas scaled to fit the pane and sends pointer / keyboard input back.
 */
export const RemoteDesktopPane: React.FC<RemoteDesktopPaneProps> = ({
  host,
  protocol,
  sessionId,
  keys,
  identities,
  isVisible,
  isFocused,
  inWorkspace,
  sessionDisplayName,
  onStatusChange,
  onCloseSession,
  onDetachPointerDown,
}) => {
  const { t } = useI18n();
  const backend = useRemoteDesktopBackend();
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const [state, setState] = useState<ConnectionState>({ status: 'connecting' });
  const [attempt, setAttempt] = useState(0);

  // Backend session id of the current attempt, and its remote desktop size.
  const backendIdRef = useRef<string | null>(null);
  const remoteSizeRef = useRef({ width: 0, height: 0 });
  const pendingInputRef = useRef<RemoteDesktopInputEvent[]>([]);
  const flushHandleRef = useRef<number | null>(null);
  const pressedKeysRef = useRef(new Map<string, { key: string; code: string }>());
  const wheelRemainderRef = useRef({ x: 0, y: 0 });
  const lastPointerRef = useRef({ x: 0, y: 0, buttons: 0 });

  const onStatusChangeRef = useRef(onStatusChange);
  onStatusChangeRef.current = onStatusChange;
  // Connection parameters are read when an attempt starts; editing the host
  // while connected must not tear the session down.
  const connectionRef = useRef({ host, keys, identities, protocol });
  connectionRef.current = { host, keys, identities, protocol };

  const flushInput = useCallback(() => {
    flushHandleRef.current = null;
    const events = pendingInputRef.current;
    const backendId = backendIdRef.current;
    if (events.length === 0) return;
    pendingInputRef.current = [];
    if (!backendId) return;
    backend.sendInput(backendId, events);
  }, [backend]);

  const queueInput = useCallback((event: RemoteDesktopInputEvent) => {
    if (!backendIdRef.current) return;
    const queue = pendingInputRef.current;
    const last = queue[queue.length - 1];
    // Pointer moves outpace the frame rate: keep only the newest position
    // while the button state is unchanged.
    if (event.type === 'pointer' && last?.type === 'pointer' && last.buttons === event.buttons) {
      queue[queue.length - 1] = event;
    } else {
      queue.push(event);
    }
    if (flushHandleRef.current === null) {
      flushHandleRef.current = window.requestAnimationFrame(flushInput);
    }
  }, [flushInput]);

  const handleEvent = useCallback((event: RemoteDesktopEvent) => {
    const canvas = canvasRef.current;
    switch (event.type) {
      case 'connected':
      case 'resize': {
        remoteSizeRef.current = { width: event.width, height: event.height };
        if (canvas) {
          // Resizing a canvas clears it; the server repaints afterwards.
          canvas.width = event.width;
          canvas.height = event.height;
        }
        if (event.type === 'connected') {
          setState({ status: 'connected' });
          onStatusChangeRef.current?.(sessionId, 'connected');
        }
        break;
      }
      case 'frame': {
        const context = canvas?.getContext('2d');
        if (!context) break;
        context.putImageData(new ImageData(event.rgba, event.width, event.height), event.x, event.y);
        break;
      }
      case 'copyRect': {
        const context = canvas?.getContext('2d');
        if (!context || !canvas) break;
        context.drawImage(
          canvas,
          event.srcX, event.srcY, event.width, event.height,
          event.dstX, event.dstY, event.width, event.height,
        );
        break;
      }
      case 'clipboard': {
        // Remote copy → local clipboard, like every desktop viewer does.
        backend.writeClipboardText(event.text);
        break;
      }
      case 'closed': {
        backendIdRef.current = null;
        pendingInputRef.current = [];
        pressedKeysRef.current.clear();
        setState({ status: 'disconnected', error: event.error });
        onStatusChangeRef.current?.(sessionId, 'disconnected');
        break;
      }
      default:
        break;
    }
  }, [backend, sessionId]);

  // One connection per attempt. `attempt` changes on "Reconnect".
  useEffect(() => {
    const { host: target, keys: sshKeys, identities: ids, protocol: proto } = connectionRef.current;
    let cancelled = false;

    const fail = (error: string) => {
      if (cancelled) return;
      setState({ status: 'disconnected', error });
      onStatusChangeRef.current?.(sessionId, 'disconnected');
    };

    setState({ status: 'connecting' });
    onStatusChangeRef.current?.(sessionId, 'connecting');
    remoteSizeRef.current = { width: 0, height: 0 };

    if (!backend.available()) {
      fail(t('remoteDesktop.error.unsupported'));
      return undefined;
    }

    const auth = resolveHostAuth({ host: target, keys: sshKeys, identities: ids });
    // A value that is still an encrypted blob means the vault could not be
    // decrypted; sending it would just lock the account out.
    if (isEncryptedCredentialPlaceholder(auth.password)) {
      fail(t('remoteDesktop.error.credentialsUnavailable'));
      return undefined;
    }
    if (proto === 'rdp' && !auth.username?.trim()) {
      fail(t('remoteDesktop.error.usernameRequired'));
      return undefined;
    }

    const body = bodyRef.current;
    const size = resolveRequestedDesktopSize(
      body ? { width: body.clientWidth, height: body.clientHeight } : null,
    );

    backend.start(
      {
        protocol: proto,
        hostname: target.hostname,
        port: resolveRemoteDesktopPort(proto, target.port),
        username: proto === 'rdp' ? auth.username?.trim() : undefined,
        password: auth.password || undefined,
        domain: proto === 'rdp' ? target.rdpDomain?.trim() || undefined : undefined,
        width: size.width,
        height: size.height,
      },
      (event) => {
        if (!cancelled) handleEvent(event);
      },
    ).then((backendId) => {
      if (cancelled) {
        backend.close(backendId);
        return;
      }
      backendIdRef.current = backendId;
    }).catch((error: unknown) => {
      fail(error instanceof Error ? error.message : String(error));
    });

    const pressedKeys = pressedKeysRef.current;
    return () => {
      cancelled = true;
      const backendId = backendIdRef.current;
      backendIdRef.current = null;
      pendingInputRef.current = [];
      pressedKeys.clear();
      if (flushHandleRef.current !== null) {
        window.cancelAnimationFrame(flushHandleRef.current);
        flushHandleRef.current = null;
      }
      if (backendId) backend.close(backendId);
    };
    // `t` is intentionally not a dependency: a language switch must not reconnect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attempt, backend, handleEvent, sessionId]);

  // Keyboard focus follows the pane focus, like a terminal.
  useEffect(() => {
    if (isVisible && isFocused && state.status === 'connected') {
      canvasRef.current?.focus({ preventScroll: true });
    }
  }, [isFocused, isVisible, state.status]);

  const pointerPosition = useCallback((event: { clientX: number; clientY: number }) => {
    const canvas = canvasRef.current;
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    const { width, height } = remoteSizeRef.current;
    if (width === 0 || height === 0) return null;
    return mapPointerToRemote(event.clientX - rect.left, event.clientY - rect.top, {
      boxWidth: rect.width,
      boxHeight: rect.height,
      remoteWidth: width,
      remoteHeight: height,
    });
  }, []);

  const handlePointer = useCallback((event: React.PointerEvent<HTMLCanvasElement>) => {
    const position = pointerPosition(event);
    if (!position) return;
    const buttons = domButtonsToRemoteMask(event.buttons);
    lastPointerRef.current = { ...position, buttons };
    queueInput({ type: 'pointer', ...position, buttons });
  }, [pointerPosition, queueInput]);

  const handlePointerDown = useCallback((event: React.PointerEvent<HTMLCanvasElement>) => {
    event.currentTarget.focus({ preventScroll: true });
    // Keep receiving moves and the release when a drag leaves the canvas.
    try {
      event.currentTarget.setPointerCapture(event.pointerId);
    } catch {
      // Capture is best effort (synthetic pointers cannot be captured).
    }
    handlePointer(event);
  }, [handlePointer]);

  // `wheel` must be a non-passive native listener to stop the page scrolling.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      const position = pointerPosition(event);
      if (!position) return;
      const vertical = accumulateWheelNotches(wheelRemainderRef.current.y, event.deltaY, event.deltaMode, 'y');
      const horizontal = accumulateWheelNotches(wheelRemainderRef.current.x, event.deltaX, event.deltaMode, 'x');
      wheelRemainderRef.current = { x: horizontal.remainder, y: vertical.remainder };
      if (vertical.notches === 0 && horizontal.notches === 0) return;
      queueInput({ type: 'wheel', ...position, deltaX: horizontal.notches, deltaY: vertical.notches });
    };
    canvas.addEventListener('wheel', onWheel, { passive: false });
    return () => canvas.removeEventListener('wheel', onWheel);
  }, [pointerPosition, queueInput]);

  const handleKey = useCallback((event: React.KeyboardEvent<HTMLCanvasElement>, down: boolean) => {
    // App hotkeys are consumed in the capture phase before this runs, so
    // everything arriving here belongs to the remote desktop.
    event.preventDefault();
    event.stopPropagation();
    const input = resolveRemoteKeyEvent(event, down);
    if (!input) return;
    const id = event.code || event.key;
    if (down) pressedKeysRef.current.set(id, { key: event.key, code: event.code });
    else pressedKeysRef.current.delete(id);
    queueInput(input);
  }, [queueInput]);

  // Keys held while focus leaves would stay pressed on the remote side.
  const releaseHeldInput = useCallback(() => {
    for (const held of pressedKeysRef.current.values()) {
      const input = resolveRemoteKeyEvent(held, false);
      if (input) queueInput(input);
    }
    pressedKeysRef.current.clear();
    if (lastPointerRef.current.buttons !== 0) {
      lastPointerRef.current = { ...lastPointerRef.current, buttons: 0 };
      queueInput({ type: 'pointer', ...lastPointerRef.current });
    }
  }, [queueInput]);

  const handleReconnect = useCallback(() => setAttempt((value) => value + 1), []);
  const handleClose = useCallback(() => onCloseSession?.(sessionId), [onCloseSession, sessionId]);

  const title = sessionDisplayName || host.label || host.hostname;
  const endpoint = `${host.hostname}:${resolveRemoteDesktopPort(protocol, host.port)}`;

  return (
    <div
      className="flex h-full w-full flex-col bg-background text-foreground"
      data-section="remote-desktop-pane"
      data-remote-desktop-protocol={protocol}
      data-remote-desktop-status={state.status}
    >
      <div className="flex h-7 shrink-0 items-center gap-1 border-b border-border/60 px-1.5 text-[11px]">
        {inWorkspace && onDetachPointerDown && (
          <div
            role="button"
            tabIndex={-1}
            title={t('terminal.toolbar.dragPane')}
            aria-label={t('terminal.toolbar.dragPane')}
            className="flex h-6 w-5 shrink-0 cursor-grab items-center justify-center rounded-md opacity-45 transition-colors hover:bg-secondary/80 hover:opacity-90 active:cursor-grabbing"
            data-terminal-detach-drag-handle="true"
            onPointerDown={onDetachPointerDown}
          >
            <GripVertical size={12} strokeWidth={2} aria-hidden="true" />
          </div>
        )}
        <Monitor size={12} className="shrink-0 opacity-70" aria-hidden="true" />
        <span className="min-w-0 truncate font-semibold" title={title}>{title}</span>
        <span className="shrink-0 rounded bg-primary/10 px-1.5 py-0.5 text-[10px] leading-none text-primary">
          {protocol.toUpperCase()}
        </span>
        <span className="min-w-0 truncate text-muted-foreground" title={endpoint}>{endpoint}</span>
        <div className="ml-auto flex shrink-0 items-center gap-0.5">
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            title={t('remoteDesktop.reconnect')}
            aria-label={t('remoteDesktop.reconnect')}
            onClick={handleReconnect}
          >
            <RefreshCcw size={12} />
          </Button>
          {onCloseSession && (
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6"
              title={t('remoteDesktop.close')}
              aria-label={t('remoteDesktop.close')}
              onClick={handleClose}
            >
              <X size={12} />
            </Button>
          )}
        </div>
      </div>

      <div ref={bodyRef} className="relative min-h-0 flex-1 overflow-hidden bg-black">
        <canvas
          ref={canvasRef}
          tabIndex={0}
          data-remote-desktop-input="true"
          aria-label={t('remoteDesktop.canvasLabel', { host: title })}
          className={cn(
            'absolute inset-0 h-full w-full object-contain outline-none',
            state.status !== 'connected' && 'opacity-30',
          )}
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointer}
          onPointerUp={handlePointer}
          onKeyDown={(event) => handleKey(event, true)}
          onKeyUp={(event) => handleKey(event, false)}
          onBlur={releaseHeldInput}
          onContextMenu={(event) => event.preventDefault()}
        />
        {state.status !== 'connected' && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 p-6 text-center text-sm text-white/90">
            {state.status === 'connecting' ? (
              <span>{t('remoteDesktop.status.connecting', { host: endpoint })}</span>
            ) : (
              <>
                <span className="font-medium">{t('remoteDesktop.status.disconnected')}</span>
                {state.error && (
                  <span className="max-w-xl break-words text-xs text-white/70">{state.error}</span>
                )}
                <Button size="sm" variant="secondary" onClick={handleReconnect}>
                  <RefreshCcw size={14} className="mr-1.5" /> {t('remoteDesktop.reconnect')}
                </Button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
RemoteDesktopPane.displayName = 'RemoteDesktopPane';

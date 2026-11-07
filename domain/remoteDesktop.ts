/**
 * Remote desktop (VNC / RDP) domain helpers: protocol predicates, the binary
 * frame format of the backend channel, and the translation of DOM input
 * events into the protocol-neutral input events the backend expects.
 *
 * Pure functions only; the view lives in `components/remoteDesktop/`.
 */

export type RemoteDesktopProtocol = 'vnc' | 'rdp';

export const REMOTE_DESKTOP_DEFAULT_PORTS: Record<RemoteDesktopProtocol, number> = {
  vnc: 5900,
  rdp: 3389,
};

export const isRemoteDesktopProtocol = (protocol?: string | null): protocol is RemoteDesktopProtocol => (
  protocol === 'vnc' || protocol === 'rdp'
);

export const isRemoteDesktopHost = (host?: { protocol?: string } | null): boolean => (
  isRemoteDesktopProtocol(host?.protocol)
);

/** Port to dial: the host's own port, else the protocol's well-known one. */
export const resolveRemoteDesktopPort = (
  protocol: RemoteDesktopProtocol,
  port?: number | null,
): number => (
  typeof port === 'number' && Number.isInteger(port) && port > 0 && port <= 65535
    ? port
    : REMOTE_DESKTOP_DEFAULT_PORTS[protocol]
);

// ---------------------------------------------------------------------------
// Backend → renderer messages
// ---------------------------------------------------------------------------

/** JSON control messages of a session (see `RemoteDesktopControlEvent` in Rust). */
export type RemoteDesktopControlEvent =
  | { type: 'connected'; width: number; height: number }
  | { type: 'resize'; width: number; height: number }
  | { type: 'clipboard'; text: string }
  | { type: 'bell' }
  | { type: 'closed'; error?: string };

export type RemoteDesktopFrameMessage =
  | { type: 'frame'; x: number; y: number; width: number; height: number; rgba: Uint8ClampedArray<ArrayBuffer> }
  | { type: 'copyRect'; srcX: number; srcY: number; dstX: number; dstY: number; width: number; height: number };

export type RemoteDesktopEvent = RemoteDesktopControlEvent | RemoteDesktopFrameMessage;

const TAG_FRAME = 1;
const TAG_COPY_RECT = 2;
const FRAME_HEADER_BYTES = 9;
const COPY_RECT_BYTES = 13;

/**
 * Decode a binary channel message. Layout (all `u16` little endian):
 * `[1][x][y][width][height]` + RGBA pixels, or
 * `[2][srcX][srcY][dstX][dstY][width][height]`.
 * Returns null for anything malformed so a bad message cannot throw in the
 * paint loop.
 */
export function decodeRemoteDesktopBinaryMessage(buffer: ArrayBuffer): RemoteDesktopFrameMessage | null {
  if (buffer.byteLength < 1) return null;
  const view = new DataView(buffer);
  const tag = view.getUint8(0);

  if (tag === TAG_FRAME) {
    if (buffer.byteLength < FRAME_HEADER_BYTES) return null;
    const width = view.getUint16(5, true);
    const height = view.getUint16(7, true);
    const pixelBytes = width * height * 4;
    if (width === 0 || height === 0 || buffer.byteLength !== FRAME_HEADER_BYTES + pixelBytes) return null;
    return {
      type: 'frame',
      x: view.getUint16(1, true),
      y: view.getUint16(3, true),
      width,
      height,
      rgba: new Uint8ClampedArray(buffer, FRAME_HEADER_BYTES, pixelBytes),
    };
  }

  if (tag === TAG_COPY_RECT) {
    if (buffer.byteLength !== COPY_RECT_BYTES) return null;
    return {
      type: 'copyRect',
      srcX: view.getUint16(1, true),
      srcY: view.getUint16(3, true),
      dstX: view.getUint16(5, true),
      dstY: view.getUint16(7, true),
      width: view.getUint16(9, true),
      height: view.getUint16(11, true),
    };
  }

  return null;
}

export function isRemoteDesktopControlEvent(value: unknown): value is RemoteDesktopControlEvent {
  if (!value || typeof value !== 'object') return false;
  const type = (value as { type?: unknown }).type;
  return type === 'connected' || type === 'resize' || type === 'clipboard' || type === 'bell' || type === 'closed';
}

// ---------------------------------------------------------------------------
// Renderer → backend input
// ---------------------------------------------------------------------------

/** Input events of `sendRemoteDesktopInput` (see `RemoteDesktopInputEvent` in Rust). */
export type RemoteDesktopInputEvent =
  | { type: 'pointer'; x: number; y: number; buttons: number }
  | { type: 'wheel'; x: number; y: number; deltaX: number; deltaY: number }
  | { type: 'key'; down: boolean; keysym: number; scancode: number }
  | { type: 'clipboard'; text: string }
  | { type: 'refresh' };

/**
 * DOM `MouseEvent.buttons` (bit 0 left, bit 1 right, bit 2 middle) → the
 * remote button mask (bit 0 left, bit 1 middle, bit 2 right).
 */
export function domButtonsToRemoteMask(buttons: number): number {
  return (buttons & 1) | ((buttons & 4) >> 1) | ((buttons & 2) << 1);
}

export interface RemoteDesktopViewport {
  /** Displayed size of the canvas element box, in CSS pixels. */
  boxWidth: number;
  boxHeight: number;
  /** Remote desktop size, in remote pixels. */
  remoteWidth: number;
  remoteHeight: number;
}

/**
 * Where the desktop is drawn inside the canvas box when it is scaled to fit
 * while keeping its aspect ratio (CSS `object-fit: contain`).
 */
export function resolveRemoteDesktopContentRect(viewport: RemoteDesktopViewport): {
  left: number;
  top: number;
  width: number;
  height: number;
  scale: number;
} {
  const { boxWidth, boxHeight, remoteWidth, remoteHeight } = viewport;
  if (boxWidth <= 0 || boxHeight <= 0 || remoteWidth <= 0 || remoteHeight <= 0) {
    return { left: 0, top: 0, width: 0, height: 0, scale: 0 };
  }
  const scale = Math.min(boxWidth / remoteWidth, boxHeight / remoteHeight);
  const width = remoteWidth * scale;
  const height = remoteHeight * scale;
  return { left: (boxWidth - width) / 2, top: (boxHeight - height) / 2, width, height, scale };
}

/**
 * Translate a pointer position inside the canvas box (CSS pixels, relative
 * to the box's top-left corner) into remote desktop pixels. Positions in the
 * letterbox bars are clamped to the nearest desktop edge so a drag that
 * leaves the picture keeps tracking.
 */
export function mapPointerToRemote(
  offsetX: number,
  offsetY: number,
  viewport: RemoteDesktopViewport,
): { x: number; y: number } {
  const content = resolveRemoteDesktopContentRect(viewport);
  if (content.scale <= 0) return { x: 0, y: 0 };
  const clamp = (value: number, max: number) => Math.min(Math.max(Math.floor(value), 0), max);
  return {
    x: clamp((offsetX - content.left) / content.scale, viewport.remoteWidth - 1),
    y: clamp((offsetY - content.top) / content.scale, viewport.remoteHeight - 1),
  };
}

const PIXELS_PER_WHEEL_NOTCH = 100;
const LINES_PER_WHEEL_NOTCH = 3;

/**
 * Wheel delta → whole notches, carrying the remainder so that slow trackpad
 * scrolling accumulates instead of being rounded away. Returns the notches to
 * send and the new remainder. The sign follows the remote convention:
 * positive scrolls up / right, the opposite of DOM `deltaY`.
 */
export function accumulateWheelNotches(
  remainder: number,
  delta: number,
  deltaMode: number,
  axis: 'x' | 'y',
): { notches: number; remainder: number } {
  // deltaMode: 0 pixels, 1 lines, 2 pages.
  const perNotch = deltaMode === 1 ? LINES_PER_WHEEL_NOTCH : deltaMode === 2 ? 1 : PIXELS_PER_WHEEL_NOTCH;
  const total = remainder + delta / perNotch;
  const whole = Math.trunc(total);
  // DOM: positive deltaY scrolls down, positive deltaX scrolls right.
  const notches = axis === 'y' ? -whole : whole;
  return { notches: notches === 0 ? 0 : notches, remainder: total - whole };
}

// X11 keysyms of the non-printing keys, by `KeyboardEvent.key`.
const NAMED_KEYSYMS: Record<string, number> = {
  Backspace: 0xff08,
  Tab: 0xff09,
  Enter: 0xff0d,
  Escape: 0xff1b,
  Delete: 0xffff,
  Home: 0xff50,
  ArrowLeft: 0xff51,
  ArrowUp: 0xff52,
  ArrowRight: 0xff53,
  ArrowDown: 0xff54,
  PageUp: 0xff55,
  PageDown: 0xff56,
  End: 0xff57,
  Insert: 0xff63,
  Pause: 0xff13,
  ScrollLock: 0xff14,
  PrintScreen: 0xff61,
  ContextMenu: 0xff67,
  NumLock: 0xff7f,
  CapsLock: 0xffe5,
  AltGraph: 0xfe03,
  F1: 0xffbe,
  F2: 0xffbf,
  F3: 0xffc0,
  F4: 0xffc1,
  F5: 0xffc2,
  F6: 0xffc3,
  F7: 0xffc4,
  F8: 0xffc5,
  F9: 0xffc6,
  F10: 0xffc7,
  F11: 0xffc8,
  F12: 0xffc9,
};

// Modifier keysyms: [left, right].
const MODIFIER_KEYSYMS: Record<string, [number, number]> = {
  Shift: [0xffe1, 0xffe2],
  Control: [0xffe3, 0xffe4],
  Alt: [0xffe9, 0xffea],
  Meta: [0xffeb, 0xffec],
};

/** X11 keysym for a DOM key event, or 0 when the key has none. */
export function resolveKeysym(key: string, code: string): number {
  const modifier = MODIFIER_KEYSYMS[key];
  if (modifier) return code.endsWith('Right') ? modifier[1] : modifier[0];
  const named = NAMED_KEYSYMS[key];
  if (named !== undefined) return named;

  // A single character (one code point; may be a surrogate pair).
  const chars = Array.from(key);
  if (chars.length !== 1) return 0;
  const codePoint = chars[0].codePointAt(0) ?? 0;
  if (codePoint < 0x20 || (codePoint >= 0x7f && codePoint < 0xa0)) return 0;
  // Latin-1 keysyms equal the code point; everything else is "Unicode keysym".
  return codePoint <= 0xff ? codePoint : 0x01000000 + codePoint;
}

const EXTENDED = 0xe000;

// PC set-1 scancodes by `KeyboardEvent.code` (physical key position).
const SCANCODES: Record<string, number> = {
  Escape: 0x01,
  Digit1: 0x02,
  Digit2: 0x03,
  Digit3: 0x04,
  Digit4: 0x05,
  Digit5: 0x06,
  Digit6: 0x07,
  Digit7: 0x08,
  Digit8: 0x09,
  Digit9: 0x0a,
  Digit0: 0x0b,
  Minus: 0x0c,
  Equal: 0x0d,
  Backspace: 0x0e,
  Tab: 0x0f,
  KeyQ: 0x10,
  KeyW: 0x11,
  KeyE: 0x12,
  KeyR: 0x13,
  KeyT: 0x14,
  KeyY: 0x15,
  KeyU: 0x16,
  KeyI: 0x17,
  KeyO: 0x18,
  KeyP: 0x19,
  BracketLeft: 0x1a,
  BracketRight: 0x1b,
  Enter: 0x1c,
  ControlLeft: 0x1d,
  KeyA: 0x1e,
  KeyS: 0x1f,
  KeyD: 0x20,
  KeyF: 0x21,
  KeyG: 0x22,
  KeyH: 0x23,
  KeyJ: 0x24,
  KeyK: 0x25,
  KeyL: 0x26,
  Semicolon: 0x27,
  Quote: 0x28,
  Backquote: 0x29,
  ShiftLeft: 0x2a,
  Backslash: 0x2b,
  KeyZ: 0x2c,
  KeyX: 0x2d,
  KeyC: 0x2e,
  KeyV: 0x2f,
  KeyB: 0x30,
  KeyN: 0x31,
  KeyM: 0x32,
  Comma: 0x33,
  Period: 0x34,
  Slash: 0x35,
  ShiftRight: 0x36,
  NumpadMultiply: 0x37,
  AltLeft: 0x38,
  Space: 0x39,
  CapsLock: 0x3a,
  F1: 0x3b,
  F2: 0x3c,
  F3: 0x3d,
  F4: 0x3e,
  F5: 0x3f,
  F6: 0x40,
  F7: 0x41,
  F8: 0x42,
  F9: 0x43,
  F10: 0x44,
  NumLock: 0x45,
  ScrollLock: 0x46,
  Numpad7: 0x47,
  Numpad8: 0x48,
  Numpad9: 0x49,
  NumpadSubtract: 0x4a,
  Numpad4: 0x4b,
  Numpad5: 0x4c,
  Numpad6: 0x4d,
  NumpadAdd: 0x4e,
  Numpad1: 0x4f,
  Numpad2: 0x50,
  Numpad3: 0x51,
  Numpad0: 0x52,
  NumpadDecimal: 0x53,
  IntlBackslash: 0x56,
  F11: 0x57,
  F12: 0x58,
  NumpadEnter: EXTENDED | 0x1c,
  ControlRight: EXTENDED | 0x1d,
  NumpadDivide: EXTENDED | 0x35,
  PrintScreen: EXTENDED | 0x37,
  AltRight: EXTENDED | 0x38,
  Home: EXTENDED | 0x47,
  ArrowUp: EXTENDED | 0x48,
  PageUp: EXTENDED | 0x49,
  ArrowLeft: EXTENDED | 0x4b,
  ArrowRight: EXTENDED | 0x4d,
  End: EXTENDED | 0x4f,
  ArrowDown: EXTENDED | 0x50,
  PageDown: EXTENDED | 0x51,
  Insert: EXTENDED | 0x52,
  Delete: EXTENDED | 0x53,
  MetaLeft: EXTENDED | 0x5b,
  MetaRight: EXTENDED | 0x5c,
  ContextMenu: EXTENDED | 0x5d,
};

/** PC set-1 scancode (`0xE000` or-ed in for extended keys), or 0 when unknown. */
export function resolveScancode(code: string): number {
  return SCANCODES[code] ?? 0;
}

/**
 * Build the key input event for a DOM keyboard event, or null when the key
 * maps to nothing in either keyspace (dead keys, IME composition, media keys).
 */
export function resolveRemoteKeyEvent(
  event: { key: string; code: string },
  down: boolean,
): Extract<RemoteDesktopInputEvent, { type: 'key' }> | null {
  const keysym = resolveKeysym(event.key, event.code);
  const scancode = resolveScancode(event.code);
  if (keysym === 0 && scancode === 0) return null;
  return { type: 'key', down, keysym, scancode };
}

// ---------------------------------------------------------------------------
// Vault hosts
// ---------------------------------------------------------------------------

export const REMOTE_DESKTOP_HOST_TAG: Record<RemoteDesktopProtocol, string> = {
  vnc: 'vnc',
  rdp: 'rdp',
};

export interface RemoteDesktopHostInput {
  id?: string;
  protocol: RemoteDesktopProtocol;
  label?: string;
  hostname?: string;
  port?: number | null;
  /** RDP only; VNC authentication has no user name. */
  username?: string;
  password?: string;
  /** RDP logon domain. */
  domain?: string;
  group?: string;
  tags?: string[];
}

/**
 * Build a VNC / RDP vault host. These hosts reuse the generic `port`,
 * `username` and `password` fields for the desktop connection; the port is
 * always stored explicitly so nothing can substitute the SSH default (22).
 */
export function createRemoteDesktopHost(input: RemoteDesktopHostInput): import('./models').Host {
  const { protocol } = input;
  const hostname = input.hostname?.trim() ?? '';
  const domain = protocol === 'rdp' ? input.domain?.trim() : '';
  return {
    id: input.id ?? `${protocol}-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`,
    label: input.label?.trim() || hostname || protocol.toUpperCase(),
    hostname,
    port: resolveRemoteDesktopPort(protocol, input.port),
    username: protocol === 'rdp' ? input.username?.trim() ?? '' : '',
    password: input.password ? input.password : undefined,
    rdpDomain: domain || undefined,
    group: input.group?.trim() || '',
    tags: input.tags ?? [REMOTE_DESKTOP_HOST_TAG[protocol]],
    // RDP targets are Windows machines in practice; VNC is most common on Linux.
    os: protocol === 'rdp' ? 'windows' : 'linux',
    protocol,
    createdAt: Date.now(),
  };
}

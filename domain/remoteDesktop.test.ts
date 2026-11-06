import assert from 'node:assert/strict';
import test from 'node:test';

import {
  accumulateWheelNotches,
  decodeRemoteDesktopBinaryMessage,
  domButtonsToRemoteMask,
  isRemoteDesktopControlEvent,
  isRemoteDesktopHost,
  isRemoteDesktopProtocol,
  mapPointerToRemote,
  resolveKeysym,
  resolveRemoteDesktopContentRect,
  resolveRemoteDesktopPort,
  resolveRemoteKeyEvent,
  resolveScancode,
} from './remoteDesktop';

test('only vnc and rdp are remote desktop protocols', () => {
  assert.equal(isRemoteDesktopProtocol('vnc'), true);
  assert.equal(isRemoteDesktopProtocol('rdp'), true);
  for (const protocol of ['ssh', 'telnet', 'local', 'serial', 'plugin:acme.x', '', undefined, null]) {
    assert.equal(isRemoteDesktopProtocol(protocol), false, String(protocol));
  }
  assert.equal(isRemoteDesktopHost({ protocol: 'rdp' }), true);
  assert.equal(isRemoteDesktopHost({}), false);
  assert.equal(isRemoteDesktopHost(undefined), false);
});

test('the port falls back to the protocol default', () => {
  assert.equal(resolveRemoteDesktopPort('vnc'), 5900);
  assert.equal(resolveRemoteDesktopPort('rdp', undefined), 3389);
  assert.equal(resolveRemoteDesktopPort('vnc', 5901), 5901);
  for (const invalid of [0, -1, 70000, 1.5, Number.NaN]) {
    assert.equal(resolveRemoteDesktopPort('rdp', invalid), 3389, String(invalid));
  }
});

test('binary messages decode into frames and copy rects, and malformed ones are dropped', () => {
  const frame = decodeRemoteDesktopBinaryMessage(
    new Uint8Array([1, 0x02, 0x01, 3, 0, 1, 0, 2, 0, 1, 2, 3, 255, 4, 5, 6, 255]).buffer,
  );
  assert.ok(frame && frame.type === 'frame');
  assert.deepEqual([frame.x, frame.y, frame.width, frame.height], [0x0102, 3, 1, 2]);
  assert.deepEqual(Array.from(frame.rgba), [1, 2, 3, 255, 4, 5, 6, 255]);

  assert.deepEqual(
    decodeRemoteDesktopBinaryMessage(new Uint8Array([2, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0]).buffer),
    { type: 'copyRect', srcX: 1, srcY: 2, dstX: 3, dstY: 4, width: 5, height: 6 },
  );

  // Empty, unknown tag, truncated header, pixel count mismatch, zero size.
  assert.equal(decodeRemoteDesktopBinaryMessage(new ArrayBuffer(0)), null);
  assert.equal(decodeRemoteDesktopBinaryMessage(new Uint8Array([9, 0, 0]).buffer), null);
  assert.equal(decodeRemoteDesktopBinaryMessage(new Uint8Array([1, 0, 0, 0]).buffer), null);
  assert.equal(decodeRemoteDesktopBinaryMessage(new Uint8Array([1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 2]).buffer), null);
  assert.equal(decodeRemoteDesktopBinaryMessage(new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0, 0]).buffer), null);
  assert.equal(decodeRemoteDesktopBinaryMessage(new Uint8Array([2, 1, 0]).buffer), null);
});

test('control events are recognised by their type tag', () => {
  assert.equal(isRemoteDesktopControlEvent({ type: 'connected', width: 1, height: 1 }), true);
  assert.equal(isRemoteDesktopControlEvent({ type: 'closed' }), true);
  assert.equal(isRemoteDesktopControlEvent({ type: 'frame' }), false);
  assert.equal(isRemoteDesktopControlEvent(null), false);
  assert.equal(isRemoteDesktopControlEvent('closed'), false);
});

test('DOM button bits are reordered into the remote mask', () => {
  assert.equal(domButtonsToRemoteMask(0), 0);
  assert.equal(domButtonsToRemoteMask(1), 0b001, 'left');
  assert.equal(domButtonsToRemoteMask(2), 0b100, 'DOM right is bit 1, remote right is bit 2');
  assert.equal(domButtonsToRemoteMask(4), 0b010, 'DOM middle is bit 2, remote middle is bit 1');
  assert.equal(domButtonsToRemoteMask(7), 0b111);
  assert.equal(domButtonsToRemoteMask(8 | 16), 0, 'back/forward buttons are not forwarded');
});

test('pointer positions map through the letterboxed, scaled picture', () => {
  // A 1000x500 desktop in a 500x500 box: scale 0.5, bars of 125px above and below.
  const viewport = { boxWidth: 500, boxHeight: 500, remoteWidth: 1000, remoteHeight: 500 };
  assert.deepEqual(resolveRemoteDesktopContentRect(viewport), { left: 0, top: 125, width: 500, height: 250, scale: 0.5 });

  assert.deepEqual(mapPointerToRemote(0, 125, viewport), { x: 0, y: 0 });
  assert.deepEqual(mapPointerToRemote(250, 250, viewport), { x: 500, y: 250 });
  // Inside the bars and beyond the edges: clamped onto the desktop.
  assert.deepEqual(mapPointerToRemote(250, 10, viewport), { x: 500, y: 0 });
  assert.deepEqual(mapPointerToRemote(9999, 9999, viewport), { x: 999, y: 499 });
  assert.deepEqual(mapPointerToRemote(-50, 300, viewport), { x: 0, y: 350 });

  // Nothing to map onto before the first `connected`.
  assert.deepEqual(mapPointerToRemote(10, 10, { ...viewport, remoteWidth: 0 }), { x: 0, y: 0 });
});

test('wheel deltas accumulate into whole notches with the remote sign', () => {
  // Scrolling down in the DOM is positive deltaY; the remote wants negative.
  assert.deepEqual(accumulateWheelNotches(0, 100, 0, 'y'), { notches: -1, remainder: 0 });
  assert.deepEqual(accumulateWheelNotches(0, -250, 0, 'y'), { notches: 2, remainder: -0.5 });
  // Small trackpad steps add up across events.
  const first = accumulateWheelNotches(0, 40, 0, 'y');
  assert.equal(first.notches, 0);
  const second = accumulateWheelNotches(first.remainder, 70, 0, 'y');
  assert.equal(second.notches, -1);
  // Line mode: three lines per notch. Horizontal keeps the DOM sign.
  assert.equal(accumulateWheelNotches(0, 3, 1, 'y').notches, -1);
  assert.equal(accumulateWheelNotches(0, 100, 0, 'x').notches, 1);
});

test('keys resolve to X11 keysyms', () => {
  assert.equal(resolveKeysym('a', 'KeyA'), 0x61);
  assert.equal(resolveKeysym('A', 'KeyA'), 0x41);
  assert.equal(resolveKeysym(' ', 'Space'), 0x20);
  assert.equal(resolveKeysym('é', 'KeyE'), 0xe9, 'Latin-1 keysyms equal the code point');
  assert.equal(resolveKeysym('中', ''), 0x01004e2d, 'other characters use the Unicode keysym range');
  assert.equal(resolveKeysym('😀', ''), 0x01000000 + 0x1f600, 'astral characters are one key');
  assert.equal(resolveKeysym('Enter', 'Enter'), 0xff0d);
  assert.equal(resolveKeysym('ArrowLeft', 'ArrowLeft'), 0xff51);
  assert.equal(resolveKeysym('F12', 'F12'), 0xffc9);
  assert.equal(resolveKeysym('Shift', 'ShiftLeft'), 0xffe1);
  assert.equal(resolveKeysym('Shift', 'ShiftRight'), 0xffe2);
  assert.equal(resolveKeysym('Control', 'ControlRight'), 0xffe4);
  assert.equal(resolveKeysym('Dead', 'Quote'), 0);
  assert.equal(resolveKeysym('Process', 'KeyA'), 0);
});

test('physical keys resolve to set-1 scancodes', () => {
  assert.equal(resolveScancode('KeyA'), 0x1e);
  assert.equal(resolveScancode('Enter'), 0x1c);
  assert.equal(resolveScancode('NumpadEnter'), 0xe01c, 'extended keys carry the 0xE000 marker');
  assert.equal(resolveScancode('ArrowUp'), 0xe048);
  assert.equal(resolveScancode('Delete'), 0xe053);
  assert.equal(resolveScancode('MetaLeft'), 0xe05b);
  assert.equal(resolveScancode('MediaPlayPause'), 0);
});

test('key events carry both keyspaces and unmappable keys are skipped', () => {
  assert.deepEqual(resolveRemoteKeyEvent({ key: 'a', code: 'KeyA' }, true), {
    type: 'key', down: true, keysym: 0x61, scancode: 0x1e,
  });
  // An IME-produced character has no physical key: keysym only.
  assert.deepEqual(resolveRemoteKeyEvent({ key: '中', code: '' }, false), {
    type: 'key', down: false, keysym: 0x01004e2d, scancode: 0,
  });
  // A dead key still has a physical position for RDP.
  assert.deepEqual(resolveRemoteKeyEvent({ key: 'Dead', code: 'Quote' }, true), {
    type: 'key', down: true, keysym: 0, scancode: 0x28,
  });
  assert.equal(resolveRemoteKeyEvent({ key: 'Unidentified', code: '' }, true), null);
});

// ---------------------------------------------------------------------------
// Vault hosts and protocol gates
// ---------------------------------------------------------------------------

import { applyGroupDefaults } from './groupConfig';
import { getVaultHostRowSubtitle } from './localShellHost';
import { isBuiltInHostProtocol } from './pluginConnection';
import { createRemoteDesktopHost } from './remoteDesktop';
import { canOpenDualPaneSftp } from './sftpDualPaneOpen';
import { resolveTerminalHibernateEnabledForProtocol } from './terminalHibernate';

test('a remote desktop host always stores an explicit port and only the fields its protocol uses', () => {
  const vnc = createRemoteDesktopHost({
    protocol: 'vnc',
    hostname: ' 10.0.0.5 ',
    username: 'ignored',
    password: 'pw',
    domain: 'CORP',
    group: ' lab ',
  });
  assert.equal(vnc.protocol, 'vnc');
  assert.equal(vnc.hostname, '10.0.0.5');
  assert.equal(vnc.port, 5900);
  assert.equal(vnc.username, '', 'VNC has no user name');
  assert.equal(vnc.rdpDomain, undefined);
  assert.equal(vnc.password, 'pw');
  assert.equal(vnc.label, '10.0.0.5', 'the label defaults to the address');
  assert.equal(vnc.group, 'lab');
  assert.deepEqual(vnc.tags, ['vnc']);

  const rdp = createRemoteDesktopHost({
    id: 'rdp-1',
    protocol: 'rdp',
    label: ' Build box ',
    hostname: 'win.example.test',
    port: 13389,
    username: ' alice ',
    password: '',
    domain: ' CORP ',
  });
  assert.equal(rdp.id, 'rdp-1');
  assert.equal(rdp.label, 'Build box');
  assert.equal(rdp.port, 13389);
  assert.equal(rdp.username, 'alice');
  assert.equal(rdp.rdpDomain, 'CORP');
  assert.equal(rdp.password, undefined, 'an empty password is not stored');
  assert.equal(rdp.os, 'windows');
});

test('group SSH defaults never leak into a remote desktop host', () => {
  const host = createRemoteDesktopHost({ protocol: 'vnc', hostname: 'desk.example.test' });
  const effective = applyGroupDefaults(host, {
    username: 'root',
    password: 'ssh-secret',
    port: 2222,
    protocol: 'telnet',
    startupCommand: 'uptime',
    moshEnabled: true,
    hostChain: { hostIds: ['bastion'] },
  });
  assert.equal(effective.password, undefined, 'the SSH password must not become the VNC password');
  assert.equal(effective.username, '');
  assert.equal(effective.port, 5900);
  assert.equal(effective.protocol, 'vnc');
  assert.equal(effective.startupCommand, undefined);
  assert.equal(effective.moshEnabled, undefined);
  assert.equal(effective.hostChain, undefined);
});

test('remote desktop protocols are built in but excluded from terminal-only features', () => {
  assert.equal(isBuiltInHostProtocol('vnc'), true);
  assert.equal(isBuiltInHostProtocol('rdp'), true);
  assert.equal(canOpenDualPaneSftp({ protocol: 'vnc' }), false);
  assert.equal(canOpenDualPaneSftp({ protocol: 'rdp' }), false);
  assert.equal(canOpenDualPaneSftp({ protocol: 'ssh' }), true);
  // There is no xterm runtime to hibernate behind a desktop canvas.
  assert.equal(resolveTerminalHibernateEnabledForProtocol({ hibernateHiddenTabs: true }, 'rdp'), false);
  assert.equal(resolveTerminalHibernateEnabledForProtocol({ hibernateHiddenTabs: true }, 'ssh'), true);
});

test('host rows show a bare address for desktop hosts without a user name', () => {
  assert.equal(getVaultHostRowSubtitle({ protocol: 'vnc', username: '', hostname: 'desk' }), 'desk');
  assert.equal(getVaultHostRowSubtitle({ protocol: 'rdp', username: 'alice', hostname: 'win' }), 'alice@win');
  assert.equal(getVaultHostRowSubtitle({ protocol: 'ssh', username: '', hostname: 'srv' }), '@srv');
});

import assert from 'node:assert/strict';
import test from 'node:test';

import en from './en';
import ru from './ru';
import es from './es';
import zhCN from './zh-CN';
import zhTW from './zh-TW';

const keys = [
  'vault.hosts.newRdpHost',
  'vault.hosts.newVncHost',
  'remoteDesktop.reconnect',
  'remoteDesktop.close',
  'remoteDesktop.canvasLabel',
  'remoteDesktop.status.connecting',
  'remoteDesktop.status.disconnected',
  'remoteDesktop.error.unsupported',
  'remoteDesktop.error.credentialsUnavailable',
  'remoteDesktop.error.usernameRequired',
  'remoteDesktop.panel.title.new.vnc',
  'remoteDesktop.panel.title.new.rdp',
  'remoteDesktop.panel.title.edit.vnc',
  'remoteDesktop.panel.title.edit.rdp',
  'remoteDesktop.field.label',
  'remoteDesktop.field.labelPlaceholder',
  'remoteDesktop.field.hostname',
  'remoteDesktop.field.port',
  'remoteDesktop.field.username',
  'remoteDesktop.field.domain',
  'remoteDesktop.field.domainPlaceholder',
  'remoteDesktop.field.password',
  'remoteDesktop.field.passwordHint.rdp',
  'remoteDesktop.field.passwordHint.vnc',
  'remoteDesktop.saveAndConnect',
] as const;

test('remote desktop strings exist in every shipped locale', () => {
  for (const [locale, messages] of Object.entries({ en, es, 'zh-CN': zhCN, 'zh-TW': zhTW, ru })) {
    for (const key of keys) {
      assert.equal(typeof messages[key], 'string', `${locale} is missing ${key}`);
      assert.notEqual(messages[key], '', `${locale} has an empty ${key}`);
    }
  }
});

test('interpolated remote desktop strings keep their placeholder in every locale', () => {
  for (const [locale, messages] of Object.entries({ en, es, 'zh-CN': zhCN, 'zh-TW': zhTW, ru })) {
    for (const key of ['remoteDesktop.canvasLabel', 'remoteDesktop.status.connecting'] as const) {
      assert.match(messages[key], /\{host\}/, `${locale} ${key} must keep {host}`);
    }
  }
});

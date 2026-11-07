import assert from 'node:assert/strict';
import test from 'node:test';
import { externalUrl } from './externalLinks';

const APP = 'tauri://localhost/index.html#/settings';

test('web and mail URLs are external', () => {
  assert.equal(externalUrl('https://github.com/login/device', APP), 'https://github.com/login/device');
  assert.equal(externalUrl(new URL('http://example.com/a'), APP), 'http://example.com/a');
  assert.equal(externalUrl('mailto:a@b.c', APP), 'mailto:a@b.c');
});

test('app routes, other schemes and junk stay in the webview', () => {
  assert.equal(externalUrl('#/vault', APP), null);
  assert.equal(externalUrl('/index.html', APP), null);
  assert.equal(externalUrl('javascript:alert(1)', APP), null);
  assert.equal(externalUrl('file:///etc/passwd', APP), null);
  assert.equal(externalUrl('', APP), null);
  assert.equal(externalUrl(undefined, APP), null);
});

test('same-origin http pages (dev server) are not external', () => {
  assert.equal(externalUrl('http://localhost:5173/x', 'http://localhost:5173/'), null);
  assert.equal(externalUrl('https://github.com', 'http://localhost:5173/'), 'https://github.com/');
});

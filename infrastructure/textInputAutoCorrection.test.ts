import assert from 'node:assert/strict';
import test from 'node:test';

import { disableAutoCorrection, installAutoCorrectionGuard } from './textInputAutoCorrection';

const field = (tagName: string, attrs: Record<string, string> = {}) => {
  const store = new Map(Object.entries(attrs));
  return {
    tagName,
    hasAttribute: (name: string) => store.has(name),
    getAttribute: (name: string) => store.get(name) ?? null,
    setAttribute: (name: string, value: string) => { store.set(name, value); },
    attrs: store,
  };
};

test('turns substitutions off on a plain text input', () => {
  const input = field('INPUT');
  assert.equal(disableAutoCorrection(input), true);
  assert.equal(input.attrs.get('autocapitalize'), 'off');
  assert.equal(input.attrs.get('autocorrect'), 'off');
  assert.equal(input.attrs.get('spellcheck'), 'false');
});

test('covers textareas but leaves their spell checking alone', () => {
  const area = field('TEXTAREA');
  assert.equal(disableAutoCorrection(area), true);
  assert.equal(area.attrs.get('autocapitalize'), 'off');
  assert.equal(area.attrs.get('autocorrect'), 'off');
  assert.equal(area.attrs.has('spellcheck'), false);
});

test('keeps attributes a field set for itself', () => {
  const input = field('INPUT', { type: 'text', autocapitalize: 'words', spellcheck: 'true' });
  disableAutoCorrection(input);
  assert.equal(input.attrs.get('autocapitalize'), 'words');
  assert.equal(input.attrs.get('spellcheck'), 'true');
  assert.equal(input.attrs.get('autocorrect'), 'off');
});

test('ignores non-text inputs and other elements', () => {
  for (const type of ['checkbox', 'number', 'file', 'range', 'color']) {
    const input = field('INPUT', { type });
    assert.equal(disableAutoCorrection(input), false, type);
    assert.equal(input.attrs.size, 1, type);
  }
  assert.equal(disableAutoCorrection(field('DIV')), false);
  assert.equal(disableAutoCorrection(null), false);
});

test('the guard handles focusin and the already-focused field', () => {
  const focused = field('INPUT');
  const listeners = new Map<string, (event: Event) => void>();
  const doc = {
    activeElement: focused,
    addEventListener: (name: string, fn: (event: Event) => void) => { listeners.set(name, fn); },
    removeEventListener: (name: string) => { listeners.delete(name); },
  } as unknown as Document;

  const uninstall = installAutoCorrectionGuard(doc);
  assert.equal(focused.attrs.get('autocapitalize'), 'off');

  const next = field('INPUT', { type: 'search' });
  listeners.get('focusin')?.({ target: next } as unknown as Event);
  assert.equal(next.attrs.get('autocapitalize'), 'off');

  uninstall();
  assert.equal(listeners.size, 0);
});

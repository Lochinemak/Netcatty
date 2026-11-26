import test from 'node:test';
import assert from 'node:assert/strict';

import { addProviderModelId } from './ProviderModelListEditor';

test('addProviderModelId appends a trimmed new id', () => {
  assert.deepEqual(addProviderModelId(['a'], '  b '), ['a', 'b']);
});

test('addProviderModelId ignores blanks, duplicates and the default model', () => {
  assert.deepEqual(addProviderModelId(['a'], '   '), ['a']);
  assert.deepEqual(addProviderModelId(['a'], 'a'), ['a']);
  assert.deepEqual(addProviderModelId(['a'], 'gpt-5', ' gpt-5 '), ['a']);
});

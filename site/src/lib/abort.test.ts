import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isAbortError } from './abort.ts';

test('isAbortError matches only a DOMException named AbortError', () => {
  assert.equal(isAbortError(new DOMException('The operation was aborted.', 'AbortError')), true);
  assert.equal(isAbortError(new DOMException('Something else.', 'NotFoundError')), false);
  assert.equal(isAbortError(new Error('Aborted')), false);
  assert.equal(isAbortError({ name: 'AbortError' }), false);
  assert.equal(isAbortError(null), false);
  assert.equal(isAbortError(undefined), false);
  assert.equal(isAbortError('AbortError'), false);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scrollToHashWhenReady } from './hashScroll.ts';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

test('scrolls at once when the target is already mounted', () => {
  let scrolled = 0;
  let lookedUp = 0;
  const cancel = scrollToHashWhenReady(
    '#pricing',
    () => {
      lookedUp += 1;
      return { scrollIntoView: () => { scrolled += 1; } };
    },
    { intervalMs: 10, timeoutMs: 500 },
  );
  assert.equal(scrolled, 1);
  assert.equal(lookedUp, 1);
  cancel();
});

test('keeps polling until the target mounts', async () => {
  let scrolled = 0;
  let lookedUp = 0;
  const el = { scrollIntoView: () => { scrolled += 1; } };
  scrollToHashWhenReady(
    '#swarm',
    () => {
      lookedUp += 1;
      return lookedUp >= 4 ? el : null;
    },
    { intervalMs: 10, timeoutMs: 500 },
  );
  await sleep(150);
  assert.equal(scrolled, 1);
});

test('gives up after the timeout when the target never mounts', async () => {
  let scrolled = 0;
  let lookedUp = 0;
  scrollToHashWhenReady(
    '#faq',
    () => {
      lookedUp += 1;
      return null;
    },
    { intervalMs: 10, timeoutMs: 50 },
  );
  await sleep(120);
  const stoppedAt = lookedUp;
  assert.equal(scrolled, 0);
  assert.ok(stoppedAt > 1 && stoppedAt < 20);
  await sleep(100);
  assert.equal(lookedUp, stoppedAt);
});

test('cancel stops polling before the target mounts', async () => {
  let scrolled = 0;
  let mounted = false;
  const cancel = scrollToHashWhenReady(
    '#how',
    () => (mounted ? { scrollIntoView: () => { scrolled += 1; } } : null),
    { intervalMs: 10, timeoutMs: 500 },
  );
  cancel();
  mounted = true;
  await sleep(100);
  assert.equal(scrolled, 0);
});

test('a bad selector stops polling instead of throwing', async () => {
  let lookedUp = 0;
  scrollToHashWhenReady(
    '#[bad',
    () => {
      lookedUp += 1;
      throw new Error('bad selector');
    },
    { intervalMs: 10, timeoutMs: 500 },
  );
  await sleep(80);
  assert.equal(lookedUp, 1);
});

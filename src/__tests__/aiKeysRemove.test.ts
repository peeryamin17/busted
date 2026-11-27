// Remove-button behaviour in the real popup code (src/popup/active.ts),
// driven through the minimal DOM/fetch shim in aiKeysRemoveDom.mjs.
// Each case loads a fresh copy of active.ts (query-busted import) over a
// fresh DOM, so module-level popup state never leaks between cases.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildDomFromPopupHtml,
  documentShim,
  keyRow,
  makeChromeStorage,
  makeFetch,
  observe,
  registry,
  removeButtons,
  settle,
} from './aiKeysRemoveDom.mjs';

const unhandled: string[] = [];
process.on('unhandledRejection', (e) => {
  unhandled.push(e instanceof Error ? `${e.name}: ${e.message}` : String(e));
});

type Scenario = {
  keys: ReturnType<typeof keyRow>[];
  deleteBehavior: 'ok' | '404' | 'throw' | 'hang' | 'hang-apply';
  keysAfterDelete?: '500';
  capsAfterDelete?: '500' | 'malformed';
};

async function loadPane(scenario: Scenario, tag: string) {
  unhandled.length = 0;
  registry.clear();
  buildDomFromPopupHtml(new URL('../popup/popup.html', import.meta.url).pathname);
  (globalThis as unknown as { document: unknown }).document = documentShim;
  const { chrome } = makeChromeStorage({
    'bugseek:apiKey': 'bs_testkey1234567890',
    'bugseek:legacyKeysCleaned': true,
  });
  (globalThis as unknown as { chrome: unknown }).chrome = chrome;
  const fake = makeFetch(scenario);
  (globalThis as unknown as { fetch: unknown }).fetch = fake.fetch;
  const spec = `../popup/active.ts?remove-${tag}`;
  const mod = (await import(spec)) as {
    initActivePane: (tabId: number, tabUrl: string) => Promise<void>;
  };
  await mod.initActivePane(1, 'https://example.com/');
  await settle(fake);
  assert.equal(observe().rowCount, 1, 'key row renders before the click');
  return fake;
}

test('remove: DELETE ok then keys GET 500 still drops the row (case b)', async () => {
  const fake = await loadPane(
    { keys: [keyRow('qwen', '****9Qi4')], deleteBehavior: 'ok', keysAfterDelete: '500' },
    'b',
  );
  removeButtons()[0].click();
  await settle(fake);
  const seen = observe();
  assert.equal(seen.rowCount, 0, 'row is gone even though the refresh failed');
  assert.deepEqual(fake.serverKeys, [], 'key is deleted server-side');
  assert.match(seen.statusText, /removed/, 'status says the key was removed');
  assert.match(seen.errorText, /Could not load saved keys/, 'refresh failure is shown honestly');
  assert.equal(unhandled.length, 0, 'no unhandled rejection');
});

test('remove: DELETE ok then capabilities GET 500 still drops the row (case c)', async () => {
  const fake = await loadPane(
    { keys: [keyRow('qwen', '****9Qi4')], deleteBehavior: 'ok', capsAfterDelete: '500' },
    'c',
  );
  removeButtons()[0].click();
  await settle(fake);
  const seen = observe();
  assert.equal(seen.rowCount, 0, 'row is gone even though the refresh failed');
  assert.match(seen.statusText, /removed/, 'status says the key was removed');
  assert.match(seen.errorText, /Could not load providers/, 'refresh failure is shown honestly');
  assert.equal(unhandled.length, 0, 'no unhandled rejection');
});

test('remove: DELETE ok then malformed capabilities still drops the row (case d)', async () => {
  const fake = await loadPane(
    { keys: [keyRow('qwen', '****9Qi4')], deleteBehavior: 'ok', capsAfterDelete: 'malformed' },
    'd',
  );
  removeButtons()[0].click();
  await settle(fake);
  const seen = observe();
  assert.equal(seen.rowCount, 0, 'row is gone even though the refresh blew up');
  assert.ok(seen.errorText.length > 0, 'refresh failure is shown, not swallowed');
  assert.equal(unhandled.length, 0, `no unhandled rejection, got: ${unhandled.join('; ')}`);
});

test('remove: DELETE 404 means already gone, so the row drops (case e)', async () => {
  const fake = await loadPane({ keys: [keyRow('qwen', '****9Qi4')], deleteBehavior: '404' }, 'e');
  removeButtons()[0].click();
  await settle(fake);
  const seen = observe();
  assert.equal(seen.rowCount, 0, 'row is gone: a 404 means the key is already gone server-side');
  assert.match(seen.statusText, /removed/, 'status says the key was removed');
  assert.equal(unhandled.length, 0, 'no unhandled rejection');
});

test('remove: DELETE times out with the key still saved keeps the row and the button (case f2)', async () => {
  const fake = await loadPane({ keys: [keyRow('qwen', '****9Qi4')], deleteBehavior: 'hang' }, 'f2');
  removeButtons()[0].click();
  await settle(fake);
  const seen = observe();
  assert.equal(seen.rowCount, 1, 'row stays: the delete never landed');
  assert.equal(seen.rows[0].removeDisabled, false, 'button is re-enabled after the timeout');
  assert.ok(seen.errorText.length > 0, 'timeout error is shown honestly');
  assert.equal(fake.serverKeys.length, 1, 'key is still saved server-side');
  assert.equal(unhandled.length, 0, 'no unhandled rejection');
});

test('remove: DELETE times out but the server applied it, retry 404s, row still drops (case h)', async () => {
  const fake = await loadPane(
    { keys: [keyRow('qwen', '****9Qi4')], deleteBehavior: 'hang-apply' },
    'h',
  );
  removeButtons()[0].click();
  await settle(fake);
  const afterFirst = observe();
  assert.equal(afterFirst.rowCount, 1, 'row stays after the timed-out click: delete was unconfirmed');
  assert.equal(afterFirst.rows[0].removeDisabled, false, 'button is re-enabled after the timeout');
  assert.deepEqual(fake.serverKeys, [], 'server applied the delete despite the timeout');
  const retry = removeButtons()[0];
  assert.ok(retry, 'Remove button is still there to retry with');
  retry.click();
  await settle(fake);
  const afterRetry = observe();
  assert.equal(afterRetry.rowCount, 0, 'retry 404s but the row drops: the key is gone');
  assert.match(afterRetry.statusText, /removed/, 'status says the key was removed');
  assert.equal(unhandled.length, 0, 'no unhandled rejection');
});

test('remove: happy path drops the row with no error (case a)', async () => {
  const fake = await loadPane({ keys: [keyRow('qwen', '****9Qi4')], deleteBehavior: 'ok' }, 'a');
  removeButtons()[0].click();
  await settle(fake);
  const seen = observe();
  assert.equal(seen.rowCount, 0, 'row is gone');
  assert.match(seen.statusText, /removed/, 'status says the key was removed');
  assert.equal(seen.errorHidden, true, 'no error left showing after a clean remove');
  assert.equal(unhandled.length, 0, 'no unhandled rejection');
});

/**
 * Unit tests for notification channels + senders (src/notify/channels.ts,
 * src/notify/send.ts, src/routes/notify.ts public view).
 * No network, no DB, no LLM, fetch and SMTP are injected fakes.
 *
 * Run:  npx tsx test/notify.test.ts   (from backend/)
 */
import { encryptSecret } from '../src/lib/crypto.js';
import { MemorySecretStore } from '../src/secrets/store.js';
import {
  MemoryNotifyChannelStore,
  channelMatchesEvent,
  validateNotifyChannelInput,
  validateNotifyTarget,
  type NotifyChannelRecord,
} from '../src/notify/channels.js';
import {
  NotifyService,
  type FetchFn,
  type NotifyEvent,
  type SmtpTransport,
} from '../src/notify/send.js';
import { channelPublicView } from '../src/routes/notify.js';

let failures = 0;
let checks = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  checks++;
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const USER = 'user-1';
const OTHER_USER = 'user-2';

// ── Fake fetch: records calls, answers from a per-test handler ──────────

interface FakeReply {
  status: number;
  headers?: Record<string, string>;
  body?: string;
}

function makeFakeFetch(handler: (url: string, init?: RequestInit) => FakeReply) {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const fn: FetchFn = async (url, init) => {
    calls.push({ url, init });
    const reply = handler(url, init);
    return new Response(reply.body ?? '', {
      status: reply.status,
      headers: reply.headers,
    });
  };
  return { fn, calls };
}

function okFetch(): ReturnType<typeof makeFakeFetch> {
  return makeFakeFetch(() => ({ status: 200, body: '{"ok":true}' }));
}

// ── Fake SMTP transport: records mails ───────────────────────────────────

function makeFakeSmtp() {
  const mails: Array<{ from: string; to: string; subject: string; text: string }> = [];
  const transport: SmtpTransport = {
    async sendMail(opts) {
      mails.push({ ...opts });
    },
  };
  return { factory: () => transport, mails };
}

const findingHigh: NotifyEvent = {
  kind: 'finding-high',
  taskId: 'task-1',
  title: 'High finding on example.com',
  severity: 'high',
  url: 'https://bugseek-ai.vercel.app/app',
};

const findingCritical: NotifyEvent = {
  ...findingHigh,
  kind: 'finding-critical',
  title: 'Critical finding on example.com',
  severity: 'critical',
};

const taskCompleted: NotifyEvent = {
  kind: 'task-completed',
  taskId: 'task-1',
  title: 'Task finished',
  severity: 'info',
};

async function main() {
  // ── 1. Channel validation ──
  {
    let threw = false;
    try {
      validateNotifyTarget('webhook', { url: 'ftp://hooks.example.com/x' });
    } catch (e) {
      threw = /invalid_webhook_url/.test((e as Error).message);
    }
    check('validation: ftp webhook URL rejected', threw);
    let threw2 = false;
    try {
      validateNotifyTarget('webhook', { url: 'not a url' });
    } catch {
      threw2 = true;
    }
    check('validation: unparseable webhook URL rejected', threw2);
    for (const badPort of [0, 70000, -1, 1.5, 'abc']) {
      let threwPort = false;
      try {
        validateNotifyTarget('smtp', {
          host: 'mail.example.com', port: badPort, user: 'u',
          from: 'a@example.com', to: 'b@example.com',
        });
      } catch (e) {
        threwPort = /invalid_smtp_port/.test((e as Error).message);
      }
      check(`validation: SMTP port ${String(badPort)} rejected`, threwPort);
    }
    let threwHost = false;
    try {
      validateNotifyTarget('smtp', {
        host: '  ', port: 25, user: 'u', from: 'a@example.com', to: 'b@example.com',
      });
    } catch (e) {
      threwHost = /invalid_smtp_host/.test((e as Error).message);
    }
    check('validation: empty SMTP host rejected', threwHost);
    let threwChat = false;
    try {
      validateNotifyTarget('telegram', { chatId: '' });
    } catch (e) {
      threwChat = /invalid_telegram_chat_id/.test((e as Error).message);
    }
    check('validation: empty Telegram chat id rejected', threwChat);
    const good = validateNotifyChannelInput({
      userId: USER,
      type: 'webhook',
      label: 'hooks',
      target: { url: 'https://hooks.example.com/notify' },
    });
    check('validation: good webhook input passes', good.type === 'webhook' && good.enabled === true);
    check('validation: default filters cover every event', good.filters.events.length === 4);
    check('validation: default min severity is info', good.filters.minSeverity === 'info');
  }

  // ── 2. Filter logic via fan-out ──
  {
    const channels = new MemoryNotifyChannelStore();
    const secrets = new MemorySecretStore();
    const fetchFake = okFetch();
    const criticalOnly = await channels.create({
      userId: USER,
      type: 'webhook',
      label: 'critical-only',
      target: { url: 'https://hooks.example.com/critical' },
      filters: { minSeverity: 'critical', events: ['finding-critical', 'finding-high'] },
    });
    const taskOnly = await channels.create({
      userId: USER,
      type: 'webhook',
      label: 'task-only',
      target: { url: 'https://hooks.example.com/tasks' },
      filters: { minSeverity: 'info', events: ['task-completed'] },
    });
    const disabled = await channels.create({
      userId: USER,
      type: 'webhook',
      label: 'disabled',
      target: { url: 'https://hooks.example.com/off' },
      enabled: false,
    });
    const service = new NotifyService({ channels, secrets, fetchFn: fetchFake.fn });

    fetchFake.calls.length = 0;
    const highResults = await service.notifyEvent(USER, findingHigh);
    check('filter: high finding sends to no channel', fetchFake.calls.length === 0, fetchFake.calls);
    check(
      'filter: critical-only channel reports filtered out for a high finding',
      highResults.find((r) => r.channelId === criticalOnly.id)?.error === 'event_filtered_out',
      highResults,
    );
    check(
      'filter: task-completed channel reports filtered out for a finding',
      highResults.find((r) => r.channelId === taskOnly.id)?.error === 'event_filtered_out',
      highResults,
    );
    check(
      'filter: disabled channel reports channel_disabled',
      highResults.find((r) => r.channelId === disabled.id)?.error === 'channel_disabled',
      highResults,
    );

    fetchFake.calls.length = 0;
    const criticalResults = await service.notifyEvent(USER, findingCritical);
    check('filter: critical finding sends to exactly one channel', fetchFake.calls.length === 1, fetchFake.calls);
    check(
      'filter: the one send goes to the critical-only channel',
      fetchFake.calls[0]?.url === 'https://hooks.example.com/critical',
      fetchFake.calls,
    );
    check(
      'filter: critical send reports ok',
      criticalResults.find((r) => r.channelId === criticalOnly.id)?.ok === true,
      criticalResults,
    );

    fetchFake.calls.length = 0;
    await service.notifyEvent(USER, taskCompleted);
    check('filter: task-completed sends to the task channel only', fetchFake.calls.length === 1, fetchFake.calls);
    check(
      'filter: task send goes to the task-only channel',
      fetchFake.calls[0]?.url === 'https://hooks.example.com/tasks',
      fetchFake.calls,
    );

    // Direct matcher: disabled never matches, whatever the event.
    check(
      'filter: channelMatchesEvent false for a disabled channel',
      channelMatchesEvent(disabled, { kind: 'task-completed', severity: 'info' }) === false,
    );
    check(
      'filter: channelMatchesEvent true for a matching enabled channel',
      channelMatchesEvent(criticalOnly, { kind: 'finding-critical', severity: 'critical' }) === true,
    );
  }

  // ── 3. Webhook send shape ──
  {
    const channels = new MemoryNotifyChannelStore();
    const secrets = new MemorySecretStore();
    const fetchFake = okFetch();
    const channel = await channels.create({
      userId: USER,
      type: 'webhook',
      label: 'hooks',
      target: { url: 'https://hooks.example.com/notify' },
    });
    const service = new NotifyService({ channels, secrets, fetchFn: fetchFake.fn });
    const result = await service.sendToChannel(channel, findingCritical, { ignoreFilters: true });
    check('webhook: send reports ok', result.ok === true, result);
    const call = fetchFake.calls[0];
    check('webhook: POST method', call?.init?.method === 'POST', call?.init);
    const headers = call?.init?.headers as Record<string, string> | undefined;
    check('webhook: JSON content type', headers?.['content-type'] === 'application/json', headers);
    const body = JSON.parse(String(call?.init?.body ?? '{}')) as Record<string, unknown>;
    check('webhook: body carries the event kind', body['event'] === 'finding-critical', body);
    check('webhook: body carries the task id', body['taskId'] === 'task-1', body);
    check('webhook: body carries the title', body['title'] === 'Critical finding on example.com', body);
    check('webhook: body carries the severity', body['severity'] === 'critical', body);
    check('webhook: body carries the url', body['url'] === 'https://bugseek-ai.vercel.app/app', body);
    check('webhook: no auth header without a stored secret', headers?.['authorization'] === undefined, headers);
  }

  // ── 4. Redirects: cross-origin refused, same-origin followed ──
  {
    const channels = new MemoryNotifyChannelStore();
    const secrets = new MemorySecretStore();
    const evil = makeFakeFetch((url) =>
      url === 'https://hooks.example.com/notify'
        ? { status: 302, headers: { location: 'https://evil.example.com/steal' } }
        : { status: 200, body: '{}' },
    );
    const channel = await channels.create({
      userId: USER,
      type: 'webhook',
      label: 'hooks',
      target: { url: 'https://hooks.example.com/notify' },
    });
    const service = new NotifyService({ channels, secrets, fetchFn: evil.fn });
    const result = await service.sendToChannel(channel, findingCritical, { ignoreFilters: true });
    check('redirect: cross-origin redirect refused', result.ok === false, result);
    check(
      'redirect: refusal names the rule',
      result.error === 'cross_origin_redirect_refused',
      result,
    );
    check('redirect: evil origin never fetched', evil.calls.length === 1, evil.calls);

    const sameOrigin = makeFakeFetch((url) =>
      url === 'https://hooks.example.com/notify'
        ? { status: 302, headers: { location: '/notify2' } }
        : { status: 200, body: '{"ok":true}' },
    );
    const service2 = new NotifyService({ channels, secrets, fetchFn: sameOrigin.fn });
    const result2 = await service2.sendToChannel(channel, findingCritical, { ignoreFilters: true });
    check('redirect: same-origin redirect followed to ok', result2.ok === true, result2);
    check('redirect: same-origin hop fetched twice', sameOrigin.calls.length === 2, sameOrigin.calls);
    check(
      'redirect: second hop is the resolved same-origin URL',
      sameOrigin.calls[1]?.url === 'https://hooks.example.com/notify2',
      sameOrigin.calls,
    );
  }

  // ── 5. Response cap ──
  {
    const channels = new MemoryNotifyChannelStore();
    const secrets = new MemorySecretStore();
    const huge = makeFakeFetch(() => ({ status: 200, body: 'x'.repeat(1_048_577) }));
    const channel = await channels.create({
      userId: USER,
      type: 'webhook',
      label: 'hooks',
      target: { url: 'https://hooks.example.com/notify' },
    });
    const service = new NotifyService({ channels, secrets, fetchFn: huge.fn });
    const result = await service.sendToChannel(channel, findingCritical, { ignoreFilters: true });
    check('cap: response over 1 MiB fails the send', result.ok === false && result.error === 'response_too_large', result);
  }

  // ── 6. Telegram: token only in the request, never in a returned record ──
  {
    const channels = new MemoryNotifyChannelStore();
    const secrets = new MemorySecretStore();
    const fetchFake = okFetch();
    const token = '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11';
    const channel = await channels.create({
      userId: USER,
      type: 'telegram',
      label: 'tg',
      target: { chatId: '-1001234567890' },
    });
    await secrets.save({
      userId: USER,
      kind: 'notify',
      label: channel.id,
      encryptedValue: encryptSecret(token),
      hint: '1234••••ew11',
    });
    const service = new NotifyService({ channels, secrets, fetchFn: fetchFake.fn });
    const result = await service.sendToChannel(channel, findingCritical, { ignoreFilters: true });
    check('telegram: send reports ok', result.ok === true, result);
    const call = fetchFake.calls[0];
    check(
      'telegram: request goes to the bot token URL',
      call?.url === `https://api.telegram.org/bot${token}/sendMessage`,
      call?.url,
    );
    const body = JSON.parse(String(call?.init?.body ?? '{}')) as Record<string, unknown>;
    check('telegram: body carries the chat id', body['chat_id'] === '-1001234567890', body);
    check('telegram: body text names the finding', String(body['text'] ?? '').includes('Critical finding'), body);
    check('telegram: returned result never contains the token', !JSON.stringify(result).includes(token), result);
    check('telegram: channel record never contains the token', !JSON.stringify(channel).includes(token), channel);
    check(
      'telegram: stored hint is masked, not the token',
      (await secrets.list(USER, 'notify'))[0]?.hint === '1234••••ew11',
    );

    // No stored token → clean failure, no throw.
    const noToken = await channels.create({
      userId: USER,
      type: 'telegram',
      label: 'tg-no-token',
      target: { chatId: '123' },
    });
    const missing = await service.sendToChannel(noToken, findingCritical, { ignoreFilters: true });
    check('telegram: missing token fails cleanly', missing.ok === false && missing.error === 'telegram_token_missing', missing);
  }

  // ── 7. Rate limit: 11th send in a minute dropped, counted ──
  {
    const channels = new MemoryNotifyChannelStore();
    const secrets = new MemorySecretStore();
    const fetchFake = okFetch();
    let nowMs = 1_000_000;
    const channel = await channels.create({
      userId: USER,
      type: 'webhook',
      label: 'hooks',
      target: { url: 'https://hooks.example.com/notify' },
    });
    const service = new NotifyService({
      channels,
      secrets,
      fetchFn: fetchFake.fn,
      now: () => nowMs,
    });
    let okCount = 0;
    let last;
    for (let i = 0; i < 11; i++) {
      last = await service.sendToChannel(channel, findingCritical, { ignoreFilters: true });
      if (last.ok) okCount++;
    }
    check('rate: first 10 sends in a minute succeed', okCount === 10, { okCount });
    check('rate: 11th send dropped', last?.ok === false && last?.rateLimited === true, last);
    check('rate: drop reason is rate_limited', last?.error === 'rate_limited', last);
    check('rate: one drop counted', service.droppedCount(channel.id) === 1);
    check('rate: exactly 10 fetches happened', fetchFake.calls.length === 10, fetchFake.calls.length);
    // A minute later the budget refills.
    nowMs += 61_000;
    const after = await service.sendToChannel(channel, findingCritical, { ignoreFilters: true });
    check('rate: budget refills after the window', after.ok === true, after);
  }

  // ── 8. Send failure returns ok:false without throwing ──
  {
    const channels = new MemoryNotifyChannelStore();
    const secrets = new MemorySecretStore();
    const exploding: FetchFn = async () => {
      throw new Error('boom');
    };
    const channel = await channels.create({
      userId: USER,
      type: 'webhook',
      label: 'hooks',
      target: { url: 'https://hooks.example.com/notify' },
    });
    const service = new NotifyService({ channels, secrets, fetchFn: exploding });
    let result;
    let threw = false;
    try {
      result = await service.sendToChannel(channel, findingCritical, { ignoreFilters: true });
    } catch {
      threw = true;
    }
    check('failure: throwing fetch does not throw to the caller', threw === false);
    check('failure: throwing fetch returns ok:false', result?.ok === false, result);

    const failing = makeFakeFetch(() => ({ status: 500, body: 'nope' }));
    const service2 = new NotifyService({ channels, secrets, fetchFn: failing.fn });
    const httpResult = await service2.sendToChannel(channel, findingCritical, { ignoreFilters: true });
    check('failure: HTTP 500 returns ok:false', httpResult.ok === false && httpResult.error === 'webhook_http_500', httpResult);

    const fanout = await service2.notifyEvent(USER, findingCritical);
    check('failure: fan-out still returns per-channel results', fanout.length === 1 && fanout[0]?.ok === false, fanout);
  }

  // ── 9. SMTP via the injected transport ──
  {
    const channels = new MemoryNotifyChannelStore();
    const secrets = new MemorySecretStore();
    const smtp = makeFakeSmtp();
    const channel = await channels.create({
      userId: USER,
      type: 'smtp',
      label: 'mail',
      target: {
        host: 'mail.example.com', port: 25, user: 'alerts',
        from: 'alerts@example.com', to: 'peer@example.com',
      },
    });
    await secrets.save({
      userId: USER,
      kind: 'notify',
      label: channel.id,
      encryptedValue: encryptSecret('smtp-password'),
      hint: 'smtp••••word',
    });
    const service = new NotifyService({
      channels,
      secrets,
      fetchFn: okFetch().fn,
      smtpTransportFactory: smtp.factory,
    });
    const result = await service.sendToChannel(channel, findingCritical, { ignoreFilters: true });
    check('smtp: send reports ok', result.ok === true, result);
    check('smtp: exactly one mail sent', smtp.mails.length === 1, smtp.mails);
    check('smtp: mail from the channel address', smtp.mails[0]?.from === 'alerts@example.com', smtp.mails[0]);
    check('smtp: mail to the channel address', smtp.mails[0]?.to === 'peer@example.com', smtp.mails[0]);
    check('smtp: subject names the finding', (smtp.mails[0]?.subject ?? '').includes('Critical finding'), smtp.mails[0]);
    check('smtp: returned result never contains the password', !JSON.stringify(result).includes('smtp-password'), result);

    const noPassword = await channels.create({
      userId: USER,
      type: 'smtp',
      label: 'mail-no-pass',
      target: {
        host: 'mail.example.com', port: 25, user: 'alerts',
        from: 'alerts@example.com', to: 'peer@example.com',
      },
    });
    const missing = await service.sendToChannel(noPassword, findingCritical, { ignoreFilters: true });
    check('smtp: missing password fails cleanly', missing.ok === false && missing.error === 'smtp_password_missing', missing);
  }

  // ── 10. List responses: hint only, never ciphertext ──
  {
    const channels = new MemoryNotifyChannelStore();
    const secrets = new MemorySecretStore();
    const channel = await channels.create({
      userId: USER,
      type: 'telegram',
      label: 'tg',
      target: { chatId: '123' },
    });
    const stored = await secrets.save({
      userId: USER,
      kind: 'notify',
      label: channel.id,
      encryptedValue: encryptSecret('123456:SECRET-TOKEN'),
      hint: '1234••••OKEN',
    });
    const summaries = await secrets.list(USER, 'notify');
    const view = channelPublicView(channel, summaries[0]?.hint ?? null);
    const dumped = JSON.stringify(view);
    check('list: public view carries the masked hint', view.secretHint === '1234••••OKEN', view);
    check('list: public view never contains ciphertext', !dumped.includes(stored.encryptedValue), dumped);
    check('list: public view never contains the plaintext secret', !dumped.includes('123456:SECRET-TOKEN'), dumped);
    check('list: public view has no encryptedValue field', !('encryptedValue' in view), view);
  }

  // ── 11. Store: list/remove scoping ──
  {
    const channels = new MemoryNotifyChannelStore();
    const mine = await channels.create({
      userId: USER,
      type: 'webhook',
      label: 'mine',
      target: { url: 'https://hooks.example.com/a' },
    });
    await channels.create({
      userId: OTHER_USER,
      type: 'webhook',
      label: 'theirs',
      target: { url: 'https://hooks.example.com/b' },
    });
    const listed = await channels.listForUser(USER);
    check('store: list returns only the caller\'s channels', listed.length === 1 && listed[0]?.id === mine.id, listed);
    check('store: removing another user\'s channel fails', (await channels.remove(mine.id, OTHER_USER)) === false);
    check('store: owner can remove', (await channels.remove(mine.id, USER)) === true);
    check('store: removed channel reads as null', (await channels.get(mine.id)) === null);
  }

  if (failures > 0) {
    console.error(`${failures} of ${checks} notify test(s) failed`);
    process.exit(1);
  }
  console.log(`ALL NOTIFY TESTS PASSED (${checks} checks)`);
  process.exit(0);
}

main().catch((e) => {
  console.error('notify test crashed', e);
  process.exit(1);
});

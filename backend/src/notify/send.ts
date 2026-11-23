/**
 * Notification senders: webhook, Telegram, SMTP. Best-effort: a failure
 * returns {ok:false} and never throws. At most 10 sends per 60 s per
 * channel. SMTP here is plain, no TLS.
 */
import net from 'node:net';
import { decryptSecret } from '../lib/crypto.js';
import type { SecretStore } from '../secrets/store.js';
import {
  channelMatchesEvent,
  type NotifyChannelRecord,
  type NotifyChannelStore,
  type NotifyEventKind,
  type NotifySeverity,
} from './channels.js';

/** One event worth telling the operator about. */
export interface NotifyEvent {
  kind: NotifyEventKind;
  taskId: string;
  title: string;
  severity: NotifySeverity;
  url?: string;
}

export interface SendResult {
  ok: boolean;
  channelId: string;
  error?: string;
  /** True when the send was dropped by the per-channel rate limit. */
  rateLimited?: boolean;
}

/** Minimal fetch shape (global fetch, or an injected fake in tests). */
export type FetchFn = (url: string, init?: RequestInit) => Promise<Response>;

/** A mail transport: the only thing the fan-out needs from SMTP. */
export interface SmtpTransport {
  sendMail(opts: { from: string; to: string; subject: string; text: string }): Promise<void>;
}

export type SmtpTransportFactory = (opts: {
  host: string;
  port: number;
  user: string;
  password: string;
}) => SmtpTransport;

export const SEND_TIMEOUT_MS = 10_000;
export const WEBHOOK_MAX_RESPONSE_BYTES = 1_048_576; // 1 MiB
export const RATE_LIMIT_MAX_SENDS = 10;
export const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_REDIRECT_HOPS = 3;

function fail(channelId: string, error: string): SendResult {
  return { ok: false, channelId, error };
}

/** In-process per-channel rate limiter: max N sends per window. Drops are counted, never thrown. */
export class ChannelRateLimiter {
  private readonly hits = new Map<string, number[]>();
  private readonly drops = new Map<string, number>();

  constructor(
    private readonly maxPerWindow: number = RATE_LIMIT_MAX_SENDS,
    private readonly windowMs: number = RATE_LIMIT_WINDOW_MS,
  ) {}

  /** True when the channel may send now (and the send is booked). */
  tryAcquire(channelId: string, nowMs: number): boolean {
    const recent = (this.hits.get(channelId) ?? []).filter((t) => nowMs - t < this.windowMs);
    if (recent.length >= this.maxPerWindow) {
      this.hits.set(channelId, recent);
      this.drops.set(channelId, (this.drops.get(channelId) ?? 0) + 1);
      return false;
    }
    recent.push(nowMs);
    this.hits.set(channelId, recent);
    return true;
  }

  droppedCount(channelId: string): number {
    return this.drops.get(channelId) ?? 0;
  }
}

/**
 * Read a response body up to `cap` bytes. Over the cap the reader is
 * cancelled and the result is marked too-large, so a runaway response
 * can never fill memory.
 */
async function readCappedBody(
  res: Response,
  cap: number,
): Promise<{ ok: boolean; text: string }> {
  if (!res.body) return { ok: true, text: '' };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > cap) {
        await reader.cancel().catch(() => undefined);
        return { ok: false, text: '' };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, text: '' };
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, text: new TextDecoder().decode(merged) };
}

function webhookPayload(event: NotifyEvent): Record<string, unknown> {
  return {
    event: event.kind,
    taskId: event.taskId,
    title: event.title,
    severity: event.severity,
    url: event.url ?? null,
  };
}

/**
 * POST the webhook payload, following same-origin redirects for at
 * most 3 hops and refusing any cross-origin redirect. Returns the
 * final response (never throws for HTTP-level outcomes).
 */
export async function postWebhook(
  fetchFn: FetchFn,
  url: string,
  event: NotifyEvent,
  extraHeaders?: Record<string, string>,
): Promise<{ ok: boolean; error?: string }> {
  const body = JSON.stringify(webhookPayload(event));
  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
    let res: Response;
    try {
      res = await fetchFn(current, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(extraHeaders ?? {}),
        },
        body,
        redirect: 'manual',
        signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
      });
    } catch (err) {
      const name = (err as Error)?.name ?? '';
      if (name === 'TimeoutError' || name === 'AbortError') return { ok: false, error: 'webhook_timeout' };
      return { ok: false, error: 'webhook_request_failed' };
    }
    const location = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && location) {
      await res.arrayBuffer().catch(() => undefined);
      let next: URL;
      try {
        next = new URL(location, current);
      } catch {
        return { ok: false, error: 'webhook_bad_redirect' };
      }
      if (next.origin !== new URL(current).origin) {
        return { ok: false, error: 'cross_origin_redirect_refused' };
      }
      if (hop === MAX_REDIRECT_HOPS) return { ok: false, error: 'too_many_redirects' };
      current = next.toString();
      continue;
    }
    const capped = await readCappedBody(res, WEBHOOK_MAX_RESPONSE_BYTES);
    if (!capped.ok) return { ok: false, error: 'response_too_large' };
    if (!res.ok) return { ok: false, error: `webhook_http_${res.status}` };
    return { ok: true };
  }
  return { ok: false, error: 'too_many_redirects' };
}

function formatEventText(event: NotifyEvent): string {
  const lines = [
    `[BugSeek] ${event.title}`,
    `Event: ${event.kind}`,
    `Task: ${event.taskId}`,
    `Severity: ${event.severity}`,
  ];
  if (event.url) lines.push(`Link: ${event.url}`);
  return lines.join('\n');
}

/**
 * Send one event through one Telegram channel. The bot token comes
 * from the secrets store (decrypted here, at send time only) and is
 * never included in any returned value or error string.
 */
export async function sendTelegram(
  fetchFn: FetchFn,
  secrets: SecretStore,
  channel: NotifyChannelRecord,
  event: NotifyEvent,
): Promise<SendResult> {
  const target = channel.target;
  if (!('chatId' in target)) return fail(channel.id, 'telegram_bad_target');
  let token: string;
  try {
    const stored = await secrets.get(channel.userId, 'notify', channel.id);
    if (!stored) return fail(channel.id, 'telegram_token_missing');
    token = decryptSecret(stored.encryptedValue);
  } catch {
    return fail(channel.id, 'telegram_token_unreadable');
  }
  let res: Response;
  try {
    res = await fetchFn(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: target.chatId, text: formatEventText(event) }),
      redirect: 'manual',
      signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    });
  } catch (err) {
    const name = (err as Error)?.name ?? '';
    if (name === 'TimeoutError' || name === 'AbortError') return fail(channel.id, 'telegram_timeout');
    return fail(channel.id, 'telegram_request_failed');
  }
  await readCappedBody(res, WEBHOOK_MAX_RESPONSE_BYTES);
  if (!res.ok) return fail(channel.id, `telegram_http_${res.status}`);
  return { ok: true, channelId: channel.id };
}

/** Send one event through one webhook channel. A stored secret (if any) is sent as a Bearer token. */
export async function sendWebhook(
  fetchFn: FetchFn,
  secrets: SecretStore,
  channel: NotifyChannelRecord,
  event: NotifyEvent,
): Promise<SendResult> {
  const target = channel.target;
  if (!('url' in target)) return fail(channel.id, 'webhook_bad_target');
  let extraHeaders: Record<string, string> | undefined;
  try {
    const stored = await secrets.get(channel.userId, 'notify', channel.id);
    if (stored) {
      extraHeaders = { authorization: `Bearer ${decryptSecret(stored.encryptedValue)}` };
    }
  } catch {
    return fail(channel.id, 'webhook_secret_unreadable');
  }
  const result = await postWebhook(fetchFn, target.url, event, extraHeaders);
  return result.ok ? { ok: true, channelId: channel.id } : fail(channel.id, result.error ?? 'webhook_failed');
}

/** Send one event through one SMTP channel, via the injected transport factory. */
export async function sendSmtp(
  factory: SmtpTransportFactory,
  secrets: SecretStore,
  channel: NotifyChannelRecord,
  event: NotifyEvent,
): Promise<SendResult> {
  const target = channel.target;
  if (!('host' in target)) return fail(channel.id, 'smtp_bad_target');
  let password: string;
  try {
    const stored = await secrets.get(channel.userId, 'notify', channel.id);
    if (!stored) return fail(channel.id, 'smtp_password_missing');
    password = decryptSecret(stored.encryptedValue);
  } catch {
    return fail(channel.id, 'smtp_password_unreadable');
  }
  try {
    const transport = factory({
      host: target.host,
      port: target.port,
      user: target.user,
      password,
    });
    await transport.sendMail({
      from: target.from,
      to: target.to,
      subject: `[BugSeek] ${event.title}`,
      text: formatEventText(event),
    });
  } catch (err) {
    const name = (err as Error)?.name ?? '';
    if (name === 'TimeoutError' || /timeout|timed out/i.test((err as Error)?.message ?? '')) {
      return fail(channel.id, 'smtp_timeout');
    }
    return fail(channel.id, 'smtp_send_failed');
  }
  return { ok: true, channelId: channel.id };
}

export interface NotifyServiceDeps {
  channels: NotifyChannelStore;
  secrets: SecretStore;
  /** Defaults to global fetch. Tests inject a fake. */
  fetchFn?: FetchFn;
  /** Defaults to NodeSmtpTransport. Tests inject a fake factory. */
  smtpTransportFactory?: SmtpTransportFactory;
  /** Defaults to Date.now. Tests inject a fixed clock. */
  now?: () => number;
  /** Max sends per channel per window (default 10). */
  rateLimitMax?: number;
}

/**
 * The fan-out: load a user's enabled channels, apply each channel's
 * filters, and send to the matching ones only. Individual send
 * failures come back as per-channel `{ok:false, error}` results,
 * never as throws.
 */
export class NotifyService {
  private readonly channels: NotifyChannelStore;
  private readonly secrets: SecretStore;
  private readonly fetchFn: FetchFn;
  private readonly smtpTransportFactory: SmtpTransportFactory;
  private readonly now: () => number;
  private readonly limiter: ChannelRateLimiter;

  constructor(deps: NotifyServiceDeps) {
    this.channels = deps.channels;
    this.secrets = deps.secrets;
    this.fetchFn = deps.fetchFn ?? fetch;
    this.smtpTransportFactory = deps.smtpTransportFactory ?? ((opts) => new NodeSmtpTransport(opts));
    this.now = deps.now ?? Date.now;
    this.limiter = new ChannelRateLimiter(deps.rateLimitMax, RATE_LIMIT_WINDOW_MS);
  }

  /** How many sends to this channel the rate limit has dropped. */
  droppedCount(channelId: string): number {
    return this.limiter.droppedCount(channelId);
  }

  /**
   * Send one event through one channel. Filters are applied unless
   * `ignoreFilters` is set (the test endpoint uses that: a test is an
   * explicit operator action, not an event the filters should gate).
   * Never throws for a send failure.
   */
  async sendToChannel(
    channel: NotifyChannelRecord,
    event: NotifyEvent,
    opts?: { ignoreFilters?: boolean },
  ): Promise<SendResult> {
    if (!channel.enabled) return fail(channel.id, 'channel_disabled');
    if (!opts?.ignoreFilters && !channelMatchesEvent(channel, event)) {
      return fail(channel.id, 'event_filtered_out');
    }
    if (!this.limiter.tryAcquire(channel.id, this.now())) {
      return { ok: false, channelId: channel.id, error: 'rate_limited', rateLimited: true };
    }
    try {
      if (channel.type === 'webhook') return await sendWebhook(this.fetchFn, this.secrets, channel, event);
      if (channel.type === 'telegram') return await sendTelegram(this.fetchFn, this.secrets, channel, event);
      return await sendSmtp(this.smtpTransportFactory, this.secrets, channel, event);
    } catch {
      // A sender that throws anyway must not take the fan-out down with it.
      return fail(channel.id, 'send_failed');
    }
  }

  /** Send a test event through one channel, bypassing its filters. */
  async sendTest(channel: NotifyChannelRecord): Promise<SendResult> {
    const testEvent: NotifyEvent = {
      kind: 'task-completed',
      taskId: 'test',
      title: 'BugSeek test notification',
      severity: 'info',
      url: 'https://bugseek-ai.vercel.app/app',
    };
    return this.sendToChannel(channel, testEvent, { ignoreFilters: true });
  }

  /** Fan out one event to every matching channel the user enabled. */
  async notifyEvent(userId: string, event: NotifyEvent): Promise<SendResult[]> {
    const channels = await this.channels.listForUser(userId);
    const results: SendResult[] = [];
    for (const channel of channels) {
      results.push(await this.sendToChannel(channel, event));
    }
    return results;
  }
}

// ── Plain-SMTP transport (no TLS) ────────────────────────────────────────

/**
 * Minimal SMTP client over a plain TCP socket: greeting, EHLO,
 * AUTH PLAIN, MAIL FROM, RCPT TO, DATA, QUIT. 10 s overall timeout.
 *
 * No TLS: this speaks plain SMTP only. Do not point it at a
 * server that requires STARTTLS or implicit TLS (ports 465/587 on
 * most providers), those connections will fail at EHLO/AUTH. For
 * production alerts use a webhook or Telegram instead, or plug a
 * real transport into `SmtpTransport`.
 */
export class NodeSmtpTransport implements SmtpTransport {
  private readonly host: string;
  private readonly port: number;
  private readonly user: string;
  private readonly password: string;
  private readonly timeoutMs: number;

  constructor(opts: { host: string; port: number; user: string; password: string; timeoutMs?: number }) {
    this.host = opts.host;
    this.port = opts.port;
    this.user = opts.user;
    this.password = opts.password;
    this.timeoutMs = opts.timeoutMs ?? SEND_TIMEOUT_MS;
  }

  async sendMail(opts: { from: string; to: string; subject: string; text: string }): Promise<void> {
    const { host, port, user, password, timeoutMs } = this;
    await new Promise<void>((resolve, reject) => {
      const socket = net.createConnection({ host, port });
      let settled = false;
      const timer = setTimeout(() => failSocket(new Error('smtp_timeout')), timeoutMs);
      const failSocket = (err: Error): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        reject(err);
      };
      const done = (): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.end();
        resolve();
      };
      socket.on('error', (err) => failSocket(err as Error));

      // Line-buffered reader over the socket.
      let buffer = '';
      const queuedLines: string[] = [];
      const waiters: Array<(line: string) => void> = [];
      socket.on('data', (chunk: Buffer) => {
        buffer += chunk.toString('utf8');
        let idx = buffer.indexOf('\r\n');
        while (idx >= 0) {
          const line = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          const waiter = waiters.shift();
          if (waiter) waiter(line);
          else queuedLines.push(line);
          idx = buffer.indexOf('\r\n');
        }
      });
      const readLine = (): Promise<string> => {
        const queued = queuedLines.shift();
        if (queued !== undefined) return Promise.resolve(queued);
        return new Promise((res) => waiters.push(res));
      };
      // One reply, including multi-line replies ("250-..." … "250...").
      const readReply = async (): Promise<{ code: number; text: string }> => {
        const first = await readLine();
        const code = Number.parseInt(first.slice(0, 3), 10);
        const textLines = [first.slice(4)];
        let line = first;
        while (line.length > 3 && line[3] === '-') {
          line = await readLine();
          textLines.push(line.slice(4));
        }
        return { code, text: textLines.join('\n') };
      };
      const command = async (cmd: string, expectCode: number): Promise<void> => {
        socket.write(`${cmd}\r\n`);
        const reply = await readReply();
        if (reply.code !== expectCode) {
          // Never include the command text: AUTH PLAIN carries the password.
          throw new Error(`smtp_unexpected_reply: ${reply.code}`);
        }
      };
      const dotStuff = (text: string): string =>
        text
          .split(/\r?\n/)
          .map((line) => (line.startsWith('.') ? `.${line}` : line))
          .join('\r\n');

      void (async () => {
        try {
          const greeting = await readReply();
          if (greeting.code !== 220) throw new Error(`smtp_unexpected_reply: ${greeting.code}`);
          await command('EHLO localhost', 250);
          const auth = Buffer.from(`\0${user}\0${password}`, 'utf8').toString('base64');
          await command(`AUTH PLAIN ${auth}`, 235);
          await command(`MAIL FROM:<${opts.from}>`, 250);
          await command(`RCPT TO:<${opts.to}>`, 250);
          await command('DATA', 354);
          const message = [
            `From: ${opts.from}`,
            `To: ${opts.to}`,
            `Subject: ${opts.subject}`,
            'Content-Type: text/plain; charset=utf-8',
            '',
            dotStuff(opts.text),
            '.',
            '',
          ].join('\r\n');
          socket.write(message);
          const dataReply = await readReply();
          if (dataReply.code !== 250) throw new Error(`smtp_unexpected_reply: ${dataReply.code}`);
          await command('QUIT', 221).catch(() => undefined);
          done();
        } catch (err) {
          failSocket(err as Error);
        }
      })();
    });
  }
}

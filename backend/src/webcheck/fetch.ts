import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import zlib from 'node:zlib';
import type { LookupFunction } from 'node:net';
import {
  assertPublicUrl,
  resolvePublicHost,
  defaultResolver,
  type HostResolver,
  type ResolvedAddress,
} from './guard.js';
import type { TlsInfo } from './types.js';

/**
 * The patrol's guarded fetcher.
 *
 * Every request — the original URL and each redirect hop — is gated
 * through the SSRF guard, and the socket connects to the exact address
 * set the guard approved (custom DNS lookup), so a host cannot pass
 * the check and then rebind to 127.0.0.1. GET only, capped body,
 * capped time, and the timings the website-info matrix needs.
 */

const USER_AGENT = 'BugSeek-Demo/1.0 (+https://bugseek-ai.vercel.app)';

export interface FetchedResponse {
  /** Final URL after redirects. */
  url: string;
  status: number;
  /** Lowercased header map (multi-values joined); set-cookie kept apart. */
  headers: Record<string, string>;
  setCookie: string[];
  /** Decoded body text ('' for binary or undecodable bodies). */
  body: string;
  /** Raw bytes received, capped at the byte limit. */
  bytes: number;
  ttfbMs: number;
  totalMs: number;
  redirectCount: number;
  compression: string | null;
}

export interface GuardedFetchOptions {
  maxBytes?: number;
  timeoutMs?: number;
  maxRedirects?: number;
}

export type GuardedFetcher = (url: string, opts?: GuardedFetchOptions) => Promise<FetchedResponse>;

function pinnedLookup(addresses: ResolvedAddress[]): LookupFunction {
  return (_hostname, options, callback) => {
    if ((options as { all?: boolean }).all) {
      callback(null, addresses);
    } else {
      const first = addresses[0] as ResolvedAddress;
      callback(null, first.address, first.family);
    }
  };
}

function decodeBody(raw: Buffer, contentEncoding: string | undefined): string {
  try {
    if (!contentEncoding) return raw.toString('utf8');
    const enc = contentEncoding.toLowerCase();
    if (enc.includes('gzip') || enc.includes('x-gzip')) return zlib.gunzipSync(raw).toString('utf8');
    if (enc.includes('deflate')) return zlib.inflateSync(raw).toString('utf8');
    if (enc.includes('br')) return zlib.brotliDecompressSync(raw).toString('utf8');
    return raw.toString('utf8');
  } catch {
    return '';
  }
}

function requestOnce(
  url: URL,
  addresses: ResolvedAddress[],
  timeoutMs: number,
  maxBytes: number,
): Promise<{
  status: number;
  headers: Record<string, string>;
  setCookie: string[];
  body: string;
  bytes: number;
  ttfbMs: number;
  totalMs: number;
  compression: string | null;
}> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;
    const req = lib.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port ? Number(url.port) : isHttps ? 443 : 80,
        path: `${url.pathname}${url.search}`,
        method: 'GET',
        agent: false,
        lookup: pinnedLookup(addresses),
        headers: {
          'User-Agent': USER_AGENT,
          Accept: 'text/html,application/xhtml+xml,application/json,text/plain,*/*',
          'Accept-Encoding': 'gzip, deflate, br',
        },
      },
      (res) => {
        const ttfbMs = Date.now() - started;
        const chunks: Buffer[] = [];
        let received = 0;
        let settled = false;
        const finish = () => {
          if (settled) return;
          settled = true;
          const raw = Buffer.concat(chunks);
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (k.toLowerCase() === 'set-cookie') continue;
            if (typeof v === 'string') headers[k.toLowerCase()] = v;
            else if (Array.isArray(v)) headers[k.toLowerCase()] = v.join(', ');
          }
          const encoding = res.headers['content-encoding'];
          resolve({
            status: res.statusCode ?? 0,
            headers,
            setCookie: res.headers['set-cookie'] ?? [],
            body: decodeBody(raw, typeof encoding === 'string' ? encoding : undefined),
            bytes: received,
            ttfbMs,
            totalMs: Date.now() - started,
            compression: typeof encoding === 'string' ? encoding : null,
          });
        };
        res.on('data', (chunk: Buffer) => {
          received += chunk.length;
          if (received <= maxBytes) {
            chunks.push(chunk);
          } else if (chunks.length === 0 || Buffer.concat(chunks).length < maxBytes) {
            // Keep the first maxBytes; weight still counts what arrived.
            const room = maxBytes - Buffer.concat(chunks).length;
            if (room > 0) chunks.push(chunk.subarray(0, room));
          }
          if (received >= maxBytes) {
            res.destroy();
            finish();
          }
        });
        res.on('end', finish);
        res.on('error', () => finish());
      },
    );
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Timed out after ${Math.round(timeoutMs / 1000)}s`));
    });
    req.on('error', reject);
    req.end();
  });
}

export function createGuardedFetcher(resolver: HostResolver = defaultResolver): GuardedFetcher {
  return async (rawUrl, opts = {}) => {
    const maxBytes = opts.maxBytes ?? 2_000_000;
    const timeoutMs = opts.timeoutMs ?? 10_000;
    const maxRedirects = opts.maxRedirects ?? 3;

    let current = assertPublicUrl(rawUrl);
    let redirectCount = 0;

    for (;;) {
      const addresses = await resolvePublicHost(current.hostname, resolver);
      const res = await requestOnce(current, addresses, timeoutMs, maxBytes);
      const location = res.headers['location'];
      const isRedirect = [301, 302, 303, 307, 308].includes(res.status) && Boolean(location);

      if (!isRedirect) {
        return { url: current.toString(), redirectCount, ...res };
      }
      if (redirectCount >= maxRedirects) {
        throw Object.assign(new Error(`Too many redirects (>${maxRedirects}) at ${current.hostname}`), {
          statusCode: 502,
        });
      }
      redirectCount++;
      current = assertPublicUrl(new URL(location as string, current).toString());
    }
  };
}

/**
 * TLS probe for an https host: connects (certificate verification OFF
 * so a broken chain can be observed rather than refused), reads the
 * peer certificate, and grades it. Connects to a guard-approved
 * address with proper SNI; returns null when the handshake fails.
 */
export async function probeTls(
  hostname: string,
  addresses?: ResolvedAddress[],
  timeoutMs = 5_000,
): Promise<TlsInfo | null> {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const remote = addresses?.[0];
  return new Promise((resolve) => {
    let settled = false;
    const done = (v: TlsInfo | null) => {
      if (!settled) {
        settled = true;
        resolve(v);
      }
    };
    const socket = tls.connect({
      host: remote?.address ?? host,
      servername: host,
      port: 443,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    });
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      const validTo = cert?.valid_to ? new Date(cert.valid_to) : null;
      const rawProtocol = socket.getProtocol();
      socket.destroy();
      const firstString = (v: string | string[] | undefined): string | null =>
        typeof v === 'string' ? v : Array.isArray(v) ? (v[0] ?? null) : null;
      done({
        issuer: firstString(cert?.issuer?.O) ?? firstString(cert?.issuer?.CN),
        subject: firstString(cert?.subject?.CN),
        validTo: validTo ? validTo.toISOString() : null,
        daysLeft: validTo ? Math.floor((validTo.getTime() - Date.now()) / 86_400_000) : null,
        authorized: socket.authorized,
        authorizationError: socket.authorized
          ? undefined
          : String((socket as unknown as { authorizationError?: Error }).authorizationError ?? 'certificate not trusted'),
        protocol: typeof rawProtocol === 'string' ? rawProtocol : null,
      });
    });
    socket.once('timeout', () => {
      socket.destroy();
      done(null);
    });
    socket.once('error', () => done(null));
  });
}

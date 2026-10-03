import dns from 'node:dns/promises';
import net from 'node:net';

/**
 * SSRF guard for the web demo patrol.
 *
 * The patrol fetches arbitrary user-supplied sites, so every URL —
 * the original and every redirect hop — must prove it points at the
 * public internet before a socket opens: http(s) only, no embedded
 * credentials, and EVERY resolved address must be public. One private
 * answer in the DNS set refuses the whole run (rebinding defence).
 *
 * The resolver is injectable so tests exercise the guard without
 * touching live DNS.
 */

export interface ResolvedAddress {
  address: string;
  family: number;
}

export type HostResolver = (hostname: string) => Promise<ResolvedAddress[]>;

export const defaultResolver: HostResolver = async (hostname) =>
  dns.lookup(hostname, { all: true, verbatim: true });

function guardError(message: string): Error {
  return Object.assign(new Error(message), { statusCode: 400 });
}

export function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts as [number, number, number, number];
  if (a === 0) return true; // 0.0.0.0/8 "this host"
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a >= 224) return true; // multicast + reserved
  return false;
}

function firstHextet(ip: string): number {
  if (ip.startsWith('::')) return 0;
  const head = ip.split(':')[0] ?? '';
  const n = parseInt(head, 16);
  return Number.isNaN(n) ? 0 : n;
}

export function isPrivateAddress(ip: string): boolean {
  const lower = ip.toLowerCase().split('%')[0] ?? ip; // drop any zone id

  // IPv4-mapped IPv6 (::ffff:1.2.3.4 or ::ffff:7f00:1): the embedded
  // IPv4 decides. Unparseable mapped forms fail closed.
  const mapped = /^::ffff:(.+)$/.exec(lower);
  if (mapped) {
    const tail = mapped[1] as string;
    if (net.isIPv4(tail)) return isPrivateIpv4(tail);
    const hex = tail.replace(/:/g, '');
    if (/^[0-9a-f]{1,8}$/.test(hex)) {
      const n = parseInt(hex, 16);
      return isPrivateIpv4(
        [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'),
      );
    }
    return true;
  }

  if (net.isIPv4(lower)) return isPrivateIpv4(lower);
  if (!net.isIPv6(lower)) return true; // not an address at all — fail closed

  if (lower === '::1' || lower === '::') return true; // loopback / unspecified
  const head = firstHextet(lower);
  if (head >= 0xfe80 && head <= 0xfebf) return true; // fe80::/10 link-local
  if ((head & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if (head >= 0xff00) return true; // ff00::/8 multicast
  return false;
}

/**
 * Parse + policy-check a user-supplied patrol URL: http(s) only, no
 * embedded credentials (they'd leak into logs and stored rows).
 */
export function assertPublicUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw guardError('That does not look like a URL — try https://your-site.com');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw guardError('The patrol only visits http(s) sites');
  }
  if (url.username || url.password) {
    throw guardError('URLs with embedded passwords are refused — strip the credentials and retry');
  }
  if (!url.hostname) {
    throw guardError('That URL has no host to visit');
  }
  return url;
}

/**
 * Resolve a host and require EVERY answer to be public. Returns the
 * validated address set (the fetcher pins its connection to it, so
 * the answer can't change between check and connect).
 */
export async function resolvePublicHost(
  hostname: string,
  resolver: HostResolver = defaultResolver,
): Promise<ResolvedAddress[]> {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    if (isPrivateAddress(host)) {
      throw guardError(
        `${host} is a private or internal address — the patrol only visits public sites`,
      );
    }
    return [{ address: host, family: net.isIPv6(host) ? 6 : 4 }];
  }

  let records: ResolvedAddress[];
  try {
    records = await resolver(host);
  } catch {
    throw guardError(`Could not resolve ${host} — check the address and try again`);
  }
  if (records.length === 0) {
    throw guardError(`Could not resolve ${host} — check the address and try again`);
  }
  for (const r of records) {
    if (isPrivateAddress(r.address)) {
      throw guardError(
        `${host} resolves to a private address (${r.address}) — the patrol only visits public sites`,
      );
    }
  }
  return records;
}

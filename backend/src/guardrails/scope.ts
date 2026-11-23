import dns from 'node:dns/promises';
import net from 'node:net';
import type { ScopePolicy } from '../types.js';

/**
 * LEGAL GUARDRAIL, scope enforcement (product plan §8).
 *
 * The agent must respect defined scope boundaries. Every URL the agent (or any
 * active-testing tool) touches passes through `assertUrlAllowed` / `isUrlInScope`.
 * There is no code path for active requests that skips this check.
 */

export function normalizeTargetUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw Object.assign(new Error('Invalid target URL'), { statusCode: 400 });
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw Object.assign(new Error('Target URL must use http(s)'), { statusCode: 400 });
  }
  return url;
}

export interface ScopeCheck {
  allowed: boolean;
  reason?: string;
}

export function isUrlInScope(urlStr: string, target: URL, scope: ScopePolicy): ScopeCheck {
  let url: URL;
  try {
    url = new URL(urlStr);
  } catch {
    return { allowed: false, reason: 'malformed URL' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { allowed: false, reason: `protocol ${url.protocol} not allowed` };
  }

  const host = url.hostname.toLowerCase();
  const targetHost = target.hostname.toLowerCase();

  if (scope.excludedHosts.some((h) => host === h.toLowerCase() || host.endsWith(`.${h.toLowerCase()}`))) {
    return { allowed: false, reason: `host ${host} is excluded from scope` };
  }
  if (scope.excludedPaths.some((p) => url.pathname === p || url.pathname.startsWith(p.endsWith('/') ? p : `${p}/`))) {
    return { allowed: false, reason: `path ${url.pathname} is excluded from scope` };
  }

  switch (scope.mode) {
    case 'page':
      if (url.origin !== target.origin || url.pathname !== target.pathname) {
        return { allowed: false, reason: 'scope is limited to the single target page' };
      }
      return { allowed: true };
    case 'subdomain':
      if (host !== targetHost) {
        return { allowed: false, reason: `host ${host} is outside the target subdomain scope` };
      }
      return { allowed: true };
    case 'full-domain': {
      const inDomain = host === targetHost || (scope.includeSubdomains && host.endsWith(`.${targetHost}`));
      if (!inDomain) {
        return { allowed: false, reason: `host ${host} is outside the target domain scope` };
      }
      return { allowed: true };
    }
  }
}

/** True for loopback, RFC-1918, link-local, CGNAT and other non-public IPv4. */
export function isPrivateIpv4(ip: string): boolean {
  const [a, b, c] = ip.split('.').map(Number);
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b !== undefined && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24
  if (a === 100 && b !== undefined && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a === 198 && b !== undefined && b >= 18 && b <= 19) return true; // benchmarking 198.18.0.0/15
  if (a === 127) return true; // loopback
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 169 && b === 254) return true; // link-local
  if (a >= 224) return true; // multicast + reserved
  return false;
}

export function isPrivateIpv6(ip: string): boolean {
  const norm = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (norm === '::1' || norm === '::') return true;
  if (norm.startsWith('fc') || norm.startsWith('fd')) return true;
  if (/^fe[89ab][0-9a-f]:/.test(norm)) return true;
  if (norm.startsWith('::ffff:')) {
    return isPrivateIpv4(norm.slice(7));
  }
  return false;
}

/** True for loopback, RFC-1918, link-local, CGNAT and other non-public IPs (v4 + v6). */
export function isPrivateIp(ip: string): boolean {
  if (!net.isIP(ip)) return false;
  const lower = ip.toLowerCase();
  // IPv4-mapped IPv6 literals (::ffff:127.0.0.1, ::ffff:7f00:1): the embedded
  // IPv4 address determines privateness. Unparseable mapped forms fail closed.
  const mapped = /^::ffff:(.+)$/.exec(lower);
  if (mapped) {
    const tail = mapped[1];
    if (net.isIPv4(tail)) return isPrivateIp(tail);
    const hex = tail.replace(/:/g, '');
    if (/^[0-9a-f]{1,8}$/.test(hex)) {
      const n = parseInt(hex, 16);
      return isPrivateIp([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'));
    }
    return true;
  }
  if (net.isIPv4(ip)) return isPrivateIpv4(ip);
  return isPrivateIpv6(ip);
}

export interface ResolvedHostAddress {
  address: string;
  family: number;
}

function ssrfError(message: string): Error {
  return Object.assign(new Error(message), { statusCode: 400 });
}

/**
 * Resolve a hostname and require EVERY answer to be public. Returns the
 * validated address set, so the caller can pin its connection to it
 * instead of resolving the host a second time at connect.
 */
export async function resolvePublicAddresses(
  hostname: string,
  allowPrivate: boolean,
): Promise<ResolvedHostAddress[]> {
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname) && !allowPrivate) {
      throw ssrfError(`Refusing to scan private IP ${hostname} (SSRF guardrail)`);
    }
    return [{ address: hostname, family: net.isIPv6(hostname) ? 6 : 4 }];
  }
  let records: Array<{ address: string; family: number }>;
  try {
    records = await dns.lookup(hostname, { all: true });
  } catch {
    throw ssrfError(`Could not resolve host ${hostname}`);
  }
  for (const r of records) {
    if (isPrivateIp(r.address) && !allowPrivate) {
      throw ssrfError(
        `Refusing to scan ${hostname}: resolves to private IP ${r.address} (SSRF guardrail)`,
      );
    }
  }
  return records;
}

/**
 * SSRF guard: resolve the hostname and refuse private / internal addresses.
 * Bypassable ONLY via ALLOW_PRIVATE_TARGETS=true (for local test apps like
 * OWASP Juice Shop / DVWA), which config.ts forbids in production.
 */
export async function assertPublicHost(hostname: string, allowPrivate: boolean): Promise<void> {
  await resolvePublicAddresses(hostname, allowPrivate);
}

export function assertUrlAllowed(urlStr: string, target: URL, scope: ScopePolicy): URL {
  const check = isUrlInScope(urlStr, target, scope);
  if (!check.allowed) {
    throw Object.assign(new Error(`Out of scope: ${check.reason}`), { statusCode: 403 });
  }
  return new URL(urlStr);
}

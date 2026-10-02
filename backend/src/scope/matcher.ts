import net from 'node:net';
import type { ScopeEntry, ScopeProgramme, ScopeVerdict } from './types.js';

/**
 * Pure matching of a target against a programme's published scope.
 *
 * Conventions (both platforms):
 * - a listed host covers itself and its subdomains ("example.org" also
 *   covers "www.example.org"), unless it was published as "*.example.org",
 *   which covers subdomains only — never the bare host;
 * - an asset published with a path ("https://shop.example.net/store")
 *   covers that path and everything beneath it;
 * - out-of-scope listings always win over in-scope ones;
 * - matching is case-insensitive and ignores ports and trailing dots.
 */

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;

/** Normalise a host for comparison: lowercase, no port, no trailing dot. */
export function normaliseHostName(host: string): string {
  return host
    .trim()
    .toLowerCase()
    .replace(/:\d+$/, '')
    .replace(/\.$/, '');
}

/**
 * Parse one published scope identifier into a matchable entry.
 * Returns null for anything that is not a web asset we can check —
 * app-store ids, source repos, IP ranges, redacted entries, and so on.
 */
export function parseScopeEntry(raw: string): ScopeEntry | null {
  if (typeof raw !== 'string') return null;
  const id = raw.trim().toLowerCase();
  if (!id) return null;

  let hostPart = id;
  let pathPart = '';

  const scheme = /^([a-z][a-z0-9+.-]*):\/\//.exec(id);
  if (scheme) {
    if (scheme[1] !== 'http' && scheme[1] !== 'https') return null;
    const rest = id.slice(scheme[0].length);
    const slash = rest.indexOf('/');
    hostPart = slash === -1 ? rest : rest.slice(0, slash);
    pathPart = slash === -1 ? '' : rest.slice(slash);
  } else {
    const slash = id.indexOf('/');
    if (slash !== -1) {
      hostPart = id.slice(0, slash);
      pathPart = id.slice(slash);
    }
  }

  hostPart = hostPart.split('@').pop() ?? hostPart;
  pathPart = pathPart.split(/[?#]/)[0] ?? '';

  let wildcard = false;
  if (hostPart.startsWith('*.')) {
    wildcard = true;
    hostPart = hostPart.slice(2);
  }
  hostPart = normaliseHostName(hostPart);
  if (!hostPart || net.isIP(hostPart) || !DOMAIN_RE.test(hostPart)) return null;

  let pathPrefix: string | undefined;
  if (pathPart && pathPart !== '/') {
    const trimmed = pathPart.replace(/\/+$/, '');
    if (trimmed) pathPrefix = trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
  }

  return {
    raw: raw.trim(),
    host: hostPart,
    wildcard,
    ...(pathPrefix ? { pathPrefix } : {}),
  };
}

interface ParsedTarget {
  host: string;
  path: string;
}

/** Parse the target (full URL or bare host) into the parts matching needs. */
export function parseTarget(target: string): ParsedTarget | null {
  const trimmed = target.trim();
  if (!trimmed) return null;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  const host = normaliseHostName(url.hostname);
  if (!host) return null;
  return { host, path: url.pathname.toLowerCase() || '/' };
}

function hostMatches(entry: ScopeEntry, targetHost: string): boolean {
  if (entry.wildcard) return targetHost.endsWith(`.${entry.host}`);
  return targetHost === entry.host || targetHost.endsWith(`.${entry.host}`);
}

function entryMatches(
  entry: ScopeEntry,
  targetHost: string,
  targetPath: string,
): boolean {
  if (!hostMatches(entry, targetHost)) return false;
  if (!entry.pathPrefix) return true;
  return (
    targetPath === entry.pathPrefix ||
    targetPath.startsWith(`${entry.pathPrefix}/`)
  );
}

export interface ScopeMatch {
  verdict: Exclude<ScopeVerdict, 'programme_not_found'>;
  matchedEntry?: string;
  reason: string;
}

/** Match a target against one programme's published scope. */
export function matchProgrammeScope(
  programme: ScopeProgramme,
  target: string,
): ScopeMatch {
  const parsed = parseTarget(target);
  if (!parsed) {
    return {
      verdict: 'unknown',
      reason:
        "That target doesn't look like a web address, so the programme check can't run.",
    };
  }
  if (net.isIP(parsed.host)) {
    return {
      verdict: 'unknown',
      reason:
        "IP-address targets aren't matched against published domain scope.",
    };
  }

  // Exclusions first: an explicit out-of-scope listing always wins.
  for (const entry of programme.outOfScope) {
    if (entryMatches(entry, parsed.host, parsed.path)) {
      return {
        verdict: 'out_of_scope',
        matchedEntry: entry.raw,
        reason: `${parsed.host} is listed out of scope for ${programme.name} (${entry.raw}).`,
      };
    }
  }
  for (const entry of programme.inScope) {
    if (entryMatches(entry, parsed.host, parsed.path)) {
      return {
        verdict: 'in_scope',
        matchedEntry: entry.raw,
        reason: `${parsed.host} is covered by ${programme.name}'s published scope (${entry.raw}).`,
      };
    }
  }

  if (!programme.hasWebAssets) {
    return {
      verdict: 'unknown',
      reason: `${programme.name}'s published assets aren't websites, so this host can't be checked against them.`,
    };
  }
  return {
    verdict: 'out_of_scope',
    reason: `${parsed.host} doesn't appear in ${programme.name}'s published scope.`,
  };
}

/**
 * Passive source-map check (Phase 3).
 *
 * Production JavaScript bundles sometimes ship with their source maps exposed
 * (app.js.map), handing attackers the original unminified sources — complete
 * with developer comments, hidden routes and occasionally hardcoded secrets.
 *
 * For each same-origin script we try the sourceMappingURL comment first, then
 * the conventional `<script>.map` location. Exposed maps are parsed for their
 * original sources; secret patterns run over sourcesContent just like they do
 * over fetched scripts.
 */
import { SECRET_PATTERNS, isPlaceholder, redactSecret } from '../lib/regexes';
import type { Finding } from '../lib/types';

export interface FetchedScript {
  url: string;
  code: string;
}

export interface ExposedSourceMap {
  jsUrl: string;
  mapUrl: string;
  sources: string[];
  sourcesContent: string[];
}

const MAX_MAPS = 6;
const FETCH_TIMEOUT_MS = 8000;
const MAX_MAP_BYTES = 5 * 1024 * 1024;
const SOURCE_MAP_URL_RE = /\/\/#\s*sourceMappingURL=([^\s*]+)/;
const MAX_SECRET_MATCHES = 5;

let findingSeq = 0;

async function fetchWithTimeout(url: string): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Try to locate and parse source maps for same-origin scripts.
 * Only GETs static .map files — no different from what the browser itself
 * would fetch for DevTools.
 */
export async function fetchSourceMaps(
  scripts: FetchedScript[],
  pageUrl: string,
): Promise<ExposedSourceMap[]> {
  const pageOrigin = new URL(pageUrl).origin;
  const results: ExposedSourceMap[] = [];

  for (const script of scripts.slice(0, MAX_MAPS)) {
    let scriptUrl: URL;
    try {
      scriptUrl = new URL(script.url);
    } catch {
      continue;
    }
    if (scriptUrl.origin !== pageOrigin) continue;

    // Prefer an explicit sourceMappingURL comment; fall back to url + '.map'.
    const candidates: string[] = [];
    const m =
      script.code.slice(-4000).match(SOURCE_MAP_URL_RE) ??
      script.code.match(SOURCE_MAP_URL_RE);
    if (m && !m[1].startsWith('data:')) {
      try {
        candidates.push(new URL(m[1], script.url).toString());
      } catch {
        /* unresolvable — use the conventional location */
      }
    }
    const conventional = script.url + '.map';
    if (!candidates.includes(conventional)) candidates.push(conventional);

    for (const candidate of candidates) {
      try {
        const res = await fetchWithTimeout(candidate);
        if (!res.ok) continue;
        const text = await res.text();
        if (!text || text.length > MAX_MAP_BYTES) continue;
        let map: unknown;
        try {
          map = JSON.parse(text);
        } catch {
          continue;
        }
        if (!map || typeof map !== 'object') continue;
        const { sources, sourcesContent } = map as {
          sources?: unknown;
          sourcesContent?: unknown;
        };
        if (!Array.isArray(sources)) continue;
        results.push({
          jsUrl: script.url,
          mapUrl: candidate,
          sources: sources.filter((s): s is string => typeof s === 'string'),
          sourcesContent: Array.isArray(sourcesContent)
            ? sourcesContent.filter((s): s is string => typeof s === 'string')
            : [],
        });
        break; // one map per script is enough
      } catch {
        /* unreachable — try the next candidate */
      }
    }
  }
  return results;
}

/** Turn exposed source maps into findings (map exposure + secrets inside). */
export function scanSourceMaps(maps: ExposedSourceMap[]): Finding[] {
  const findings: Finding[] = [];

  for (const map of maps) {
    findings.push({
      id: `sourcemap-${findingSeq++}`,
      category: 'sourcemap',
      title: 'Exposed JavaScript source map',
      description:
        `The production bundle ${shortUrl(map.jsUrl)} ships with its source map exposed at ` +
        `${shortUrl(map.mapUrl)}. Source maps contain the original unminified sources — often with ` +
        `developer comments and internal route names — giving attackers a head start on finding deeper issues. ` +
        `Remove .map files from production deployments or restrict them to authenticated developers.`,
      severity: 'low',
      confidence: 'high',
      location: map.mapUrl,
      evidence: `${map.sources.length} original source file(s) reconstructed${map.sourcesContent.length > 0 ? ' (sourcesContent embedded)' : ''}`,
      remediation:
        'Do not deploy .map files to production, or serve them only to authenticated staff. ' +
        'If you use a bundler, disable source-map output for production builds.',
    });

    // Run the standard secret patterns over the reconstructed original sources.
    const corpus = map.sourcesContent.join('\n');
    if (!corpus) continue;
    for (const pattern of SECRET_PATTERNS) {
      const flags = pattern.regex.flags.includes('g')
        ? pattern.regex.flags
        : pattern.regex.flags + 'g';
      const re = new RegExp(pattern.regex.source, flags);
      let match: RegExpExecArray | null;
      let reported = 0;
      while ((match = re.exec(corpus)) !== null && reported < MAX_SECRET_MATCHES) {
        if (match.index === re.lastIndex) re.lastIndex++;
        const matched = match[0];
        if (isPlaceholder(matched)) continue;
        reported++;
        findings.push({
          id: `sourcemap-secret-${pattern.id}-${findingSeq++}`,
          category: 'secrets',
          title: `${pattern.name} exposed in source-mapped original sources`,
          description: pattern.description,
          severity: pattern.severity,
          confidence: pattern.severity === 'critical' || pattern.severity === 'high' ? 'high' : 'medium',
          location: `source map ${shortUrl(map.mapUrl)} → original sources`,
          evidence: redactSecret(matched),
          remediation: pattern.remediation,
        });
      }
    }
  }

  return findings;
}

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname.split('/').slice(-2).join('/');
  } catch {
    return url.slice(-60);
  }
}

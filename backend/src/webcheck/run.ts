import { assertPublicUrl, resolvePublicHost, type HostResolver } from './guard.js';
import {
  createGuardedFetcher,
  probeTls,
  type GuardedFetcher,
} from './fetch.js';
import { analyseWebCheck, type ProbeSnapshot, type ScriptSnapshot } from './checks.js';
import {
  buildPerfInfo,
  fetchDnsInfo,
  fetchDomainInfo,
  fetchServerInfo,
  registrableHost,
  type JsonFetcher,
} from './info.js';
import type { WebFinding, WebInfo } from './types.js';

/**
 * One full patrol run: guard → fetch → probe → analyse → matrix.
 * Composes the focused modules; every external read is best-effort
 * except the main page fetch itself (a site that cannot be fetched
 * is an error worth showing, not a blank result).
 */

export interface PatrolDeps {
  resolver?: HostResolver;
  fetcher?: GuardedFetcher;
  jsonFetcher?: JsonFetcher;
}

export interface PatrolOutcome {
  url: string;
  host: string;
  findings: WebFinding[];
  info: WebInfo;
}

const PROBE_PATHS = {
  env: '/.env',
  gitHead: '/.git/HEAD',
  gitConfig: '/.git/config',
  backupSql: '/backup.sql',
  svnEntries: '/.svn/entries',
  robots: '/robots.txt',
} as const;

function extractScriptUrls(html: string, base: string): string[] {
  const urls: string[] = [];
  for (const m of html.matchAll(/<script[^>]*\bsrc=["']([^"']+)["']/gi)) {
    try {
      const u = new URL(m[1] as string, base);
      if (u.protocol === 'http:' || u.protocol === 'https:') urls.push(u.toString());
    } catch {
      /* unparseable src — not a file we can patrol */
    }
    if (urls.length >= 4) break;
  }
  return [...new Set(urls)];
}

function extractInlineScripts(html: string): string[] {
  const blocks: string[] = [];
  for (const m of html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
    const code = (m[1] ?? '').trim();
    if (code) blocks.push(code);
    if (blocks.length >= 4) break;
  }
  return blocks;
}

async function tryJson(raw: string): Promise<Record<string, unknown> | null> {
  try {
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export async function runWebPatrol(
  rawUrl: string,
  deps: PatrolDeps = {},
): Promise<PatrolOutcome> {
  const fetcher = deps.fetcher ?? createGuardedFetcher(deps.resolver);
  const target = assertPublicUrl(rawUrl);

  let page;
  try {
    page = await fetcher(target.toString(), { maxBytes: 2_000_000, timeoutMs: 10_000 });
  } catch (err) {
    if ((err as { statusCode?: number }).statusCode) throw err;
    throw Object.assign(
      new Error(`Couldn't reach ${target.hostname} — it didn't answer in time. Check the address and try again.`),
      { statusCode: 502 },
    );
  }

  const finalUrl = page.url;
  const final = new URL(finalUrl);
  const origin = final.origin;
  const pageSnapshot = {
    finalUrl,
    status: page.status,
    headers: page.headers,
    setCookie: page.setCookie,
    body: page.body,
  };

  const quiet = async <T,>(p: Promise<T>): Promise<T | null> => {
    try {
      return await p;
    } catch {
      return null;
    }
  };

  /* Probes + scripts + TLS + public records, all in parallel. */
  const probe = (path: string) =>
    quiet(fetcher(`${origin}${path}`, { maxBytes: 64_000, timeoutMs: 6_000 }));

  const probePaths = Object.entries(PROBE_PATHS) as Array<[keyof typeof PROBE_PATHS, string]>;
  const scriptUrls = extractScriptUrls(page.body, finalUrl);

  const [probeResults, scriptResults, tlsInfo, dnsInfo, domainInfo] = await Promise.all([
    Promise.all(probePaths.map(([, p]) => probe(p))),
    Promise.all(
      scriptUrls.map((u) =>
        quiet(fetcher(u, { maxBytes: 512_000, timeoutMs: 6_000 })),
      ),
    ),
    final.protocol === 'https:'
      ? quiet(resolvePublicHost(final.hostname, deps.resolver)).then((addrs) =>
          probeTls(final.hostname, addrs ?? undefined),
        )
      : Promise.resolve(null),
    fetchDnsInfo(final.hostname, registrableHost(final.hostname), deps.jsonFetcher),
    fetchDomainInfo(registrableHost(final.hostname), deps.jsonFetcher),
  ]);

  const probes = {} as Record<keyof typeof PROBE_PATHS, ProbeSnapshot | null>;
  probePaths.forEach(([key, path], i) => {
    const r = probeResults[i];
    probes[key] = r ? { path, status: r.status, body: r.body } : null;
  });

  const scripts: ScriptSnapshot[] = [];
  scriptResults.forEach((r, i) => {
    if (r) scripts.push({ url: scriptUrls[i] as string, body: r.body });
  });
  extractInlineScripts(page.body).forEach((code, i) => {
    scripts.push({ url: `${finalUrl}#inline-${i + 1}`, body: code });
  });

  /* Source maps: comment pointer first, then the served .map guess. */
  const sourceMaps: Array<{ scriptUrl: string; mapUrl: string }> = [];
  for (const script of scripts.slice(0, 4)) {
    if (script.url.includes('#inline')) continue;
    const tail = script.body.slice(-2_048);
    const pointed = /sourceMappingURL=([^\s'"]+)/.exec(tail)?.[1];
    const candidates = pointed
      ? [new URL(pointed, script.url).toString()]
      : [`${script.url}.map`];
    for (const candidate of candidates) {
      const mapRes = await quiet(
        fetcher(candidate, { maxBytes: 512_000, timeoutMs: 5_000 }),
      );
      if (mapRes && mapRes.status === 200) {
        const parsed = await tryJson(mapRes.body);
        if (parsed && Array.isArray(parsed['sources'])) {
          sourceMaps.push({ scriptUrl: script.url, mapUrl: candidate });
          break;
        }
      }
    }
    if (sourceMaps.length >= 3) break;
  }

  /* Public API documentation: discovered URLs + the usual address. */
  let apiDocUrl: string | null = null;
  const docCandidates = new Set<string>([`${origin}/openapi.json`]);
  const textSources = [page.body, ...scripts.map((s) => s.body)];
  for (const text of textSources) {
    for (const m of text.matchAll(/["'`](\/?[\w./-]*(?:openapi|swagger)[\w./-]*\.json)["'`]/gi)) {
      try {
        docCandidates.add(new URL(m[1] as string, finalUrl).toString());
      } catch {
        /* ignore */
      }
    }
  }
  for (const candidate of docCandidates) {
    const docRes = await quiet(
      fetcher(candidate, { maxBytes: 512_000, timeoutMs: 5_000 }),
    );
    if (docRes && docRes.status === 200) {
      const parsed = await tryJson(docRes.body);
      if (parsed && ('openapi' in parsed || 'swagger' in parsed)) {
        apiDocUrl = candidate;
        break;
      }
    }
  }

  const serverInfo = await fetchServerInfo(dnsInfo.a[0] ?? null, deps.jsonFetcher);
  const securityTxtRes = await quiet(
    fetcher(`${origin}/.well-known/security.txt`, { maxBytes: 16_000, timeoutMs: 4_000 }),
  );

  const { findings, api } = analyseWebCheck({
    page: pageSnapshot,
    probes,
    scripts,
    sourceMaps,
    apiDocUrl,
    tls: tlsInfo,
  });

  const info: WebInfo = {
    perf: buildPerfInfo(page),
    server: serverInfo,
    domain: domainInfo,
    dns: dnsInfo,
    tls: tlsInfo,
    api,
    robotsTxt: probes.robots !== null && probes.robots.status === 200,
    securityTxt: securityTxtRes !== null && securityTxtRes.status === 200,
  };

  return { url: target.toString(), host: target.hostname, findings, info };
}

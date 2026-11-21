export interface DiscoveredEndpoint {
  path: string;
  source: 'js_bundle' | 'inline_script';
  scriptUrl: string;
  params: string[];
  kind: 'api' | 'spa_route' | 'graphql';
}

export interface BundleScanResult {
  scriptsScanned: number;
  bytesScanned: number;
  endpoints: DiscoveredEndpoint[];
  spaRoutes: string[];
  warnings: string[];
}

const MAX_SCRIPTS = 15;
const MAX_BYTES_PER_SCRIPT = 2 * 1024 * 1024; // 2 MB cap to protect browser memory
const FETCH_CONCURRENCY = 4;

// Ignore static assets and common noise paths
const STATIC_ASSET_RE =
  /\.(png|jpe?g|gif|svg|webp|ico|css|scss|woff2?|ttf|eot|mp4|webm|map|pdf|zip)(\?.*)?$/i;

// Matches quoted relative API paths like "/api/Users/", "/rest/user/login", "/v2/orders/:id"
const API_PATH_RE =
  /['"`](\/(?:api|rest|graphql|v[0-9]+|auth|admin|internal|oauth|user|users|order|orders|basket|baskets|ftp|metrics|swagger|api-docs)(?:\/[A-Za-z0-9_\-.:{}?=&%$]+)*)['"`]/g;

// Matches Angular/React/Vue router path definitions: path: 'score-board' or path="/admin"
const SPA_ROUTE_RE =
  /(?:\bpath\s*[:=]\s*['"`]([A-Za-z0-9_\-/:]+)['"`])/g;

// Matches query parameter keys inside URLs or template strings
const PARAM_RE = /[?&]([A-Za-z_][A-Za-z0-9_-]{0,32})=/g;
const COLON_PARAM_RE = /:([A-Za-z_][A-Za-z0-9_]{0,32})/g;

function normalizePath(raw: string): string {
  // Collapse template expressions like ${id} -> :param
  return raw
    .replace(/\$\{[^}]+\}/g, ':param')
    .replace(/\/{2,}/g, '/')
    .trim();
}

function extractParams(path: string): string[] {
  const params = new Set<string>();
  for (const m of path.matchAll(PARAM_RE)) params.add(m[1]);
  for (const m of path.matchAll(COLON_PARAM_RE)) params.add(m[1]);
  return [...params];
}

export function extractFromJsSource(
  source: string,
  scriptUrl: string,
  sourceKind: 'js_bundle' | 'inline_script'
): { endpoints: DiscoveredEndpoint[]; spaRoutes: string[] } {
  const endpointMap = new Map<string, DiscoveredEndpoint>();
  const spaRoutes = new Set<string>();

  for (const match of source.matchAll(API_PATH_RE)) {
    const normalized = normalizePath(match[1]);
    if (normalized.length < 3 || normalized.length > 180) continue;
    if (STATIC_ASSET_RE.test(normalized)) continue;

    const kind = normalized.includes('graphql') ? 'graphql' : 'api';
    if (!endpointMap.has(normalized)) {
      endpointMap.set(normalized, {
        path: normalized,
        source: sourceKind,
        scriptUrl,
        params: extractParams(normalized),
        kind,
      });
    }
  }

  for (const match of source.matchAll(SPA_ROUTE_RE)) {
    const route = match[1].trim();
    if (!route || route === '*' || route === '**' || route.length > 120) continue;
    if (STATIC_ASSET_RE.test(route)) continue;
    spaRoutes.add(route.startsWith('/') ? route : `/${route}`);
  }

  return {
    endpoints: [...endpointMap.values()],
    spaRoutes: [...spaRoutes],
  };
}

export async function scanPageBundles(
  pageOrigin: string,
  scriptUrls: string[],
  inlineScripts: string[]
): Promise<BundleScanResult> {
  const warnings: string[] = [];
  const sameOriginUrls = [...new Set(scriptUrls)]
    .filter((u) => {
      try {
        return new URL(u, pageOrigin).origin === pageOrigin;
      } catch {
        return false;
      }
    })
    .slice(0, MAX_SCRIPTS);

  const allEndpoints = new Map<string, DiscoveredEndpoint>();
  const allRoutes = new Set<string>();
  let bytesScanned = 0;
  let scriptsScanned = 0;

  // 1. Scan inline scripts first
  for (const code of inlineScripts) {
    if (!code || code.length > MAX_BYTES_PER_SCRIPT) continue;
    bytesScanned += code.length;
    const { endpoints, spaRoutes } = extractFromJsSource(code, pageOrigin, 'inline_script');
    endpoints.forEach((e) => allEndpoints.set(e.path, e));
    spaRoutes.forEach((r) => allRoutes.add(r));
  }

  // 2. Bounded-concurrency fetch for same-origin JS bundles
  let cursor = 0;
  async function worker() {
    while (cursor < sameOriginUrls.length) {
      const url = sameOriginUrls[cursor++];
      try {
        const res = await fetch(url, { credentials: 'omit' });
        if (!res.ok) continue;
        const contentLength = Number(res.headers.get('content-length') || 0);
        if (contentLength > MAX_BYTES_PER_SCRIPT) {
          warnings.push(`Skipped ${url} (${Math.round(contentLength / 1024)} KB exceeds cap)`);
          continue;
        }
        const text = await res.text();
        if (text.length > MAX_BYTES_PER_SCRIPT) continue;

        bytesScanned += text.length;
        scriptsScanned++;

        const { endpoints, spaRoutes } = extractFromJsSource(text, url, 'js_bundle');
        endpoints.forEach((e) => allEndpoints.set(e.path, e));
        spaRoutes.forEach((r) => allRoutes.add(r));
      } catch {
        warnings.push(`Failed to fetch bundle: ${url}`);
      }
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(FETCH_CONCURRENCY, sameOriginUrls.length) }, () => worker())
  );

  return {
    scriptsScanned,
    bytesScanned,
    endpoints: [...allEndpoints.values()],
    spaRoutes: [...allRoutes],
    warnings,
  };
}

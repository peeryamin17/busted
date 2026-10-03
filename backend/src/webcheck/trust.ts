import type { TrustAssessment } from './types.js';

/**
 * The trust layer — is this page a trap?
 *
 * The security score grades how a site is configured; this module asks
 * the other question: does it behave like a phish? It consults live
 * phishing feeds and Google Safe Browsing when configured, recognises
 * the warning interstitials CDNs serve over known traps, and stacks
 * small tells (borrowed brand names, free-host ground, week-old
 * domains, password boxes in the wrong neighbourhood) into a verdict.
 *
 * Invariants:
 *  - never throws — the worst outcome is a quiet 'clear';
 *  - never adds findings and never touches the security score;
 *  - every network read fails open (a dead feed is an empty feed).
 */

export interface TrustInput {
  /** The address the patrol ended on, after redirects. */
  finalUrl: string;
  /** The final host. */
  host: string;
  pageTitle: string | null;
  /** The main page body (already capped at 2MB by the fetcher). */
  body: string;
  /** The final HTTP status. */
  status: number;
  /** RDAP registration date of the registrable domain, when readable. */
  domainCreatedIso: string | null;
}

export interface TrustDeps {
  /** Injectable feed lookup for tests: a hit when url/host appears in a live phishing feed. */
  feedMatch?: (url: string, host: string) => Promise<{ source: string } | null>;
  /** Injectable Safe Browsing check; the default reads SAFE_BROWSING_API_KEY. */
  safeBrowsing?: (url: string) => Promise<boolean>;
}

/* ── live phishing feeds (URLhaus + OpenPhish, both key-less) ─── */

const FEED_SOURCES: Array<{ source: string; url: string }> = [
  { source: 'urlhaus', url: 'https://urlhaus.abuse.ch/downloads/text/' },
  { source: 'openphish', url: 'https://openphish.com/feed.txt' },
];
const FEED_TTL_MS = 60 * 60 * 1000;
const FEED_MAX_BYTES = 4_000_000;

interface FeedIndex {
  /** Normalised URL → the feed that listed it. */
  exact: Map<string, string>;
  /** Host whose feed entry sits at path '/' → the feed that listed it. */
  hostRoot: Map<string, string>;
  fetchedAt: number;
}

let feedState: FeedIndex | null = null;
let feedLoad: Promise<FeedIndex> | null = null;

/** A URL reduced to a comparable shape: no fragment, no trailing slash. */
function normaliseUrl(raw: string): { key: string; host: string; path: string } | null {
  try {
    const u = new URL(raw.trim());
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    const host = u.hostname.toLowerCase();
    let path = u.pathname || '/';
    if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);
    const key = `${u.protocol}//${host}${u.port ? `:${u.port}` : ''}${path}${u.search}`;
    return { key, host, path };
  } catch {
    return null;
  }
}

async function fetchTextCapped(url: string, maxBytes: number, timeoutMs = 6_000): Promise<string> {
  const res = await fetch(url, {
    headers: { 'User-Agent': 'BugSeek-Demo/1.0 (+https://bugseek-ai.vercel.app)' },
    signal: AbortSignal.timeout(timeoutMs),
    redirect: 'follow',
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  if (!res.body) throw new Error('empty body');
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new Error('feed larger than the cap');
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const chunk of chunks) {
    buf.set(chunk, off);
    off += chunk.byteLength;
  }
  return new TextDecoder().decode(buf);
}

/** Both feeds, fetched together, indexed once and shared for an hour. */
async function loadFeedIndex(): Promise<FeedIndex> {
  if (feedState && Date.now() - feedState.fetchedAt < FEED_TTL_MS) return feedState;
  if (feedLoad) return feedLoad;
  feedLoad = (async () => {
    const exact = new Map<string, string>();
    const hostRoot = new Map<string, string>();
    // Fetch in parallel, parse in source order (first feed wins ties).
    const texts = await Promise.all(
      FEED_SOURCES.map(async ({ url }) => {
        try {
          return await fetchTextCapped(url, FEED_MAX_BYTES);
        } catch {
          return null; /* a dead feed is an empty feed */
        }
      }),
    );
    FEED_SOURCES.forEach(({ source }, i) => {
      const text = texts[i];
      if (!text) return;
      for (const line of text.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const n = normaliseUrl(trimmed);
        if (!n) continue;
        if (!exact.has(n.key)) exact.set(n.key, source);
        if (n.path === '/' && !hostRoot.has(n.host)) hostRoot.set(n.host, source);
      }
    });
    feedState = { exact, hostRoot, fetchedAt: Date.now() };
    return feedState;
  })();
  try {
    return await feedLoad;
  } finally {
    feedLoad = null;
  }
}

/**
 * The default feed lookup. A hit is the checked URL appearing verbatim
 * (trailing-slash-insensitive), or a listed URL on the same host whose
 * path is '/' — feeds report whole hosts that way.
 */
const defaultFeedMatch = async (
  url: string,
  host: string,
): Promise<{ source: string } | null> => {
  const index = await loadFeedIndex();
  const target = normaliseUrl(url);
  if (target) {
    const hit = index.exact.get(target.key);
    if (hit) return { source: hit };
  }
  const root = index.hostRoot.get(host.toLowerCase());
  return root ? { source: root } : null;
};

/* ── Google Safe Browsing (only when a key is configured) ─────── */

async function defaultSafeBrowsing(url: string): Promise<boolean> {
  const key = process.env['SAFE_BROWSING_API_KEY'];
  if (!key) return false;
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'bugseek-demo', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }],
          },
        }),
        signal: AbortSignal.timeout(6_000),
      },
    );
    if (!res.ok) return false;
    const data = (await res.json()) as { matches?: unknown[] };
    return Array.isArray(data.matches) && data.matches.length > 0;
  } catch {
    return false;
  }
}

/* ── the tells ────────────────────────────────────────────────── */

const PHISHING_WARNING_RE =
  /suspected phishing|deceptive site ahead|phishing warning|reported phishing/i;

const BRAND_LURE_RE =
  /(paypal|apple|microsoft|amazon|netflix|binance|coinbase|metamask|chase|wellsfargo|bankofamerica|instagram|facebook|whatsapp|telegram|login|signin|verify|secure|account|update|confirm|support|wallet|recover|unlock)/i;

/** Disposable subdomain platforms — free to pitch, free to abandon. */
const FREE_HOST_SUFFIXES = [
  'pages.dev', 'vercel.app', 'netlify.app', 'github.io', 'web.app',
  'firebaseapp.com', 'glitch.me', 'repl.co', 'replit.app', 'surge.sh',
  'onrender.com', 'workers.dev', 'blogspot.com', 'wordpress.com',
  'weebly.com', 'wixsite.com', 'azurewebsites.net', 'pythonanywhere.com',
  '000webhostapp.com', 'infinityfreeapp.com', 'epizy.com',
];

const PASSWORD_FIELD_RE = /type\s*=\s*["']password["']/i;

const isIpLiteral = (host: string): boolean =>
  /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');

function freeHostSuffixOf(host: string): string | null {
  for (const suffix of FREE_HOST_SUFFIXES) {
    if (host === suffix || host.endsWith(`.${suffix}`)) return suffix;
  }
  return null;
}

/** The page a visitor would read, with every tag and script stripped. */
function visibleTextOf(body: string): string {
  return body
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

const SOURCE_LABELS: Record<string, string> = {
  urlhaus: 'URLhaus',
  openphish: 'OpenPhish',
  'google-safe-browsing': 'Google Safe Browsing',
  'page-warning': 'the host’s own warning page',
  heuristics: 'BugSeek’s own tell-tale signs',
};
const sourceLabel = (source: string): string => SOURCE_LABELS[source] ?? source;

/* ── the assessment ───────────────────────────────────────────── */

export async function assessTrust(
  input: TrustInput,
  deps: TrustDeps = {},
): Promise<TrustAssessment> {
  try {
    return await assess(input, deps);
  } catch {
    // The trust layer must never break a patrol: silence reads 'clear'.
    return { verdict: 'clear', reasons: [], sources: [] };
  }
}

async function assess(input: TrustInput, deps: TrustDeps): Promise<TrustAssessment> {
  const host = input.host.toLowerCase().replace(/^\[|\]$/g, '');
  const consulted: string[] = [];
  const badReasons: string[] = [];
  const badSources: string[] = [];

  /* Known-bad, first: live reports and the host's own warning. */
  if (deps.feedMatch) {
    try {
      const hit = await deps.feedMatch(input.finalUrl, host);
      if (hit) {
        badSources.push(hit.source);
        badReasons.push(
          `This address shows up in a live phishing feed (${sourceLabel(hit.source)}) — reported by people who watch for exactly this.`,
        );
      }
    } catch {
      /* fail open */
    }
  } else {
    consulted.push(...FEED_SOURCES.map((f) => f.source));
    try {
      const hit = await defaultFeedMatch(input.finalUrl, host);
      if (hit) {
        badSources.push(hit.source);
        badReasons.push(
          `This address shows up in a live phishing feed (${sourceLabel(hit.source)}) — reported by people who watch for exactly this.`,
        );
      }
    } catch {
      /* fail open */
    }
  }

  const safeBrowsingConfigured =
    deps.safeBrowsing !== undefined || Boolean(process.env['SAFE_BROWSING_API_KEY']);
  if (safeBrowsingConfigured) {
    consulted.push('google-safe-browsing');
    try {
      const flagged = await (deps.safeBrowsing ?? defaultSafeBrowsing)(input.finalUrl);
      if (flagged) {
        badSources.push('google-safe-browsing');
        badReasons.push('Google Safe Browsing flags this address as dangerous.');
      }
    } catch {
      /* fail open */
    }
  }

  if (
    PHISHING_WARNING_RE.test(input.pageTitle ?? '') ||
    PHISHING_WARNING_RE.test(input.body)
  ) {
    badSources.push('page-warning');
    badReasons.push(
      'The page itself is a phishing warning served by the host/CDN — someone upstream has already flagged this address.',
    );
  }

  if (badSources.length > 0) {
    return {
      verdict: 'known-bad',
      reasons: badReasons,
      sources: [...new Set(badSources)],
    };
  }

  /* Suspicious: small tells, stacked. */
  let points = 0;
  const reasons: string[] = [];
  const signal = (pts: number, reason: string) => {
    points += pts;
    reasons.push(reason);
  };

  const brandToken = BRAND_LURE_RE.exec(host)?.[1]?.toLowerCase() ?? null;
  const freeHost = freeHostSuffixOf(host);
  const labels = host.split('.').filter(Boolean);

  if (brandToken) {
    signal(
      1,
      `The name name-drops “${brandToken}” — real brands sign you in from their own domain, not from an address like this.`,
    );
  }
  if (freeHost) {
    signal(
      1,
      `It lives on a free hosting platform (${freeHost}) — disposable ground where a trap costs nothing to pitch and less to abandon.`,
    );
  }
  if (input.domainCreatedIso) {
    const created = new Date(input.domainCreatedIso).getTime();
    if (Number.isFinite(created)) {
      const ageDays = Math.floor((Date.now() - created) / 86_400_000);
      if (ageDays <= 30) {
        const days = Math.max(0, ageDays);
        signal(
          2,
          `The domain was registered ${days} day${days === 1 ? '' : 's'} ago — traps burn fast and rarely live long enough to grow old.`,
        );
      }
    }
  }
  if (labels.some((l) => l.startsWith('xn--'))) {
    signal(
      1,
      'The address hides behind punycode (xn--) — the encoding look-alike domains use to imitate real brands.',
    );
  }
  if (isIpLiteral(host)) {
    signal(
      2,
      'The address is a bare IP number instead of a name — legitimate services practically always have a name.',
    );
  }
  if (labels.length >= 4) {
    signal(
      1,
      'The address is buried under a stack of subdomains — a favourite way to borrow a trusted name’s coat.',
    );
  } else {
    const leftmost = labels[0] ?? '';
    if (leftmost.length >= 22 && /^[a-z0-9-]+$/i.test(leftmost)) {
      signal(1, 'The first chunk of the address is a long, random-looking string — minted, not named.');
    }
  }
  if (visibleTextOf(input.body).length < 40 && Buffer.byteLength(input.body, 'utf8') < 3000) {
    signal(
      1,
      'The page shows an ordinary visitor almost nothing — whatever it really does, it seems to be saving it for the intended visitor.',
    );
  }
  if (PASSWORD_FIELD_RE.test(input.body) && (brandToken || freeHost)) {
    const where = brandToken
      ? `a name borrowed from a brand (“${brandToken}”)`
      : `a free hosting platform (${freeHost})`;
    signal(2, `It asks for a password from ${where} — the exact shape of a credential trap.`);
  }

  if (points >= 2) {
    return { verdict: 'suspicious', reasons: reasons.slice(0, 5), sources: ['heuristics'] };
  }
  return { verdict: 'clear', reasons: [], sources: consulted };
}

/**
 * Deep surface scanner (Phase 4) — devtools-grade passive inventory.
 *
 * Where the Phase 1 scanners report individual problems, this module maps
 * the whole runtime surface a developer would inspect in DevTools:
 *   - every cookie catalogued, with session carriers identified
 *   - web-storage session material (JWTs / auth tokens readable by any JS)
 *   - payment gateways fingerprinted + card-collection posture
 *   - third-party integrations grouped by purpose (analytics, chat, ads…)
 *
 * Purely observational — this module makes NO network requests. Storage
 * values are never read here: the content script already reduced them to
 * key names + shapes, and cookie evidence lists names only.
 */
import type { DomScanData, Finding } from '../lib/types';

let seq = 0;
const nid = (p: string) => `deep-${p}-${seq++}`;

const AUTH_KEY_RE = /(token|auth|jwt|session|sess|access|refresh|bearer|sid)/i;

/* ------------------------------------------------------------------ */
/* Cookies — full inventory                                            */
/* ------------------------------------------------------------------ */

const SESSION_NAME_RE =
  /(sess|session|auth|token|jwt|sid|phpsessid|jsessionid|aspsession|connect\.sid|csrf)/i;

async function inventoryCookies(url: string): Promise<Finding[]> {
  let cookies: chrome.cookies.Cookie[];
  try {
    cookies = await chrome.cookies.getAll({ url });
  } catch {
    return []; // cookieAuditor already reports API failures
  }
  if (cookies.length === 0) return [];

  const sessionCarriers = cookies.filter((c) => SESSION_NAME_RE.test(c.name));
  const browserSession = cookies.filter((c) => c.session);
  const persistent = cookies.length - browserSession.length;
  const sharedScope = cookies.filter((c) => c.domain.startsWith('.'));

  const lines = [
    `${cookies.length} cookies visible for this page: ${persistent} persistent, ${browserSession.length} browser-session.`,
    sessionCarriers.length > 0
      ? `Session/auth carriers (${sessionCarriers.length}): ${sessionCarriers.map((c) => c.name).join(', ')}.`
      : 'No cookie names look like session/auth carriers.',
    sharedScope.length > 0
      ? `${sharedScope.length} cookie(s) are scoped to a parent domain and shared with all subdomains.`
      : 'All cookies are host-only.',
    'Full inventory (name · domain · lifetime):',
    ...cookies
      .slice(0, 60)
      .map(
        (c) =>
          `· ${c.name} · ${c.domain} · ${c.session ? 'browser-session' : `expires ${c.expirationDate ? new Date(c.expirationDate * 1000).toISOString().slice(0, 10) : 'n/a'}`}${SESSION_NAME_RE.test(c.name) ? ' · session-like' : ''}`,
      ),
  ];

  return [
    {
      id: nid('cookies'),
      category: 'session',
      title: `Cookie inventory: ${cookies.length} cookies, ${sessionCarriers.length} session-like`,
      description: lines.join('\n'),
      severity: 'info',
      confidence: 'high',
      remediation:
        'Review the inventory: retire cookies you no longer need, keep session carriers HttpOnly + Secure + SameSite, and prefer host-only scope.',
    },
  ];
}

/* ------------------------------------------------------------------ */
/* Web storage — session material readable by any script               */
/* ------------------------------------------------------------------ */

function scanStorage(dom: DomScanData): Finding[] {
  const findings: Finding[] = [];
  const storage = dom.storage ?? { local: [], session: [] };

  for (const [storeName, entries] of [
    ['localStorage', storage.local] as const,
    ['sessionStorage', storage.session] as const,
  ]) {
    const persistent = storeName === 'localStorage';
    for (const e of entries) {
      if (e.shape === 'jwt') {
        const jwtNotes: string[] = [];
        if (e.jwt) {
          jwtNotes.push(`Algorithm: ${e.jwt.alg}.`);
          if (e.jwt.alg.toLowerCase() === 'none') {
            jwtNotes.push(
              'The token declares alg=none — if the backend accepts unsigned tokens, anyone can forge a session for any user.',
            );
          }
          if (!e.jwt.hasExpiry) {
            jwtNotes.push('No exp claim — this token may never expire, so a single theft is permanent.');
          }
          if (e.jwt.claimKeys.length > 0) {
            jwtNotes.push(`Claims carried: ${e.jwt.claimKeys.join(', ')} (names only, values never captured).`);
          }
        }
        findings.push({
          id: nid('jwt'),
          category: 'session',
          title: `JWT stored in ${storeName} ("${e.key}")`,
          description:
            `A JSON Web Token lives in ${storeName} under the key "${e.key}". Any JavaScript on this ` +
            'page — including any injected script via an XSS flaw or a compromised third-party ' +
            'integration — can read it and impersonate the session. Unlike an HttpOnly cookie, ' +
            'web storage offers the token no protection at all.' +
            (jwtNotes.length > 0 ? ` ${jwtNotes.join(' ')}` : ''),
          severity: persistent ? 'high' : 'medium',
          confidence: 'high',
          location: `${storeName} key "${e.key}"`,
          evidence: `value shape: JWT (${e.valueLength} chars) — value never captured`,
          remediation:
            'Prefer session cookies with HttpOnly + Secure + SameSite for auth tokens. If a token must be kept client-side, keep it in memory, not web storage.',
        });
      } else if (AUTH_KEY_RE.test(e.key) && (e.shape === 'long-opaque' || e.shape === 'uuid')) {
        findings.push({
          id: nid('storage-token'),
          category: 'session',
          title: `Possible auth token in ${storeName} ("${e.key}")`,
          description:
            `The ${storeName} key "${e.key}" has an auth-like name and an opaque token-shaped value ` +
            `(${e.valueLength} chars). Web storage is readable by every script on the page, so a token ` +
            'stored here is one XSS away from account takeover.',
          severity: persistent ? 'medium' : 'low',
          confidence: 'medium',
          location: `${storeName} key "${e.key}"`,
          evidence: `value shape: ${e.shape} — value never captured`,
          remediation:
            'Move auth material to HttpOnly cookies, or confirm this key does not carry session authority.',
        });
      }
    }
  }

  if (storage.local.length + storage.session.length > 0) {
    findings.push({
      id: nid('storage-summary'),
      category: 'session',
      title: `Web storage inventory: ${storage.local.length} local + ${storage.session.length} session keys`,
      description:
        'Keys observed (names and value shapes only — values are never captured): ' +
        [...storage.local.map((e) => `local:${e.key} (${e.shape})`), ...storage.session.map((e) => `session:${e.key} (${e.shape})`)]
          .slice(0, 60)
          .join(', '),
      severity: 'info',
      confidence: 'high',
      remediation: 'Audit stored keys periodically; anything auth-shaped belongs in HttpOnly cookies.',
    });
  }

  return findings;
}

/* ------------------------------------------------------------------ */
/* Payments — gateway fingerprinting + card-collection posture         */
/* ------------------------------------------------------------------ */

const GATEWAYS: Array<{ name: string; re: RegExp }> = [
  { name: 'Stripe', re: /(js|checkout)\.stripe\.com/i },
  { name: 'PayPal', re: /(paypal\.com\/sdk|paypalobjects\.com|checkout\.paypal\.com)/i },
  { name: 'Razorpay', re: /checkout\.razorpay\.com/i },
  { name: 'Adyen', re: /checkoutshopper-(live|test)\.adyen\.com/i },
  { name: 'Checkout.com', re: /payments\.checkout\.com/i },
  { name: 'Braintree', re: /js\.braintreegateway\.com/i },
  { name: 'Square', re: /(sandbox\.web|web)\.squarecdn\.com|squareup\.com/i },
  { name: 'Mollie', re: /js\.mollie\.com/i },
  { name: 'Cashfree', re: /sdk\.cashfree\.com/i },
  { name: 'PayU', re: /(secure\.payu\.in|bolt\.payu\.in)/i },
  { name: 'Klarna', re: /(klarna\.com|payments\.klarna\.com)/i },
  { name: 'Amazon Pay', re: /payments-(eu|na|fe)\.amazon\.com/i },
];

const CARD_INPUT_RE = /(cc[-_]?num|card[-_]?num|cardnumber|pan\b|cc_number)/i;

function scanPayments(dom: DomScanData): Finding[] {
  const findings: Finding[] = [];
  const surfaces = [
    ...dom.externalScripts,
    ...dom.iframes.map((f) => f.src),
    ...dom.forms.map((f) => f.action),
  ].filter(Boolean);

  const detected = new Map<string, string>();
  for (const s of surfaces) {
    for (const g of GATEWAYS) {
      if (g.re.test(s) && !detected.has(g.name)) {
        try {
          detected.set(g.name, new URL(s).host);
        } catch {
          detected.set(g.name, s.slice(0, 60));
        }
      }
    }
  }

  if (detected.size > 0) {
    findings.push({
      id: nid('gateway'),
      category: 'payments',
      title: `Payment gateway${detected.size > 1 ? 's' : ''}: ${[...detected.keys()].join(', ')}`,
      description:
        'Payment processing is delegated to: ' +
        [...detected.entries()].map(([n, h]) => `${n} (${h})`).join('; ') +
        '. Gateway scripts/iframes on a page can observe checkout behaviour; keep the set ' +
        'minimal and load gateway assets only on pages that need them.',
      severity: 'info',
      confidence: 'high',
      remediation: 'No action needed if expected. Remove gateway loaders from non-checkout pages.',
    });
  }

  // Card fields collected on the merchant's own origin (no gateway iframe)?
  const hasCardInput = dom.inputs.some(
    (i) => CARD_INPUT_RE.test(`${i.name} ${i.id}`),
  );
  const hasGatewayIframe = dom.iframes.some((f) => GATEWAYS.some((g) => g.re.test(f.src)));
  if (hasCardInput && detected.size === 0 && !hasGatewayIframe) {
    findings.push({
      id: nid('card-origin'),
      category: 'payments',
      title: 'Card-style inputs with no payment gateway detected',
      description:
        'This page contains inputs that look like card-number fields, but no known payment ' +
        'gateway script or iframe was observed. If raw card numbers are posted to the site\'s ' +
        'own servers, the merchant takes on the heaviest PCI DSS scope (SAQ D) and any ' +
        'server-side logging bug becomes a card breach.',
      severity: 'medium',
      confidence: 'low',
      location: dom.url,
      remediation:
        'Use the gateway\'s hosted fields / redirect checkout so card data never touches your servers (SAQ A), or document the PCI posture deliberately.',
    });
  }

  return findings;
}

/* ------------------------------------------------------------------ */
/* Integrations — third-party map grouped by purpose                   */
/* ------------------------------------------------------------------ */

const INTEGRATION_GROUPS: Array<{ group: string; re: RegExp }> = [
  { group: 'analytics', re: /(google-analytics\.com|googletagmanager\.com|analytics\.|plausible\.io|mixpanel\.com|segment\.(io|com)|hotjar\.com|clarity\.ms|posthog\.com|matomo|amplitude\.com)/i },
  { group: 'advertising', re: /(doubleclick\.net|googlesyndication\.com|googleadservices\.com|adsrvr\.org|criteo\.com|taboola\.com|outbrain\.com|amazon-adsystem\.com)/i },
  { group: 'chat & support', re: /(intercom\.io|intercomcdn\.com|crisp\.chat|tawk\.to|zendesk\.com|zdassets\.com|drift\.com|hubspot\.com|hs-script\.com|freshdesk\.com)/i },
  { group: 'social embeds', re: /(connect\.facebook\.net|platform\.twitter\.com|syndication\.twitter\.com|embed\.bsky\.app|cdn\.instagram\.com|linkedin\.com\/embed)/i },
  { group: 'video', re: /(youtube\.com\/embed|youtube-nocookie\.com|player\.vimeo\.com)/i },
  { group: 'fonts & CDN assets', re: /(fonts\.googleapis\.com|fonts\.gstatic\.com|cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|cdn\.jsdelivr|maxcdn\.bootstrapcdn\.com)/i },
  { group: 'auth providers', re: /(accounts\.google\.com|appleid\.apple\.com|connect\.facebook\.net.*login|login\.microsoftonline\.com|github\.com\/login\/oauth)/i },
];

function scanIntegrations(dom: DomScanData): Finding[] {
  let pageHost = '';
  try {
    pageHost = new URL(dom.url).host;
  } catch {
    return [];
  }

  const thirdParty = new Map<string, string>(); // host -> group
  const urls = [...dom.externalScripts, ...dom.iframes.map((f) => f.src)].filter(Boolean);
  for (const u of urls) {
    let host = '';
    try {
      host = new URL(u).host;
    } catch {
      continue;
    }
    if (!host || host === pageHost) continue;
    if (GATEWAYS.some((g) => g.re.test(u))) continue; // payments reported separately
    const grp = INTEGRATION_GROUPS.find((g) => g.re.test(u))?.group ?? 'other third party';
    if (!thirdParty.has(host)) thirdParty.set(host, grp);
  }
  if (thirdParty.size === 0) return [];

  const byGroup = new Map<string, string[]>();
  for (const [host, grp] of thirdParty) {
    byGroup.set(grp, [...(byGroup.get(grp) ?? []), host]);
  }
  const summary = [...byGroup.entries()]
    .map(([g, hosts]) => `${g}: ${hosts.join(', ')}`)
    .join(' · ');

  return [
    {
      id: nid('integrations'),
      category: 'integrations',
      title: `Integration map: ${thirdParty.size} third-party host${thirdParty.size > 1 ? 's' : ''}`,
      description:
        `This page loads code or embeds from ${thirdParty.size} third-party hosts. ${summary}. ` +
        'Every third party is part of your attack surface: their compromise becomes your XSS, ' +
        'and their scripts can read everything the user types outside their own iframes.',
      severity: 'info',
      confidence: 'high',
      remediation:
        'Keep an inventory of third parties, pin CDN assets with SRI where possible, and load marketing/chat widgets only where they earn their place.',
    },
  ];
}

/* ------------------------------------------------------------------ */

export async function scanDeepSurface(dom: DomScanData): Promise<Finding[]> {
  const findings: Finding[] = [];
  findings.push(...(await inventoryCookies(dom.url)));
  findings.push(...scanStorage(dom));
  findings.push(...scanPayments(dom));
  findings.push(...scanIntegrations(dom));
  return findings;
}

import { SEVERITY_ORDER, type Severity } from '../types.js';
import type { ApiInfo, TlsInfo, WebFinding } from './types.js';

/**
 * Pure analysis for the web demo patrol.
 *
 * Everything here works over already-fetched snapshots — no I/O — so
 * it is unit-testable offline and the redaction rules are reviewable
 * in one place: cookie findings name the cookie, never its value;
 * secret findings name the key TYPE and the file, never the matched
 * string; .env evidence lists key NAMES only.
 */

export interface PageSnapshot {
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  setCookie: string[];
  body: string;
}

export interface ProbeSnapshot {
  path: string;
  status: number;
  body: string;
}

export interface ScriptSnapshot {
  url: string;
  body: string;
}

export interface WebCheckInput {
  page: PageSnapshot;
  probes: {
    env: ProbeSnapshot | null;
    gitHead: ProbeSnapshot | null;
    gitConfig: ProbeSnapshot | null;
    backupSql: ProbeSnapshot | null;
    svnEntries: ProbeSnapshot | null;
    robots: ProbeSnapshot | null;
  };
  scripts: ScriptSnapshot[];
  /** Source maps already confirmed served (fetched + parsed by run.ts). */
  sourceMaps: Array<{ scriptUrl: string; mapUrl: string }>;
  /** Confirmed publicly-fetchable OpenAPI/Swagger doc URL, if any. */
  apiDocUrl: string | null;
  tls: TlsInfo | null;
}

const SESSION_COOKIE_NAME = /(sess|session|sid|auth|token|jwt|login|remember)/i;

const SECRET_PATTERNS: Array<{ type: string; severity: Severity; re: RegExp }> = [
  { type: 'Stripe live secret key', severity: 'critical', re: /sk_live_[0-9A-Za-z]{16,}/ },
  { type: 'AWS access key', severity: 'high', re: /AKIA[0-9A-Z]{16}/ },
  { type: 'GitHub personal access token', severity: 'high', re: /ghp_[0-9A-Za-z]{36}/ },
  { type: 'Stripe restricted API key', severity: 'high', re: /rk_live_[0-9A-Za-z]{16,}/ },
  { type: 'Google API key', severity: 'medium', re: /AIza[0-9A-Za-z\-_]{35}/ },
];

function parseSetCookie(raw: string): {
  name: string;
  attrs: Map<string, string | true>;
} {
  const parts = raw.split(';');
  const first = parts[0] ?? '';
  const eq = first.indexOf('=');
  const name = (eq >= 0 ? first.slice(0, eq) : first).trim();
  const attrs = new Map<string, string | true>();
  for (const part of parts.slice(1)) {
    const p = part.trim();
    if (!p) continue;
    const i = p.indexOf('=');
    if (i >= 0) attrs.set(p.slice(0, i).trim().toLowerCase(), p.slice(i + 1).trim());
    else attrs.set(p.toLowerCase(), true);
  }
  return { name, attrs };
}

function cookieLifetimeDays(attrs: Map<string, string | true>): number | null {
  const maxAge = attrs.get('max-age');
  if (typeof maxAge === 'string') {
    const secs = Number(maxAge);
    if (Number.isFinite(secs)) return Math.ceil(secs / 86_400);
  }
  const expires = attrs.get('expires');
  if (typeof expires === 'string') {
    const t = Date.parse(expires);
    if (!Number.isNaN(t)) return Math.ceil((t - Date.now()) / 86_400_000);
  }
  return null;
}

export function analyseWebCheck(input: WebCheckInput): {
  findings: WebFinding[];
  api: ApiInfo;
} {
  const findings: WebFinding[] = [];
  const { page } = input;
  const https = page.finalUrl.startsWith('https://');
  const headers = page.headers;
  const add = (f: WebFinding) => findings.push(f);

  /* ── response headers ─────────────────────────────────────────── */
  const csp = headers['content-security-policy'];
  if (!csp) {
    add({
      severity: 'medium',
      category: 'headers',
      title: 'No Content-Security-Policy',
      detail:
        "Without a CSP, any injected script runs with the page's full trust. Start with default-src 'self' and loosen only what the site needs.",
      evidence: page.finalUrl,
      confidence: 'high',
    });
  }
  if (https && !headers['strict-transport-security']) {
    add({
      severity: 'medium',
      category: 'headers',
      title: 'No HSTS header',
      detail:
        'Browsers are not told to insist on HTTPS, so a first visit can be downgraded to plain HTTP. Add Strict-Transport-Security with a growing max-age.',
      evidence: page.finalUrl,
      confidence: 'high',
    });
  }
  const frameAncestors = csp?.toLowerCase().includes('frame-ancestors');
  if (!headers['x-frame-options'] && !frameAncestors) {
    add({
      severity: 'low',
      category: 'headers',
      title: 'Clickjacking protection missing',
      detail:
        'Nothing stops another site framing this page and tricking clicks. Send X-Frame-Options: DENY (or SAMEORIGIN) or a CSP frame-ancestors rule.',
      confidence: 'high',
    });
  }
  const xcto = headers['x-content-type-options']?.toLowerCase();
  if (xcto !== 'nosniff') {
    add({
      severity: 'low',
      category: 'headers',
      title: 'No X-Content-Type-Options: nosniff',
      detail:
        'Browsers may MIME-sniff responses into executable content. One header — nosniff — closes that door.',
      confidence: 'high',
    });
  }
  if (!headers['referrer-policy']) {
    add({
      severity: 'info',
      category: 'headers',
      title: 'No Referrer-Policy',
      detail:
        'Full URLs (paths, tokens and all) leak to third parties via the Referer header. strict-origin-when-cross-origin is the sane default.',
      confidence: 'high',
    });
  }
  if (!headers['permissions-policy']) {
    add({
      severity: 'info',
      category: 'headers',
      title: 'No Permissions-Policy',
      detail:
        'Camera, microphone and geolocation stay available to any embedded frame. A Permissions-Policy switches off what the page never uses.',
      confidence: 'high',
    });
  }

  /* ── server banners ───────────────────────────────────────────── */
  for (const [header, label] of [
    ['server', 'Server'],
    ['x-powered-by', 'X-Powered-By'],
  ] as const) {
    const value = headers[header];
    if (!value) continue;
    const hasVersion = /\d/.test(value);
    add({
      severity: hasVersion ? 'low' : 'info',
      category: 'tech',
      title: `${label} banner advertises the stack`,
      detail: hasVersion
        ? `The ${label} header names exact software versions — a shopping list for anyone checking known CVEs. Strip it or drop the version.`
        : `The ${label} header confirms the stack to anyone who asks. Removing it costs nothing.`,
      evidence: `${label}: ${value}`.slice(0, 120),
      confidence: 'high',
    });
  }

  /* ── cookies ──────────────────────────────────────────────────── */
  const seenCookieIssues = new Set<string>();
  for (const raw of page.setCookie) {
    const { name, attrs } = parseSetCookie(raw);
    if (!name) continue;
    const sessionLike = SESSION_COOKIE_NAME.test(name);
    const push = (severity: Severity, title: string, detail: string) => {
      const key = `${name}|${title}`;
      if (seenCookieIssues.has(key)) return;
      seenCookieIssues.add(key);
      add({
        severity,
        category: 'cookies',
        title,
        detail,
        evidence: `cookie: ${name}`,
        confidence: 'high',
      });
    };
    if (https && !attrs.has('secure')) {
      push(
        sessionLike ? 'medium' : 'low',
        `Cookie "${name}" travels without Secure`,
        'The Secure flag keeps the cookie off plain-HTTP requests. Without it, one stray http:// link leaks it in clear text.',
      );
    }
    if (sessionLike && !attrs.has('httponly')) {
      push(
        'medium',
        `Session cookie "${name}" is readable by JavaScript`,
        'No HttpOnly flag — any script on the page (including injected ones) can read this cookie and walk off with the session.',
      );
    }
    if (!attrs.has('samesite')) {
      push(
        'low',
        `Cookie "${name}" has no SameSite`,
        'SameSite=Lax is the floor: it keeps the cookie out of most cross-site requests and blunts CSRF.',
      );
    }
    const days = cookieLifetimeDays(attrs);
    if (days !== null && days > 30) {
      push(
        'low',
        `Cookie "${name}" lives for ${days} days`,
        'Long-lived cookies stretch the window a stolen value stays useful. Session cookies should die with the session, or within days — not months.',
      );
    }
  }

  /* ── TLS ──────────────────────────────────────────────────────── */
  if (https && input.tls) {
    if (!input.tls.authorized) {
      add({
        severity: 'high',
        category: 'tls',
        title: 'TLS certificate is not trusted',
        detail: `The chain failed validation (${input.tls.authorizationError ?? 'untrusted'}). Browsers will warn every visitor away — or worse, train them to click through.`,
        confidence: 'high',
      });
    } else if (input.tls.daysLeft !== null && input.tls.daysLeft < 0) {
      add({
        severity: 'high',
        category: 'tls',
        title: 'TLS certificate has expired',
        detail: `The certificate expired ${Math.abs(input.tls.daysLeft)} day(s) ago. Renew it and put renewal on autopilot.`,
        confidence: 'high',
      });
    } else if (input.tls.daysLeft !== null && input.tls.daysLeft < 14) {
      add({
        severity: 'medium',
        category: 'tls',
        title: `TLS certificate expires in ${input.tls.daysLeft} days`,
        detail: 'Under two weeks of cover left. If renewal is manual, it is exactly the kind that gets forgotten.',
        confidence: 'high',
      });
    }
  }

  /* ── sensitive files (authorised probes, signature-verified) ──── */
  const probes = input.probes;
  if (probes.env && probes.env.status === 200 && /^\w+=/m.test(probes.env.body)) {
    const keyNames = [
      ...new Set(
        [...probes.env.body.matchAll(/^([A-Za-z_][A-Za-z0-9_]*)\s*=/gm)].map((m) => m[1] as string),
      ),
    ].slice(0, 12);
    if (keyNames.length >= 1) {
      add({
        severity: 'critical',
        category: 'files',
        title: '/.env is publicly readable',
        detail:
          'The environment file answers anyone who asks. BugSeek recorded the key NAMES only — never the values — but assume every one of them is public and rotate them.',
        evidence: `keys seen: ${keyNames.join(', ')}`,
        confidence: 'high',
      });
    }
  }
  if (probes.gitHead && probes.gitHead.status === 200 && probes.gitHead.body.startsWith('ref:')) {
    add({
      severity: 'high',
      category: 'files',
      title: 'Git repository exposed (/.git/HEAD)',
      detail:
        'The .git directory is web-readable — the full source history can be reconstructed from it. Block dotfiles at the server and redeploy.',
      evidence: probes.gitHead.path,
      confidence: 'high',
    });
  }
  if (probes.gitConfig && probes.gitConfig.status === 200 && probes.gitConfig.body.includes('[core]')) {
    add({
      severity: 'high',
      category: 'files',
      title: 'Git config exposed (/.git/config)',
      detail:
        'The repo config confirms the exposed .git directory and can reveal remote URLs (sometimes with credentials baked in). Serve the app, not the repo.',
      evidence: probes.gitConfig.path,
      confidence: 'high',
    });
  }
  if (
    probes.backupSql &&
    probes.backupSql.status === 200 &&
    /(CREATE TABLE|INSERT INTO|mysqldump)/i.test(probes.backupSql.body)
  ) {
    add({
      severity: 'high',
      category: 'files',
      title: 'Database backup left in the web root (/backup.sql)',
      detail:
        'A SQL dump answers at a guessable address — schema, users, everything in it. Move backups out of the served directory entirely.',
      evidence: probes.backupSql.path,
      confidence: 'high',
    });
  }
  if (probes.svnEntries && probes.svnEntries.status === 200 && /^\d+\s*$/m.test(probes.svnEntries.body.slice(0, 64))) {
    add({
      severity: 'medium',
      category: 'files',
      title: 'SVN metadata exposed (/.svn/entries)',
      detail:
        'Version-control leftovers map the source tree for anyone curious. Old VCS directories should never survive a deploy.',
      evidence: probes.svnEntries.path,
      confidence: 'medium',
    });
  }
  if (probes.robots && probes.robots.status === 200) {
    const interesting = [
      ...new Set(
        [...probes.robots.body.matchAll(/^Disallow:\s*(\/\S*)/gim)]
          .map((m) => m[1] as string)
          .filter((p) => /(admin|backup|api|config|private|internal)/i.test(p)),
      ),
    ].slice(0, 5);
    if (interesting.length > 0) {
      add({
        severity: 'low',
        category: 'files',
        title: 'robots.txt advertises interesting paths',
        detail:
          'robots.txt is a public signpost — Disallow lines tell crawlers (and hunters) exactly where the interesting doors are. It hides nothing; access control does.',
        evidence: interesting.join(', '),
        confidence: 'medium',
      });
    }
  }

  /* ── source maps ──────────────────────────────────────────────── */
  for (const sm of input.sourceMaps.slice(0, 3)) {
    add({
      severity: 'medium',
      category: 'source map',
      title: 'Source map ships the original source',
      detail:
        'A served .map file hands anyone the readable, commented source of the bundled code — comments, variable names and all. Keep maps out of production builds.',
      evidence: sm.mapUrl,
      confidence: 'high',
    });
  }

  /* ── mixed content ────────────────────────────────────────────── */
  if (https) {
    const mixed = page.body.match(/(?:src|href)\s*=\s*["']http:\/\//gi);
    if (mixed && mixed.length > 0) {
      add({
        severity: 'low',
        category: 'content',
        title: `Mixed content: ${mixed.length} insecure subresource${mixed.length === 1 ? '' : 's'}`,
        detail:
          'This HTTPS page pulls resources over plain HTTP — those requests can be intercepted and rewritten in transit. Point every subresource at https://.',
        confidence: 'medium',
      });
    }
  }

  /* ── API surface + secrets, from the site's own code ──────────── */
  const endpoints = new Set<string>();
  let graphql = false;
  const scanText = (text: string) => {
    for (const m of text.matchAll(/["'`](\/api\/[A-Za-z0-9_\-./:%{}]+)["'`]/g)) {
      endpoints.add(m[1] as string);
    }
    for (const m of text.matchAll(/["'`](https?:\/\/[^"'`\s]+)["'`]/g)) {
      try {
        const u = new URL(m[1] as string);
        if (u.pathname.startsWith('/api/')) endpoints.add(u.pathname);
        if (u.pathname.includes('graphql')) graphql = true;
      } catch {
        /* not a URL */
      }
    }
    if (/\/graphql\b/.test(text)) graphql = true;
  };
  scanText(page.body);

  const seenSecrets = new Set<string>();
  for (const script of input.scripts) {
    scanText(script.body);
    for (const pattern of SECRET_PATTERNS) {
      if (!pattern.re.test(script.body)) continue;
      const key = `${pattern.type}|${script.url}`;
      if (seenSecrets.has(key)) continue;
      seenSecrets.add(key);
      add({
        severity: pattern.severity,
        category: 'secrets',
        title: `${pattern.type} in shipped JavaScript`,
        detail:
          'A live-looking credential is sitting in code every visitor downloads. BugSeek names the type and file only — treat the value as public: revoke it, then move secrets server-side.',
        evidence: script.url,
        confidence: 'medium',
      });
    }
  }

  if (input.apiDocUrl) {
    add({
      severity: 'medium',
      category: 'api',
      title: 'API documentation is publicly readable',
      detail:
        'The OpenAPI/Swagger document answers without sign-in — a complete map of endpoints, parameters and shapes for anyone planning a visit. Gate it like the API it describes.',
      evidence: input.apiDocUrl,
      confidence: 'high',
    });
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  return {
    findings,
    api: {
      endpoints: [...endpoints].slice(0, 20),
      openApiDoc: Boolean(input.apiDocUrl),
      graphql,
    },
  };
}

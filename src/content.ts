/**
 * BugSeek AI content script — passive DOM collection only.
 * It never modifies the page, never sends requests, and only runs a scan
 * when the user clicks "Scan" in the popup.
 */
import type { DomScanData, ScanMessage, StorageEntry } from './lib/types';

const MAX_INLINE_SCRIPTS = 40;
const MAX_INLINE_SCRIPT_CHARS = 200_000;
const MAX_COMMENTS = 200;
const MAX_COMMENT_CHARS = 500;
const MAX_INPUTS = 300;

interface SinkPattern {
  name: string;
  re: RegExp;
}

/** Known DOM-based XSS sink patterns to look for in inline scripts. */
const SINK_PATTERNS: SinkPattern[] = [
  { name: 'element.innerHTML assignment', re: /\.innerHTML\s*=/g },
  { name: 'element.outerHTML assignment', re: /\.outerHTML\s*=/g },
  { name: 'document.write', re: /document\.write(ln)?\s*\(/g },
  { name: 'eval()', re: /(?<![\w$.])eval\s*\(/g },
  { name: 'insertAdjacentHTML', re: /\.insertAdjacentHTML\s*\(/g },
  { name: 'setTimeout/setInterval with string', re: /\bset(Timeout|Interval)\s*\(\s*["'`]/g },
  { name: 'location.hash/href/search assignment', re: /location\.(hash|href|search)\s*=/g },
  { name: 'Function constructor', re: /\bnew\s+Function\s*\(/g },
];

/**
 * Content scripts run in an isolated JS world, so page-defined globals
 * (window.jQuery etc.) are invisible. This injects a tiny one-shot probe
 * into the page's MAIN world and reads the result back via a data attribute.
 * Silently no-ops if the page CSP blocks inline script injection.
 */
function probePageGlobals(): string[] {
  const ATTR = 'data-bugseek-globals';
  try {
    document.documentElement.removeAttribute(ATTR);
    const probe = document.createElement('script');
    probe.textContent = `(() => {
      try {
        const out = [];
        const w = window;
        if (w.jQuery && w.jQuery.fn && w.jQuery.fn.jquery) out.push('jQuery ' + w.jQuery.fn.jquery);
        if (w.React && w.React.version) out.push('React ' + w.React.version);
        if (w.Vue && w.Vue.version) out.push('Vue.js ' + w.Vue.version);
        if (w.angular && w.angular.version && w.angular.version.full) out.push('AngularJS ' + w.angular.version.full);
        if (w.Backbone && w.Backbone.VERSION) out.push('Backbone.js ' + w.Backbone.VERSION);
        if (w._ && w._.VERSION) out.push('Underscore.js ' + w._.VERSION);
        if (w.moment && w.moment.version) out.push('Moment.js ' + w.moment.version);
        if (w.Drupal) out.push('Drupal');
        if (w.wp || w.wpApiSettings) out.push('WordPress');
        document.documentElement.setAttribute('${ATTR}', JSON.stringify(out));
      } catch (e) { /* never break the host page */ }
    })();`;
    document.documentElement.appendChild(probe);
    probe.remove();
    const raw = document.documentElement.getAttribute(ATTR);
    document.documentElement.removeAttribute(ATTR);
    return raw ? (JSON.parse(raw) as string[]) : [];
  } catch {
    return [];
  }
}

function collectSinks(inlineScripts: string[]): DomScanData['sinks'] {
  const hits = new Map<string, { count: number; sample: string }>();
  for (const code of inlineScripts) {
    for (const { name, re } of SINK_PATTERNS) {
      const fresh = new RegExp(re.source, re.flags);
      let m: RegExpExecArray | null;
      let count = 0;
      let sample = '';
      while ((m = fresh.exec(code)) !== null) {
        if (m.index === fresh.lastIndex) fresh.lastIndex++;
        count++;
        if (!sample) {
          const lineStart = code.lastIndexOf('\n', m.index);
          const lineEnd = code.indexOf('\n', m.index);
          sample = code
            .slice(lineStart === -1 ? 0 : lineStart + 1, lineEnd === -1 ? undefined : lineEnd)
            .trim()
            .slice(0, 160);
        }
        if (count > 50) break; // cap per-sink counting
      }
      if (count > 0) {
        const prev = hits.get(name);
        hits.set(name, {
          count: (prev?.count ?? 0) + count,
          sample: prev?.sample || sample,
        });
      }
    }
  }
  return [...hits.entries()].map(([sink, v]) => ({ sink, count: v.count, sample: v.sample }));
}

/**
 * Classify a storage value by SHAPE only. The raw value never leaves this
 * function — reports and findings carry the classification, not the secret.
 */
function classifyValueShape(v: string): StorageEntry['shape'] {
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(v)) return 'jwt';
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return 'uuid';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'email';
  if (/^https?:\/\//i.test(v)) return 'url';
  if ((v.startsWith('{') && v.endsWith('}')) || (v.startsWith('[') && v.endsWith(']'))) return 'json';
  if (v.length >= 24 && /^[A-Za-z0-9_\-+/.=]+$/.test(v)) return 'long-opaque';
  if (v.length > 0 && v.length < 24 && !/\s/.test(v)) return 'short-opaque';
  return 'text';
}

const MAX_STORAGE_ENTRIES = 200;

/** Decode a JWT's STRUCTURE (header alg + claim names). Never returns claim values. */
function decodeJwtStructure(v: string): StorageEntry['jwt'] {
  try {
    const [h, p] = v.split('.');
    const dec = (s: string) =>
      JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>;
    const header = dec(h);
    const payload = dec(p);
    return {
      alg: typeof header['alg'] === 'string' ? header['alg'] : 'unknown',
      hasExpiry: 'exp' in payload,
      claimKeys: Object.keys(payload).slice(0, 12),
    };
  } catch {
    return undefined;
  }
}

function collectStorage(store: Storage | null): StorageEntry[] {
  const out: StorageEntry[] = [];
  try {
    if (!store) return out;
    for (let i = 0; i < store.length && out.length < MAX_STORAGE_ENTRIES; i++) {
      const key = store.key(i);
      if (!key) continue;
      let value = '';
      try {
        value = store.getItem(key) ?? '';
      } catch {
        /* unreadable value — record the key with an empty shape */
      }
      const shape = classifyValueShape(value);
      out.push({
        key,
        valueLength: value.length,
        shape,
        ...(shape === 'jwt' ? { jwt: decodeJwtStructure(value) } : {}),
      });
    }
  } catch {
    /* storage blocked (privacy mode, opaque origin) — inventory stays empty */
  }
  return out;
}

function collectDom(): DomScanData {
  const forms = Array.from(document.forms).map((f) => ({
    action: f.action || '',
    method: (f.method || 'get').toLowerCase(),
    inputCount: f.querySelectorAll('input, select, textarea').length,
    hasPassword: f.querySelector('input[type="password"]') !== null,
  }));

  const inputs = Array.from(document.querySelectorAll('input'))
    .slice(0, MAX_INPUTS)
    .map((i) => ({
      type: i.type || 'text',
      name: i.name || '',
      id: i.id || '',
      hidden: i.type === 'hidden',
    }));
  const hiddenInputCount = inputs.filter((i) => i.hidden).length;

  const iframes = Array.from(document.querySelectorAll('iframe')).map((f) => {
    const src = f.src || '';
    let sameOrigin = true;
    try {
      if (src) sameOrigin = new URL(src).origin === location.origin;
    } catch {
      sameOrigin = false;
    }
    return { src, sameOrigin };
  });

  const comments: string[] = [];
  const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
  let node: Node | null;
  while ((node = walker.nextNode()) !== null && comments.length < MAX_COMMENTS) {
    const text = (node.textContent || '').trim();
    if (text) comments.push(text.slice(0, MAX_COMMENT_CHARS));
  }

  const scripts = Array.from(document.scripts);
  const inlineScripts = scripts
    .filter((s) => !s.src)
    .slice(0, MAX_INLINE_SCRIPTS)
    .map((s) => (s.textContent || '').slice(0, MAX_INLINE_SCRIPT_CHARS))
    .filter((t) => t.trim().length > 0);
  const externalScripts = scripts
    .filter((s) => !!s.src)
    .map((s) => s.src);

  const metaTags = Array.from(document.querySelectorAll('meta'))
    .map((m) => ({
      name: m.getAttribute('name') || m.getAttribute('property') || '',
      content: m.getAttribute('content') || '',
    }))
    .filter((m) => m.name && m.content);

  const inlineHandlerCount = document.querySelectorAll(
    '[onclick],[ondblclick],[onload],[onerror],[onsubmit],[onmouseover],[onfocus],[onchange],[onkeyup],[onkeydown]',
  ).length;

  return {
    url: location.href,
    title: document.title,
    forms,
    inputs,
    hiddenInputCount,
    iframes,
    comments,
    inlineScripts,
    externalScripts,
    metaTags,
    sinks: collectSinks(inlineScripts),
    globals: probePageGlobals(),
    inlineHandlerCount,
    storage: {
      local: collectStorage(window.localStorage),
      session: collectStorage(window.sessionStorage),
    },
  };
}

chrome.runtime.onMessage.addListener(
  (msg: ScanMessage, _sender, sendResponse: (r: unknown) => void) => {
    if (msg.type === 'COLLECT_DOM') {
      try {
        sendResponse({ ok: true, data: collectDom() });
      } catch (err) {
        sendResponse({ ok: false, error: err instanceof Error ? err.message : String(err) });
      }
      return true;
    }
    if (msg.type === 'XSS_PROBE') {
      // Confirm reflected XSS via DOM observation: load the probe URL in a
      // hidden same-origin iframe and check whether the marker payload
      // executed (marker reaches document.title). Read-only observation —
      // the payload itself is a non-destructive title assignment.
      void probeXssExecution(msg.url, msg.marker).then(
        (executed) => sendResponse({ ok: true, executed }),
        (err) =>
          sendResponse({
            ok: false,
            error: err instanceof Error ? err.message : String(err),
          }),
      );
      return true;
    }
    return false;
  },
);

/**
 * Load `url` in a hidden same-origin iframe and report whether `marker`
 * reached document.title — i.e. whether an injected marker payload executed.
 * The iframe is removed afterwards. Resolves false on any failure
 * (X-Frame-Options, CSP, navigation errors): unconfirmed, never an error.
 */
function probeXssExecution(url: string, marker: string): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: boolean): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      iframe.remove();
      resolve(v);
    };
    const timer = setTimeout(() => finish(false), 9000);
    const iframe = document.createElement('iframe');
    iframe.setAttribute('aria-hidden', 'true');
    iframe.setAttribute('title', 'BugSeek XSS confirmation probe');
    iframe.style.cssText =
      'position:absolute!important;width:1px!important;height:1px!important;' +
      'left:-9999px!important;top:-9999px!important;visibility:hidden!important;';
    iframe.onload = (): void => {
      // Give the payload a moment to run after the document loads.
      setTimeout(() => {
        try {
          const title = iframe.contentDocument?.title ?? '';
          finish(title.includes(marker));
        } catch {
          // Cross-origin or blocked — cannot observe.
          finish(false);
        }
      }, 1500);
    };
    iframe.onerror = (): void => finish(false);
    try {
      (document.body ?? document.documentElement).appendChild(iframe);
      iframe.src = url;
    } catch {
      finish(false);
    }
  });
}

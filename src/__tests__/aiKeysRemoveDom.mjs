// DOM + chrome + fetch shim for loading the REAL src/popup/active.ts under Node.
// No repo files are touched; this file lives in /tmp only.
import { readFileSync } from 'node:fs';

export class El {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.children = [];
    this.listeners = {};
    this._text = '';
    this.hidden = false;
    this.disabled = false;
    this.checked = false;
    this.value = '';
    this.placeholder = '';
    this.type = '';
    this.title = '';
    this.className = '';
    this.files = null;
    this.style = {};
    this._id = '';
    this.parent = null;
    this.classList = {
      add: (c) => {
        const parts = new Set(this.className.split(/\s+/).filter(Boolean));
        parts.add(c);
        this.className = [...parts].join(' ');
      },
      remove: (c) => {
        this.className = this.className
          .split(/\s+/)
          .filter((x) => x && x !== c)
          .join(' ');
      },
      contains: (c) => this.className.split(/\s+/).includes(c),
    };
  }
  get id() {
    return this._id;
  }
  set id(v) {
    this._id = v;
    if (v) registry.set(v, this);
  }
  get textContent() {
    return this._text + this.children.map((c) => c.textContent ?? '').join('');
  }
  set textContent(v) {
    this._text = String(v ?? '');
    this.children = [];
  }
  get innerHTML() {
    return '';
  }
  set innerHTML(_v) {
    this._text = '';
    this.children = [];
  }
  appendChild(c) {
    this.children.push(c);
    c.parent = this;
    return c;
  }
  addEventListener(t, f) {
    (this.listeners[t] ??= []).push(f);
  }
  removeEventListener(t, f) {
    this.listeners[t] = (this.listeners[t] ?? []).filter((x) => x !== f);
  }
  click() {
    const e = { preventDefault() {}, stopPropagation() {}, target: this };
    for (const f of [...(this.listeners.click ?? [])]) f(e);
  }
  querySelector() {
    return null;
  }
  querySelectorAll() {
    return [];
  }
  focus() {}
  setCustomValidity() {}
  reportValidity() {
    return true;
  }
  dispatchEvent() {
    return true;
  }
}

export const registry = new Map();

export const documentShim = {
  getElementById: (id) => registry.get(id) ?? null,
  createElement: (tag) => new El(tag),
  createElementNS: (_ns, tag) => new El(tag),
  createTextNode: (text) => ({ nodeType: 3, textContent: String(text), parent: null }),
  addEventListener() {},
  dispatchEvent() {
    return true;
  },
};

/** Pre-create one element per id found in the real popup.html, honouring `hidden`. */
export function buildDomFromPopupHtml(htmlPath) {
  const html = readFileSync(htmlPath, 'utf8');
  const tagRe = /<([a-zA-Z][a-zA-Z0-9]*)[^>]*\bid="([^"]+)"[^>]*>/g;
  let m;
  const ids = [];
  while ((m = tagRe.exec(html))) {
    const [, tag, id] = m;
    const el = new El(tag);
    el.id = id;
    el.hidden = /\bhidden\b/.test(m[0]);
    ids.push(id);
  }
  return ids;
}

// ---- chrome.storage.local -------------------------------------------------
export function makeChromeStorage(initial = {}) {
  const store = { ...initial };
  return {
    store,
    chrome: {
      storage: {
        local: {
          get: async (keys) => {
            const list = Array.isArray(keys) ? keys : [keys];
            return Object.fromEntries(list.map((k) => [k, store[k]]));
          },
          set: async (obj) => Object.assign(store, obj),
          remove: async (key) => {
            for (const k of Array.isArray(key) ? key : [key]) delete store[k];
          },
        },
      },
      runtime: { sendMessage: async () => undefined },
    },
  };
}

// ---- stateful fake backend ------------------------------------------------
export function capsPayload() {
  return {
    version: '0.4.0',
    runtime: 'cloud',
    llmProviders: [
      {
        id: 'qwen',
        label: 'Qwen (DashScope)',
        mode: 'hosted',
        available: true,
        defaultModels: { worker: 'qwen3.7-plus', reasoning: 'qwen3.8-max' },
      },
      {
        id: 'gemini',
        label: 'Gemini',
        mode: 'hosted',
        available: true,
        defaultModels: { worker: 'gemini-2.5-flash', reasoning: 'gemini-2.5-pro' },
      },
    ],
    engines: [],
  };
}

export function keyRow(providerId, hint) {
  return {
    providerId,
    keyHint: hint,
    baseUrl:
      providerId === 'qwen'
        ? 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1'
        : 'https://generativelanguage.googleapis.com/v1beta',
    verifiedAt: '2026-11-27T00:00:00.000Z',
    discoveredModels: providerId === 'qwen' ? ['qwen3.7-plus', 'qwen4-max'] : ['gemini-2.5-flash'],
  };
}

export function routingFor(providerId) {
  return {
    workerProvider: providerId,
    workerModel: providerId === 'qwen' ? 'qwen3.7-plus' : 'gemini-2.5-flash',
    reasoningProvider: providerId,
    reasoningModel: providerId === 'qwen' ? 'qwen3.8-max' : 'gemini-2.5-pro',
  };
}

/**
 * scenario: {
 *   keys: SavedAiKey[] (initial server state),
 *   deleteBehavior: 'ok' | '404' | 'throw' | 'hang-apply' | 'hang',
 *   capsAfterDelete: 'ok' | '500' | 'malformed',
 *   keysAfterDelete: 'ok' | '500',
 * }
 * Failures apply only AFTER the first DELETE, so the initial render succeeds
 * (matching the user story: the key was added fine, Remove then misbehaves).
 */
export function makeFetch(scenario) {
  const log = [];
  let inflight = 0;
  let deletedOnce = false;
  const serverKeys = scenario.keys.map((k) => ({ ...k }));
  const routing = routingFor(scenario.keys[0]?.providerId ?? 'qwen');

  const json = (body, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });

  async function handler(input, init = {}) {
    const url = String(input);
    const method = (init.method ?? 'GET').toUpperCase();
    const path = url.replace(/^https?:\/\/[^/]+/, '');
    const signal = init.signal;
    const entry = { method, path, result: 'pending' };
    log.push(entry);
    inflight++;
    try {
      if (path === '/api/v1/health' && method === 'GET') {
        entry.result = '200';
        return json({ ok: true });
      }
      if (path === '/api/v1/account' && method === 'GET') {
        entry.result = '200';
        return json({ email: 'peer@example.com', plan: 'free', operator: false });
      }
      if (path === '/api/engines/status' && method === 'GET') {
        entry.result = '200';
        return json({ engines: [] });
      }
      if (path === '/api/v1/capabilities' && method === 'GET') {
        if (deletedOnce && scenario.capsAfterDelete === '500') {
          entry.result = '500';
          return json({ error: 'upstream provider list unavailable' }, 500);
        }
        if (deletedOnce && scenario.capsAfterDelete === 'malformed') {
          entry.result = '200-malformed';
          return json({ version: '0.4.0', runtime: 'cloud', engines: [] }); // no llmProviders
        }
        entry.result = '200';
        return json(capsPayload());
      }
      if (path === '/api/v1/ai-keys' && method === 'GET') {
        if (deletedOnce && scenario.keysAfterDelete === '500') {
          entry.result = '500';
          return json({ error: 'database exploded' }, 500);
        }
        entry.result = '200';
        return json({ keys: serverKeys, routing, hasByok: serverKeys.length > 0 });
      }
      const del = path.match(/^\/api\/v1\/ai-keys\/([^/]+)$/);
      if (del && method === 'DELETE') {
        const id = decodeURIComponent(del[1]);
        deletedOnce = true;
        const idx = serverKeys.findIndex((k) => k.providerId === id);
        // 'hang' hangs every DELETE (backend unreachable); 'hang-apply'
        // hangs only the FIRST DELETE (the one the client times out on),
        // so a retry after the timeout sees the 404 for the already-deleted key.
        const hangThisTime =
          scenario.deleteBehavior === 'hang' ||
          (scenario.deleteBehavior === 'hang-apply' && !handler._hangUsed);
        if (scenario.deleteBehavior === 'throw') {
          entry.result = 'threw TypeError: fetch failed';
          throw new TypeError('fetch failed');
        }
        if (hangThisTime) {
          handler._hangUsed = true;
          if (scenario.deleteBehavior === 'hang-apply' && idx >= 0) serverKeys.splice(idx, 1);
          entry.result = 'hung-then-aborted';
          // Never resolves on its own; honours the AbortSignal like a real
          // fetch would, so fetchJson's 8s AbortSignal.timeout() fires.
          await new Promise((_, reject) => {
            if (signal?.aborted) {
              reject(new DOMException('The operation timed out.', 'TimeoutError'));
              return;
            }
            signal?.addEventListener(
              'abort',
              () => reject(new DOMException('The operation timed out.', 'TimeoutError')),
              { once: true },
            );
          });
        }
        if (scenario.deleteBehavior === '404' || idx < 0) {
          // A 404 means the key is already gone server-side, so a later
          // GET must not list it again: the row the popup shows is stale.
          if (idx >= 0) serverKeys.splice(idx, 1);
          entry.result = '404';
          return json({ error: `No saved key for provider ${id}.` }, 404);
        }
        serverKeys.splice(idx, 1);
        entry.result = '200';
        return json({ deleted: true, hasByok: serverKeys.length > 0 });
      }
      entry.result = '404-unmocked';
      return json({ error: `unmocked ${method} ${path}` }, 404);
    } catch (err) {
      if (entry.result === 'pending') entry.result = `threw ${err?.name ?? '?'}: ${err?.message ?? err}`;
      throw err;
    } finally {
      inflight--;
    }
  }

  return {
    fetch: handler,
    log,
    serverKeys,
    get inflight() {
      return inflight;
    },
  };
}

/** Wait until no fetch is in flight and 120ms have passed with no new fetch. */
export async function settle(fake, timeoutMs = 25000) {
  const start = Date.now();
  let lastCount = fake.log.length;
  let quietSince = Date.now();
  while (Date.now() - start < timeoutMs) {
    await new Promise((r) => setTimeout(r, 25));
    if (fake.log.length !== lastCount) {
      lastCount = fake.log.length;
      quietSince = Date.now();
    }
    if (fake.inflight === 0 && Date.now() - quietSince >= 120) return;
  }
  throw new Error(`settle timed out after ${timeoutMs}ms (inflight=${fake.inflight})`);
}

/** Snapshot exactly what the user sees in the AI-keys section + status line. */
export function observe() {
  const list = registry.get('ai-keys-saved');
  const rows = (list?.children ?? [])
    .filter((c) => c.className === 'ai-key-row')
    .map((row) => {
      const btn = row.children.find((c) => c.tagName === 'BUTTON');
      const name = row.children.find((c) => c.tagName === 'SPAN')?.textContent ?? '';
      return { name, removeButtonPresent: !!btn, removeDisabled: btn ? !!btn.disabled : null };
    });
  const empty = (list?.children ?? [])
    .filter((c) => c.tagName === 'P')
    .map((c) => c.textContent);
  const errEl = registry.get('ai-key-error');
  const statusEl = registry.get('active-status');
  return {
    rowCount: rows.length,
    rows,
    emptyStateText: empty,
    errorHidden: errEl ? !!errEl.hidden : null,
    errorText: errEl && !errEl.hidden ? errEl.textContent : '',
    statusText: statusEl ? statusEl.textContent : '',
    serverKeysNote: undefined,
  };
}

export function removeButtons() {
  const list = registry.get('ai-keys-saved');
  return (list?.children ?? [])
    .filter((c) => c.className === 'ai-key-row')
    .map((row) => row.children.find((c) => c.tagName === 'BUTTON'))
    .filter(Boolean);
}

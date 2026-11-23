/**
 * Unit tests for ASM import (src/asm/adapters.ts, src/asm/import.ts)
 * and the ASM routes (src/routes/asm.ts).
 * No network, no DB, no LLM.
 *
 * Run:  npx tsx test/asm.test.ts   (from backend/)
 */
import Fastify from 'fastify';
import { MemoryDatabase } from '../src/db/db.js';
import { generateSessionToken, hashSessionToken } from '../src/auth/session.js';
import { MemoryGraphStore } from '../src/graph/store.js';
import type { AssetKind } from '../src/graph/types.js';
import {
  ScopeSentryAdapter,
  validateRawAssets,
  type RawAsset,
} from '../src/asm/adapters.js';
import { graphAssetSink, importAssets, type ImportAssetSink } from '../src/asm/import.js';
import { asmRoutes } from '../src/routes/asm.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

/** In-memory sink keyed by company scope id, for merge-scoping tests. */
class MemorySink implements ImportAssetSink {
  private rows = new Map<string, Array<{ kind: string; value: string; host: string | null }>>();

  async listAssets(scopeId: string) {
    return (this.rows.get(scopeId) ?? []).map((r) => ({ kind: r.kind, value: r.value }));
  }

  async addAsset(input: { scopeId: string; kind: AssetKind; value: string; host?: string | null }) {
    const list = this.rows.get(input.scopeId) ?? [];
    list.push({ kind: input.kind, value: input.value, host: input.host ?? null });
    this.rows.set(input.scopeId, list);
    return { kind: input.kind, value: input.value };
  }

  count(scopeId: string): number {
    return this.rows.get(scopeId)?.length ?? 0;
  }
}

const inline = (assets: RawAsset[]) => ({ name: 'inline', listAssets: async () => assets });

async function main() {
  // ── 1. Raw-asset validation ──
  {
    let threw = false;
    try {
      validateRawAssets([{ kind: 'host', value: 'example.com' }]);
    } catch (e) {
      threw = /invalid_asset_kind/.test((e as Error).message);
    }
    check('validate: bad kind rejected', threw);
    let threw2 = false;
    try {
      validateRawAssets([{ kind: 'domain', value: '   ' }]);
    } catch (e) {
      threw2 = /non-empty string/.test((e as Error).message);
    }
    check('validate: empty value rejected', threw2);
    let threw3 = false;
    try {
      validateRawAssets([{ kind: 'domain', value: 'example.com', meta: { n: 7 } }]);
    } catch {
      threw3 = true;
    }
    check('validate: non-string meta value rejected', threw3);
    const ok = validateRawAssets([
      { kind: 'domain', value: 'example.com', parent: 'example.com', meta: { src: 'x' } },
    ]);
    check('validate: good row passes through', ok.length === 1 && ok[0].kind === 'domain');
  }

  // ── 2. json-file adapter removed: inline assets only, validated up front ──
  {
    // The disk-reading adapter is gone: the backend never reads a
    // caller-named path off its own disk. The json-file route now takes
    // inline rows and validates them before import.
    let threw = false;
    try {
      validateRawAssets([{ kind: 'host', value: 'example.com' }]);
    } catch (e) {
      threw = /invalid_asset_kind/.test((e as Error).message);
    }
    check('json-file: bad kind rejected by validation', threw);

    let threw2 = false;
    try {
      validateRawAssets({ items: [] });
    } catch (e) {
      threw2 = /assets must be an array/.test((e as Error).message);
    }
    check('json-file: non-array assets rejected by validation', threw2);

    let threw3 = false;
    try {
      validateRawAssets([{ kind: 'domain', value: '   ' }]);
    } catch (e) {
      threw3 = /must be a non-empty string/.test((e as Error).message);
    }
    check('json-file: empty value rejected by validation', threw3);

    const ok = validateRawAssets([
      { kind: 'domain', value: 'example.com', parent: 'example.com', meta: { src: 'x' } },
    ]);
    check('json-file: good rows pass validation', ok.length === 1 && ok[0].kind === 'domain');
  }

  // ── 3. Import dedup: within-batch and re-import ──
  {
    const sink = new MemorySink();
    const first = await importAssets({
      adapter: inline([
        { kind: 'domain', value: 'example.com' },
        { kind: 'domain', value: 'example.com' },
        { kind: 'subdomain', value: 'api.example.com', parent: 'example.com' },
      ]),
      companyId: 'co-1',
      userId: 'user-1',
      assetStore: sink,
    });
    check('dedup: same asset twice in one batch = 1 imported + 1 skipped', first.imported === 1 + 1 && first.skippedDuplicates === 1, first);
    check('dedup: batch wrote 2 rows', sink.count('co-1') === 2);
    const second = await importAssets({
      adapter: inline([
        { kind: 'domain', value: 'example.com' },
        { kind: 'subdomain', value: 'api.example.com' },
      ]),
      companyId: 'co-1',
      userId: 'user-1',
      assetStore: sink,
    });
    check('dedup: re-import of existing assets = all skipped', second.imported === 0 && second.skippedDuplicates === 2, second);
    check('dedup: store still holds 2 rows', sink.count('co-1') === 2);
  }

  // ── 4. Normalisation: uppercase host + scheme stripped ──
  {
    const sink = new MemorySink();
    const result = await importAssets({
      adapter: inline([
        { kind: 'domain', value: 'HTTPS://EXAMPLE.COM:8080/path?x=1' },
        { kind: 'subdomain', value: 'API.Example.COM.' },
        { kind: 'ip', value: '203.0.113.7' },
        { kind: 'port', value: '443', parent: 'Example.COM' },
        { kind: 'site', value: 'https://Shop.Example.com/Admin/' },
        { kind: 'domain', value: 'not a host!!' },
        { kind: 'ip', value: '999.1.1.1' },
        { kind: 'port', value: '70000' },
      ]),
      companyId: 'co-1',
      userId: 'user-1',
      assetStore: sink,
    });
    check('normalise: uppercase + scheme + port stripped from domain', result.written.some((w) => w.kind === 'domain' && w.value === 'example.com'), result.written);
    check('normalise: subdomain lowercased, trailing dot stripped', result.written.some((w) => w.value === 'api.example.com'), result.written);
    check('normalise: port becomes host:port service', result.written.some((w) => w.kind === 'service' && w.value === 'example.com:443'), result.written);
    check('normalise: site lowercases host, keeps path', result.written.some((w) => w.kind === 'endpoint' && w.value === 'https://shop.example.com/Admin/'), result.written);
    check('normalise: invalid rows reported, never dropped', result.rejected.length === 3, result.rejected);
    check('normalise: invalid host reason names the value', result.rejected.some((r) => r.reason.includes('not a host')));
    check('normalise: 5 imported, 3 rejected', result.imported === 5 && result.errors.length === 0, result);
  }

  // ── 5. Merge scoping: same host, two companies = two rows ──
  {
    const sink = new MemorySink();
    const a = await importAssets({
      adapter: inline([{ kind: 'domain', value: 'shared.example.com' }]),
      companyId: 'co-a', userId: 'user-1', assetStore: sink,
    });
    const b = await importAssets({
      adapter: inline([{ kind: 'domain', value: 'shared.example.com' }]),
      companyId: 'co-b', userId: 'user-1', assetStore: sink,
    });
    check('scope: same host imports for two companies', a.imported === 1 && b.imported === 1);
    check('scope: each company holds its own row', sink.count('co-a') === 1 && sink.count('co-b') === 1);
  }

  // ── 6. Real graph sink: assets land in the task's asset graph ──
  {
    const graph = new MemoryGraphStore();
    const task = await graph.createTask({ userId: 'user-1', goalText: 'g', targetUrl: 'https://example.com' });
    const result = await importAssets({
      adapter: inline([{ kind: 'domain', value: 'example.com' }]),
      companyId: 'co-1',
      userId: 'user-1',
      assetStore: graphAssetSink(graph, task.id),
    });
    check('graph sink: import writes into the real graph', result.imported === 1, result);
    const assets = await graph.listAssets(task.id);
    check('graph sink: asset is a domain row in the task graph', assets.length === 1 && assets[0].kind === 'domain' && assets[0].value === 'example.com', assets);
    const again = await importAssets({
      adapter: inline([{ kind: 'domain', value: 'example.com' }]),
      companyId: 'co-1',
      userId: 'user-1',
      assetStore: graphAssetSink(graph, task.id),
    });
    check('graph sink: re-import dedups against the graph', again.imported === 0 && again.skippedDuplicates === 1, again);
  }

  // ── 7. ScopeSentry adapter: good shape, bad shape, auth failure ──
  {
    const goodFetch = (async (_url: string, _opts: unknown) =>
      new Response(JSON.stringify({ assets: [{ kind: 'domain', value: 'example.com' }], nextPage: null }), { status: 200 })) as typeof fetch;
    const good = await new ScopeSentryAdapter({
      baseUrl: 'https://asm.example.com', apiKey: 'k', project: 'p', fetchFn: goodFetch,
    }).listAssets();
    check('scopesentry: well-shaped response lists assets', good.length === 1 && good[0].value === 'example.com');

    const pagedFetch = (async (url: string) => {
      const page = new URL(url).searchParams.get('page');
      const body = page === '1'
        ? { assets: [{ kind: 'domain', value: 'a.example.com' }], nextPage: '2' }
        : { assets: [{ kind: 'domain', value: 'b.example.com' }], nextPage: null };
      return new Response(JSON.stringify(body), { status: 200 });
    }) as typeof fetch;
    const paged = await new ScopeSentryAdapter({
      baseUrl: 'https://asm.example.com', apiKey: 'k', project: 'p', fetchFn: pagedFetch,
    }).listAssets();
    check('scopesentry: paged listing follows nextPage', paged.length === 2, paged);

    const wrongFetch = (async () =>
      new Response(JSON.stringify({ items: [{ kind: 'domain', value: 'example.com' }] }), { status: 200 })) as typeof fetch;
    let threw = false;
    try {
      await new ScopeSentryAdapter({ baseUrl: 'https://asm.example.com', apiKey: 'k', project: 'p', fetchFn: wrongFetch }).listAssets();
    } catch (e) {
      threw = /unexpected_response_shape/.test((e as Error).message);
    }
    check('scopesentry: unexpected shape rejected, never coerced', threw);

    const badRowFetch = (async () =>
      new Response(JSON.stringify({ assets: [{ kind: 'host', value: 'example.com' }] }), { status: 200 })) as typeof fetch;
    let threw2 = false;
    try {
      await new ScopeSentryAdapter({ baseUrl: 'https://asm.example.com', apiKey: 'k', project: 'p', fetchFn: badRowFetch }).listAssets();
    } catch (e) {
      threw2 = /invalid_asset_row/.test((e as Error).message);
    }
    check('scopesentry: invalid row rejected, never coerced', threw2);

    const authFetch = (async () => new Response('nope', { status: 401 })) as typeof fetch;
    let threw3 = false;
    try {
      await new ScopeSentryAdapter({ baseUrl: 'https://asm.example.com', apiKey: 'bad', project: 'p', fetchFn: authFetch }).listAssets();
    } catch (e) {
      threw3 = /auth_failed/.test((e as Error).message);
    }
    check('scopesentry: 401 surfaces as auth failure', threw3);

    let threw4 = false;
    try {
      // eslint-disable-next-line no-new
      new ScopeSentryAdapter({ baseUrl: 'https://asm.example.com', apiKey: '', project: 'p' });
    } catch (e) {
      threw4 = /api_key_required/.test((e as Error).message);
    }
    check('scopesentry: missing key rejected at construction', threw4);
  }

  // ── 8. Routes: adapters list + inline import into the graph ──
  {
    const db = new MemoryDatabase();
    const user = await db.createUser('user@example.com', 'unused-hash');
    const token = generateSessionToken();
    await db.createSession(user.id, hashSessionToken(token), new Date(Date.now() + 3600_000).toISOString());
    const cookie = `bs_session=${token}`;
    const graph = new MemoryGraphStore();
    const task = await graph.createTask({ userId: user.id, goalText: 'g', targetUrl: 'https://example.com' });

    const app = Fastify();
    await asmRoutes(app as never, { db, graph });

    const unauth = await app.inject({ method: 'GET', url: '/api/asm/adapters' });
    check('route: unauthenticated adapters list → 401', unauth.statusCode === 401);

    const list = await app.inject({ method: 'GET', url: '/api/asm/adapters', headers: { cookie } });
    const listBody = JSON.parse(list.body) as { adapters: Array<{ name: string; verified: boolean }> };
    check('route: adapters list returns both adapters', listBody.adapters.length === 2, listBody);
    check('route: json-file is verified, scopesentry is contract-only',
      listBody.adapters.find((a) => a.name === 'json-file')?.verified === true &&
      listBody.adapters.find((a) => a.name === 'scopesentry')?.verified === false, listBody);

    const imported = await app.inject({
      method: 'POST',
      url: '/api/asm/import',
      headers: { cookie },
      payload: {
        adapter: 'json-file', companyId: 'co-1', taskId: task.id,
        assets: [
          { kind: 'domain', value: 'EXAMPLE.com' },
          { kind: 'domain', value: 'example.com' },
          { kind: 'domain', value: 'bad host!!' },
        ],
      },
    });
    const importBody = JSON.parse(imported.body) as { imported: number; skippedDuplicates: number; rejected: unknown[] };
    check('route: import returns 200 with counts', imported.statusCode === 200 && importBody.imported === 1 && importBody.skippedDuplicates === 1 && importBody.rejected.length === 1, importBody);
    const assets = await graph.listAssets(task.id);
    check('route: imported asset landed in the task graph', assets.length === 1 && assets[0].value === 'example.com', assets);

    const otherTask = await app.inject({
      method: 'POST',
      url: '/api/asm/import',
      headers: { cookie },
      payload: { adapter: 'json-file', companyId: 'co-1', taskId: '00000000-0000-0000-0000-000000000000', assets: [] },
    });
    check('route: unknown task → 404', otherTask.statusCode === 404);
  }

  if (failures > 0) { console.error(`${failures} asm test(s) failed`); process.exit(1); }
  console.log('ALL ASM TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('asm test crashed', e); process.exit(1); });

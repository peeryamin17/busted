/**
 * ASM import: normalise, dedup, and merge raw assets into the asset graph.
 * A data import, never a scan: no DNS, no fetches, no port probes.
 * Dedup key is (kind, value, companyId).
 */
import type { GraphStore } from '../graph/store.js';
import type { AssetKind, AssetRecord } from '../graph/types.js';
import type { AssetSourceAdapter, RawAsset } from './adapters.js';

/** The minimal surface importAssets needs from any asset store. */
export interface ImportAssetSink {
  /** Assets already stored under this scope key (companyId). */
  listAssets(scopeId: string): Promise<Array<{ kind: string; value: string }>>;
  addAsset(input: {
    scopeId: string;
    kind: AssetKind;
    value: string;
    host?: string | null;
  }): Promise<unknown>;
}

/**
 * Adapt the real graph store to the import sink. `taskId` is the task
 * whose asset graph receives the rows; `scopeId` is accepted (it is
 * the companyId the caller dedups on) but the graph itself stores
 * rows per task, so the sink keeps no separate per-company partition
 * inside the graph, the company scoping lives in the import's dedup
 * key and in the task the import was run for.
 */
export function graphAssetSink(graph: GraphStore, taskId: string): ImportAssetSink {
  return {
    async listAssets(_scopeId: string) {
      return graph.listAssets(taskId);
    },
    async addAsset(input) {
      const asset: AssetRecord = await graph.addAsset({
        taskId,
        kind: input.kind,
        value: input.value,
        host: input.host ?? null,
      });
      return asset;
    },
  };
}

/** One row the import refused, with the reason, reported, never dropped. */
export interface RejectedAsset {
  raw: RawAsset;
  reason: string;
}

export interface ImportResult {
  imported: number;
  skippedDuplicates: number;
  rejected: RejectedAsset[];
  /** Fatal errors (e.g. the adapter itself failed). Empty on success. */
  errors: string[];
  /** The normalised assets that were actually written, in order. */
  written: Array<{ kind: AssetKind; value: string; host: string | null }>;
}

export interface ImportAssetsInput {
  adapter: AssetSourceAdapter;
  companyId: string;
  userId: string;
  assetStore: ImportAssetSink;
}

// ── Normalisation ────────────────────────────────────────────────────────

const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IPV6_RE = /^(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i;

function stripScheme(value: string): string {
  return value.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
}

/** Lowercase a host and drop any trailing dot, port, path or scheme. */
function normaliseHost(value: string): string {
  let host = stripScheme(value.trim().toLowerCase());
  host = host.split('/')[0].split('?')[0].split('#')[0];
  // A trailing :port on a bare host, keep the host, drop the port
  // (ports are their own asset kind, never part of a domain value).
  if (!host.startsWith('[')) {
    const lastColon = host.lastIndexOf(':');
    if (lastColon > 0 && /^\d+$/.test(host.slice(lastColon + 1))) {
      host = host.slice(0, lastColon);
    }
  }
  return host.replace(/\.$/, '');
}

/**
 * Normalise one raw asset into the graph's (kind, value, host) shape,
 * or return a rejection reason. `userId` is unused today, the store
 * enforces ownership upstream (routes scope every read/write to the
 * authenticated user), and is kept in the signature so the import
 * can be audited per user later without changing callers.
 */
export function normaliseRawAsset(
  raw: RawAsset,
  _userId: string,
): { kind: AssetKind; value: string; host: string | null } | { reject: string } {
  const value = raw.value.trim();
  switch (raw.kind) {
    case 'domain':
    case 'subdomain': {
      const host = normaliseHost(value);
      if (!HOST_RE.test(host)) return { reject: `invalid host: ${value}` };
      return { kind: 'domain', value: host, host };
    }
    case 'ip': {
      const ip = value.toLowerCase();
      if (!IPV4_RE.test(ip) && !IPV6_RE.test(ip)) {
        return { reject: `invalid IP address: ${value}` };
      }
      return { kind: 'ip', value: ip, host: ip };
    }
    case 'port': {
      if (!/^\d+$/.test(value)) return { reject: `invalid port: ${value}` };
      const port = Number(value);
      if (port < 1 || port > 65535) return { reject: `port out of range: ${value}` };
      const parent = raw.parent ? normaliseHost(raw.parent) : null;
      if (parent && !HOST_RE.test(parent) && !IPV4_RE.test(parent) && !IPV6_RE.test(parent)) {
        return { reject: `invalid port parent host: ${raw.parent}` };
      }
      // A port belongs to a host: `example.com:443`. Without a parent
      // it is just the bare port number, still a service row.
      return { kind: 'service', value: parent ? `${parent}:${port}` : String(port), host: parent };
    }
    case 'site':
    case 'endpoint': {
      let url: URL;
      try {
        url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`);
      } catch {
        return { reject: `invalid URL: ${value}` };
      }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return { reject: `unsupported URL scheme: ${url.protocol}` };
      }
      const host = url.hostname.toLowerCase();
      const normalised = `${url.protocol}//${host}${url.port ? `:${url.port}` : ''}${url.pathname}${url.search}${url.hash}`;
      return { kind: 'endpoint', value: normalised, host };
    }
    default:
      return { reject: `unknown asset kind: ${String((raw as RawAsset).kind)}` };
  }
}

// ── Import ───────────────────────────────────────────────────────────────

/**
 * Pull assets from the adapter and merge them into the store under
 * `companyId`. Values are normalised (lowercase hosts, schemes and
 * ports stripped from domains), deduped against the store AND within
 * the batch on (kind, value, companyId), and written in batch order.
 * Rejected rows are returned with reasons; the adapter failing
 * outright is reported in `errors` with nothing written.
 */
export async function importAssets(input: ImportAssetsInput): Promise<ImportResult> {
  const { adapter, companyId, userId, assetStore } = input;
  if (!companyId?.trim()) throw new Error('import_company_required');
  let raw: RawAsset[];
  try {
    raw = await adapter.listAssets({ companyId });
  } catch (err) {
    return {
      imported: 0,
      skippedDuplicates: 0,
      rejected: [],
      errors: [`${adapter.name}: ${(err as Error).message}`],
      written: [],
    };
  }

  const existing = await assetStore.listAssets(companyId);
  const seen = new Set(existing.map((a) => `${a.kind}\n${a.value}`));
  const result: ImportResult = {
    imported: 0,
    skippedDuplicates: 0,
    rejected: [],
    errors: [],
    written: [],
  };

  for (const row of raw) {
    const normalised = normaliseRawAsset(row, userId);
    if ('reject' in normalised) {
      result.rejected.push({ raw: row, reason: normalised.reject });
      continue;
    }
    const key = `${normalised.kind}\n${normalised.value}`;
    if (seen.has(key)) {
      result.skippedDuplicates++;
      continue;
    }
    seen.add(key);
    await assetStore.addAsset({
      scopeId: companyId,
      kind: normalised.kind,
      value: normalised.value,
      host: normalised.host,
    });
    result.imported++;
    result.written.push(normalised);
  }
  return result;
}

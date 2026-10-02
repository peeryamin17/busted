import { matchProgrammeScope, parseScopeEntry } from './matcher.js';
import type {
  ScopeCheckResult,
  ScopeEntry,
  ScopePlatform,
  ScopeProgramme,
  ScopeProgrammeSummary,
} from './types.js';

/**
 * Programme scope dataset — the public HackerOne/Bugcrowd scope listings,
 * mirrored by the community bounty-targets-data project and fetched at
 * runtime. Nothing is vendored into this repo; the data is cached in memory
 * for a few hours and refreshed lazily.
 *
 * If the upstream data can't be fetched, checks degrade to an honest
 * "unknown" — a scope check must never take the product down with it.
 */

const DATA_URLS: Record<ScopePlatform, string> = {
  hackerone:
    'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json',
  bugcrowd:
    'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json',
};

/** Refresh the mirror every six hours. */
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
/** After a failed fetch, wait five minutes before trying again. */
const FAILURE_TTL_MS = 5 * 60 * 1000;
const SEARCH_LIMIT = 25;

const PLATFORM_LABEL: Record<ScopePlatform, string> = {
  hackerone: 'HackerOne',
  bugcrowd: 'Bugcrowd',
};

export type ScopeFetch = (
  url: string,
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

// ---------------------------------------------------------------------------
// Raw dataset normalisation
// ---------------------------------------------------------------------------

/** Asset types that describe websites we can check (per platform). */
const HACKERONE_WEB_TYPES = new Set(['URL', 'WILDCARD', 'API']);
const BUGCROWD_WEB_TYPES = new Set(['website', 'api']);

function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === 'object' && v !== null
    ? (v as Record<string, unknown>)
    : null;
}

function asString(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() ? v.trim() : undefined;
}

interface RawLists {
  inScopeRaw: unknown[];
  outOfScopeRaw: unknown[];
}

function targetLists(raw: unknown): RawLists {
  const rec = asRecord(raw);
  const targets = asRecord(rec?.['targets']);
  const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
  return {
    inScopeRaw: list(targets?.['in_scope']),
    outOfScopeRaw: list(targets?.['out_of_scope']),
  };
}

export function normaliseHackerOneProgrammes(raw: unknown): ScopeProgramme[] {
  if (!Array.isArray(raw)) return [];
  const programmes: ScopeProgramme[] = [];
  for (const item of raw) {
    const rec = asRecord(item);
    const handle = asString(rec?.['handle'])?.toLowerCase();
    if (!rec || !handle) continue;
    const { inScopeRaw, outOfScopeRaw } = targetLists(rec);

    const parseSide = (entries: unknown[], submittableOnly: boolean) => {
      const parsed: ScopeEntry[] = [];
      let webAssets = 0;
      for (const e of entries) {
        const t = asRecord(e);
        const type = asString(t?.['asset_type']);
        if (!t || !type || !HACKERONE_WEB_TYPES.has(type)) continue;
        const entry = parseScopeEntry(asString(t['asset_identifier']) ?? '');
        if (!entry) continue;
        webAssets++;
        // Assets the programme has closed to submissions don't count
        // as cover, but they still prove the programme lists web assets.
        if (submittableOnly && t['eligible_for_submission'] === false) continue;
        parsed.push(entry);
      }
      return { parsed, webAssets };
    };

    const inSide = parseSide(inScopeRaw, true);
    const outSide = parseSide(outOfScopeRaw, false);
    programmes.push({
      platform: 'hackerone',
      handle,
      name: asString(rec['name']) ?? handle,
      url: asString(rec['url']),
      inScope: inSide.parsed,
      outOfScope: outSide.parsed,
      hasWebAssets: inSide.webAssets + outSide.webAssets > 0,
    });
  }
  return programmes;
}

/** Bugcrowd programme URLs look like /engagements/<handle>; the handle is the last segment. */
function bugcrowdHandle(url: string | undefined): string | undefined {
  if (!url) return undefined;
  const segments = url.split('/').filter(Boolean);
  return segments[segments.length - 1]?.toLowerCase();
}

export function normaliseBugcrowdProgrammes(raw: unknown): ScopeProgramme[] {
  if (!Array.isArray(raw)) return [];
  const programmes: ScopeProgramme[] = [];
  for (const item of raw) {
    const rec = asRecord(item);
    const url = asString(rec?.['url']);
    const handle = bugcrowdHandle(url);
    if (!rec || !handle) continue;
    const { inScopeRaw, outOfScopeRaw } = targetLists(rec);

    const parseSide = (entries: unknown[]) => {
      const parsed: ScopeEntry[] = [];
      for (const e of entries) {
        const t = asRecord(e);
        const type = asString(t?.['type']);
        if (!t || !type || !BUGCROWD_WEB_TYPES.has(type)) continue;
        const entry = parseScopeEntry(asString(t['target']) ?? '');
        if (entry) parsed.push(entry);
      }
      return parsed;
    };

    const inScope = parseSide(inScopeRaw);
    const outOfScope = parseSide(outOfScopeRaw);
    programmes.push({
      platform: 'bugcrowd',
      handle,
      name: asString(rec['name']) ?? handle,
      url,
      inScope,
      outOfScope,
      hasWebAssets: inScope.length + outOfScope.length > 0,
    });
  }
  return programmes;
}

// ---------------------------------------------------------------------------
// Cached dataset + checks
// ---------------------------------------------------------------------------

interface CacheSlot {
  programmes: ScopeProgramme[] | null;
  fetchedAt: number;
  failedAt: number;
  inflight?: Promise<ScopeProgramme[] | null>;
}

export class ScopeDataset {
  private readonly fetchImpl: ScopeFetch;
  private readonly ttlMs: number;
  private readonly failureTtlMs: number;
  private readonly now: () => number;
  private readonly slots = new Map<ScopePlatform, CacheSlot>();

  constructor(
    opts: {
      fetchImpl?: ScopeFetch;
      ttlMs?: number;
      failureTtlMs?: number;
      now?: () => number;
    } = {},
  ) {
    this.fetchImpl =
      opts.fetchImpl ?? ((url) => fetch(url) as ReturnType<ScopeFetch>);
    this.ttlMs = opts.ttlMs ?? CACHE_TTL_MS;
    this.failureTtlMs = opts.failureTtlMs ?? FAILURE_TTL_MS;
    this.now = opts.now ?? (() => Date.now());
  }

  private slot(platform: ScopePlatform): CacheSlot {
    let slot = this.slots.get(platform);
    if (!slot) {
      slot = { programmes: null, fetchedAt: 0, failedAt: 0 };
      this.slots.set(platform, slot);
    }
    return slot;
  }

  /**
   * The normalised programme list for a platform, or null when the data
   * is unavailable (fetch failed and nothing is cached).
   */
  async programmes(platform: ScopePlatform): Promise<ScopeProgramme[] | null> {
    const slot = this.slot(platform);
    const now = this.now();
    if (slot.programmes && now - slot.fetchedAt < this.ttlMs) {
      return slot.programmes;
    }
    if (!slot.programmes && slot.failedAt && now - slot.failedAt < this.failureTtlMs) {
      return null;
    }
    if (!slot.inflight) {
      slot.inflight = this.load(platform, slot).finally(() => {
        slot.inflight = undefined;
      });
    }
    return slot.inflight;
  }

  private async load(
    platform: ScopePlatform,
    slot: CacheSlot,
  ): Promise<ScopeProgramme[] | null> {
    try {
      const res = await this.fetchImpl(DATA_URLS[platform]);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const raw = await res.json();
      const programmes =
        platform === 'hackerone'
          ? normaliseHackerOneProgrammes(raw)
          : normaliseBugcrowdProgrammes(raw);
      if (programmes.length === 0) throw new Error('empty dataset');
      slot.programmes = programmes;
      slot.fetchedAt = this.now();
      slot.failedAt = 0;
      return programmes;
    } catch {
      slot.failedAt = this.now();
      // Stale data beats no data.
      return slot.programmes;
    }
  }

  /** Search programmes by handle or name. Null when no data is available at all. */
  async search(
    platform: ScopePlatform | undefined,
    query: string,
  ): Promise<ScopeProgrammeSummary[] | null> {
    const platforms: ScopePlatform[] = platform
      ? [platform]
      : ['hackerone', 'bugcrowd'];
    const q = query.trim().toLowerCase();
    const results: ScopeProgrammeSummary[] = [];
    let anyData = false;
    for (const p of platforms) {
      const programmes = await this.programmes(p);
      if (!programmes) continue;
      anyData = true;
      for (const programme of programmes) {
        if (
          !q ||
          programme.handle.includes(q) ||
          programme.name.toLowerCase().includes(q)
        ) {
          results.push({
            platform: programme.platform,
            handle: programme.handle,
            name: programme.name,
            url: programme.url,
          });
        }
      }
    }
    if (!anyData) return null;
    results.sort((a, b) => a.name.localeCompare(b.name));
    return results.slice(0, SEARCH_LIMIT);
  }

  /** Check one target against one programme's published scope. */
  async checkScope(
    platform: ScopePlatform,
    handle: string,
    target: string,
  ): Promise<ScopeCheckResult> {
    const normalisedHandle = handle.trim().toLowerCase();
    const base = {
      platform,
      handle: normalisedHandle,
      checkedAt: new Date().toISOString(),
    };
    const programmes = await this.programmes(platform);
    if (!programmes) {
      return {
        ...base,
        verdict: 'unknown',
        reason:
          'Programme scope data is unavailable just now — the check will retry shortly.',
      };
    }
    const programme = programmes.find((p) => p.handle === normalisedHandle);
    if (!programme) {
      return {
        ...base,
        verdict: 'programme_not_found',
        reason: `No ${PLATFORM_LABEL[platform]} programme found for "${normalisedHandle}".`,
      };
    }
    const match = matchProgrammeScope(programme, target);
    return {
      ...base,
      verdict: match.verdict,
      programmeName: programme.name,
      matchedEntry: match.matchedEntry,
      reason: match.reason,
    };
  }
}

/** Shared dataset for the running server (one cache per process). */
export const sharedScopeDataset = new ScopeDataset();

/**
 * Scan-creation gate: run the scope check for a scan that names a programme.
 * An out-of-scope verdict stops the scan here (403) — before credits are
 * charged. Every other verdict is returned so it can be recorded on the
 * scan as authorisation evidence. A scope verdict never authorises a scan
 * by itself; the signed authorisation statement is still required.
 */
export async function assertProgrammeScope(
  dataset: ScopeDataset,
  platform: ScopePlatform,
  handle: string,
  target: string,
): Promise<ScopeCheckResult> {
  const result = await dataset.checkScope(platform, handle, target);
  if (result.verdict === 'out_of_scope') {
    throw Object.assign(
      new Error(
        `${result.reason} The scan has not been charged — active checks don't run against targets a programme places outside its scope.`,
      ),
      { statusCode: 403 },
    );
  }
  return result;
}

/**
 * ASM source adapters: read-only bridges that list raw assets for import.
 * Adapters never probe the assets. Endpoint shapes are contract-only:
 * a mismatched response fails loudly instead of silently coercing data.
 * Credentials are never stored here.
 */
import { config as appConfig } from '../config.js';
import { assertPublicHost } from '../guardrails/scope.js';

export type RawAssetKind = 'domain' | 'subdomain' | 'ip' | 'port' | 'site' | 'endpoint';

export const RAW_ASSET_KINDS: readonly RawAssetKind[] = [
  'domain',
  'subdomain',
  'ip',
  'port',
  'site',
  'endpoint',
];

/** One asset as a source reports it, before normalisation. */
export interface RawAsset {
  kind: RawAssetKind;
  value: string;
  parent?: string;
  meta?: Record<string, string>;
}

/** A source an import can pull assets from. */
export interface AssetSourceAdapter {
  name: string;
  listAssets(input?: Record<string, unknown>): Promise<RawAsset[]>;
}

// ── Shared validation ────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertRawAssetKind(kind: unknown): asserts kind is RawAssetKind {
  if (typeof kind !== 'string' || !(RAW_ASSET_KINDS as readonly string[]).includes(kind)) {
    throw new Error(`invalid_asset_kind: ${String(kind)}`);
  }
}

/**
 * Validate one raw asset row and return a clean copy. Throws on the
 * first problem (bad kind, missing/empty value, non-string parent or
 * meta values), callers report the row, never silently drop it.
 */
export function validateRawAsset(row: unknown, where = 'asset'): RawAsset {
  if (!isRecord(row)) throw new Error(`${where}: asset must be an object`);
  assertRawAssetKind(row['kind']);
  const value = row['value'];
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${where}: asset value must be a non-empty string`);
  }
  const out: RawAsset = { kind: row['kind'], value: value.trim() };
  if (row['parent'] !== undefined) {
    if (typeof row['parent'] !== 'string' || !row['parent'].trim()) {
      throw new Error(`${where}: parent must be a non-empty string when present`);
    }
    out.parent = row['parent'].trim();
  }
  if (row['meta'] !== undefined) {
    if (!isRecord(row['meta'])) throw new Error(`${where}: meta must be an object`);
    const meta: Record<string, string> = {};
    for (const [k, v] of Object.entries(row['meta'])) {
      if (typeof v !== 'string') throw new Error(`${where}: meta.${k} must be a string`);
      meta[k] = v;
    }
    out.meta = meta;
  }
  return out;
}

/** Validate a whole list; throws on the first invalid row (index named). */
export function validateRawAssets(rows: unknown): RawAsset[] {
  if (!Array.isArray(rows)) throw new Error('assets must be an array');
  return rows.map((row, i) => validateRawAsset(row, `assets[${i}]`));
}

// ── ScopeSentry-style adapter (contract-only) ────────────────────────────

/** Per-request timeout for ScopeSentry listing calls. */
export const SCOPESENTRY_TIMEOUT_MS = 30_000;
/** Cap on one ScopeSentry response body: asset lists are small. */
export const SCOPESENTRY_MAX_BODY_BYTES = 5_000_000;

/** Read a JSON response body with a hard byte cap, streaming when possible. */
async function readCappedJson(res: Response, maxBytes: number): Promise<unknown> {
  let text: string;
  if (res.body) {
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel().catch(() => undefined);
          throw new Error(`scopesentry_response_too_large: response exceeded ${maxBytes} bytes`);
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    text = Buffer.concat(chunks).toString('utf8');
  } else {
    text = await res.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) {
      throw new Error(`scopesentry_response_too_large: response exceeded ${maxBytes} bytes`);
    }
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error('scopesentry_unexpected_response_shape: response is not JSON');
  }
}

export interface ScopeSentryAdapterConfig {
  /** Base URL of the ASM API, e.g. `https://scopesentry.example.com`. */
  baseUrl: string;
  /** API key, sent as the `X-API-Key` header. Request-scoped only. */
  apiKey: string;
  /** Project (or workspace) whose assets are listed. */
  project: string;
  /**
   * UNVERIFIED: path of the paged asset-list endpoint, relative to
   * baseUrl. The public ScopeSentry surface is an MCP server, not a
   * documented REST API, so no list path can be asserted from public
   * knowledge, the caller supplies the path their deployment serves
   * and this default is only a starting guess, never a verified fact.
   */
  listPath?: string;
  /**
   * Optional fetch implementation (tests inject a stub; production
   * uses the global fetch). The adapter never fetches the assets
   * themselves, only the ASM API.
   */
  fetchFn?: typeof fetch;
  /** Safety cap on pages followed; defaults to 50. */
  maxPages?: number;
}

export const DEFAULT_SCOPESENTRY_LIST_PATH = '/api/assets';

/**
 * Thin client over a ScopeSentry-style ASM API.
 *
 * Assumed exchange (UNVERIFIED, every piece of this paragraph is an
 * assumption, not a verified fact): `GET {baseUrl}{listPath}?project=
 * <project>&page=<n>` with header `X-API-Key: <key>` returns JSON of
 * shape `{assets: RawAsset[], nextPage?: string | null}`; `nextPage`,
 * when present, is the next page token (or full query string) and the
 * listing ends when it is absent/null. If the server answers anything
 * else, a different top-level shape, an `assets` that is not an array,
 * a row that fails validation, the adapter throws instead of coercing
 * the response into assets. A 401/403 surfaces as
 * `scopesentry_auth_failed`; any other non-2xx as
 * `scopesentry_http_<status>`.
 *
 * What is verified: only the auth header name (`X-API-Key`) and the
 * idea of a per-type paged list, both from the survey of the
 * ScopeSentry skill. Endpoint paths, query parameters, pagination
 * fields and row shapes are NOT verified against a live ScopeSentry
 * deployment, no live check was possible in this pass.
 */
export class ScopeSentryAdapter implements AssetSourceAdapter {
  readonly name = 'scopesentry';

  private readonly baseUrl: string;
  private readonly baseUrlObj: URL;
  private readonly apiKey: string;
  private readonly project: string;
  private readonly listPath: string;
  private readonly fetchFn: typeof fetch;
  private readonly maxPages: number;
  /** True when the caller did not inject a fetch: the production path, SSRF-checked. */
  private readonly usesDefaultFetch: boolean;
  /** Private targets are refused on the default fetch unless allowed in non-production. */
  private readonly allowPrivate: boolean;

  constructor(config: ScopeSentryAdapterConfig) {
    if (!config.baseUrl?.trim()) throw new Error('scopesentry_base_url_required');
    let parsed: URL;
    try {
      parsed = new URL(config.baseUrl.trim());
    } catch {
      throw new Error('scopesentry_invalid_base_url');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('scopesentry_invalid_base_url');
    }
    if (!config.apiKey?.trim()) throw new Error('scopesentry_api_key_required');
    if (!config.project?.trim()) throw new Error('scopesentry_project_required');
    this.baseUrl = parsed.toString().replace(/\/+$/, '');
    this.baseUrlObj = parsed;
    this.apiKey = config.apiKey;
    this.project = config.project;
    this.listPath = config.listPath ?? DEFAULT_SCOPESENTRY_LIST_PATH;
    this.fetchFn = config.fetchFn ?? fetch;
    this.maxPages = config.maxPages ?? 50;
    this.usesDefaultFetch = !config.fetchFn;
    this.allowPrivate = appConfig.nodeEnv !== 'production' && appConfig.allowPrivateTargets;
  }

  async listAssets(input?: Record<string, unknown>): Promise<RawAsset[]> {
    const project = typeof input?.['project'] === 'string' && input['project'].trim()
      ? (input['project'] as string)
      : this.project;
    // The base host is caller-supplied: refuse private targets before
    // the API key goes anywhere. An injected fetch owns its transport
    // (tests), so the check runs on the default fetch only.
    if (this.usesDefaultFetch) {
      await assertPublicHost(this.baseUrlObj.hostname, this.allowPrivate);
    }
    const out: RawAsset[] = [];
    // UNVERIFIED: pagination is assumed to be a `page` query param
    // plus a `nextPage` token in the response (see class comment).
    let page = '1';
    for (let n = 0; n < this.maxPages; n++) {
      const url =
        `${this.baseUrl}${this.listPath}` +
        `?project=${encodeURIComponent(project)}&page=${encodeURIComponent(page)}`;
      let res: Response;
      try {
        res = await this.fetchFn(url, {
          headers: { 'X-API-Key': this.apiKey },
          signal: AbortSignal.timeout(SCOPESENTRY_TIMEOUT_MS),
        });
      } catch (err) {
        throw new Error(`scopesentry_request_failed: ${(err as Error).message}`);
      }
      if (res.status === 401 || res.status === 403) {
        throw new Error('scopesentry_auth_failed');
      }
      if (!res.ok) throw new Error(`scopesentry_http_${res.status}`);
      const body = await readCappedJson(res, SCOPESENTRY_MAX_BODY_BYTES);
      // The response shape is asserted, never coerced: anything that
      // is not `{assets: [...]}` is a hard failure.
      if (!isRecord(body) || !Array.isArray(body['assets'])) {
        throw new Error(
          'scopesentry_unexpected_response_shape: expected {assets: [...]}',
        );
      }
      const rows = body['assets'].map((row, i) => {
        try {
          return validateRawAsset(row, `scopesentry assets[${i}]`);
        } catch (err) {
          throw new Error(`scopesentry_invalid_asset_row: ${(err as Error).message}`);
        }
      });
      out.push(...rows);
      const next = body['nextPage'];
      if (next == null || next === '') break;
      if (typeof next !== 'string') {
        throw new Error('scopesentry_unexpected_response_shape: nextPage must be a string');
      }
      page = next;
    }
    return out;
  }
}

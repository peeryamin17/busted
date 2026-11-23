/**
 * Per-user web-search settings: one row per user, the default provider.
 * A setting, not a credential, so it never lives in user_secrets.
 * 'deepseek' is rejected as a default. No row means 'duckduckgo'.
 */
import type { SearchProviderName } from './providers.js';
import { DEFAULT_SEARCH_PROVIDER, canSearch, isSearchProviderName } from './providers.js';

/** One user's search default. */
export interface SearchSettings {
  userId: string;
  provider: SearchProviderName;
  updatedAt: string; // ISO
}

export interface SearchSettingsStore {
  get(userId: string): Promise<SearchSettings | null>;
  /** Upserts the default provider. Throws on an unknown or non-search provider. */
  set(userId: string, provider: SearchProviderName): Promise<SearchSettings>;
}

const nowIso = () => new Date().toISOString();

export function assertSearchableProvider(provider: string): asserts provider is SearchProviderName {
  if (!isSearchProviderName(provider)) {
    throw new Error(`unknown_search_provider: ${provider}`);
  }
  if (!canSearch(provider)) {
    throw new Error(
      'search_provider_not_supported: deepseek — DeepSeek offers no web-search API, so it cannot be the default search provider.',
    );
  }
}

export class MemorySearchSettingsStore implements SearchSettingsStore {
  private settings = new Map<string, SearchSettings>();

  async get(userId: string): Promise<SearchSettings | null> {
    const found = this.settings.get(userId);
    return found ? { ...found } : null;
  }

  async set(userId: string, provider: SearchProviderName): Promise<SearchSettings> {
    assertSearchableProvider(provider);
    const rec: SearchSettings = { userId, provider, updatedAt: nowIso() };
    this.settings.set(userId, rec);
    return { ...rec };
  }
}

export type SearchSettingsQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[]; rowCount?: number | null }>;

/** pg returns timestamptz as Date; a stubbed query may hand back ISO strings. */
function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export class PostgresSearchSettingsStore implements SearchSettingsStore {
  constructor(private readonly query: SearchSettingsQueryFn) {}

  private toRecord(row: Record<string, unknown>): SearchSettings {
    return {
      userId: row['user_id'] as string,
      provider: row['provider'] as SearchProviderName,
      updatedAt: toIso(row['updated_at']),
    };
  }

  async get(userId: string): Promise<SearchSettings | null> {
    const { rows } = await this.query(
      `SELECT user_id, provider, updated_at FROM search_settings WHERE user_id = $1`,
      [userId],
    );
    return rows[0] ? this.toRecord(rows[0]) : null;
  }

  async set(userId: string, provider: SearchProviderName): Promise<SearchSettings> {
    assertSearchableProvider(provider);
    const { rows } = await this.query(
      `INSERT INTO search_settings (user_id, provider)
       VALUES ($1, $2)
       ON CONFLICT (user_id)
       DO UPDATE SET provider = EXCLUDED.provider, updated_at = now()
       RETURNING user_id, provider, updated_at`,
      [userId, provider],
    );
    return this.toRecord(rows[0]);
  }
}

/** The effective default provider for a user: stored setting, else 'duckduckgo'. */
export async function resolveDefaultProvider(
  store: SearchSettingsStore,
  userId: string,
): Promise<SearchProviderName> {
  const saved = await store.get(userId).catch(() => null);
  return saved?.provider ?? DEFAULT_SEARCH_PROVIDER;
}

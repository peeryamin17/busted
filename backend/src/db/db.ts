import { randomUUID } from 'node:crypto';
import type {
  ApiKeyRecord,
  AuthorizationRecord,
  AuthzType,
  Finding,
  PairingCodeRecord,
  PlanTier,
  Scan,
  ScanStatus,
  SessionRecord,
  UserRecord,
} from '../types.js';
import type { RequesterOrigin, WebCheckRecord, WebFinding, WebInfo } from '../webcheck/types.js';

export interface CreateScanInput {
  userId: string;
  targetUrl: string;
  mode: 'passive' | 'active';
  scope: Scan['scope'];
  authorizationId?: string;
  techStack?: Scan['techStack'];
}

export interface CreateAuthorizationInput {
  userId: string;
  type: AuthzType;
  programName?: string;
  referenceUrl?: string;
  statement: string;
}

export interface ScanPatch {
  status?: ScanStatus;
  techStack?: Scan['techStack'];
  progress?: Scan['progress'];
  error?: string;
  startedAt?: string;
  finishedAt?: string;
}

export interface InsertWebCheckInput {
  userId: string;
  url: string;
  host: string;
  authorized: boolean;
  score: number | null;
  grade: string | null;
  findings: WebFinding[];
  info: WebInfo;
  requesterIp?: string | null;
  requesterGeo?: RequesterOrigin | null;
}

/**
 * Persistence abstraction. `MemoryDatabase` is the default so `npm run dev`
 * works with zero infrastructure; `PostgresDatabase` (Supabase-compatible
 * PostgreSQL) is used when DATABASE_URL is set. Both obey the same contract.
 */
export interface Database {
  readonly kind: 'memory' | 'postgres';

  createUser(email: string, passwordHash: string): Promise<UserRecord>;
  getUserByGoogleSub(googleSub: string): Promise<UserRecord | null>;
  /**
   * Google sign-in upsert: find by Google subject id, else by email
   * (linking the Google id onto that account), else create the user.
   * Refreshes profile fields and stamps lastLoginAt. Returns the user.
   */
  recordGoogleLogin(profile: {
    googleSub: string;
    email: string;
    name?: string;
    avatarUrl?: string;
  }): Promise<UserRecord>;
  listUsers(limit: number): Promise<UserRecord[]>;
  getUserByEmail(email: string): Promise<UserRecord | null>;
  getUserById(id: string): Promise<UserRecord | null>;
  setUserPlan(userId: string, plan: PlanTier): Promise<void>;

  /** Create a website session; only the token's SHA-256 hash is passed in/stored. */
  createSession(userId: string, tokenHash: string, expiresAtIso: string): Promise<SessionRecord>;
  /** Look up a live session by token hash; expired rows are deleted and read as null. */
  getSessionByTokenHash(tokenHash: string): Promise<SessionRecord | null>;
  /** Session + its user in one lookup (the per-request auth path). */
  getSessionWithUser(
    tokenHash: string,
  ): Promise<{ session: SessionRecord; user: UserRecord } | null>;
  deleteSession(tokenHash: string): Promise<void>;
  /** Stamp a session as used just now (the inactivity clock's reset). */
  touchSession(tokenHash: string): Promise<void>;
  /** One active session per account: drop a user's other sessions. */
  deleteOtherSessions(userId: string, keepTokenHash: string): Promise<void>;
  /** Sweep rows whose absolute expiry has passed. */
  pruneExpiredSessions(): Promise<void>;

  createApiKey(
    userId: string,
    name: string,
    keyHash: string,
    keyPrefix: string
  ): Promise<ApiKeyRecord>;
  listApiKeys(userId: string): Promise<ApiKeyRecord[]>;
  getApiKeyByHash(keyHash: string): Promise<ApiKeyRecord | null>;
  touchApiKey(id: string): Promise<void>;
  revokeApiKey(id: string, userId: string): Promise<boolean>;

  createPairingCode(
    userId: string,
    codeHash: string,
    expiresAtIso: string
  ): Promise<PairingCodeRecord>;
  getPairingCodeByHash(codeHash: string): Promise<PairingCodeRecord | null>;
  /** Mark a link code used; false when it was already used (single-use race guard). */
  markPairingCodeUsed(id: string): Promise<boolean>;
  /** Drop a user's unused link codes (a fresh mint supersedes them). */
  deleteUnusedPairingCodes(userId: string): Promise<void>;

  createAuthorization(input: CreateAuthorizationInput): Promise<AuthorizationRecord>;
  getAuthorization(id: string): Promise<AuthorizationRecord | null>;

  createScan(input: CreateScanInput): Promise<Scan>;
  updateScan(id: string, patch: ScanPatch): Promise<Scan | null>;
  getScan(id: string): Promise<Scan | null>;
  listScans(userId: string, limit: number, offset: number): Promise<{ scans: Scan[]; total: number }>;

  addFinding(f: Omit<Finding, 'id' | 'createdAt'>): Promise<Finding>;
  /** Insert many findings for one scan in a single round trip. */
  addFindings(items: Array<Omit<Finding, 'id' | 'createdAt'>>): Promise<Finding[]>;
  listFindings(scanId: string): Promise<Finding[]>;

  recordUsage(userId: string, kind: string, quantity: number, scanId?: string): Promise<void>;
  countScansSince(userId: string, sinceIso: string): Promise<number>;
  sumUsageSince(userId: string, kind: string, sinceIso: string): Promise<number>;

  /** Add an email to the launch waitlist; `already` is true when it was on the list already. */
  addWaitlistEmail(email: string, source?: string): Promise<{ already: boolean }>;

  /** Store a completed web-demo patrol (full, ungated result). */
  insertWebCheck(input: InsertWebCheckInput): Promise<WebCheckRecord>;
  /** A user's patrol runs, newest first. */
  listWebChecks(userId: string, limit: number): Promise<WebCheckRecord[]>;
  /** One patrol run, only when it belongs to the user. */
  getWebCheck(userId: string, id: string): Promise<WebCheckRecord | null>;
  /** How many patrols a user has stored (quota counting — never fetch rows to count). */
  countWebChecks(userId: string): Promise<number>;
  /** History rows plus the user's total run count, in one query. */
  listWebCheckSummariesCounted(
    userId: string,
    limit: number,
  ): Promise<{ runs: WebCheckSummary[]; total: number }>;
  /**
   * History-list rows WITHOUT the heavy columns: scalar fields, the
   * finding count and the trust verdict, so listing a vault never
   * drags the full findings/info JSON out of the database.
   */
  listWebCheckSummaries(userId: string, limit: number): Promise<WebCheckSummary[]>;

  close(): Promise<void>;
}

/** One history-list row (see listWebCheckSummaries). */
export interface WebCheckSummary {
  id: string;
  url: string;
  host: string;
  score: number | null;
  grade: string | null;
  findingCount: number;
  trustVerdict: string | null;
  requesterIp: string | null;
  requesterGeo: RequesterOrigin | null;
  createdAt: string;
}

const nowIso = () => new Date().toISOString();

export class MemoryDatabase implements Database {
  readonly kind = 'memory' as const;
  private users = new Map<string, UserRecord>();
  private usersByEmail = new Map<string, UserRecord>();
  private usersByGoogleSub = new Map<string, UserRecord>();
  private sessions = new Map<string, SessionRecord>(); // by token hash
  private apiKeys = new Map<string, ApiKeyRecord>();
  private apiKeysByHash = new Map<string, ApiKeyRecord>();
  private pairingCodes = new Map<string, PairingCodeRecord>();
  private pairingCodesByHash = new Map<string, PairingCodeRecord>();
  private authorizations = new Map<string, AuthorizationRecord>();
  private scans = new Map<string, Scan>();
  private findings = new Map<string, Finding[]>();
  private usage: Array<{ userId: string; kind: string; quantity: number; scanId?: string; at: string }> = [];
  private waitlist = new Set<string>(); // normalised emails
  private webChecks: WebCheckRecord[] = [];

  async createUser(email: string, passwordHash: string): Promise<UserRecord> {
    const normalized = email.trim().toLowerCase();
    if (this.usersByEmail.has(normalized)) throw new Error('email_taken');
    const user: UserRecord = {
      id: randomUUID(),
      email: normalized,
      passwordHash,
      plan: 'free',
      createdAt: nowIso(),
    };
    this.users.set(user.id, user);
    this.usersByEmail.set(normalized, user);
    return { ...user };
  }

  async getUserByEmail(email: string): Promise<UserRecord | null> {
    return this.usersByEmail.get(email.trim().toLowerCase()) ?? null;
  }

  async getUserByGoogleSub(googleSub: string): Promise<UserRecord | null> {
    const u = this.usersByGoogleSub.get(googleSub);
    return u ? { ...u } : null;
  }

  async recordGoogleLogin(profile: {
    googleSub: string;
    email: string;
    name?: string;
    avatarUrl?: string;
  }): Promise<UserRecord> {
    let user = this.usersByGoogleSub.get(profile.googleSub) ?? null;
    if (!user) {
      const byEmail = this.usersByEmail.get(profile.email.trim().toLowerCase()) ?? null;
      if (byEmail) {
        byEmail.googleSub = profile.googleSub;
        this.usersByGoogleSub.set(profile.googleSub, byEmail);
        user = byEmail;
      }
    }
    if (!user) {
      const created = await this.createUser(profile.email, '');
      const stored = this.users.get(created.id);
      if (!stored) return created;
      stored.googleSub = profile.googleSub;
      this.usersByGoogleSub.set(profile.googleSub, stored);
      user = stored;
    }
    if (profile.name !== undefined) user.name = profile.name;
    if (profile.avatarUrl !== undefined) user.avatarUrl = profile.avatarUrl;
    user.lastLoginAt = nowIso();
    return { ...user };
  }

  async createSession(userId: string, tokenHash: string, expiresAtIso: string): Promise<SessionRecord> {
    const rec: SessionRecord = {
      id: randomUUID(),
      userId,
      tokenHash,
      createdAt: nowIso(),
      expiresAt: expiresAtIso,
      lastSeenAt: nowIso(),
    };
    this.sessions.set(tokenHash, rec);
    return { ...rec };
  }

  async getSessionByTokenHash(tokenHash: string): Promise<SessionRecord | null> {
    const rec = this.sessions.get(tokenHash);
    if (!rec) return null;
    if (rec.expiresAt <= nowIso()) {
      this.sessions.delete(tokenHash);
      return null;
    }
    return { ...rec };
  }

  async getSessionWithUser(
    tokenHash: string,
  ): Promise<{ session: SessionRecord; user: UserRecord } | null> {
    const session = await this.getSessionByTokenHash(tokenHash);
    if (!session) return null;
    const user = this.users.get(session.userId);
    return user ? { session, user: { ...user } } : null;
  }

  async deleteSession(tokenHash: string): Promise<void> {
    this.sessions.delete(tokenHash);
  }

  async touchSession(tokenHash: string): Promise<void> {
    const rec = this.sessions.get(tokenHash);
    if (!rec) return;
    // The stamp exists to spot five idle minutes; writing it on every
    // request is waste. Once a minute is fresh enough.
    if (Date.now() - Date.parse(rec.lastSeenAt) < 60_000) return;
    rec.lastSeenAt = nowIso();
  }

  async deleteOtherSessions(userId: string, keepTokenHash: string): Promise<void> {
    for (const [hash, rec] of this.sessions) {
      if (rec.userId === userId && hash !== keepTokenHash) this.sessions.delete(hash);
    }
  }

  async pruneExpiredSessions(): Promise<void> {
    const now = nowIso();
    for (const [hash, rec] of this.sessions) {
      if (rec.expiresAt <= now) this.sessions.delete(hash);
    }
  }

  async listUsers(limit: number): Promise<UserRecord[]> {
    return [...this.users.values()]
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, Math.max(1, Math.min(1000, limit)))
      .map((u) => ({ ...u }));
  }

  async getUserById(id: string): Promise<UserRecord | null> {
    return this.users.get(id) ?? null;
  }

  async setUserPlan(userId: string, plan: PlanTier): Promise<void> {
    const u = this.users.get(userId);
    if (u) u.plan = plan;
  }

  async createApiKey(
    userId: string,
    name: string,
    keyHash: string,
    keyPrefix: string
  ): Promise<ApiKeyRecord> {
    const rec: ApiKeyRecord = {
      id: randomUUID(),
      userId,
      name,
      keyHash,
      keyPrefix,
      createdAt: nowIso(),
    };
    this.apiKeys.set(rec.id, rec);
    this.apiKeysByHash.set(keyHash, rec);
    return { ...rec };
  }

  async listApiKeys(userId: string): Promise<ApiKeyRecord[]> {
    return [...this.apiKeys.values()].filter((k) => k.userId === userId).map((k) => ({ ...k }));
  }

  async getApiKeyByHash(keyHash: string): Promise<ApiKeyRecord | null> {
    return this.apiKeysByHash.get(keyHash) ?? null;
  }

  async touchApiKey(id: string): Promise<void> {
    const k = this.apiKeys.get(id);
    if (k) k.lastUsedAt = nowIso();
  }

  async revokeApiKey(id: string, userId: string): Promise<boolean> {
    const k = this.apiKeys.get(id);
    if (!k || k.userId !== userId || k.revokedAt) return false;
    k.revokedAt = nowIso();
    return true;
  }

  async createPairingCode(
    userId: string,
    codeHash: string,
    expiresAtIso: string
  ): Promise<PairingCodeRecord> {
    const rec: PairingCodeRecord = {
      id: randomUUID(),
      userId,
      codeHash,
      createdAt: nowIso(),
      expiresAt: expiresAtIso,
    };
    this.pairingCodes.set(rec.id, rec);
    this.pairingCodesByHash.set(codeHash, rec);
    return { ...rec };
  }

  async getPairingCodeByHash(codeHash: string): Promise<PairingCodeRecord | null> {
    return this.pairingCodesByHash.get(codeHash) ?? null;
  }

  async markPairingCodeUsed(id: string): Promise<boolean> {
    const rec = this.pairingCodes.get(id);
    if (!rec || rec.usedAt) return false;
    rec.usedAt = nowIso();
    return true;
  }

  async deleteUnusedPairingCodes(userId: string): Promise<void> {
    for (const rec of [...this.pairingCodes.values()]) {
      if (rec.userId === userId && !rec.usedAt) {
        this.pairingCodes.delete(rec.id);
        this.pairingCodesByHash.delete(rec.codeHash);
      }
    }
  }

  async createAuthorization(input: CreateAuthorizationInput): Promise<AuthorizationRecord> {
    const rec: AuthorizationRecord = {
      id: randomUUID(),
      confirmedAt: nowIso(),
      ...input,
    };
    this.authorizations.set(rec.id, rec);
    return { ...rec };
  }

  async getAuthorization(id: string): Promise<AuthorizationRecord | null> {
    return this.authorizations.get(id) ?? null;
  }

  async createScan(input: CreateScanInput): Promise<Scan> {
    const scan: Scan = {
      id: randomUUID(),
      userId: input.userId,
      targetUrl: input.targetUrl,
      mode: input.mode,
      status: 'queued',
      scope: input.scope,
      authorizationId: input.authorizationId,
      techStack: input.techStack ?? [],
      progress: { completedSteps: 0, totalSteps: 0 },
      createdAt: nowIso(),
    };
    this.scans.set(scan.id, scan);
    this.findings.set(scan.id, []);
    return { ...scan };
  }

  async updateScan(id: string, patch: ScanPatch): Promise<Scan | null> {
    const s = this.scans.get(id);
    if (!s) return null;
    Object.assign(s, patch);
    return { ...s };
  }

  async getScan(id: string): Promise<Scan | null> {
    const s = this.scans.get(id);
    return s ? { ...s } : null;
  }

  async listScans(
    userId: string,
    limit: number,
    offset: number
  ): Promise<{ scans: Scan[]; total: number }> {
    const all = [...this.scans.values()]
      .filter((s) => s.userId === userId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    return {
      scans: all.slice(offset, offset + limit).map((s) => ({ ...s })),
      total: all.length,
    };
  }

  async addFinding(f: Omit<Finding, 'id' | 'createdAt'>): Promise<Finding> {
    const rec: Finding = { ...f, id: randomUUID(), createdAt: nowIso() };
    const list = this.findings.get(f.scanId);
    if (!list) throw new Error('scan_not_found');
    list.push(rec);
    return { ...rec };
  }

  async addFindings(items: Array<Omit<Finding, 'id' | 'createdAt'>>): Promise<Finding[]> {
    const out: Finding[] = [];
    for (const f of items) out.push(await this.addFinding(f));
    return out;
  }

  async listFindings(scanId: string): Promise<Finding[]> {
    return (this.findings.get(scanId) ?? []).map((f) => ({ ...f }));
  }

  async recordUsage(userId: string, kind: string, quantity: number, scanId?: string): Promise<void> {
    this.usage.push({ userId, kind, quantity, scanId, at: nowIso() });
  }

  async countScansSince(userId: string, sinceIso: string): Promise<number> {
    return this.usage.filter(
      (u) => u.userId === userId && u.kind === 'scan' && u.at >= sinceIso
    ).length;
  }

  async sumUsageSince(userId: string, kind: string, sinceIso: string): Promise<number> {
    return this.usage
      .filter((u) => u.userId === userId && u.kind === kind && u.at >= sinceIso)
      .reduce((sum, u) => sum + u.quantity, 0);
  }

  async addWaitlistEmail(email: string): Promise<{ already: boolean }> {
    const normalized = email.trim().toLowerCase();
    if (this.waitlist.has(normalized)) return { already: true };
    this.waitlist.add(normalized);
    return { already: false };
  }

  async insertWebCheck(input: InsertWebCheckInput): Promise<WebCheckRecord> {
    const rec: WebCheckRecord = {
      id: randomUUID(),
      createdAt: nowIso(),
      ...input,
      findings: input.findings.map((f) => ({ ...f })),
      info: structuredClone(input.info),
      requesterIp: input.requesterIp ?? null,
      requesterGeo: input.requesterGeo ? structuredClone(input.requesterGeo) : null,
    };
    this.webChecks.push(rec);
    return { ...rec };
  }

  async listWebChecks(userId: string, limit: number): Promise<WebCheckRecord[]> {
    return this.webChecks
      .filter((r) => r.userId === userId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .slice(0, Math.max(1, limit))
      .map((r) => ({ ...r }));
  }

  async getWebCheck(userId: string, id: string): Promise<WebCheckRecord | null> {
    const rec = this.webChecks.find((r) => r.userId === userId && r.id === id);
    return rec ? { ...rec } : null;
  }

  async countWebChecks(userId: string): Promise<number> {
    return this.webChecks.reduce((n, r) => (r.userId === userId ? n + 1 : n), 0);
  }

  async listWebCheckSummaries(userId: string, limit: number): Promise<WebCheckSummary[]> {
    return this.webChecks
      .filter((r) => r.userId === userId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .slice(0, Math.max(1, limit))
      .map((r) => ({
        id: r.id,
        url: r.url,
        host: r.host,
        score: r.score,
        grade: r.grade,
        findingCount: r.findings.length,
        trustVerdict: r.info.trust?.verdict ?? null,
        requesterIp: r.requesterIp,
        requesterGeo: r.requesterGeo,
        createdAt: r.createdAt,
      }));
  }

  async listWebCheckSummariesCounted(
    userId: string,
    limit: number,
  ): Promise<{ runs: WebCheckSummary[]; total: number }> {
    const runs = await this.listWebCheckSummaries(userId, limit);
    return { runs, total: await this.countWebChecks(userId) };
  }

  async close(): Promise<void> {
    // nothing to release
  }
}

/**
 * PostgreSQL implementation (Supabase-compatible). `pg` is imported lazily
 * so the backend still boots without the dependency installed when DATABASE_URL
 * is unset (memory mode).
 */
export class PostgresDatabase implements Database {
  readonly kind = 'postgres' as const;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private pool: any;

  private constructor(pool: unknown) {
    this.pool = pool;
  }

  static async connect(databaseUrl: string): Promise<PostgresDatabase> {
    const { Pool } = await import('pg');
    const pool = new Pool({
      connectionString: databaseUrl,
      max: 10,
      // Keep a warm connection instead of paying Neon's cold-start on
      // every quiet spell, and never let one stuck query hold a
      // connection (or a request) hostage.
      idleTimeoutMillis: 300_000,
      connectionTimeoutMillis: 10_000,
      statement_timeout: 10_000,
      query_timeout: 10_000,
    });
    await pool.query('SELECT 1');
    return new PostgresDatabase(pool);
  }

  private toScan(row: Record<string, unknown>): Scan {
    return {
      id: row['id'] as string,
      userId: row['user_id'] as string,
      targetUrl: row['target_url'] as string,
      mode: row['mode'] as Scan['mode'],
      status: row['status'] as Scan['status'],
      scope: row['scope'] as Scan['scope'],
      authorizationId: (row['authorization_id'] as string) ?? undefined,
      techStack: (row['tech_stack'] as Scan['techStack']) ?? [],
      progress: row['progress'] as Scan['progress'],
      error: (row['error'] as string) ?? undefined,
      createdAt: (row['created_at'] as Date).toISOString(),
      startedAt: row['started_at'] ? (row['started_at'] as Date).toISOString() : undefined,
      finishedAt: row['finished_at'] ? (row['finished_at'] as Date).toISOString() : undefined,
    };
  }

  private toFinding(row: Record<string, unknown>): Finding {
    return {
      id: row['id'] as string,
      scanId: row['scan_id'] as string,
      category: row['category'] as string,
      title: row['title'] as string,
      description: row['description'] as string,
      severity: row['severity'] as Finding['severity'],
      cvssScore: row['cvss_score'] != null ? Number(row['cvss_score']) : undefined,
      cvssVector: (row['cvss_vector'] as string) ?? undefined,
      confidence: row['confidence'] as Finding['confidence'],
      trapProbability: Number(row['trap_probability'] ?? 0),
      honeypotSuspect: Boolean(row['honeypot_suspect']),
      location: (row['location'] as string) ?? undefined,
      evidence: (row['evidence'] as string) ?? undefined,
      reproSteps: (row['repro_steps'] as string[]) ?? [],
      remediation: (row['remediation'] as string) ?? '',
      references: (row['references'] as string[]) ?? [],
      createdAt: (row['created_at'] as Date).toISOString(),
    };
  }

  private toUser(row: Record<string, unknown>): UserRecord {
    return {
      id: row['id'] as string,
      email: row['email'] as string,
      passwordHash: row['password_hash'] as string,
      plan: row['plan'] as UserRecord['plan'],
      createdAt: (row['created_at'] as Date).toISOString(),
      googleSub: (row['google_sub'] as string) ?? undefined,
      name: (row['name'] as string) ?? undefined,
      avatarUrl: (row['avatar_url'] as string) ?? undefined,
      lastLoginAt: row['last_login_at'] ? (row['last_login_at'] as Date).toISOString() : undefined,
    };
  }

  private toSession(row: Record<string, unknown>): SessionRecord {
    return {
      id: row['id'] as string,
      userId: row['user_id'] as string,
      tokenHash: row['token_hash'] as string,
      createdAt: (row['created_at'] as Date).toISOString(),
      expiresAt: (row['expires_at'] as Date).toISOString(),
      lastSeenAt: row['last_seen_at']
        ? (row['last_seen_at'] as Date).toISOString()
        : (row['created_at'] as Date).toISOString(),
    };
  }

  async createUser(email: string, passwordHash: string): Promise<UserRecord> {
    const normalized = email.trim().toLowerCase();
    try {
      const { rows } = await this.pool.query(
        `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *`,
        [normalized, passwordHash]
      );
      return this.toUser(rows[0]);
    } catch (e: unknown) {
      if (e && typeof e === 'object' && (e as { code?: string }).code === '23505') {
        throw new Error('email_taken');
      }
      throw e;
    }
  }

  async getUserByEmail(email: string): Promise<UserRecord | null> {
    const { rows } = await this.pool.query(`SELECT * FROM users WHERE email = $1`, [
      email.trim().toLowerCase(),
    ]);
    return rows[0] ? this.toUser(rows[0]) : null;
  }

  async getUserById(id: string): Promise<UserRecord | null> {
    const { rows } = await this.pool.query(`SELECT * FROM users WHERE id = $1`, [id]);
    return rows[0] ? this.toUser(rows[0]) : null;
  }

  async getUserByGoogleSub(googleSub: string): Promise<UserRecord | null> {
    const { rows } = await this.pool.query(`SELECT * FROM users WHERE google_sub = $1`, [googleSub]);
    return rows[0] ? this.toUser(rows[0]) : null;
  }

  async recordGoogleLogin(profile: {
    googleSub: string;
    email: string;
    name?: string;
    avatarUrl?: string;
  }): Promise<UserRecord> {
    let user = await this.getUserByGoogleSub(profile.googleSub);
    if (!user) {
      user = await this.getUserByEmail(profile.email);
      if (user) {
        // Link the Google identity onto the existing account.
        await this.pool.query(`UPDATE users SET google_sub = $2 WHERE id = $1`, [
          user.id,
          profile.googleSub,
        ]);
      }
    }
    if (!user) {
      try {
        const { rows } = await this.pool.query(
          `INSERT INTO users (email, password_hash, google_sub, name, avatar_url)
           VALUES ($1, '', $2, $3, $4) RETURNING *`,
          [profile.email.trim().toLowerCase(), profile.googleSub, profile.name ?? null, profile.avatarUrl ?? null],
        );
        user = this.toUser(rows[0]);
      } catch (e: unknown) {
        // Lost a race with a concurrent first sign-in: re-read by Google id.
        if (e && typeof e === 'object' && (e as { code?: string }).code === '23505') {
          user = (await this.getUserByGoogleSub(profile.googleSub)) ?? (await this.getUserByEmail(profile.email));
          if (!user) throw e;
        } else {
          throw e;
        }
      }
    }
    await this.pool.query(
      `UPDATE users SET name = COALESCE($2, name), avatar_url = COALESCE($3, avatar_url),
         last_login_at = now() WHERE id = $1`,
      [user.id, profile.name ?? null, profile.avatarUrl ?? null],
    );
    return (await this.getUserById(user.id)) ?? user;
  }

  async createSession(userId: string, tokenHash: string, expiresAtIso: string): Promise<SessionRecord> {
    const { rows } = await this.pool.query(
      `INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3::timestamptz) RETURNING *`,
      [userId, tokenHash, expiresAtIso],
    );
    return this.toSession(rows[0]);
  }

  async getSessionByTokenHash(tokenHash: string): Promise<SessionRecord | null> {
    const { rows } = await this.pool.query(`SELECT * FROM sessions WHERE token_hash = $1`, [tokenHash]);
    if (!rows[0]) return null;
    const rec = this.toSession(rows[0]);
    if (rec.expiresAt <= new Date().toISOString()) {
      await this.deleteSession(tokenHash);
      return null;
    }
    return rec;
  }

  async getSessionWithUser(
    tokenHash: string,
  ): Promise<{ session: SessionRecord; user: UserRecord } | null> {
    const { rows } = await this.pool.query(
      `SELECT u.*,
              s.id AS session_id,
              s.user_id AS session_user_id,
              s.token_hash AS session_token_hash,
              s.created_at AS session_created_at,
              s.expires_at AS session_expires_at,
              s.last_seen_at AS session_last_seen_at
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1`,
      [tokenHash],
    );
    const row = rows[0];
    if (!row) return null;
    const session: SessionRecord = {
      id: row['session_id'] as string,
      userId: row['session_user_id'] as string,
      tokenHash: row['session_token_hash'] as string,
      createdAt: (row['session_created_at'] as Date).toISOString(),
      expiresAt: (row['session_expires_at'] as Date).toISOString(),
      lastSeenAt: row['session_last_seen_at']
        ? (row['session_last_seen_at'] as Date).toISOString()
        : (row['session_created_at'] as Date).toISOString(),
    };
    if (session.expiresAt <= new Date().toISOString()) {
      await this.deleteSession(tokenHash);
      return null;
    }
    return { session, user: this.toUser(row) };
  }

  async deleteSession(tokenHash: string): Promise<void> {
    await this.pool.query(`DELETE FROM sessions WHERE token_hash = $1`, [tokenHash]);
  }

  async touchSession(tokenHash: string): Promise<void> {
    // Stamp at most once a minute: the clock only needs to spot five
    // idle minutes, and an UPDATE per request is a write tax on reads.
    await this.pool.query(
      `UPDATE sessions SET last_seen_at = now()
       WHERE token_hash = $1 AND last_seen_at < now() - interval '1 minute'`,
      [tokenHash],
    );
  }

  async deleteOtherSessions(userId: string, keepTokenHash: string): Promise<void> {
    await this.pool.query(
      `DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2`,
      [userId, keepTokenHash],
    );
  }

  async pruneExpiredSessions(): Promise<void> {
    await this.pool.query(`DELETE FROM sessions WHERE expires_at <= now()`);
  }

  async listUsers(limit: number): Promise<UserRecord[]> {
    const { rows } = await this.pool.query(`SELECT * FROM users ORDER BY created_at DESC LIMIT $1`, [
      Math.max(1, Math.min(1000, limit)),
    ]);
    return rows.map((row: Record<string, unknown>) => this.toUser(row));
  }

  async setUserPlan(userId: string, plan: PlanTier): Promise<void> {
    await this.pool.query(`UPDATE users SET plan = $2 WHERE id = $1`, [userId, plan]);
  }

  async createApiKey(
    userId: string,
    name: string,
    keyHash: string,
    keyPrefix: string
  ): Promise<ApiKeyRecord> {
    const { rows } = await this.pool.query(
      `INSERT INTO api_keys (user_id, name, key_hash, key_prefix)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [userId, name, keyHash, keyPrefix]
    );
    const r = rows[0];
    return {
      id: r.id,
      userId: r.user_id,
      name: r.name,
      keyHash: r.key_hash,
      keyPrefix: r.key_prefix,
      createdAt: r.created_at.toISOString(),
      lastUsedAt: r.last_used_at?.toISOString(),
      revokedAt: r.revoked_at?.toISOString(),
    };
  }

  async listApiKeys(userId: string): Promise<ApiKeyRecord[]> {
    const { rows } = await this.pool.query(
      `SELECT * FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId]
    );
    return rows.map((r: Record<string, unknown>) => ({
      id: r['id'] as string,
      userId: r['user_id'] as string,
      name: r['name'] as string,
      keyHash: '***',
      keyPrefix: r['key_prefix'] as string,
      createdAt: (r['created_at'] as Date).toISOString(),
      lastUsedAt: r['last_used_at'] ? (r['last_used_at'] as Date).toISOString() : undefined,
      revokedAt: r['revoked_at'] ? (r['revoked_at'] as Date).toISOString() : undefined,
    }));
  }

  async getApiKeyByHash(keyHash: string): Promise<ApiKeyRecord | null> {
    const { rows } = await this.pool.query(`SELECT * FROM api_keys WHERE key_hash = $1`, [keyHash]);
    if (!rows[0]) return null;
    const r = rows[0];
    return {
      id: r.id,
      userId: r.user_id,
      name: r.name,
      keyHash: r.key_hash,
      keyPrefix: r.key_prefix,
      createdAt: r.created_at.toISOString(),
      lastUsedAt: r.last_used_at?.toISOString(),
      revokedAt: r.revoked_at?.toISOString(),
    };
  }

  async touchApiKey(id: string): Promise<void> {
    await this.pool.query(`UPDATE api_keys SET last_used_at = now() WHERE id = $1`, [id]);
  }

  async revokeApiKey(id: string, userId: string): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
      [id, userId]
    );
    return (rowCount ?? 0) > 0;
  }

  async createPairingCode(
    userId: string,
    codeHash: string,
    expiresAtIso: string
  ): Promise<PairingCodeRecord> {
    const { rows } = await this.pool.query(
      `INSERT INTO pairing_codes (user_id, code_hash, expires_at)
       VALUES ($1, $2, $3) RETURNING *`,
      [userId, codeHash, expiresAtIso]
    );
    const r = rows[0];
    return {
      id: r.id,
      userId: r.user_id,
      codeHash: r.code_hash,
      createdAt: r.created_at.toISOString(),
      expiresAt: r.expires_at.toISOString(),
      usedAt: r.used_at?.toISOString(),
    };
  }

  async getPairingCodeByHash(codeHash: string): Promise<PairingCodeRecord | null> {
    const { rows } = await this.pool.query(
      `SELECT * FROM pairing_codes WHERE code_hash = $1`,
      [codeHash]
    );
    if (!rows[0]) return null;
    const r = rows[0];
    return {
      id: r.id,
      userId: r.user_id,
      codeHash: r.code_hash,
      createdAt: r.created_at.toISOString(),
      expiresAt: r.expires_at.toISOString(),
      usedAt: r.used_at?.toISOString(),
    };
  }

  async markPairingCodeUsed(id: string): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `UPDATE pairing_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL`,
      [id]
    );
    return (rowCount ?? 0) > 0;
  }

  async deleteUnusedPairingCodes(userId: string): Promise<void> {
    await this.pool.query(
      `DELETE FROM pairing_codes WHERE user_id = $1 AND used_at IS NULL`,
      [userId]
    );
  }

  async createAuthorization(input: CreateAuthorizationInput): Promise<AuthorizationRecord> {
    const { rows } = await this.pool.query(
      `INSERT INTO authorizations (user_id, type, program_name, reference_url, statement)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [input.userId, input.type, input.programName ?? null, input.referenceUrl ?? null, input.statement]
    );
    const r = rows[0];
    return {
      id: r.id,
      userId: r.user_id,
      type: r.type,
      programName: r.program_name ?? undefined,
      referenceUrl: r.reference_url ?? undefined,
      statement: r.statement,
      confirmedAt: r.confirmed_at.toISOString(),
    };
  }

  async getAuthorization(id: string): Promise<AuthorizationRecord | null> {
    const { rows } = await this.pool.query(`SELECT * FROM authorizations WHERE id = $1`, [id]);
    if (!rows[0]) return null;
    const r = rows[0];
    return {
      id: r.id,
      userId: r.user_id,
      type: r.type,
      programName: r.program_name ?? undefined,
      referenceUrl: r.reference_url ?? undefined,
      statement: r.statement,
      confirmedAt: r.confirmed_at.toISOString(),
    };
  }

  async createScan(input: CreateScanInput): Promise<Scan> {
    const { rows } = await this.pool.query(
      `INSERT INTO scans (user_id, target_url, mode, scope, authorization_id, tech_stack, progress)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6::jsonb, $7::jsonb) RETURNING *`,
      [
        input.userId,
        input.targetUrl,
        input.mode,
        JSON.stringify(input.scope),
        input.authorizationId ?? null,
        JSON.stringify(input.techStack ?? []),
        JSON.stringify({ completedSteps: 0, totalSteps: 0 }),
      ]
    );
    return this.toScan(rows[0]);
  }

  async updateScan(id: string, patch: ScanPatch): Promise<Scan | null> {
    const sets: string[] = [];
    const vals: unknown[] = [];
    let i = 1;
    const push = (col: string, v: unknown, json = false) => {
      sets.push(`${col} = $${i++}${json ? '::jsonb' : ''}`);
      vals.push(json ? JSON.stringify(v) : v);
    };
    if (patch.status !== undefined) push('status', patch.status);
    if (patch.techStack !== undefined) push('tech_stack', patch.techStack, true);
    if (patch.progress !== undefined) push('progress', patch.progress, true);
    if (patch.error !== undefined) push('error', patch.error);
    if (patch.startedAt !== undefined) push('started_at', patch.startedAt);
    if (patch.finishedAt !== undefined) push('finished_at', patch.finishedAt);
    if (sets.length === 0) return this.getScan(id);
    vals.push(id);
    const { rows } = await this.pool.query(
      `UPDATE scans SET ${sets.join(', ')} WHERE id = $${i} RETURNING *`,
      vals
    );
    return rows[0] ? this.toScan(rows[0]) : null;
  }

  async getScan(id: string): Promise<Scan | null> {
    const { rows } = await this.pool.query(`SELECT * FROM scans WHERE id = $1`, [id]);
    return rows[0] ? this.toScan(rows[0]) : null;
  }

  async listScans(
    userId: string,
    limit: number,
    offset: number
  ): Promise<{ scans: Scan[]; total: number }> {
    const { rows } = await this.pool.query(
      `SELECT * FROM scans WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );
    const { rows: cnt } = await this.pool.query(
      `SELECT COUNT(*)::int AS c FROM scans WHERE user_id = $1`,
      [userId]
    );
    return { scans: rows.map((r: Record<string, unknown>) => this.toScan(r)), total: cnt[0].c };
  }

  async addFinding(f: Omit<Finding, 'id' | 'createdAt'>): Promise<Finding> {
    const { rows } = await this.pool.query(
      `INSERT INTO findings
         (scan_id, category, title, description, severity, cvss_score, cvss_vector,
          confidence, trap_probability, honeypot_suspect, location, evidence,
          repro_steps, remediation, "references")
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,
      [
        f.scanId, f.category, f.title, f.description, f.severity,
        f.cvssScore ?? null, f.cvssVector ?? null, f.confidence,
        f.trapProbability, f.honeypotSuspect, f.location ?? null,
        f.evidence ?? null, f.reproSteps, f.remediation, f.references,
      ]
    );
    return this.toFinding(rows[0]);
  }

  async addFindings(items: Array<Omit<Finding, 'id' | 'createdAt'>>): Promise<Finding[]> {
    if (items.length === 0) return [];
    const cols = 15;
    const values: unknown[] = [];
    const tuples = items.map((f, i) => {
      const b = i * cols;
      values.push(
        f.scanId, f.category, f.title, f.description, f.severity,
        f.cvssScore ?? null, f.cvssVector ?? null, f.confidence,
        f.trapProbability, f.honeypotSuspect, f.location ?? null,
        f.evidence ?? null, f.reproSteps, f.remediation, f.references,
      );
      return `(${Array.from({ length: cols }, (_, j) => `$${b + j + 1}`).join(',')})`;
    });
    const { rows } = await this.pool.query(
      `INSERT INTO findings
         (scan_id, category, title, description, severity, cvss_score, cvss_vector,
          confidence, trap_probability, honeypot_suspect, location, evidence,
          repro_steps, remediation, "references")
       VALUES ${tuples.join(',')} RETURNING *`,
      values,
    );
    return rows.map((r: Record<string, unknown>) => this.toFinding(r));
  }

  async listFindings(scanId: string): Promise<Finding[]> {
    const { rows } = await this.pool.query(
      `SELECT * FROM findings WHERE scan_id = $1 ORDER BY created_at ASC`,
      [scanId]
    );
    return rows.map((r: Record<string, unknown>) => this.toFinding(r));
  }

  async recordUsage(userId: string, kind: string, quantity: number, scanId?: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO usage_events (user_id, kind, quantity, scan_id) VALUES ($1, $2, $3, $4)`,
      [userId, kind, quantity, scanId ?? null]
    );
  }

  async countScansSince(userId: string, sinceIso: string): Promise<number> {
    const { rows } = await this.pool.query(
      `SELECT COUNT(*)::int AS c FROM usage_events
       WHERE user_id = $1 AND kind = 'scan' AND created_at >= $2::timestamptz`,
      [userId, sinceIso]
    );
    return rows[0].c;
  }

  async sumUsageSince(userId: string, kind: string, sinceIso: string): Promise<number> {
    const { rows } = await this.pool.query(
      `SELECT COALESCE(SUM(quantity), 0)::int AS s FROM usage_events
       WHERE user_id = $1 AND kind = $2 AND created_at >= $3::timestamptz`,
      [userId, kind, sinceIso]
    );
    return rows[0].s;
  }

  async addWaitlistEmail(email: string, source = 'site-drop'): Promise<{ already: boolean }> {
    const { rowCount } = await this.pool.query(
      `INSERT INTO waitlist (email, source) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING`,
      [email.trim().toLowerCase(), source]
    );
    return { already: (rowCount ?? 0) === 0 };
  }

  private toWebCheck(row: Record<string, unknown>): WebCheckRecord {
    return {
      id: row['id'] as string,
      userId: row['user_id'] as string,
      url: row['url'] as string,
      host: row['host'] as string,
      authorized: Boolean(row['authorized']),
      score: row['score'] != null ? Number(row['score']) : null,
      grade: (row['grade'] as string) ?? null,
      findings: (row['findings'] as WebFinding[]) ?? [],
      info: row['info'] as WebInfo,
      requesterIp: (row['requester_ip'] as string) ?? null,
      requesterGeo: (row['requester_geo'] as RequesterOrigin) ?? null,
      createdAt: (row['created_at'] as Date).toISOString(),
    };
  }

  async insertWebCheck(input: InsertWebCheckInput): Promise<WebCheckRecord> {
    const { rows } = await this.pool.query(
      `INSERT INTO web_checks (user_id, url, host, authorized, score, grade, findings, info, requester_ip, requester_geo)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10::jsonb) RETURNING *`,
      [
        input.userId,
        input.url,
        input.host,
        input.authorized,
        input.score,
        input.grade,
        JSON.stringify(input.findings),
        JSON.stringify(input.info),
        input.requesterIp ?? null,
        JSON.stringify(input.requesterGeo ?? null),
      ]
    );
    return this.toWebCheck(rows[0]);
  }

  async listWebChecks(userId: string, limit: number): Promise<WebCheckRecord[]> {
    const { rows } = await this.pool.query(
      `SELECT * FROM web_checks WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [userId, Math.max(1, Math.min(50, limit))]
    );
    return rows.map((r: Record<string, unknown>) => this.toWebCheck(r));
  }

  async listWebCheckSummaries(userId: string, limit: number): Promise<WebCheckSummary[]> {
    const { runs } = await this.listWebCheckSummariesCounted(userId, limit);
    return runs;
  }

  async listWebCheckSummariesCounted(
    userId: string,
    limit: number,
  ): Promise<{ runs: WebCheckSummary[]; total: number }> {
    // One round trip for rows AND the lifetime total (the usage meter):
    // the window count rides on every returned row; an empty history
    // has no row to ride on, and its total is zero by definition.
    const { rows } = await this.pool.query(
      `SELECT id, url, host, score, grade, created_at, requester_ip, requester_geo,
              jsonb_array_length(findings)::int AS finding_count,
              info -> 'trust' ->> 'verdict' AS trust_verdict,
              COUNT(*) OVER()::int AS total_count
       FROM web_checks WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [userId, Math.max(1, Math.min(50, limit))],
    );
    return {
      total: rows[0] ? Number(rows[0]['total_count'] ?? 0) : 0,
      runs: rows.map((r: Record<string, unknown>) => ({
        id: r['id'] as string,
        url: r['url'] as string,
        host: r['host'] as string,
        score: r['score'] != null ? Number(r['score']) : null,
        grade: (r['grade'] as string) ?? null,
        findingCount: Number(r['finding_count'] ?? 0),
        trustVerdict: (r['trust_verdict'] as string) ?? null,
        requesterIp: (r['requester_ip'] as string) ?? null,
        requesterGeo: (r['requester_geo'] as RequesterOrigin) ?? null,
        createdAt: (r['created_at'] as Date).toISOString(),
      })),
    };
  }

  async getWebCheck(userId: string, id: string): Promise<WebCheckRecord | null> {
    const { rows } = await this.pool.query(
      `SELECT * FROM web_checks WHERE user_id = $1 AND id = $2`,
      [userId, id]
    );
    return rows[0] ? this.toWebCheck(rows[0]) : null;
  }

  async countWebChecks(userId: string): Promise<number> {
    const { rows } = await this.pool.query(
      `SELECT COUNT(*)::int AS n FROM web_checks WHERE user_id = $1`,
      [userId]
    );
    return rows[0]?.n ?? 0;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

export async function createDatabase(databaseUrl?: string): Promise<Database> {
  if (databaseUrl) {
    console.log('[db] connecting to PostgreSQL (Supabase-compatible)');
    return PostgresDatabase.connect(databaseUrl);
  }
  console.log('[db] no DATABASE_URL — using in-memory store (data lost on restart)');
  return new MemoryDatabase();
}

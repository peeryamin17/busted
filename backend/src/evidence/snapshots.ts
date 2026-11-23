import { createHash } from 'node:crypto';

/**
 * Content-addressed evidence snapshots. Finding evidence is snapshotted
 * out of the disposable scan/probe flow into hash-verified blobs, so a
 * finding's proof survives after the live capture is gone and re-checks
 * by recomputing SHA-256. The hash covers content only, never identity,
 * so identical evidence hashes identically. Bodies over 256 KiB are
 * truncated, and the truncation is recorded, never silently dropped.
 */

export type EvidenceRole = 'baseline' | 'proof' | 'verification' | 'supporting';

/** Bodies larger than this are truncated. */
export const MAX_BODY_BYTES = 256 * 1024;

export interface SnapshotInput {
  role: EvidenceRole;
  url: string;
  request: string;
  body: string;
  /**
   * Identity fields, accepted for the caller's convenience and NEVER
   * hashed: they identify who/what the evidence belongs to, not what
   * the evidence IS. Linkage lives in the store (put's `link` param),
   * not in the hash.
   */
  findingId?: string;
  taskId?: string;
}

export interface EvidenceSnapshot {
  sha256: string;
  role: EvidenceRole;
  url: string;
  request: string;
  body: string;
}

/** Canonical (hashable) form of a snapshot: trimmed, truncated, ordered. */
function canonicalize(input: SnapshotInput): {
  role: EvidenceRole;
  url: string;
  request: string;
  body: string;
} {
  const url = input.url.trim();
  let request = input.request.trim();
  let body = input.body;
  const bodyBytes = Buffer.byteLength(body, 'utf8');
  if (bodyBytes > MAX_BODY_BYTES) {
    // Truncate on a byte boundary without splitting a UTF-8 sequence.
    body = Buffer.from(body, 'utf8').subarray(0, MAX_BODY_BYTES).toString('utf8');
    request += ` [evidence truncated: body exceeded ${MAX_BODY_BYTES} bytes; first ${MAX_BODY_BYTES} bytes kept]`;
  }
  return { role: input.role, url, request, body };
}

/**
 * SHA-256 hex over a canonical JSON of {role, url, request, body}.
 * Key order is fixed by the object literal, so the hash is stable.
 * Identity fields (findingId, taskId) and timestamps are excluded by
 * construction, they never appear in the hashed object.
 */
export function snapshotHash(input: SnapshotInput): string {
  const c = canonicalize(input);
  const canonical = JSON.stringify({
    role: c.role,
    url: c.url,
    request: c.request,
    body: c.body,
  });
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Build a snapshot from raw evidence: normalise (trim, truncate) and
 * hash. The returned `request` carries the truncation marker when the
 * body was cut, so a truncated snapshot is self-describing.
 */
export function createSnapshot(input: SnapshotInput): EvidenceSnapshot {
  const c = canonicalize(input);
  return { ...c, sha256: snapshotHash(input) };
}

export interface SnapshotLink {
  findingId?: string;
  taskId?: string;
}

export interface EvidenceStore {
  /**
   * Store a snapshot. Idempotent by sha256: storing the same content
   * twice stores it once (same hash → same row / same map entry).
   * `link` optionally binds the snapshot to a finding/task.
   */
  put(snapshot: EvidenceSnapshot, link?: SnapshotLink): Promise<EvidenceSnapshot>;
  get(sha256: string): Promise<EvidenceSnapshot | null>;
  listForFinding(findingId: string): Promise<EvidenceSnapshot[]>;
  /**
   * Recompute the hash from the stored fields and compare it with the
   * stored sha256. False means the stored evidence was tampered with
   * (or corrupted) after capture, the finding's proof is void.
   */
  verify(sha256: string): Promise<boolean>;
}

/**
 * In-memory store (Map-based), for tests and memory mode. `put`/`get`
 * return the stored record; `snapshots` is the backing map, exposed so
 * tests can simulate storage corruption (mutate a stored body, then
 * verify() must return false).
 */
export class MemoryEvidenceStore implements EvidenceStore {
  /** sha256 → snapshot. */
  readonly snapshots = new Map<string, EvidenceSnapshot>();
  /** findingId → set of bound snapshot sha256 values. */
  readonly links = new Map<string, Set<string>>();

  async put(snapshot: EvidenceSnapshot, link?: SnapshotLink): Promise<EvidenceSnapshot> {
    const existing = this.snapshots.get(snapshot.sha256);
    if (existing) {
      if (link?.findingId) this.addLink(link.findingId, snapshot.sha256);
      return existing;
    }
    this.snapshots.set(snapshot.sha256, snapshot);
    if (link?.findingId) this.addLink(link.findingId, snapshot.sha256);
    return snapshot;
  }

  async get(sha256: string): Promise<EvidenceSnapshot | null> {
    return this.snapshots.get(sha256) ?? null;
  }

  async listForFinding(findingId: string): Promise<EvidenceSnapshot[]> {
    const hashes = this.links.get(findingId);
    if (!hashes) return [];
    const out: EvidenceSnapshot[] = [];
    for (const sha of hashes) {
      const snap = this.snapshots.get(sha);
      if (snap) out.push(snap);
    }
    return out;
  }

  async verify(sha256: string): Promise<boolean> {
    const stored = this.snapshots.get(sha256);
    if (!stored) return false;
    return snapshotHash(stored) === sha256;
  }

  private addLink(findingId: string, sha256: string): void {
    let set = this.links.get(findingId);
    if (!set) {
      set = new Set<string>();
      this.links.set(findingId, set);
    }
    set.add(sha256);
  }
}

type QueryFn = (sql: string, params: unknown[]) => Promise<{ rows: any[] }>;

/** Map one evidence_snapshots row to an EvidenceSnapshot. */
function rowToSnapshot(row: any): EvidenceSnapshot {
  const body =
    Buffer.isBuffer(row.body)
      ? row.body.toString('utf8')
      : row.body == null
        ? ''
        : String(row.body);
  return {
    sha256: String(row.sha256),
    role: row.role as EvidenceRole,
    url: String(row.url ?? ''),
    request: String(row.request ?? ''),
    body,
  };
}

/**
 * Postgres-backed store (migration 019). Takes a query function in the
 * constructor, the coordinator wires the pool (`pool.query.bind(pool)`)
 *, so this module never imports `pg` itself. Bodies are stored as
 * bytea (Buffer) and read back as UTF-8 strings.
 */
export class PostgresEvidenceStore implements EvidenceStore {
  constructor(private readonly query: QueryFn) {}

  async put(snapshot: EvidenceSnapshot, link?: SnapshotLink): Promise<EvidenceSnapshot> {
    await this.query(
      `insert into evidence_snapshots (sha256, role, finding_id, task_id, url, request, body)
       values ($1, $2, $3, $4, $5, $6, $7)
       on conflict (sha256) do nothing`,
      [
        snapshot.sha256,
        snapshot.role,
        link?.findingId ?? null,
        link?.taskId ?? null,
        snapshot.url,
        snapshot.request,
        Buffer.from(snapshot.body, 'utf8'),
      ],
    );
    if (link?.findingId) {
      await this.query(
        `insert into finding_evidence (finding_id, snapshot_sha256, role)
         values ($1, $2, $3)
         on conflict (finding_id, snapshot_sha256) do nothing`,
        [link.findingId, snapshot.sha256, snapshot.role],
      );
    }
    return snapshot;
  }

  async get(sha256: string): Promise<EvidenceSnapshot | null> {
    const { rows } = await this.query(
      `select sha256, role, url, request, body from evidence_snapshots where sha256 = $1`,
      [sha256],
    );
    if (rows.length === 0) return null;
    return rowToSnapshot(rows[0]);
  }

  async listForFinding(findingId: string): Promise<EvidenceSnapshot[]> {
    const { rows } = await this.query(
      `select s.sha256, s.role, s.url, s.request, s.body
       from evidence_snapshots s
       join finding_evidence fe on fe.snapshot_sha256 = s.sha256
       where fe.finding_id = $1
       order by fe.created_at asc`,
      [findingId],
    );
    return rows.map(rowToSnapshot);
  }

  async verify(sha256: string): Promise<boolean> {
    const stored = await this.get(sha256);
    if (!stored) return false;
    return snapshotHash(stored) === sha256;
  }
}

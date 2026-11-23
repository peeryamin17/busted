/**
 * Target pins plus block/allow rules. A pin is human approval for a host;
 * pins are append-only history. Block beats allow, and block beats a pin.
 * This composes with the scope and SSRF guards, never replaces them.
 * Rules never compile user input into a regex.
 */
import { randomUUID } from 'node:crypto';
import net from 'node:net';

/** One approved target. One active pin per (taskId, host, port). */
export interface TargetPin {
  id: string;
  taskId: string;
  /** Lowercased hostname or IP literal, as pinned. */
  host: string;
  /** Null = the pin covers every port on this host. */
  port: number | null;
  /** User id of the human who approved this target. */
  pinnedBy: string;
  pinnedAt: string;
  active: boolean;
  deactivatedAt: string | null;
  /** `host`, or `host:port` when the pin is port-specific. */
  canonical: string;
}

export type TargetRuleKind = 'exact-host' | 'domain-suffix' | 'cidr' | 'url-prefix';
export type TargetRuleAction = 'allow' | 'block';

export interface TargetRule {
  id: string;
  userId: string;
  /** Null = user-wide rule; set = applies to one task only. */
  taskId: string | null;
  kind: TargetRuleKind;
  pattern: string;
  action: TargetRuleAction;
  createdBy: string;
  createdAt: string;
  active: boolean;
  deactivatedAt: string | null;
}

export const TARGET_RULE_KINDS: readonly TargetRuleKind[] = [
  'exact-host',
  'domain-suffix',
  'cidr',
  'url-prefix',
];
export const TARGET_RULE_ACTIONS: readonly TargetRuleAction[] = ['allow', 'block'];

// ── Normalisation / validation ───────────────────────────────────────────

export function canonicalPin(host: string, port?: number | null): string {
  const h = host.trim().toLowerCase();
  return port ? `${h}:${port}` : h;
}

/** A pin host is a bare hostname or IP literal, no scheme, path or spaces. */
export function validatePinHost(host: string): string {
  const h = host.trim().toLowerCase();
  if (!h) throw new Error('pin host must not be empty');
  if (/[\s/:?#@[\]]/.test(h)) {
    throw new Error('pin host must be a bare hostname or IP literal');
  }
  if (h.length > 253) throw new Error('pin host is too long');
  return h;
}

export function validatePinPort(port: number | null | undefined): number | null {
  if (port === undefined || port === null) return null;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('pin port must be an integer between 1 and 65535');
  }
  return port;
}

// ── IPv4 CIDR (plain integer math, no new dependency) ────────────────────

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const v = Number(p);
    if (v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

export interface ParsedCidr {
  network: number;
  mask: number;
  prefix: number;
}

/**
 * Parse an IPv4 CIDR (`a.b.c.d/p`, p in 8-32). Returns null when the
 * pattern is not a valid CIDR, callers treat that as a validation
 * error at rule creation, never at match time.
 */
export function parseCidr(pattern: string): ParsedCidr | null {
  const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/.exec(pattern.trim());
  if (!m) return null;
  const ip = ipv4ToInt(m[1]!);
  const prefix = Number(m[2]);
  if (ip === null || prefix < 8 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: (ip & mask) >>> 0, mask, prefix };
}

function cidrMatches(cidr: ParsedCidr, host: string): boolean {
  const ip = ipv4ToInt(host);
  if (ip === null) return false;
  return ((ip & cidr.mask) >>> 0) === cidr.network;
}

/**
 * Validate a rule's kind/pattern pair. Throws an Error describing the
 * problem, an invalid CIDR is rejected HERE, at creation, so matching
 * can never fail on a bad rule. Returns the normalised pattern to store.
 */
export function validateTargetRule(kind: TargetRuleKind, pattern: string): string {
  const p = pattern.trim();
  if (!p) throw new Error('rule pattern must not be empty');
  switch (kind) {
    case 'exact-host':
    case 'domain-suffix': {
      if (/[\s/:?#@[\]]/.test(p)) {
        throw new Error(`${kind} pattern must be a bare hostname`);
      }
      return p.toLowerCase();
    }
    case 'cidr': {
      if (!parseCidr(p)) {
        throw new Error(`invalid CIDR: ${p} (IPv4 /8–/32 only)`);
      }
      return p;
    }
    case 'url-prefix': {
      let url: URL;
      try {
        url = new URL(p);
      } catch {
        throw new Error(`invalid url-prefix: ${p} (must be an http(s) URL)`);
      }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        throw new Error('url-prefix must use http(s)');
      }
      return p;
    }
    default:
      throw new Error(`unknown rule kind: ${String(kind)}`);
  }
}

// ── Private / loopback literals (second line, no DNS resolution) ────────

/**
 * True for localhost / private literals, from the explicit list only:
 * `localhost`, `*.local`, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12,
 * 192.168.0.0/16, ::1 (plus ::ffff: forms of a private IPv4 literal).
 * Hostnames that are not literals are NOT private here, resolving them
 * and refusing private answers stays the SSRF guard's job
 * (`assertPublicHost` in guardrails/scope.ts).
 */
export function isLocalOrPrivateHost(host: string): boolean {
  const h = host.trim().toLowerCase();
  if (h === 'localhost' || h.endsWith('.local')) return true;
  if (!net.isIP(h)) return false;
  // IPv4-mapped IPv6 literal (::ffff:127.0.0.1): the embedded IPv4 decides.
  const mapped = /^::ffff:(.+)$/.exec(h);
  if (mapped) {
    const tail = mapped[1]!;
    if (net.isIPv4(tail)) return isLocalOrPrivateHost(tail);
    return true;
  }
  if (net.isIPv4(h)) {
    const [a, b] = h.split('.').map(Number);
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 172 && b !== undefined && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    return false;
  }
  return h === '::1';
}

// ── Rule matching (plain string ops / integer math, no RegExp) ───────────

export function ruleMatches(rule: TargetRule, host: string, url?: string): boolean {
  const h = host.trim().toLowerCase();
  switch (rule.kind) {
    case 'exact-host':
      return h === rule.pattern.toLowerCase();
    case 'domain-suffix': {
      const suffix = rule.pattern.toLowerCase();
      return h === suffix || h.endsWith(`.${suffix}`);
    }
    case 'cidr':
      return cidrMatches(parseCidr(rule.pattern)!, h);
    case 'url-prefix':
      return url !== undefined && url.startsWith(rule.pattern);
  }
}

// ── Pin matching ─────────────────────────────────────────────────────────

function pinMatches(pin: TargetPin, host: string, port?: number | null): boolean {
  if (pin.host !== host.trim().toLowerCase()) return false;
  if (pin.port === null) return true;
  return port !== undefined && port !== null && pin.port === port;
}

function canonicalSetMatches(canonicals: Set<string>, host: string, port?: number | null): boolean {
  const h = host.trim().toLowerCase();
  if (canonicals.has(h)) return true;
  if (port !== undefined && port !== null && canonicals.has(`${h}:${port}`)) return true;
  return false;
}

// ── The gate ─────────────────────────────────────────────────────────────

export type PinDecision = 'allowed' | 'ask' | 'blocked';

export interface PinGateInput {
  taskId: string;
  host: string;
  port?: number | null;
  /** Normalised URL string, needed only for url-prefix rules. */
  url?: string;
  /** Active pins for the task, as records or canonical strings. */
  pins: TargetPin[] | Set<string>;
  /** Active rules for the user (user-wide + this task's), already filtered. */
  rules: TargetRule[];
}

/**
 * Decision order: private/loopback literal → 'blocked'; block rule →
 * 'blocked'; pin present → 'allowed'; allow rule → 'allowed'; otherwise
 * → 'ask' (a human must pin the target before it is tested).
 *
 * Block beats allow on conflict, and block beats a pin: a block rule is
 * an explicit "never touch this". The gate never allows a private or
 * loopback host, even if pinned, that is the SSRF guard's job first,
 * and this check is the second line.
 */
export function checkTargetPin(input: PinGateInput): { decision: PinDecision; reason: string } {
  const host = input.host.trim().toLowerCase();
  if (isLocalOrPrivateHost(host)) {
    return { decision: 'blocked', reason: `host ${host} is localhost or private` };
  }
  const activeRules = input.rules.filter((r) => r.active);
  const blockers = activeRules.filter((r) => r.action === 'block' && ruleMatches(r, host, input.url));
  if (blockers.length > 0) {
    return {
      decision: 'blocked',
      reason: `blocked by ${blockers[0]!.kind} rule "${blockers[0]!.pattern}"`,
    };
  }
  const pinned = input.pins instanceof Set
    ? canonicalSetMatches(input.pins, host, input.port)
    : input.pins.some((p) => p.active && p.taskId === input.taskId && pinMatches(p, host, input.port));
  if (pinned) {
    return { decision: 'allowed', reason: `host ${host} is pinned for this task` };
  }
  const allowers = activeRules.filter((r) => r.action === 'allow' && ruleMatches(r, host, input.url));
  if (allowers.length > 0) {
    return {
      decision: 'allowed',
      reason: `allowed by ${allowers[0]!.kind} rule "${allowers[0]!.pattern}"`,
    };
  }
  return { decision: 'ask', reason: `host ${host} is not pinned — human approval required` };
}

// ── Store ────────────────────────────────────────────────────────────────

export interface AddPinInput {
  taskId: string;
  host: string;
  port?: number | null;
  pinnedBy: string;
}

export interface AddRuleInput {
  userId: string;
  taskId?: string | null;
  kind: TargetRuleKind;
  pattern: string;
  action: TargetRuleAction;
  createdBy: string;
}

export interface ListOptions {
  includeInactive?: boolean;
}

export interface PinStore {
  addPin(input: AddPinInput): Promise<TargetPin>;
  listPins(taskId: string, opts?: ListOptions): Promise<TargetPin[]>;
  /** Marks the active pin inactive; returns null when none was active. */
  deactivatePin(taskId: string, host: string, port?: number | null): Promise<TargetPin | null>;
  addRule(input: AddRuleInput): Promise<TargetRule>;
  /** User-wide rules plus (when taskId is given) that task's rules. */
  listRules(userId: string, taskId?: string | null, opts?: ListOptions): Promise<TargetRule[]>;
  /** Marks the rule inactive; returns null when not found / not the caller's. */
  removeRule(ruleId: string, userId: string): Promise<TargetRule | null>;
}

export class MemoryPinStore implements PinStore {
  private pins: TargetPin[] = [];
  private rules: TargetRule[] = [];

  async addPin(input: AddPinInput): Promise<TargetPin> {
    const host = validatePinHost(input.host);
    const port = validatePinPort(input.port);
    if (!input.pinnedBy) throw new Error('pinnedBy must not be empty');
    const existing = this.pins.find(
      (p) => p.active && p.taskId === input.taskId && p.host === host && p.port === port,
    );
    if (existing) return { ...existing };
    const pin: TargetPin = {
      id: randomUUID(),
      taskId: input.taskId,
      host,
      port,
      pinnedBy: input.pinnedBy,
      pinnedAt: new Date().toISOString(),
      active: true,
      deactivatedAt: null,
      canonical: canonicalPin(host, port),
    };
    this.pins.push(pin);
    return { ...pin };
  }

  async listPins(taskId: string, opts?: ListOptions): Promise<TargetPin[]> {
    return this.pins
      .filter((p) => p.taskId === taskId && (opts?.includeInactive || p.active))
      .sort((a, b) => (a.pinnedAt < b.pinnedAt ? 1 : -1))
      .map((p) => ({ ...p }));
  }

  async deactivatePin(taskId: string, host: string, port?: number | null): Promise<TargetPin | null> {
    const h = validatePinHost(host);
    const p = validatePinPort(port);
    const pin = this.pins.find(
      (x) => x.active && x.taskId === taskId && x.host === h && x.port === p,
    );
    if (!pin) return null;
    pin.active = false;
    pin.deactivatedAt = new Date().toISOString();
    return { ...pin };
  }

  async addRule(input: AddRuleInput): Promise<TargetRule> {
    if (!TARGET_RULE_KINDS.includes(input.kind)) throw new Error(`unknown rule kind: ${String(input.kind)}`);
    if (!TARGET_RULE_ACTIONS.includes(input.action)) throw new Error(`unknown rule action: ${String(input.action)}`);
    if (!input.createdBy) throw new Error('createdBy must not be empty');
    const pattern = validateTargetRule(input.kind, input.pattern);
    const rule: TargetRule = {
      id: randomUUID(),
      userId: input.userId,
      taskId: input.taskId ?? null,
      kind: input.kind,
      pattern,
      action: input.action,
      createdBy: input.createdBy,
      createdAt: new Date().toISOString(),
      active: true,
      deactivatedAt: null,
    };
    this.rules.push(rule);
    return { ...rule };
  }

  async listRules(userId: string, taskId?: string | null, opts?: ListOptions): Promise<TargetRule[]> {
    return this.rules
      .filter(
        (r) =>
          r.userId === userId &&
          (taskId === undefined || taskId === null || r.taskId === null || r.taskId === taskId) &&
          (opts?.includeInactive || r.active),
      )
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .map((r) => ({ ...r }));
  }

  async removeRule(ruleId: string, userId: string): Promise<TargetRule | null> {
    const rule = this.rules.find((r) => r.id === ruleId && r.userId === userId && r.active);
    if (!rule) return null;
    rule.active = false;
    rule.deactivatedAt = new Date().toISOString();
    return { ...rule };
  }
}

/** The only thing the Postgres store needs: a parametrised query function. */
export type PinQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[] }>;

/** pg returns timestamptz as Date; a stubbed query may hand back ISO strings. */
function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function toNullableIso(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return toIso(value);
}

export class PostgresPinStore implements PinStore {
  constructor(private readonly query: PinQueryFn) {}

  private toPin(row: Record<string, unknown>): TargetPin {
    const host = row['host'] as string;
    const port = (row['port'] as number | null) ?? null;
    return {
      id: row['id'] as string,
      taskId: row['task_id'] as string,
      host,
      port,
      pinnedBy: row['pinned_by'] as string,
      pinnedAt: toIso(row['pinned_at']),
      active: row['active'] as boolean,
      deactivatedAt: toNullableIso(row['deactivated_at']),
      canonical: canonicalPin(host, port),
    };
  }

  private toRule(row: Record<string, unknown>): TargetRule {
    return {
      id: row['id'] as string,
      userId: row['user_id'] as string,
      taskId: (row['task_id'] as string | null) ?? null,
      kind: row['kind'] as TargetRuleKind,
      pattern: row['pattern'] as string,
      action: row['action'] as TargetRuleAction,
      createdBy: row['created_by'] as string,
      createdAt: toIso(row['created_at']),
      active: row['active'] as boolean,
      deactivatedAt: toNullableIso(row['deactivated_at']),
    };
  }

  async addPin(input: AddPinInput): Promise<TargetPin> {
    const host = validatePinHost(input.host);
    const port = validatePinPort(input.port);
    if (!input.pinnedBy) throw new Error('pinnedBy must not be empty');
    const { rows: existing } = await this.query(
      `SELECT * FROM target_pins WHERE task_id = $1 AND host = $2 AND port IS NOT DISTINCT FROM $3 AND active`,
      [input.taskId, host, port],
    );
    if (existing[0]) return this.toPin(existing[0]);
    try {
      const { rows } = await this.query(
        `INSERT INTO target_pins (task_id, host, port, pinned_by) VALUES ($1, $2, $3, $4) RETURNING *`,
        [input.taskId, host, port, input.pinnedBy],
      );
      return this.toPin(rows[0]!);
    } catch (err) {
      // Lost a race with a concurrent pin for the same key: the partial
      // unique index refused the duplicate, return the winner instead.
      if ((err as { code?: string }).code === '23505') {
        const { rows } = await this.query(
          `SELECT * FROM target_pins WHERE task_id = $1 AND host = $2 AND port IS NOT DISTINCT FROM $3 AND active`,
          [input.taskId, host, port],
        );
        if (rows[0]) return this.toPin(rows[0]);
      }
      throw err;
    }
  }

  async listPins(taskId: string, opts?: ListOptions): Promise<TargetPin[]> {
    const { rows } = await this.query(
      opts?.includeInactive
        ? `SELECT * FROM target_pins WHERE task_id = $1 ORDER BY pinned_at DESC`
        : `SELECT * FROM target_pins WHERE task_id = $1 AND active ORDER BY pinned_at DESC`,
      [taskId],
    );
    return rows.map((r) => this.toPin(r));
  }

  async deactivatePin(taskId: string, host: string, port?: number | null): Promise<TargetPin | null> {
    const h = validatePinHost(host);
    const p = validatePinPort(port);
    const { rows } = await this.query(
      `UPDATE target_pins SET active = false, deactivated_at = now()
       WHERE task_id = $1 AND host = $2 AND port IS NOT DISTINCT FROM $3 AND active RETURNING *`,
      [taskId, h, p],
    );
    return rows[0] ? this.toPin(rows[0]) : null;
  }

  async addRule(input: AddRuleInput): Promise<TargetRule> {
    if (!TARGET_RULE_KINDS.includes(input.kind)) throw new Error(`unknown rule kind: ${String(input.kind)}`);
    if (!TARGET_RULE_ACTIONS.includes(input.action)) throw new Error(`unknown rule action: ${String(input.action)}`);
    if (!input.createdBy) throw new Error('createdBy must not be empty');
    const pattern = validateTargetRule(input.kind, input.pattern);
    const { rows } = await this.query(
      `INSERT INTO target_rules (user_id, task_id, kind, pattern, action, created_by)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [input.userId, input.taskId ?? null, input.kind, pattern, input.action, input.createdBy],
    );
    return this.toRule(rows[0]!);
  }

  async listRules(userId: string, taskId?: string | null, opts?: ListOptions): Promise<TargetRule[]> {
    const active = opts?.includeInactive ? '' : ' AND active';
    if (taskId === undefined || taskId === null) {
      const { rows } = await this.query(
        `SELECT * FROM target_rules WHERE user_id = $1${active} ORDER BY created_at DESC`,
        [userId],
      );
      return rows.map((r) => this.toRule(r));
    }
    const { rows } = await this.query(
      `SELECT * FROM target_rules WHERE user_id = $1 AND (task_id IS NULL OR task_id = $2)${active} ORDER BY created_at DESC`,
      [userId, taskId],
    );
    return rows.map((r) => this.toRule(r));
  }

  async removeRule(ruleId: string, userId: string): Promise<TargetRule | null> {
    const { rows } = await this.query(
      `UPDATE target_rules SET active = false, deactivated_at = now()
       WHERE id = $1 AND user_id = $2 AND active RETURNING *`,
      [ruleId, userId],
    );
    return rows[0] ? this.toRule(rows[0]) : null;
  }
}

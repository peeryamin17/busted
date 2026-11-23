/**
 * Notification channel persistence: memory and Postgres behind one
 * interface. Rows hold addresses only, never credentials. Those live in
 * the secrets store and decrypt at send time.
 */
import { randomUUID } from 'node:crypto';

export type NotifyChannelType = 'webhook' | 'telegram' | 'smtp';

export const NOTIFY_CHANNEL_TYPES: readonly NotifyChannelType[] = [
  'webhook',
  'telegram',
  'smtp',
];

export type NotifySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const NOTIFY_SEVERITIES: readonly NotifySeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
];

/** Higher rank = more severe. A channel fires when the event's rank is >= its minimum. */
export const SEVERITY_RANK: Record<NotifySeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export type NotifyEventKind =
  | 'task-completed'
  | 'finding-critical'
  | 'finding-high'
  | 'task-failed';

export const NOTIFY_EVENT_KINDS: readonly NotifyEventKind[] = [
  'task-completed',
  'finding-critical',
  'finding-high',
  'task-failed',
];

/**
 * The channel's address. Shape depends on `type`, the store does not
 * carry a discriminator here because the channel row already has one.
 * No credential ever lives in a target: webhook bearer secrets,
 * Telegram bot tokens and SMTP passwords live in the secrets store.
 */
export type NotifyTarget =
  | { url: string } // webhook
  | { chatId: string } // telegram
  | { host: string; port: number; user: string; from: string; to: string }; // smtp

export interface NotifyFilters {
  minSeverity: NotifySeverity;
  events: NotifyEventKind[];
}

/** One notification destination owned by one user. */
export interface NotifyChannelRecord {
  id: string;
  userId: string;
  type: NotifyChannelType;
  label: string;
  target: NotifyTarget;
  filters: NotifyFilters;
  enabled: boolean;
  createdAt: string; // ISO
}

export interface CreateNotifyChannelInput {
  userId: string;
  type: NotifyChannelType;
  label: string;
  /** Raw target object from the caller; validated and normalised per type. */
  target: Record<string, unknown>;
  filters?: Partial<NotifyFilters>;
  enabled?: boolean;
}

export interface NotifyChannelStore {
  create(input: CreateNotifyChannelInput): Promise<NotifyChannelRecord>;
  get(id: string): Promise<NotifyChannelRecord | null>;
  /** The user's channels, newest first. */
  listForUser(userId: string): Promise<NotifyChannelRecord[]>;
  /** True when a row owned by this user existed and was removed. */
  remove(id: string, userId: string): Promise<boolean>;
}

const nowIso = () => new Date().toISOString();

function assertChannelType(value: string): asserts value is NotifyChannelType {
  if (!(NOTIFY_CHANNEL_TYPES as readonly string[]).includes(value)) {
    throw new Error(`invalid_notify_channel_type: ${value}`);
  }
}

function assertLabel(label: string): void {
  if (!label || !label.trim()) throw new Error('notify_label_required');
  if (label.length > 100) throw new Error('notify_label_too_long');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireStringField(target: Record<string, unknown>, field: string, error: string): string {
  const value = target[field];
  if (typeof value !== 'string' || !value.trim()) throw new Error(error);
  return value.trim();
}

function requireEmailishField(target: Record<string, unknown>, field: string, error: string): string {
  const value = requireStringField(target, field, error);
  if (!value.includes('@')) throw new Error(error);
  return value;
}

/** Validate + normalise a target for its channel type. Throws on bad input. */
export function validateNotifyTarget(
  type: NotifyChannelType,
  target: unknown,
): NotifyTarget {
  if (!isRecord(target)) throw new Error(`invalid_notify_target: ${type}`);
  if (type === 'webhook') {
    const url = requireStringField(target, 'url', 'invalid_webhook_url');
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error('invalid_webhook_url');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('invalid_webhook_url');
    }
    return { url: parsed.toString() };
  }
  if (type === 'telegram') {
    const chatId = requireStringField(target, 'chatId', 'invalid_telegram_chat_id');
    return { chatId };
  }
  // smtp
  const host = requireStringField(target, 'host', 'invalid_smtp_host');
  const portRaw = target['port'];
  const port = typeof portRaw === 'string' ? Number(portRaw) : portRaw;
  if (!Number.isInteger(port) || (port as number) < 1 || (port as number) > 65535) {
    throw new Error(`invalid_smtp_port: ${String(portRaw)}`);
  }
  const user = requireStringField(target, 'user', 'invalid_smtp_user');
  const from = requireEmailishField(target, 'from', 'invalid_smtp_from');
  const to = requireEmailishField(target, 'to', 'invalid_smtp_to');
  return { host, port: port as number, user, from, to };
}

/** Validate + normalise filters, filling the "everything" defaults. */
export function validateNotifyFilters(filters?: Partial<NotifyFilters>): NotifyFilters {
  const minSeverity = filters?.minSeverity ?? 'info';
  if (!(NOTIFY_SEVERITIES as readonly string[]).includes(minSeverity)) {
    throw new Error(`invalid_min_severity: ${String(minSeverity)}`);
  }
  const events = filters?.events ?? [...NOTIFY_EVENT_KINDS];
  if (!Array.isArray(events)) throw new Error('invalid_notify_events');
  for (const event of events) {
    if (!(NOTIFY_EVENT_KINDS as readonly string[]).includes(event)) {
      throw new Error(`invalid_notify_event: ${String(event)}`);
    }
  }
  return { minSeverity, events: [...events] };
}

export interface ValidatedNotifyChannelInput {
  userId: string;
  type: NotifyChannelType;
  label: string;
  target: NotifyTarget;
  filters: NotifyFilters;
  enabled: boolean;
}

/** Validate a whole create input; returns the normalised form. Throws on bad input. */
export function validateNotifyChannelInput(
  input: CreateNotifyChannelInput,
): ValidatedNotifyChannelInput {
  assertChannelType(input.type);
  assertLabel(input.label);
  if (!input.userId || !input.userId.trim()) throw new Error('notify_user_required');
  return {
    userId: input.userId,
    type: input.type,
    label: input.label.trim(),
    target: validateNotifyTarget(input.type, input.target),
    filters: validateNotifyFilters(input.filters),
    enabled: input.enabled ?? true,
  };
}

/** True when the event's severity meets the channel's minimum. */
export function meetsSeverityThreshold(
  severity: NotifySeverity,
  minSeverity: NotifySeverity,
): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[minSeverity];
}

/** The event an alert is about, kind plus the severity it carries. */
export interface NotifyFilterEvent {
  kind: NotifyEventKind;
  severity: NotifySeverity;
}

/**
 * True when an enabled channel wants this event: the kind is in its
 * event list and the severity clears its minimum. Disabled channels
 * never match.
 */
export function channelMatchesEvent(
  channel: NotifyChannelRecord,
  event: NotifyFilterEvent,
): boolean {
  if (!channel.enabled) return false;
  if (!channel.filters.events.includes(event.kind)) return false;
  return meetsSeverityThreshold(event.severity, channel.filters.minSeverity);
}

// ── Memory implementation ────────────────────────────────────────────────

export class MemoryNotifyChannelStore implements NotifyChannelStore {
  private channels = new Map<string, NotifyChannelRecord>();

  async create(input: CreateNotifyChannelInput): Promise<NotifyChannelRecord> {
    const valid = validateNotifyChannelInput(input);
    // One label per user: re-creating a label replaces the old channel,
    // so a stale destination can never shadow the new one.
    for (const existing of this.channels.values()) {
      if (existing.userId === valid.userId && existing.label === valid.label) {
        this.channels.delete(existing.id);
      }
    }
    const record: NotifyChannelRecord = {
      id: randomUUID(),
      userId: valid.userId,
      type: valid.type,
      label: valid.label,
      target: valid.target,
      filters: { ...valid.filters, events: [...valid.filters.events] },
      enabled: valid.enabled,
      createdAt: nowIso(),
    };
    this.channels.set(record.id, record);
    return structuredClone(record);
  }

  async get(id: string): Promise<NotifyChannelRecord | null> {
    const found = this.channels.get(id);
    return found ? structuredClone(found) : null;
  }

  async listForUser(userId: string): Promise<NotifyChannelRecord[]> {
    return [...this.channels.values()]
      .filter((c) => c.userId === userId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .map((c) => structuredClone(c));
  }

  async remove(id: string, userId: string): Promise<boolean> {
    const found = this.channels.get(id);
    if (!found || found.userId !== userId) return false;
    return this.channels.delete(id);
  }
}

// ── Postgres implementation ──────────────────────────────────────────────

/** The only thing the Postgres store needs: a parametrised query function. */
export type NotifyChannelQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[]; rowCount?: number | null }>;

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function toJsonObject(value: unknown): Record<string, unknown> {
  if (value == null) return {};
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value) as unknown;
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : {};
    } catch {
      return {};
    }
  }
  return value as Record<string, unknown>;
}

export class PostgresNotifyChannelStore implements NotifyChannelStore {
  constructor(private readonly query: NotifyChannelQueryFn) {}

  private toRecord(row: Record<string, unknown>): NotifyChannelRecord {
    const filtersJson = toJsonObject(row['filters']);
    return {
      id: row['id'] as string,
      userId: row['user_id'] as string,
      type: row['type'] as NotifyChannelType,
      label: row['label'] as string,
      target: toJsonObject(row['target']) as unknown as NotifyTarget,
      filters: {
        minSeverity: (filtersJson['minSeverity'] as NotifySeverity) ?? 'info',
        events: Array.isArray(filtersJson['events'])
          ? (filtersJson['events'] as NotifyEventKind[])
          : [...NOTIFY_EVENT_KINDS],
      },
      enabled: Boolean(row['enabled']),
      createdAt: toIso(row['created_at']),
    };
  }

  async create(input: CreateNotifyChannelInput): Promise<NotifyChannelRecord> {
    const valid = validateNotifyChannelInput(input);
    const { rows } = await this.query(
      `INSERT INTO notify_channels (user_id, type, label, target, filters, enabled)
       VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6)
       ON CONFLICT (user_id, label)
       DO UPDATE SET type = EXCLUDED.type,
                     target = EXCLUDED.target,
                     filters = EXCLUDED.filters,
                     enabled = EXCLUDED.enabled
       RETURNING *`,
      [
        valid.userId,
        valid.type,
        valid.label,
        JSON.stringify(valid.target),
        JSON.stringify(valid.filters),
        valid.enabled,
      ],
    );
    return this.toRecord(rows[0]);
  }

  async get(id: string): Promise<NotifyChannelRecord | null> {
    const { rows } = await this.query(`SELECT * FROM notify_channels WHERE id = $1`, [id]);
    return rows[0] ? this.toRecord(rows[0]) : null;
  }

  async listForUser(userId: string): Promise<NotifyChannelRecord[]> {
    const { rows } = await this.query(
      `SELECT * FROM notify_channels WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId],
    );
    return rows.map((r) => this.toRecord(r));
  }

  async remove(id: string, userId: string): Promise<boolean> {
    const { rowCount } = await this.query(
      `DELETE FROM notify_channels WHERE id = $1 AND user_id = $2`,
      [id, userId],
    );
    return (rowCount ?? 0) > 0;
  }
}

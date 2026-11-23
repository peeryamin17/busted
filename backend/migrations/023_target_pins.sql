-- 023_target_pins.sql
-- Target pins + block/allow rule tables.
--
-- A pin is a human-approved target for one task. Pins are append-only:
-- unpinning sets active = false and stamps deactivated_at, never deletes
-- the row. One active pin per (task_id, host, port), enforced by a partial
-- unique index (NULL port means every port, coalesced to -1).
--
-- Rules are standing policy: exact-host, domain-suffix, IPv4 CIDR, or
-- URL-prefix patterns, allow or block, user-wide (task_id NULL) or per
-- task. Removing a rule deactivates it, never deletes it.
--
-- task_id has no foreign key yet; add `references tasks (id) on delete
-- cascade` once the task object stabilises.

create table if not exists target_pins (
  id             uuid primary key default gen_random_uuid(),
  task_id        uuid not null,
  host           text not null,
  port           integer check (port is null or (port >= 1 and port <= 65535)),
  pinned_by      text not null,
  pinned_at      timestamptz not null default now(),
  active         boolean not null default true,
  deactivated_at timestamptz
);

create unique index if not exists target_pins_active_idx
  on target_pins (task_id, host, coalesce(port, -1)) where active;

create index if not exists target_pins_task_idx
  on target_pins (task_id);

create table if not exists target_rules (
  id             uuid primary key default gen_random_uuid(),
  user_id        text not null,
  task_id        uuid,
  kind           text not null check (kind in ('exact-host', 'domain-suffix', 'cidr', 'url-prefix')),
  pattern        text not null,
  action         text not null check (action in ('allow', 'block')),
  created_by     text not null,
  created_at     timestamptz not null default now(),
  active         boolean not null default true,
  deactivated_at timestamptz
);

create index if not exists target_rules_user_idx
  on target_rules (user_id);

create index if not exists target_rules_task_idx
  on target_rules (task_id);

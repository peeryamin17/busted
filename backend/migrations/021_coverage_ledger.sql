-- 021_coverage_ledger.sql
-- Coverage ledger: one row per (task, asset, risk class) recording what
-- was actually examined. A risk class with no row for a task is
-- unexamined, never clean. Risk classes come from the specialist catalog
-- plus 'general'.
--
-- task_id has no foreign key yet; add `references tasks (id) on delete
-- cascade` once the task object stabilises.
--
-- asset_id is NULL for task-level rows. Uniqueness is enforced by an
-- expression index that coalesces NULL asset_id to the zero UUID; the
-- application upsert matches that index.

create table if not exists coverage_ledger (
  id           uuid primary key default gen_random_uuid(),
  task_id      uuid not null,
  asset_id     uuid,
  asset_value  text,
  risk_class   text not null,
  outcome      text not null check (outcome in ('tested', 'untested', 'finding', 'not_applicable')),
  evidence     text,
  reason       text,
  created_at   timestamptz not null default now()
);

create unique index if not exists coverage_ledger_task_asset_class_idx
  on coverage_ledger (task_id, coalesce(asset_id, '00000000-0000-0000-0000-000000000000'::uuid), risk_class);

create index if not exists coverage_ledger_task_idx
  on coverage_ledger (task_id);

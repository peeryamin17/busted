-- 020_retests.sql
-- Retester loop: one row per re-run of a finding's proof. The retester
-- re-runs only the finding's own benign-canary proof; it never invents
-- findings. Verdicts: reproduced, fixed, inconclusive. A retest that
-- could not run is never 'fixed'.
--
-- task_id is nullable and has no foreign key yet; the route resolves it
-- against scans and stores both ids. Add a foreign key to tasks once the
-- task object stabilises.

create table if not exists retests (
  id             uuid primary key default gen_random_uuid(),
  task_id        uuid,
  finding_id     uuid not null references findings (id) on delete cascade,
  scan_id        uuid references scans (id) on delete set null,
  verdict        text not null check (verdict in ('reproduced', 'fixed', 'inconclusive')),
  depth          text,
  evidence       jsonb not null default '[]',
  impact_summary text,
  tested_at      timestamptz not null default now(),
  method         text
);
create index if not exists retests_finding_idx on retests (finding_id);

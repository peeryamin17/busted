-- 011_swarm_jobs.sql — crash-safe persistent job queue for multiagent swarm scans.
-- Supports atomic queue claims with FOR UPDATE SKIP LOCKED and crash recovery.

create table if not exists swarm_jobs (
  id               uuid primary key default gen_random_uuid(),
  user_id          uuid not null references users(id) on delete cascade,
  target_origin    text not null,
  status           text not null default 'queued',
  auth_source      text not null default 'platform_credits',
  surface_snapshot jsonb not null default '{}'::jsonb,
  progress         jsonb not null default '{}'::jsonb,
  error_message    text,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);

create index if not exists swarm_jobs_status_created_idx on swarm_jobs (status, created_at);
create index if not exists swarm_jobs_user_idx on swarm_jobs (user_id);

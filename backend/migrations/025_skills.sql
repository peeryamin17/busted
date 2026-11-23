-- 025_skills.sql
-- Skill-gap ledger + user-added skills.
--
-- skill_gaps is the capability backlog: when the agent hits something it
-- cannot do, it records the gap instead of silently working around it.
-- One row per (task_id, capability), enforced by the unique index below.
--
-- user_skills holds operator-added skill packs. The body is playbook text
-- only: no executable directives, no secrets, and the API never serves a
-- user-added skill body raw. One row per (user_id, name); re-saving
-- replaces the row in place. Disabling sets enabled = false, never deletes
-- the row.
--
-- task_id has no foreign key yet; add `references tasks (id) on delete
-- cascade` once the task object stabilises.

create table if not exists skill_gaps (
  id         uuid primary key default gen_random_uuid(),
  task_id    uuid not null,
  user_id    text not null,
  capability text not null check (char_length(capability) <= 200),
  context    text,
  created_at timestamptz not null default now()
);

create unique index if not exists skill_gaps_task_capability_idx
  on skill_gaps (task_id, capability);

create index if not exists skill_gaps_user_idx
  on skill_gaps (user_id, created_at desc);

create index if not exists skill_gaps_task_idx
  on skill_gaps (task_id);

create table if not exists user_skills (
  id          uuid primary key default gen_random_uuid(),
  user_id     text not null,
  name        text not null,
  description text not null,
  when_to_use text not null,
  roles       text[] not null default '{}',
  tools       text[] not null default '{}',
  body        text not null,
  enabled     boolean not null default true,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create unique index if not exists user_skills_owner_idx
  on user_skills (user_id, name);

create index if not exists user_skills_user_idx
  on user_skills (user_id, created_at desc);

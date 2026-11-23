-- 032_asm_lessons.sql
-- Cross-task lessons.
--
-- `lessons` holds one rule-based lesson extracted from a completed task:
-- what worked, what failed, what repeated. Extraction is deterministic
-- and every lesson carries `evidence` naming the todolist step, finding,
-- retest or coverage entry it came from. Lessons are never deleted.
--
-- `user_lesson_mode` is the per-user promotion gate: 'shadow' (default)
-- or 'off'. There is no 'inject' value: lessons are stored for review and
-- never reach agent prompts until the operator approves promotion and the
-- gate is opened by a code change.
--
-- task_id has no foreign key yet; add `references tasks (id) on delete
-- cascade` once the task object stabilises.

create table if not exists lessons (
  id         uuid primary key default gen_random_uuid(),
  task_id    uuid not null,
  user_id    text not null,
  kind       text not null check (kind in ('worked', 'failed', 'pattern')),
  title      text not null,
  detail     text not null default '',
  evidence   jsonb not null default '[]'::jsonb,
  mode       text not null default 'shadow' check (mode in ('shadow', 'off')),
  created_at timestamptz not null default now()
);
create index if not exists lessons_user_idx
  on lessons (user_id, created_at desc);
create index if not exists lessons_task_idx
  on lessons (task_id);

create table if not exists user_lesson_mode (
  user_id    text primary key,
  mode       text not null default 'shadow' check (mode in ('shadow', 'off')),
  updated_at timestamptz not null default now()
);

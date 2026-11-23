-- 031_side_questions.sql
-- Frozen-context Q&A history.
--
-- One row per question asked against a task's frozen snapshot, with the
-- answer the model gave and how large the snapshot was (snapshot_chars).
-- Q&As are append-only: no update or delete, so the record of what was
-- asked and answered survives as an audit trail. Answers are stored as
-- given; the snapshot itself is rendered on the fly and never persisted.
--
-- task_id has no foreign key yet; add `references tasks (id) on delete
-- cascade` once the task object stabilises.

create table if not exists side_questions (
  id             uuid primary key default gen_random_uuid(),
  task_id        uuid not null,
  user_id        text not null,
  question       text not null,
  answer         text not null,
  snapshot_chars integer not null,
  created_at     timestamptz not null default now()
);

create index if not exists side_questions_task_idx
  on side_questions (task_id);

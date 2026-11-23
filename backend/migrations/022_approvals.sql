-- 022_approvals.sql
-- Approval queue: a swarm step that needs the operator pauses as a pending
-- row in task_approvals and waits for a decision. Decisions are recorded
-- forever; a decided row is never re-decided. A wait that times out marks
-- the row 'expired' and defaults to deny, never allow.
--
-- task_id has no foreign key yet; rule_id likewise has no FK to
-- approval_rules, so a removed rule's decided rows stay as the audit trail.
--
-- decided_by is text, not uuid: a user id, or `rule:<ruleId>` when a stored
-- rule decided the approval.

create table if not exists task_approvals (
  id           uuid primary key default gen_random_uuid(),
  task_id      uuid not null,
  user_id      uuid not null,
  kind         text not null check (kind in ('tool-call', 'new-target', 'judge', 'rule')),
  status       text not null default 'pending'
               check (status in ('pending', 'allowed', 'denied', 'skipped', 'expired')),
  action       text not null check (char_length(action) <= 500),
  detail       jsonb not null default '{}'::jsonb,
  rule_id      uuid,
  risk_score   int check (risk_score >= 0 and risk_score <= 100),
  requested_by text not null check (requested_by in ('swarm', 'judge', 'pin-gate')),
  decided_by   text,
  decided_at   timestamptz,
  created_at   timestamptz not null default now(),
  expires_at   timestamptz
);
create index if not exists task_approvals_task_idx
  on task_approvals (task_id, created_at desc);
create index if not exists task_approvals_pending_idx
  on task_approvals (task_id, created_at) where status = 'pending';

create table if not exists approval_rules (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null,
  task_id       uuid,
  pattern_kind  text not null check (pattern_kind in ('tool', 'target-host', 'category')),
  pattern_value text not null check (char_length(pattern_value) <= 500),
  decision      text not null check (decision in ('allow', 'ask', 'deny')),
  always_allow  boolean not null default false,
  created_at    timestamptz not null default now()
);
create index if not exists approval_rules_user_idx
  on approval_rules (user_id, created_at);

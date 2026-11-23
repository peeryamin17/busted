-- 019_evidence_snapshots.sql
-- Content-addressed evidence snapshots: finding evidence snapshotted into
-- hash-verified blobs, so a finding's proof survives after the live capture
-- is gone and re-checks by recomputing SHA-256.
--
-- evidence_snapshots is keyed by content, not identity: sha256 is the
-- SHA-256 hex of canonical JSON {role, url, request, body} with no user,
-- scan, finding, or timestamp in the hash input. finding_id and task_id
-- are linkage only, never in the hash.
--
-- finding_evidence binds snapshots to findings with a role (baseline |
-- proof | verification | supporting). A finding is "proven" only when a
-- bound proof/verification snapshot still exists and verifies. Bodies are
-- capped at 256 KiB; the body column is bytea so binary captures survive.

create table if not exists evidence_snapshots (
  id         uuid primary key default gen_random_uuid(),
  sha256     text not null unique,
  role       text not null check (role in ('baseline', 'proof', 'verification', 'supporting')),
  finding_id uuid,
  task_id    uuid,
  url        text,
  request    text,
  body       bytea,
  created_at timestamptz not null default now()
);
create index if not exists evidence_snapshots_finding_idx on evidence_snapshots (finding_id);

create table if not exists finding_evidence (
  id              uuid primary key default gen_random_uuid(),
  finding_id      uuid not null,
  snapshot_sha256 text not null references evidence_snapshots (sha256),
  role            text not null check (role in ('baseline', 'proof', 'verification', 'supporting')),
  created_at      timestamptz not null default now()
);
create unique index if not exists finding_evidence_finding_snapshot_idx
  on finding_evidence (finding_id, snapshot_sha256);

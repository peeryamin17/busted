-- 029_workspace_files.sql
-- Workspace file metadata: the "recent files" list for the per-user
-- workspace file manager, without walking the disk. One row per upload,
-- generated report, or code-intake file.
--
-- Metadata only. The bytes live on the backend host's disk, which is
-- ephemeral on the hosted backend: a row may outlive its file after a
-- redeploy. Callers treat a missing file as gone, not as a metadata error.
--
-- user_id is text, following migration 024; task_id has no foreign key.
-- kind is one of 'upload', 'report', or 'intake'.

create table if not exists workspace_files (
  id         uuid primary key default gen_random_uuid(),
  user_id    text not null,
  task_id    uuid,
  rel_path   text not null,
  size_bytes integer not null check (size_bytes >= 0),
  kind       text not null check (kind in ('upload', 'report', 'intake')),
  created_at timestamptz not null default now()
);
create index if not exists workspace_files_user_idx
  on workspace_files (user_id, created_at desc);

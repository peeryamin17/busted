-- 030_companies.sql
-- Companies + task-company links.
--
-- A company is the top of the asset graph: one customer/engagement with a
-- scope (domains in scope, plus free-form notes, stored as jsonb). Tasks
-- link to a company through task_companies; the link threads a company id
-- through tasks, findings and assets. One company per (user_id, name),
-- enforced by the unique index.
--
-- A company is never deleted out from under its tasks: remove() refuses
-- while links exist, and the company_id foreign key cascades only if a row
-- is deleted by another path.
--
-- task_id has no foreign key yet; callers resolve task ids through the
-- graph store and skip ids that no longer resolve.

create table if not exists companies (
  id         uuid primary key default gen_random_uuid(),
  user_id    text not null,
  name       text not null,
  scope      jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create unique index if not exists companies_user_name_idx
  on companies (user_id, name);

create table if not exists task_companies (
  task_id    uuid not null,
  company_id uuid not null references companies (id) on delete cascade,
  user_id    text not null,
  linked_at  timestamptz not null default now(),
  primary key (task_id, company_id)
);

create index if not exists task_companies_company_idx
  on task_companies (company_id);

create index if not exists task_companies_user_idx
  on task_companies (user_id);

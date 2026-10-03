-- Web demo checks ("THE WEB DEMO" on the site).
--
-- A signed-in user pastes a site they own, ticks the authorisation
-- box, and the backend runs a passive patrol. The FULL result is
-- stored here at run time; the API gates what it shows by plan, so
-- upgrading unblurs the stored run — nothing re-scans. `findings` and
-- `info` are the patrol's JSON products (findings carry redacted,
-- name-only evidence by construction — never secret values).
create table if not exists web_checks (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references users (id) on delete cascade,
  url        text not null,
  host       text not null,
  authorized boolean not null default false,
  score      integer,
  grade      text,
  findings   jsonb not null default '[]'::jsonb,
  info       jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists web_checks_user_created_idx
  on web_checks (user_id, created_at desc);

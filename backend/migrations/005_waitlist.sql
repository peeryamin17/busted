-- Launch waitlist ("THE DROP" on the site).
--
-- Emails from the Coming-soon form on the marketing site, stored in
-- our own database — written once, emailed once at launch, never
-- shared. `source` records which form collected the address so
-- future forms don't need a schema change.
create table if not exists waitlist (
  id         uuid primary key default gen_random_uuid(),
  email      text not null unique,
  created_at timestamptz not null default now(),
  source     text not null default 'site-drop'
);

-- email already carries the unique constraint used by the
-- ON CONFLICT dedupe in the API; no extra index needed.

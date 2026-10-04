-- 009_pairing_codes.sql — one-time link codes that pair the extension
-- with a website account. Only the SHA-256 hash of each code is stored;
-- a code expires after 10 minutes and can be exchanged exactly once
-- for a regular API key (POST /api/v1/pair).

create table if not exists pairing_codes (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references users(id) on delete cascade,
  code_hash  text not null unique,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at    timestamptz
);
create index if not exists pairing_codes_user_idx on pairing_codes (user_id);

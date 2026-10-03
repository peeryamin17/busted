-- Google sign-in identity (replaces the Clerk link from 002).
--
-- A BugSeek user can be backed by a Google account. `sub` is the stable
-- Google subject id — the identity key. Email stays the human-facing
-- unique address; name/avatar come from the Google profile. Users who
-- registered with a password link automatically on first Google sign-in
-- with the same email. password_hash stays '' for Google-only users.
alter table users add column if not exists google_sub text;
alter table users add column if not exists name text;
alter table users add column if not exists avatar_url text;
create unique index if not exists users_google_sub_idx
  on users (google_sub) where google_sub is not null;

-- Server-side sessions for the website (bs_session cookie).
-- Only the SHA-256 hash of the session token is stored, so a database
-- leak does not expose usable session tokens.
create table if not exists sessions (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references users (id) on delete cascade,
  token_hash text not null unique,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index if not exists sessions_user_idx on sessions (user_id);
create index if not exists sessions_token_hash_idx on sessions (token_hash);

-- Note: users.clerk_user_id (002) is now legacy and unread by the
-- backend. It is left in place; dropping account-link history is a
-- separate decision.

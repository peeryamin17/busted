-- Clerk identity link: a BugSeek user can be backed by a Clerk account
-- (Google sign-in). clerk_user_id is the Clerk `sub` claim; password_hash
-- stays '' for Clerk-only users (they have no BugSeek password).
alter table users add column if not exists clerk_user_id text;
create unique index if not exists users_clerk_user_id_idx
  on users (clerk_user_id) where clerk_user_id is not null;

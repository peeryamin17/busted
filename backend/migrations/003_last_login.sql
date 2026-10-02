-- Track the most recent login per user (fed by Clerk webhooks:
-- session.created on every sign-in, user.created on sign-up).
alter table users add column if not exists last_login_at timestamptz;

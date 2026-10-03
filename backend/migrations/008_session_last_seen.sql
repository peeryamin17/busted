-- 008_session_last_seen.sql — when each session last did something.
--
-- The five-minute inactivity rule (and pruning the rows it kills)
-- keys off this column. Absolute expiry stays expires_at (30 days).

alter table sessions add column if not exists last_seen_at timestamptz not null default now();

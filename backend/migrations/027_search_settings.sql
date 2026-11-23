-- 027_search_settings.sql
-- Per-user web-search defaults.
--
-- One row per user: which search provider is the default ('duckduckgo'
-- when no row exists). A setting, not a credential: provider API keys live
-- encrypted in `user_secrets` (migration 024, kind 'search') and must never
-- be stored here. `provider` is checked to the known provider names;
-- 'deepseek' is not a search provider and is not a valid default.

create table if not exists search_settings (
  user_id    text primary key,
  provider   text not null check (provider in ('duckduckgo', 'brave', 'tavily', 'keenable')),
  updated_at timestamptz not null default now()
);

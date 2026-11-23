-- 024_user_secrets.sql
-- Generic encrypted provider credentials.
--
-- One table for every user-supplied secret that is not the BYOK AI key
-- (that lives on users, migration 010): web-search provider keys, MCP
-- server credentials, notification channel credentials. Values are
-- AES-256-GCM ciphertext; the table never holds plaintext, and the API
-- only ever returns a masked hint.
--
-- `kind` namespaces rows per consumer ('search', 'mcp', 'notify'); `label`
-- is the provider/channel name within that kind. One row per (user_id,
-- kind, label); re-saving replaces the ciphertext in place.

create table if not exists user_secrets (
  id             uuid primary key default gen_random_uuid(),
  user_id        text not null,
  kind           text not null check (kind in ('search', 'mcp', 'notify')),
  label          text not null,
  encrypted_value text not null,
  hint           text not null default '',
  updated_at     timestamptz not null default now()
);

create unique index if not exists user_secrets_owner_idx
  on user_secrets (user_id, kind, label);

create index if not exists user_secrets_user_kind_idx
  on user_secrets (user_id, kind);

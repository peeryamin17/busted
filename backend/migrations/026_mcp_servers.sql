-- 026_mcp_servers.sql
-- MCP server configs.
--
-- One row per configured remote MCP server: label, http(s) URL, transport
-- ('http' for Streamable HTTP, 'sse' for legacy SSE). A stdio server is
-- rejected by the application before it can be stored: no worker host
-- exists to spawn one.
--
-- This table holds config only. Credentials live in `user_secrets`
-- (migration 024, kind 'mcp', label = server id), encrypted, never stored
-- here. Deleting a server row must be paired with deleting its secret row
-- (the routes do both).
--
-- One server per (user_id, label); a duplicate label is rejected by the
-- unique index (the store reports `mcp_server_label_taken`).

create table if not exists mcp_servers (
  id         uuid primary key default gen_random_uuid(),
  user_id    text not null,
  label      text not null,
  url        text not null,
  transport  text not null check (transport in ('http', 'sse')),
  enabled    boolean not null default true,
  created_at timestamptz not null default now()
);

create unique index if not exists mcp_servers_owner_label_idx
  on mcp_servers (user_id, label);

create index if not exists mcp_servers_user_idx
  on mcp_servers (user_id);

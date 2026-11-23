-- 017_llm_usage.sql
-- Per-call LLM token accounting: one row per LLM call, provider-native
-- token counts (input/output, cache-read/cache-write split), latency,
-- and ok/error status. No price tables here, tokens only.
--
-- llm_wire_traces is the opt-in wire trace (LLM_WIRE_TRACE=1): request
-- and response bodies, stored only after secrets are redacted and bounded
-- to 1 MiB per attempt. Retention is capped at 8 attempts per user
-- (oldest deleted on insert, in the application layer).

create table if not exists llm_usage (
  id                 uuid primary key default gen_random_uuid(),
  user_id            uuid references users (id) on delete set null,
  provider           text not null,
  model              text not null,
  tier               text check (tier in ('routine', 'reasoning', 'code')),
  input_tokens       integer not null default 0 check (input_tokens >= 0),
  output_tokens      integer not null default 0 check (output_tokens >= 0),
  cache_read_tokens  integer not null default 0 check (cache_read_tokens >= 0),
  cache_write_tokens integer not null default 0 check (cache_write_tokens >= 0),
  latency_ms         integer check (latency_ms >= 0),
  status             text not null default 'ok' check (status in ('ok', 'error')),
  created_at         timestamptz not null default now()
);
create index if not exists llm_usage_user_idx on llm_usage (user_id, created_at desc);
create index if not exists llm_usage_provider_model_idx on llm_usage (provider, model, created_at desc);

create table if not exists llm_wire_traces (
  id            uuid primary key default gen_random_uuid(),
  llm_usage_id  uuid not null references llm_usage (id) on delete cascade,
  user_id       uuid references users (id) on delete set null,
  request_body  text,
  response_body text,
  created_at    timestamptz not null default now()
);
create index if not exists llm_wire_traces_user_idx on llm_wire_traces (user_id, created_at desc);

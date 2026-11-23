-- 034_multi_provider_keys.sql
-- Per-provider BYOK keys (one encrypted key per user per provider) plus
-- the user's worker/reasoning tier routing. The legacy single key on
-- users (migration 010) stays as-is for older clients.

CREATE TABLE IF NOT EXISTS user_ai_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL CHECK (
    provider_id IN ('gemini', 'claude', 'qwen', 'kimi', 'glm', 'deepseek', 'openrouter', 'ollama')
  ),
  encrypted_key TEXT NOT NULL,
  key_hint TEXT NOT NULL,
  base_url TEXT NOT NULL,
  verified_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, provider_id)
);

CREATE TABLE IF NOT EXISTS user_llm_routing (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  worker_provider TEXT NOT NULL DEFAULT 'gemini',
  worker_model TEXT,
  reasoning_provider TEXT NOT NULL DEFAULT 'gemini',
  reasoning_model TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_ai_keys_user ON user_ai_keys(user_id);

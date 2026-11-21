-- 010_user_ai_key.sql
-- Stores each user's encrypted BYOK AI key (AES-256-GCM) and a safe masked hint.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS encrypted_ai_key TEXT,
  ADD COLUMN IF NOT EXISTS ai_provider TEXT NOT NULL DEFAULT 'gemini',
  ADD COLUMN IF NOT EXISTS ai_key_hint TEXT,
  ADD COLUMN IF NOT EXISTS ai_key_updated_at TIMESTAMPTZ;

-- 037_openai_provider.sql
-- Allow 'openai' in user_ai_keys.provider_id. Migration 034 created
-- the table with 8 providers; this widens the CHECK to 9. The
-- constraint name is the auto-generated one from 034, so the drop
-- targets it by name and the add keeps the same name.

ALTER TABLE user_ai_keys DROP CONSTRAINT IF EXISTS user_ai_keys_provider_id_check;
ALTER TABLE user_ai_keys ADD CONSTRAINT user_ai_keys_provider_id_check CHECK (
  provider_id IN ('gemini', 'claude', 'qwen', 'kimi', 'glm', 'deepseek', 'openrouter', 'openai', 'ollama')
);

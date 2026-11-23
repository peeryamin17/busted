-- 016_ai_base_url.sql
-- BYOK provider picker: store the provider-specific base URL for a
-- user's BYOK key, the DashScope region endpoint for Qwen. Gemini and
-- Ollama leave it NULL. The URL is always one of the known DashScope
-- endpoints or a custom workspace URL validated server-side (host must end
-- in.aliyuncs.com, path /compatible-mode/v1); the raw user input is never
-- stored or fetched.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS ai_base_url TEXT;

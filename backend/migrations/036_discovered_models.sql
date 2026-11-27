-- 036_discovered_models.sql
-- Model IDs each provider key can use, as returned by the provider's
-- /models list at verify time. Null when the provider has no list
-- endpoint (Claude) or the list came back empty or unparsable; a null
-- here never means the key itself is bad.

ALTER TABLE user_ai_keys ADD COLUMN IF NOT EXISTS discovered_models JSONB;

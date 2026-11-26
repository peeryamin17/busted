-- 035_corroboration_counters.sql
-- Per-campaign verification-economy counters: one row per counted tier
-- use (oracle run, strong-model re-check) or per cap skip. Caps are
-- enforced by counting 'used' rows per task and tier (20 each); a use
-- past the cap is recorded as 'skipped-for-cap', never dropped silently.
--
-- task_id has no foreign key yet, matching retests (migration 020):
-- add one to tasks once the task object stabilises. finding_ref is a
-- free-form label (finding id when known, else title + location), so
-- the head can record runs for findings that have no DB row yet.

CREATE TABLE IF NOT EXISTS corroboration_counters (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  task_id UUID NOT NULL,
  finding_ref TEXT,
  tier TEXT NOT NULL CHECK (tier IN ('oracle', 'strong-model')),
  outcome TEXT NOT NULL CHECK (outcome IN ('used', 'skipped-for-cap')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_corroboration_counters_task ON corroboration_counters (task_id, tier);

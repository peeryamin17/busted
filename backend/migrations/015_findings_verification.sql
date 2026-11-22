-- 015_findings_verification.sql
-- Swarm depth-ladder verification (Thread 4): persist the ladder's verdict
-- (verified/hint, depth, impact, canary evidence) alongside each finding,
-- so /api/scans/:id/report can render verified chains from the DB.
-- Nullable JSONB: findings from older scans and other sources have none.

ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS verification JSONB;

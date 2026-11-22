-- 014_detections.sql
-- Runtime detection layer (Thread 5, DEFENSIVE): detections the rule
-- engine persists for the site owner to read back. Evidence is redacted
-- by construction (counts, paths, key prefixes, attacker IPs — never
-- secrets, never password material, never plaintext account identifiers).

CREATE TABLE IF NOT EXISTS detections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pattern TEXT NOT NULL CHECK (pattern IN (
    'failed-login-velocity',
    'password-spray',
    'many-accounts-few-ips',
    'user-agent-diversity',
    'api-key-anomaly',
    'probe-pattern'
  )),
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  title TEXT NOT NULL,
  detail TEXT NOT NULL,
  evidence TEXT,
  dedupe_key TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS detections_user_created_idx
  ON detections (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS detections_dedupe_idx
  ON detections (user_id, dedupe_key, created_at DESC);

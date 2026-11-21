-- 013_universal_ontology.sql
-- Expands the Security Ontology to support vibe-coded BaaS, legacy monoliths, SPAs, and CMS platforms.

ALTER TABLE ontology_objects
  DROP CONSTRAINT IF EXISTS ontology_objects_object_type_check;

ALTER TABLE ontology_objects
  ADD CONSTRAINT ontology_objects_object_type_check CHECK (
    object_type IN (
      'Origin', 'Asset', 'Endpoint', 'Identity', 'Control', 'Sink', 'Resource',
      'BaaSProject', 'ClientSecret', 'StorageBucket', 'ServerAction',
      'LibraryVersion', 'HtmlForm', 'SessionCookie', 'TlsPolicy'
    )
  );

ALTER TABLE ontology_links
  DROP CONSTRAINT IF EXISTS ontology_links_link_type_check;

ALTER TABLE ontology_links
  ADD CONSTRAINT ontology_links_link_type_check CHECK (
    link_type IN (
      'DECLARES', 'PROTECTS', 'CAN_INVOKE', 'MUTATES', 'FLOWS_TO', 'HOSTS',
      'EMBEDS', 'DIRECT_DB_CALL', 'LOADS', 'POSTS_TO', 'SECURES', 'EXPOSES'
    )
  );

-- Deterministic AIP audit trail: every tool call and policy decision is logged immutably
CREATE TABLE IF NOT EXISTS aip_audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL,
  actor TEXT NOT NULL,                 -- 'head_agent' | 'validator_agent' | 'policy_gate'
  tool_name TEXT NOT NULL,
  args JSONB NOT NULL DEFAULT '{}',
  policy_decision TEXT NOT NULL CHECK (policy_decision IN ('ALLOW', 'DENY')),
  deny_reason TEXT,
  latency_ms INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aip_audit_scan ON aip_audit_log(scan_id, created_at);

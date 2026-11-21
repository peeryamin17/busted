-- 011_ontology.sql
-- Immutable evidence provenance + typed Security Ontology graph.

CREATE TABLE IF NOT EXISTS evidence_blobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL,
  sha256 TEXT NOT NULL,
  source_kind TEXT NOT NULL,           -- 'http_frame' | 'js_bundle' | 'header_audit' | 'cookie_audit'
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (scan_id, sha256)
);

CREATE TABLE IF NOT EXISTS ontology_objects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL,
  object_type TEXT NOT NULL CHECK (
    object_type IN ('Origin', 'Asset', 'Endpoint', 'Identity', 'Control', 'Sink', 'Resource')
  ),
  canonical_key TEXT NOT NULL,         -- e.g., 'POST:/api/BasketItems/:id'
  properties JSONB NOT NULL DEFAULT '{}',
  confidence REAL NOT NULL DEFAULT 1.0 CHECK (confidence >= 0 AND confidence <= 1),
  provenance_id UUID NOT NULL REFERENCES evidence_blobs(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (scan_id, object_type, canonical_key)
);

CREATE TABLE IF NOT EXISTS ontology_links (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL,
  source_id UUID NOT NULL REFERENCES ontology_objects(id) ON DELETE CASCADE,
  target_id UUID NOT NULL REFERENCES ontology_objects(id) ON DELETE CASCADE,
  link_type TEXT NOT NULL CHECK (
    link_type IN ('DECLARES', 'PROTECTS', 'CAN_INVOKE', 'MUTATES', 'FLOWS_TO', 'HOSTS')
  ),
  properties JSONB NOT NULL DEFAULT '{}',
  provenance_id UUID NOT NULL REFERENCES evidence_blobs(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (scan_id, source_id, target_id, link_type)
);

CREATE INDEX IF NOT EXISTS idx_evidence_scan_sha ON evidence_blobs(scan_id, sha256);
CREATE INDEX IF NOT EXISTS idx_ont_obj_scan_type ON ontology_objects(scan_id, object_type);
CREATE INDEX IF NOT EXISTS idx_ont_links_src ON ontology_links(scan_id, source_id, link_type);
CREATE INDEX IF NOT EXISTS idx_ont_links_tgt ON ontology_links(scan_id, target_id, link_type);

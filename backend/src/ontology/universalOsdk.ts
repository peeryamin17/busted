import type { Pool } from 'pg';

export interface OntologyRiskNode {
  nodeId: string;
  objectType: string;
  canonicalKey: string;
  properties: Record<string, unknown>;
  provenanceId: string;
  riskCategory: string;
}

export class UniversalOSDK {
  constructor(private readonly pool: Pool) {}

  /**
   * Vibe-Coded Risk Query:
   * 1. Any ClientSecret embedded in a browser Asset.
   * 2. Any BaaSProject called directly from the browser without an RLS_ENFORCED control edge.
   */
  async getVibeCodedRisks(scanId: string): Promise<OntologyRiskNode[]> {
    const { rows } = await this.pool.query<OntologyRiskNode>(
      `SELECT
         o.id            AS "nodeId",
         o.object_type   AS "objectType",
         o.canonical_key AS "canonicalKey",
         o.properties    AS "properties",
         o.provenance_id AS "provenanceId",
         'CLIENT_SECRET_EXPOSURE' AS "riskCategory"
       FROM ontology_objects o
       WHERE o.scan_id = $1 AND o.object_type = 'ClientSecret'

       UNION ALL

       SELECT
         b.id,
         b.object_type,
         b.canonical_key,
         b.properties,
         b.provenance_id,
         'DIRECT_BAAS_WITHOUT_RLS'
       FROM ontology_objects b
       WHERE b.scan_id = $1
         AND b.object_type = 'BaaSProject'
         AND NOT EXISTS (
           SELECT 1
           FROM ontology_links l
           JOIN ontology_objects c ON c.id = l.source_id
           WHERE l.scan_id = b.scan_id
             AND l.target_id = b.id
             AND l.link_type = 'PROTECTS'
             AND c.canonical_key = 'RLS_ENFORCED'
         )`,
      [scanId]
    );
    return rows;
  }

  /**
   * Legacy Monolith Control Gap Query:
   * 1. POST HtmlForms missing a CSRF_TOKEN protection edge.
   * 2. SessionCookies missing HttpOnly or Secure flags.
   */
  async getLegacyControlGaps(scanId: string): Promise<OntologyRiskNode[]> {
    const { rows } = await this.pool.query<OntologyRiskNode>(
      `SELECT
         f.id            AS "nodeId",
         f.object_type   AS "objectType",
         f.canonical_key AS "canonicalKey",
         f.properties    AS "properties",
         f.provenance_id AS "provenanceId",
         'FORM_MISSING_CSRF' AS "riskCategory"
       FROM ontology_objects f
       WHERE f.scan_id = $1
         AND f.object_type = 'HtmlForm'
         AND f.properties->>'method' = 'POST'
         AND NOT EXISTS (
           SELECT 1
           FROM ontology_links l
           JOIN ontology_objects c ON c.id = l.source_id
           WHERE l.scan_id = f.scan_id
             AND l.target_id = f.id
             AND l.link_type = 'PROTECTS'
             AND c.canonical_key = 'CSRF_TOKEN'
         )

       UNION ALL

       SELECT
         c.id,
         c.object_type,
         c.canonical_key,
         c.properties,
         c.provenance_id,
         'INSECURE_SESSION_COOKIE'
       FROM ontology_objects c
       WHERE c.scan_id = $1
         AND c.object_type = 'SessionCookie'
         AND (
           (c.properties->>'httpOnly')::boolean IS DISTINCT FROM TRUE
           OR (c.properties->>'secure')::boolean IS DISTINCT FROM TRUE
         )`,
      [scanId]
    );
    return rows;
  }
}

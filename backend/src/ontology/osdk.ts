import type { Pool } from 'pg';

export interface UnprotectedMutation {
  endpointId: string;
  canonicalKey: string;
  properties: Record<string, unknown>;
  provenanceId: string;
  invokerRole: string;
}

export interface BlastRadiusNode {
  nodeId: string;
  objectType: string;
  canonicalKey: string;
  depth: number;
  path: string[];
}

export interface GraphDelta {
  addedObjects: Array<{ objectType: string; canonicalKey: string }>;
  removedObjects: Array<{ objectType: string; canonicalKey: string }>;
  removedControls: Array<{ canonicalKey: string; properties: Record<string, unknown> }>;
}

export class BugSeekOSDK {
  constructor(private readonly pool: Pool) {}

  /**
   * Deterministic graph query:
   * Find every Endpoint that MUTATES a Resource but has NO incoming PROTECTS edge
   * from a CSRF_TOKEN control.
   */
  async getUnprotectedMutations(scanId: string): Promise<UnprotectedMutation[]> {
    const { rows } = await this.pool.query<UnprotectedMutation>(
      `SELECT
         ep.id            AS "endpointId",
         ep.canonical_key AS "canonicalKey",
         ep.properties    AS "properties",
         ep.provenance_id AS "provenanceId",
         id_obj.canonical_key AS "invokerRole"
       FROM ontology_objects ep
       JOIN ontology_links mut
         ON mut.scan_id = ep.scan_id
        AND mut.source_id = ep.id
        AND mut.link_type = 'MUTATES'
       LEFT JOIN ontology_links inv
         ON inv.scan_id = ep.scan_id
        AND inv.target_id = ep.id
        AND inv.link_type = 'CAN_INVOKE'
       LEFT JOIN ontology_objects id_obj
         ON id_obj.id = inv.source_id
       WHERE ep.scan_id = $1
         AND ep.object_type = 'Endpoint'
         AND NOT EXISTS (
           SELECT 1
           FROM ontology_links prot
           JOIN ontology_objects ctrl ON ctrl.id = prot.source_id
           WHERE prot.scan_id = ep.scan_id
             AND prot.target_id = ep.id
             AND prot.link_type = 'PROTECTS'
             AND ctrl.canonical_key = 'CSRF_TOKEN'
         )`,
      [scanId]
    );
    return rows;
  }

  /**
   * Recursive CTE traversal:
   * Computes downstream blast radius up to maxDepth hops from any compromised node.
   */
  async getBlastRadius(
    scanId: string,
    startNodeId: string,
    maxDepth = 3
  ): Promise<BlastRadiusNode[]> {
    const { rows } = await this.pool.query<BlastRadiusNode>(
      `WITH RECURSIVE traverse AS (
         SELECT
           o.id AS node_id,
           o.object_type,
           o.canonical_key,
           0 AS depth,
           ARRAY[o.canonical_key] AS path,
           ARRAY[o.id] AS visited
         FROM ontology_objects o
         WHERE o.scan_id = $1 AND o.id = $2

         UNION ALL

         SELECT
           nxt.id,
           nxt.object_type,
           nxt.canonical_key,
           t.depth + 1,
           t.path || nxt.canonical_key,
           t.visited || nxt.id
         FROM traverse t
         JOIN ontology_links l
           ON l.scan_id = $1 AND l.source_id = t.node_id
         JOIN ontology_objects nxt
           ON nxt.id = l.target_id
         WHERE t.depth < $3
           AND NOT (nxt.id = ANY(t.visited))
       )
       SELECT
         node_id       AS "nodeId",
         object_type   AS "objectType",
         canonical_key AS "canonicalKey",
         depth,
         path
       FROM traverse
       WHERE depth > 0
       ORDER BY depth ASC`,
      [scanId, startNodeId, maxDepth]
    );
    return rows;
  }

  /**
   * Temporal Drift Engine:
   * Computes Delta G = G(currentScanId) \ G(previousScanId) to detect
   * new attack surface and security control regressions across deployments.
   */
  async getGraphDelta(previousScanId: string, currentScanId: string): Promise<GraphDelta> {
    const [added, removed, removedControls] = await Promise.all([
      this.pool.query<{ objectType: string; canonicalKey: string }>(
        `SELECT cur.object_type AS "objectType", cur.canonical_key AS "canonicalKey"
         FROM ontology_objects cur
         LEFT JOIN ontology_objects prev
           ON prev.scan_id = $1
          AND prev.object_type = cur.object_type
          AND prev.canonical_key = cur.canonical_key
         WHERE cur.scan_id = $2 AND prev.id IS NULL`,
        [previousScanId, currentScanId]
      ),
      this.pool.query<{ objectType: string; canonicalKey: string }>(
        `SELECT prev.object_type AS "objectType", prev.canonical_key AS "canonicalKey"
         FROM ontology_objects prev
         LEFT JOIN ontology_objects cur
           ON cur.scan_id = $2
          AND cur.object_type = prev.object_type
          AND cur.canonical_key = prev.canonical_key
         WHERE prev.scan_id = $1 AND cur.id IS NULL`,
        [previousScanId, currentScanId]
      ),
      this.pool.query<{ canonicalKey: string; properties: Record<string, unknown> }>(
        `SELECT prev.canonical_key AS "canonicalKey", prev.properties
         FROM ontology_objects prev
         LEFT JOIN ontology_objects cur
           ON cur.scan_id = $2
          AND cur.object_type = 'Control'
          AND cur.canonical_key = prev.canonical_key
         WHERE prev.scan_id = $1
           AND prev.object_type = 'Control'
           AND cur.id IS NULL`,
        [previousScanId, currentScanId]
      ),
    ]);

    return {
      addedObjects: added.rows,
      removedObjects: removed.rows,
      removedControls: removedControls.rows,
    };
  }

  /**
   * Zero-Hallucination Gate:
   * Verifies that every provenance_id cited by an AI specialist actually exists
   * in evidence_blobs for this scan before allowing a finding into the report.
   */
  async verifyProvenance(scanId: string, provenanceIds: string[]): Promise<boolean> {
    if (provenanceIds.length === 0) return false;
    const unique = [...new Set(provenanceIds)];
    const { rows } = await this.pool.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count
       FROM evidence_blobs
       WHERE scan_id = $1 AND id = ANY($2::uuid[])`,
      [scanId, unique]
    );
    return Number(rows[0].count) === unique.length;
  }
}

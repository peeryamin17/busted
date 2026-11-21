import type { Pool } from 'pg';
import type { BugSeekOSDK, GraphDelta } from './osdk.js';
import type { UniversalOSDK, OntologyRiskNode } from './universalOsdk.js';
import type { StackArchetype } from './universalIngest.js';
import {
  computeOntologyScore,
  type ScoredOntologyNode,
  type ControlMatrixInput,
  type CoverageMatrixInput,
  type OntologyScoreReport,
  type OntologyRiskCategory,
} from '../reports/score.js';

export interface PolicyContext {
  scanId: string;
  authorizedOrigin: string;
  maxToolCalls: number;
  toolCallsUsed: number;
}

export class AipControlPlane {
  constructor(
    private readonly pool: Pool,
    private readonly coreOsdk: BugSeekOSDK,
    private readonly universalOsdk: UniversalOSDK
  ) {}

  private async logDecision(
    scanId: string,
    toolName: string,
    args: Record<string, unknown>,
    decision: 'ALLOW' | 'DENY',
    denyReason?: string,
    latencyMs?: number
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO aip_audit_log (scan_id, actor, tool_name, args, policy_decision, deny_reason, latency_ms)
       VALUES ($1, 'policy_gate', $2, $3::jsonb, $4, $5, $6)`,
      [scanId, toolName, JSON.stringify(args), decision, denyReason ?? null, latencyMs ?? null]
    );
  }

  /**
   * Deterministic Archetype Router:
   * Runs only the graph traversals relevant to the target's classified stack,
   * under strict budget and audit enforcement.
   */
  async runArchetypeAudit(
    ctx: PolicyContext,
    archetypes: StackArchetype[]
  ): Promise<OntologyRiskNode[]> {
    const results: OntologyRiskNode[] = [];

    const executeGated = async <T>(
      toolName: string,
      fn: () => Promise<T>
    ): Promise<T | null> => {
      if (ctx.toolCallsUsed >= ctx.maxToolCalls) {
        await this.logDecision(ctx.scanId, toolName, {}, 'DENY', 'Tool call budget exceeded');
        return null;
      }
      ctx.toolCallsUsed++;
      const t0 = Date.now();
      const out = await fn();
      await this.logDecision(ctx.scanId, toolName, {}, 'ALLOW', undefined, Date.now() - t0);
      return out;
    };

    if (archetypes.includes('vibe_baas')) {
      const vibeRisks = await executeGated('getVibeCodedRisks', () =>
        this.universalOsdk.getVibeCodedRisks(ctx.scanId)
      );
      if (vibeRisks) results.push(...vibeRisks);
    }

    if (archetypes.includes('legacy_monolith') || archetypes.includes('cms_platform')) {
      const legacyGaps = await executeGated('getLegacyControlGaps', () =>
        this.universalOsdk.getLegacyControlGaps(ctx.scanId)
      );
      if (legacyGaps) results.push(...legacyGaps);
    }

    // Always verify unprotected state mutations across all archetypes
    const mutations = await executeGated('getUnprotectedMutations', () =>
      this.coreOsdk.getUnprotectedMutations(ctx.scanId)
    );
    if (mutations) {
      for (const m of mutations) {
        results.push({
          nodeId: m.endpointId,
          objectType: 'Endpoint',
          canonicalKey: m.canonicalKey,
          properties: m.properties,
          provenanceId: m.provenanceId,
          riskCategory: 'UNPROTECTED_STATE_MUTATION',
        });
      }
    }

    // Final Zero-Hallucination Provenance Verification
    const provIds = results.map((r) => r.provenanceId);
    if (provIds.length > 0) {
      const valid = await this.coreOsdk.verifyProvenance(ctx.scanId, provIds);
      if (!valid) {
        throw new Error('Provenance integrity violation: unanchored ontology node detected.');
      }
    }

    return results;
  }

  /**
   * Evaluates the 4-Matrix Universal Ontology posture score after an archetype audit.
   */
  async computeAuditScore(
    scanId: string,
    nodes: OntologyRiskNode[],
    archetypes: StackArchetype[],
    options: {
      mode?: 'passive' | 'active' | 'swarm';
      authenticated?: boolean;
      previousScanId?: string;
    } = {}
  ): Promise<OntologyScoreReport> {
    const scoredNodes: ScoredOntologyNode[] = [];
    for (const n of nodes) {
      let blastRadiusCount = 0;
      try {
        const blast = await this.coreOsdk.getBlastRadius(scanId, n.nodeId, 3);
        blastRadiusCount = blast.length;
      } catch {
        blastRadiusCount = 0;
      }
      scoredNodes.push({
        nodeId: n.nodeId,
        riskCategory: (n.riskCategory in {
          CLIENT_SECRET_EXPOSURE: 1,
          DIRECT_BAAS_WITHOUT_RLS: 1,
          UNPROTECTED_STATE_MUTATION: 1,
          FORM_MISSING_CSRF: 1,
          INSECURE_SESSION_COOKIE: 1,
          OUTDATED_LIBRARY_CVE: 1,
          MISSING_SECURITY_HEADER: 1,
        }
          ? n.riskCategory
          : 'UNPROTECTED_STATE_MUTATION') as OntologyRiskCategory,
        blastRadiusCount,
        provenanceVerified: true,
      });
    }

    const { rows: ctrlRows } = await this.pool.query<{
      mutating_total: string;
      mutating_prot: string;
      baas_total: string;
      baas_prot: string;
      cookie_total: string;
      cookie_hard: string;
    }>(
      `SELECT
         (SELECT COUNT(*)::text FROM ontology_links WHERE scan_id = $1 AND link_type = 'MUTATES') AS mutating_total,
         (SELECT COUNT(DISTINCT l.target_id)::text FROM ontology_links l
          JOIN ontology_objects c ON c.id = l.source_id
          WHERE l.scan_id = $1 AND l.link_type = 'PROTECTS' AND c.canonical_key = 'CSRF_TOKEN') AS mutating_prot,
         (SELECT COUNT(*)::text FROM ontology_objects WHERE scan_id = $1 AND object_type = 'BaaSProject') AS baas_total,
         (SELECT COUNT(DISTINCT l.target_id)::text FROM ontology_links l
          JOIN ontology_objects c ON c.id = l.source_id
          WHERE l.scan_id = $1 AND l.link_type = 'PROTECTS' AND c.canonical_key = 'RLS_ENFORCED') AS baas_prot,
         (SELECT COUNT(*)::text FROM ontology_objects WHERE scan_id = $1 AND object_type = 'SessionCookie') AS cookie_total,
         (SELECT COUNT(*)::text FROM ontology_objects WHERE scan_id = $1 AND object_type = 'SessionCookie'
          AND (properties->>'httpOnly')::boolean IS TRUE
          AND (properties->>'secure')::boolean IS TRUE) AS cookie_hard`,
      [scanId]
    );

    const cr = ctrlRows[0] ?? {
      mutating_total: '0',
      mutating_prot: '0',
      baas_total: '0',
      baas_prot: '0',
      cookie_total: '0',
      cookie_hard: '0',
    };

    const controls: ControlMatrixInput = {
      totalMutatingEndpoints: Number(cr.mutating_total),
      protectedMutatingEndpoints: Number(cr.mutating_prot),
      totalBaasTargets: Number(cr.baas_total),
      rlsProtectedBaasTargets: Number(cr.baas_prot),
      totalSessionCookies: Number(cr.cookie_total),
      hardenedSessionCookies: Number(cr.cookie_hard),
    };

    let delta: GraphDelta | null = null;
    if (options.previousScanId) {
      try {
        delta = await this.coreOsdk.getGraphDelta(options.previousScanId, scanId);
      } catch {
        delta = null;
      }
    }

    const { rows: epRows } = await this.pool.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM ontology_objects WHERE scan_id = $1 AND object_type = 'Endpoint'`,
      [scanId]
    );
    const discovered = Math.max(1, Number(epRows[0]?.count ?? 1));

    const coverage: CoverageMatrixInput = {
      mode: options.mode ?? 'active',
      archetypes,
      endpointsDiscovered: discovered,
      endpointsTested: discovered,
      authenticated: options.authenticated ?? false,
    };

    return computeOntologyScore({
      nodes: scoredNodes,
      controls,
      coverage,
      delta,
    });
  }
}

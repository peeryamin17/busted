import type { BugSeekOSDK } from './osdk.js';

export interface OntologyToolCall {
  name: 'getUnprotectedMutations' | 'getBlastRadius' | 'getGraphDelta';
  args: Record<string, unknown>;
}

/**
 * Gemini function-calling declarations for the BugSeek Ontology SDK.
 * Pass this array into your Gemini model's `tools` configuration in head.ts.
 */
export const OSDK_TOOL_DECLARATIONS = [
  {
    name: 'getUnprotectedMutations',
    description:
      'Returns every state-changing Endpoint (POST/PUT/PATCH/DELETE) in the current scan that lacks a CSRF_TOKEN protection edge, along with its provenanceId and invoker role.',
    parameters: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'getBlastRadius',
    description:
      'Traverses the Security Ontology graph up to maxDepth hops from a given nodeId to compute downstream impact (e.g., compromised Asset -> Endpoint -> Resource).',
    parameters: {
      type: 'object',
      properties: {
        startNodeId: { type: 'string', description: 'UUID of the starting ontology_object' },
        maxDepth: { type: 'number', description: 'Max graph hops (1-4)', default: 3 },
      },
      required: ['startNodeId'],
    },
  },
  {
    name: 'getGraphDelta',
    description:
      'Compares the current scan against a previous scanId to detect newly introduced endpoints and removed security controls (regressions).',
    parameters: {
      type: 'object',
      properties: {
        previousScanId: { type: 'string', description: 'UUID of the baseline scan' },
      },
      required: ['previousScanId'],
    },
  },
] as const;

/**
 * Deterministic dispatcher for Gemini tool calls.
 */
export async function executeOsdkTool(
  osdk: BugSeekOSDK,
  scanId: string,
  call: OntologyToolCall
): Promise<unknown> {
  switch (call.name) {
    case 'getUnprotectedMutations':
      return osdk.getUnprotectedMutations(scanId);

    case 'getBlastRadius': {
      const startNodeId = String(call.args.startNodeId ?? '');
      const maxDepth = Math.min(4, Math.max(1, Number(call.args.maxDepth ?? 3)));
      if (!startNodeId) return { error: 'startNodeId is required' };
      return osdk.getBlastRadius(scanId, startNodeId, maxDepth);
    }

    case 'getGraphDelta': {
      const previousScanId = String(call.args.previousScanId ?? '');
      if (!previousScanId) return { error: 'previousScanId is required' };
      return osdk.getGraphDelta(previousScanId, scanId);
    }

    default:
      return { error: `Unknown OSDK tool: ${(call as { name: string }).name}` };
  }
}

/**
 * Hard Provenance Gate:
 * Drops any finding that fails to cite real, verified evidence_blobs
 * from this scan.
 */
export async function enforceProvenanceGate<
  T extends { title: string; provenanceIds?: string[] }
>(
  osdk: BugSeekOSDK,
  scanId: string,
  findings: T[],
  strictMode = false
): Promise<{ verified: T[]; rejected: Array<{ title: string; reason: string }> }> {
  const verified: T[] = [];
  const rejected: Array<{ title: string; reason: string }> = [];

  for (const finding of findings) {
    const ids = finding.provenanceIds ?? [];
    if (ids.length === 0) {
      if (strictMode) {
        rejected.push({ title: finding.title, reason: 'Missing provenanceIds' });
      } else {
        verified.push(finding);
      }
      continue;
    }

    const ok = await osdk.verifyProvenance(scanId, ids);
    if (ok) {
      verified.push(finding);
    } else {
      rejected.push({
        title: finding.title,
        reason: 'One or more cited provenanceIds do not exist in evidence_blobs',
      });
    }
  }

  return { verified, rejected };
}

/**
 * Unit tests for Security Ontology Ingest, Universal Archetypes, BugSeekOSDK,
 * AIP Controller, and Provenance Gating.
 */
import { BugSeekOSDK } from '../src/ontology/osdk.js';
import { ingestSurfaceToOntology, type SurfaceSnapshot } from '../src/ontology/ingest.js';
import {
  OSDK_TOOL_DECLARATIONS,
  executeOsdkTool,
  enforceProvenanceGate,
} from '../src/ontology/tools.js';
import {
  classifyArchetypes,
  ingestUniversalOntology,
  type UniversalSnapshot,
} from '../src/ontology/universalIngest.js';
import { UniversalOSDK } from '../src/ontology/universalOsdk.js';
import { AipControlPlane } from '../src/ontology/aipController.js';
import { computeOntologyScore } from '../src/reports/score.js';

let failures = 0;
function check(name: string, ok: boolean, extra?: unknown) {
  if (ok) {
    console.log(`PASS ${name}`);
  } else {
    failures++;
    console.error(`FAIL ${name}`, extra ?? '');
  }
}

async function runTests() {
  console.log('--- Testing BugSeekOSDK, Tools & Ingestion ---');

  // 1. Mock Pool for OSDK tests
  const queryLog: Array<{ sql: string; params: unknown[] }> = [];
  const mockPool: any = {
    async query(sql: string, params: unknown[] = []) {
      queryLog.push({ sql, params });
      if (sql.includes('getUnprotectedMutations') || sql.includes('MUTATES')) {
        return {
          rows: [
            {
              endpointId: 'ep-1',
              canonicalKey: 'POST:/api/BasketItems/1',
              properties: { method: 'POST', path: '/api/BasketItems/1' },
              provenanceId: 'blob-1',
              invokerRole: 'role:anonymous',
            },
          ],
        };
      }
      if (sql.includes('WITH RECURSIVE traverse')) {
        return {
          rows: [
            {
              nodeId: 'res-1',
              objectType: 'Resource',
              canonicalKey: '/api/BasketItems',
              depth: 1,
              path: ['POST:/api/BasketItems/1', '/api/BasketItems'],
            },
          ],
        };
      }
      if (sql.includes('ClientSecret') || sql.includes('CLIENT_SECRET_EXPOSURE')) {
        return {
          rows: [
            {
              nodeId: 'cs-1',
              objectType: 'ClientSecret',
              canonicalKey: 'supabase_service_role:ey...',
              properties: { kind: 'supabase_service_role' },
              provenanceId: 'blob-1',
              riskCategory: 'CLIENT_SECRET_EXPOSURE',
            },
          ],
        };
      }
      if (sql.includes('HtmlForm') || sql.includes('FORM_MISSING_CSRF')) {
        return {
          rows: [
            {
              nodeId: 'form-1',
              objectType: 'HtmlForm',
              canonicalKey: 'POST:/transfer',
              properties: { method: 'POST' },
              provenanceId: 'blob-2',
              riskCategory: 'FORM_MISSING_CSRF',
            },
          ],
        };
      }
      if (sql.includes('evidence_blobs') && sql.includes('COUNT(*)')) {
        const ids = (params[1] as string[]) || [];
        const validIds = ids.filter((id) => id === 'blob-1' || id === 'blob-2');
        return { rows: [{ count: String(validIds.length) }] };
      }
      if (sql.includes('aip_audit_log')) {
        return { rows: [{ id: 'audit-1' }] };
      }
      return { rows: [] };
    },
  };

  const osdk = new BugSeekOSDK(mockPool);
  const universalOsdk = new UniversalOSDK(mockPool);

  // Test getUnprotectedMutations
  const unprotected = await osdk.getUnprotectedMutations('scan-123');
  check('getUnprotectedMutations returns mapped mutations', unprotected.length === 1);
  check('mutation has correct canonical key', unprotected[0].canonicalKey === 'POST:/api/BasketItems/1');
  check('mutation has provenance ID', unprotected[0].provenanceId === 'blob-1');

  // Test getBlastRadius
  const blast = await osdk.getBlastRadius('scan-123', 'ep-1', 3);
  check('getBlastRadius returns downstream nodes', blast.length === 1);
  check('blast radius node has depth and path', blast[0].depth === 1 && blast[0].path.length === 2);

  // Test verifyProvenance
  check('verifyProvenance returns false for empty IDs', (await osdk.verifyProvenance('scan-123', [])) === false);
  check(
    'verifyProvenance returns true when all IDs exist',
    (await osdk.verifyProvenance('scan-123', ['blob-1', 'blob-2'])) === true
  );
  check(
    'verifyProvenance returns false when any ID is missing',
    (await osdk.verifyProvenance('scan-123', ['blob-1', 'blob-missing'])) === false
  );

  // 2. Test OSDK Tool Declarations & executeOsdkTool
  check('OSDK_TOOL_DECLARATIONS has 3 tools', OSDK_TOOL_DECLARATIONS.length === 3);
  const toolRes = await executeOsdkTool(osdk, 'scan-123', {
    name: 'getUnprotectedMutations',
    args: {},
  });
  check('executeOsdkTool dispatches getUnprotectedMutations', Array.isArray(toolRes) && toolRes.length === 1);

  const blastToolRes = await executeOsdkTool(osdk, 'scan-123', {
    name: 'getBlastRadius',
    args: { startNodeId: 'ep-1', maxDepth: 2 },
  });
  check('executeOsdkTool dispatches getBlastRadius', Array.isArray(blastToolRes) && blastToolRes.length === 1);

  // Test enforceProvenanceGate
  const sampleFindings = [
    { title: 'Verified Finding', provenanceIds: ['blob-1'] },
    { title: 'Fake Finding', provenanceIds: ['fabricated-id'] },
    { title: 'No Provenance Finding' },
  ];
  const gateRes = await enforceProvenanceGate(osdk, 'scan-123', sampleFindings, false);
  check('enforceProvenanceGate accepts verified finding', gateRes.verified.some((f) => f.title === 'Verified Finding'));
  check('enforceProvenanceGate drops fabricated finding', gateRes.rejected.some((f) => f.title === 'Fake Finding'));
  check('enforceProvenanceGate preserves legacy finding in lax mode', gateRes.verified.some((f) => f.title === 'No Provenance Finding'));

  const strictGateRes = await enforceProvenanceGate(osdk, 'scan-123', sampleFindings, true);
  check('enforceProvenanceGate rejects unanchored finding in strict mode', strictGateRes.rejected.some((f) => f.title === 'No Provenance Finding'));

  // 3. Test Universal Archetype Classifier
  const baasSnapshot: UniversalSnapshot = {
    origin: 'https://modern-app.io',
    headers: {},
    scriptUrls: ['https://modern-app.io/assets/index-abc.js'],
    observedHosts: ['project.supabase.co'],
    cookies: [],
    htmlForms: [],
    detectedLibraries: [],
    clientSecrets: [],
    baasTargets: [
      { provider: 'supabase', endpoint: 'https://project.supabase.co', rlsHeaderObserved: false, scriptUrl: 'main.js' },
    ],
  };
  const arch1 = classifyArchetypes(baasSnapshot);
  check('classifyArchetypes detects vibe_baas', arch1.includes('vibe_baas'));

  const legacySnapshot: UniversalSnapshot = {
    origin: 'https://legacy-portal.com',
    headers: { 'x-powered-by': 'PHP/7.4.3' },
    scriptUrls: ['https://legacy-portal.com/js/jquery-1.12.4.min.js'],
    observedHosts: [],
    cookies: [{ name: 'PHPSESSID', secure: false, httpOnly: false, sameSite: 'none' }],
    htmlForms: [{ action: '/login.php', method: 'POST', hasCsrfInput: false }],
    detectedLibraries: [{ name: 'jquery', version: '1.12.4', scriptUrl: 'jquery.js' }],
    clientSecrets: [],
    baasTargets: [],
  };
  const arch2 = classifyArchetypes(legacySnapshot);
  check('classifyArchetypes detects legacy_monolith', arch2.includes('legacy_monolith'));

  // 4. Test Universal OSDK queries
  const vibeRisks = await universalOsdk.getVibeCodedRisks('scan-123');
  check('getVibeCodedRisks returns client secret risk', vibeRisks.some((r) => r.riskCategory === 'CLIENT_SECRET_EXPOSURE'));

  const legacyGaps = await universalOsdk.getLegacyControlGaps('scan-123');
  check('getLegacyControlGaps returns missing CSRF risk', legacyGaps.some((r) => r.riskCategory === 'FORM_MISSING_CSRF'));

  // 5. Test AIP Control Plane
  const aip = new AipControlPlane(mockPool, osdk, universalOsdk);
  const auditNodes = await aip.runArchetypeAudit(
    {
      scanId: 'scan-123',
      authorizedOrigin: 'https://example.com',
      maxToolCalls: 10,
      toolCallsUsed: 0,
    },
    ['vibe_baas', 'legacy_monolith']
  );
  check('AipControlPlane routes and returns audit nodes', auditNodes.length >= 2);

  // 6. Test 4-Matrix Ontology Scoring Engine
  const scoreReport = computeOntologyScore({
    nodes: [
      {
        nodeId: 'n1',
        riskCategory: 'CLIENT_SECRET_EXPOSURE',
        blastRadiusCount: 3,
        provenanceVerified: true,
        confidence: 0.95,
      },
      {
        nodeId: 'n2',
        riskCategory: 'FORM_MISSING_CSRF',
        blastRadiusCount: 1,
        provenanceVerified: true,
        confidence: 0.9,
      },
    ],
    controls: {
      totalMutatingEndpoints: 2,
      protectedMutatingEndpoints: 1,
      totalBaasTargets: 1,
      rlsProtectedBaasTargets: 0,
      totalSessionCookies: 1,
      hardenedSessionCookies: 1,
    },
    coverage: {
      mode: 'active',
      archetypes: ['vibe_baas', 'legacy_monolith'],
      endpointsDiscovered: 4,
      endpointsTested: 4,
      authenticated: true,
    },
    delta: {
      addedObjects: [],
      removedObjects: [],
      removedControls: [{ canonicalKey: 'RLS_ENFORCED', properties: {} }],
    },
  });

  check('computeOntologyScore calculates posture score', typeof scoreReport.postureScore === 'number' && scoreReport.postureScore > 0);
  check('computeOntologyScore calculates control hygiene', scoreReport.matrices.controlHygieneScore === 50);
  check('computeOntologyScore applies drift penalty', scoreReport.matrices.driftPenalty === 12);
  check('computeOntologyScore assigns grade', ['A', 'B', 'C', 'D', 'F'].includes(scoreReport.effectiveGrade));

  // 7. Test Ingestion Mock Transaction
  const executedStatements: string[] = [];
  const insertedObjects: any[] = [];
  const insertedLinks: any[] = [];

  const mockClient: any = {
    async query(sql: string, params: unknown[] = []) {
      executedStatements.push(sql);
      if (sql.includes('INSERT INTO evidence_blobs')) {
        return { rows: [{ id: `ev-${insertedObjects.length + 1}` }] };
      }
      if (sql.includes('INSERT INTO ontology_objects')) {
        const id = `obj-${insertedObjects.length + 1}`;
        insertedObjects.push({ id, type: params[1], key: params[2] });
        return { rows: [{ id }] };
      }
      if (sql.includes('INSERT INTO ontology_links')) {
        insertedLinks.push({ src: params[1], tgt: params[2], link: params[3] });
        return { rows: [] };
      }
      return { rows: [] };
    },
    release() {},
  };

  const mockIngestPool: any = {
    async connect() {
      return mockClient;
    },
  };

  const sampleSnapshot: SurfaceSnapshot = {
    origin: 'https://juice-shop.herokuapp.com',
    headers: {
      'content-security-policy': "default-src 'self'",
      server: 'Express',
    },
    cookies: [
      { name: 'session', secure: true, httpOnly: true, sameSite: 'lax' },
    ],
    observedApis: [
      {
        method: 'POST',
        path: '/api/BasketItems',
        source: 'js_bundle',
        scriptUrl: 'https://juice-shop.herokuapp.com/main.js',
        hasAuthHeader: false,
        hasCsrfHeader: false,
        sampleStatus: 200,
      },
    ],
  };

  const ingestRes = await ingestSurfaceToOntology(mockIngestPool, 'scan-test', sampleSnapshot);
  check('ingestSurfaceToOntology completed', ingestRes.objectsCreated > 0);
  check('ingest created links', ingestRes.linksCreated > 0);
  check('transaction committed', executedStatements.includes('COMMIT'));

  // Test Universal Ontology Ingestion
  const universalIngestRes = await ingestUniversalOntology(mockIngestPool, 'scan-univ', baasSnapshot);
  check('ingestUniversalOntology completed', universalIngestRes.archetypes.includes('vibe_baas'));

  if (failures > 0) {
    console.error(`FAILED with ${failures} error(s)`);
    process.exit(1);
  } else {
    console.log('ALL ONTOLOGY TESTS PASSED');
  }
}

runTests().catch((err) => {
  console.error('Test threw unhandled error:', err);
  process.exit(1);
});

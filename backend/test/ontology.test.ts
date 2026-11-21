/**
 * Unit tests for Security Ontology Ingest & BugSeekOSDK.
 */
import { BugSeekOSDK } from '../src/ontology/osdk.js';
import { ingestSurfaceToOntology, type SurfaceSnapshot } from '../src/ontology/ingest.js';

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
  console.log('--- Testing BugSeekOSDK & Ontology Ingestion ---');

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
      if (sql.includes('evidence_blobs') && sql.includes('COUNT(*)')) {
        const ids = (params[1] as string[]) || [];
        // Simulate that blob-1 and blob-2 exist, but blob-unknown does not
        const validIds = ids.filter((id) => id === 'blob-1' || id === 'blob-2');
        return { rows: [{ count: String(validIds.length) }] };
      }
      return { rows: [] };
    },
  };

  const osdk = new BugSeekOSDK(mockPool);

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

  // 2. Test Ingestion Mock Transaction
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

  const createdTypes = insertedObjects.map((o) => o.type);
  check('Origin created', createdTypes.includes('Origin'));
  check('CSP Control created', createdTypes.includes('Control'));
  check('Identity nodes created', createdTypes.includes('Identity'));
  check('Endpoint created', createdTypes.includes('Endpoint'));
  check('Asset created from bundle', createdTypes.includes('Asset'));
  check('Resource created for mutating POST', createdTypes.includes('Resource'));

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

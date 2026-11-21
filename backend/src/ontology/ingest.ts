import crypto from 'node:crypto';
import type { Pool, PoolClient } from 'pg';

export type ObjectType =
  | 'Origin'
  | 'Asset'
  | 'Endpoint'
  | 'Identity'
  | 'Control'
  | 'Sink'
  | 'Resource';

export type LinkType =
  | 'DECLARES'
  | 'PROTECTS'
  | 'CAN_INVOKE'
  | 'MUTATES'
  | 'FLOWS_TO'
  | 'HOSTS';

export interface SurfaceSnapshot {
  origin: string;
  headers: Record<string, string>;
  cookies: Array<{
    name: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: string;
  }>;
  observedApis: Array<{
    method: string;
    path: string;
    source: 'live_traffic' | 'js_bundle' | 'dom_form';
    scriptUrl?: string;
    hasAuthHeader: boolean;
    hasCsrfHeader?: boolean;
    sampleStatus?: number;
  }>;
}

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function sha256Json(payload: unknown): string {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(payload))
    .digest('hex');
}

async function upsertEvidence(
  client: PoolClient,
  scanId: string,
  sourceKind: string,
  payload: unknown
): Promise<string> {
  const hash = sha256Json(payload);
  const { rows } = await client.query<{ id: string }>(
    `INSERT INTO evidence_blobs (scan_id, sha256, source_kind, payload)
     VALUES ($1, $2, $3, $4::jsonb)
     ON CONFLICT (scan_id, sha256) DO UPDATE SET source_kind = EXCLUDED.source_kind
     RETURNING id`,
    [scanId, hash, sourceKind, JSON.stringify(payload)]
  );
  return rows[0].id;
}

async function upsertObject(
  client: PoolClient,
  params: {
    scanId: string;
    objectType: ObjectType;
    canonicalKey: string;
    properties: Record<string, unknown>;
    provenanceId: string;
    confidence?: number;
  }
): Promise<string> {
  const { rows } = await client.query<{ id: string }>(
    `INSERT INTO ontology_objects (scan_id, object_type, canonical_key, properties, confidence, provenance_id)
     VALUES ($1, $2, $3, $4::jsonb, $5, $6)
     ON CONFLICT (scan_id, object_type, canonical_key)
     DO UPDATE SET
       properties = ontology_objects.properties || EXCLUDED.properties,
       confidence = GREATEST(ontology_objects.confidence, EXCLUDED.confidence)
     RETURNING id`,
    [
      params.scanId,
      params.objectType,
      params.canonicalKey,
      JSON.stringify(params.properties),
      params.confidence ?? 1.0,
      params.provenanceId,
    ]
  );
  return rows[0].id;
}

async function upsertLink(
  client: PoolClient,
  params: {
    scanId: string;
    sourceId: string;
    targetId: string;
    linkType: LinkType;
    provenanceId: string;
    properties?: Record<string, unknown>;
  }
): Promise<void> {
  await client.query(
    `INSERT INTO ontology_links (scan_id, source_id, target_id, link_type, properties, provenance_id)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6)
     ON CONFLICT (scan_id, source_id, target_id, link_type)
     DO UPDATE SET properties = ontology_links.properties || EXCLUDED.properties`,
    [
      params.scanId,
      params.sourceId,
      params.targetId,
      params.linkType,
      JSON.stringify(params.properties ?? {}),
      params.provenanceId,
    ]
  );
}

export async function ingestSurfaceToOntology(
  pool: Pool,
  scanId: string,
  snapshot: SurfaceSnapshot
): Promise<{ objectsCreated: number; linksCreated: number }> {
  const client = await pool.connect();
  let objectsCreated = 0;
  let linksCreated = 0;

  try {
    await client.query('BEGIN');

    // 1. Root Origin + Header Controls
    const headerProvId = await upsertEvidence(client, scanId, 'header_audit', {
      origin: snapshot.origin,
      headers: snapshot.headers,
    });

    const originId = await upsertObject(client, {
      scanId,
      objectType: 'Origin',
      canonicalKey: snapshot.origin,
      properties: { headersCount: Object.keys(snapshot.headers).length },
      provenanceId: headerProvId,
    });
    objectsCreated++;

    const lowerHeaders = Object.fromEntries(
      Object.entries(snapshot.headers).map(([k, v]) => [k.toLowerCase(), v])
    );

    if (lowerHeaders['content-security-policy']) {
      const cspId = await upsertObject(client, {
        scanId,
        objectType: 'Control',
        canonicalKey: 'CSP',
        properties: { policy: lowerHeaders['content-security-policy'] },
        provenanceId: headerProvId,
      });
      await upsertLink(client, {
        scanId,
        sourceId: cspId,
        targetId: originId,
        linkType: 'PROTECTS',
        provenanceId: headerProvId,
      });
      objectsCreated++;
      linksCreated++;
    }

    // 2. Identity Nodes (Anonymous vs Authenticated)
    const anonId = await upsertObject(client, {
      scanId,
      objectType: 'Identity',
      canonicalKey: 'role:anonymous',
      properties: { authenticated: false },
      provenanceId: headerProvId,
    });
    const authId = await upsertObject(client, {
      scanId,
      objectType: 'Identity',
      canonicalKey: 'role:authenticated',
      properties: { authenticated: true },
      provenanceId: headerProvId,
    });
    objectsCreated += 2;

    // 3. Endpoints, Assets, and Control Edges
    for (const api of snapshot.observedApis) {
      const method = api.method.toUpperCase();
      const epKey = `${method}:${api.path}`;
      const epProvId = await upsertEvidence(client, scanId, api.source, api);

      const endpointId = await upsertObject(client, {
        scanId,
        objectType: 'Endpoint',
        canonicalKey: epKey,
        properties: {
          method,
          path: api.path,
          source: api.source,
          sampleStatus: api.sampleStatus ?? null,
        },
        provenanceId: epProvId,
      });
      objectsCreated++;

      await upsertLink(client, {
        scanId,
        sourceId: originId,
        targetId: endpointId,
        linkType: 'HOSTS',
        provenanceId: epProvId,
      });
      linksCreated++;

      // Link declaring JS asset if discovered in a bundle
      if (api.scriptUrl) {
        const assetId = await upsertObject(client, {
          scanId,
          objectType: 'Asset',
          canonicalKey: api.scriptUrl,
          properties: { kind: 'js_bundle' },
          provenanceId: epProvId,
        });
        await upsertLink(client, {
          scanId,
          sourceId: assetId,
          targetId: endpointId,
          linkType: 'DECLARES',
          provenanceId: epProvId,
        });
        objectsCreated++;
        linksCreated++;
      }

      // Identity reachability
      await upsertLink(client, {
        scanId,
        sourceId: api.hasAuthHeader ? authId : anonId,
        targetId: endpointId,
        linkType: 'CAN_INVOKE',
        provenanceId: epProvId,
      });
      linksCreated++;

      // Mutation & CSRF control tracking
      if (MUTATING_METHODS.has(method)) {
        const resourceKey = api.path.split('/').slice(0, 3).join('/') || '/';
        const resourceId = await upsertObject(client, {
          scanId,
          objectType: 'Resource',
          canonicalKey: resourceKey,
          properties: { rootPath: resourceKey },
          provenanceId: epProvId,
        });
        await upsertLink(client, {
          scanId,
          sourceId: endpointId,
          targetId: resourceId,
          linkType: 'MUTATES',
          provenanceId: epProvId,
        });
        objectsCreated++;
        linksCreated++;

        if (api.hasCsrfHeader) {
          const csrfId = await upsertObject(client, {
            scanId,
            objectType: 'Control',
            canonicalKey: 'CSRF_TOKEN',
            properties: { enforced: true },
            provenanceId: epProvId,
          });
          await upsertLink(client, {
            scanId,
            sourceId: csrfId,
            targetId: endpointId,
            linkType: 'PROTECTS',
            provenanceId: epProvId,
          });
          objectsCreated++;
          linksCreated++;
        }
      }
    }

    await client.query('COMMIT');
    return { objectsCreated, linksCreated };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

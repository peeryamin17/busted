import crypto from 'node:crypto';
import type { Pool, PoolClient } from 'pg';

export type StackArchetype =
  | 'vibe_baas'
  | 'modern_spa'
  | 'legacy_monolith'
  | 'cms_platform';

export interface UniversalSnapshot {
  origin: string;
  headers: Record<string, string>;
  scriptUrls: string[];
  observedHosts: string[];
  cookies: Array<{
    name: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: string;
  }>;
  htmlForms: Array<{
    action: string;
    method: string;
    hasCsrfInput: boolean;
  }>;
  detectedLibraries: Array<{
    name: string;
    version: string;
    scriptUrl: string;
  }>;
  clientSecrets: Array<{
    kind: string;           // e.g., 'supabase_service_role' | 'stripe_live' | 'openai_key'
    redactedValue: string;  // Never store raw secret in graph properties
    scriptUrl: string;
  }>;
  baasTargets: Array<{
    provider: 'supabase' | 'firebase' | 'convex' | 'clerk';
    endpoint: string;
    rlsHeaderObserved: boolean;
    scriptUrl: string;
  }>;
}

function sha256(payload: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

export function classifyArchetypes(snapshot: UniversalSnapshot): StackArchetype[] {
  const archetypes = new Set<StackArchetype>();
  const headerBlob = JSON.stringify(snapshot.headers).toLowerCase();
  const hostBlob = snapshot.observedHosts.join(' ').toLowerCase();
  const scriptBlob = snapshot.scriptUrls.join(' ').toLowerCase();

  if (
    snapshot.baasTargets.length > 0 ||
    /supabase\.co|firebaseio\.com|convex\.cloud|clerk\./.test(hostBlob + scriptBlob)
  ) {
    archetypes.add('vibe_baas');
  }
  if (/\/_next\/|\/assets\/index-|main\.[a-f0-9]+\.js|chunk-/.test(scriptBlob)) {
    archetypes.add('modern_spa');
  }
  if (
    snapshot.htmlForms.length > 0 ||
    /x-powered-by.*(php|asp\.net)|phpsessid|jsessionid|jquery-1\.|jquery-2\./.test(
      headerBlob + scriptBlob
    )
  ) {
    archetypes.add('legacy_monolith');
  }
  if (/wp-content|wp-includes|drupal|shopify/.test(scriptBlob + headerBlob)) {
    archetypes.add('cms_platform');
  }

  return archetypes.size > 0 ? [...archetypes] : ['modern_spa'];
}

async function upsertEvidence(
  client: PoolClient,
  scanId: string,
  sourceKind: string,
  payload: unknown
): Promise<string> {
  const { rows } = await client.query<{ id: string }>(
    `INSERT INTO evidence_blobs (scan_id, sha256, source_kind, payload)
     VALUES ($1, $2, $3, $4::jsonb)
     ON CONFLICT (scan_id, sha256) DO UPDATE SET source_kind = EXCLUDED.source_kind
     RETURNING id`,
    [scanId, sha256(payload), sourceKind, JSON.stringify(payload)]
  );
  return rows[0].id;
}

async function upsertObject(
  client: PoolClient,
  scanId: string,
  objectType: string,
  canonicalKey: string,
  properties: Record<string, unknown>,
  provenanceId: string
): Promise<string> {
  const { rows } = await client.query<{ id: string }>(
    `INSERT INTO ontology_objects (scan_id, object_type, canonical_key, properties, provenance_id)
     VALUES ($1, $2, $3, $4::jsonb, $5)
     ON CONFLICT (scan_id, object_type, canonical_key)
     DO UPDATE SET properties = ontology_objects.properties || EXCLUDED.properties
     RETURNING id`,
    [scanId, objectType, canonicalKey, JSON.stringify(properties), provenanceId]
  );
  return rows[0].id;
}

async function upsertLink(
  client: PoolClient,
  scanId: string,
  sourceId: string,
  targetId: string,
  linkType: string,
  provenanceId: string
): Promise<void> {
  await client.query(
    `INSERT INTO ontology_links (scan_id, source_id, target_id, link_type, provenance_id)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (scan_id, source_id, target_id, link_type) DO NOTHING`,
    [scanId, sourceId, targetId, linkType, provenanceId]
  );
}

export async function ingestUniversalOntology(
  pool: Pool,
  scanId: string,
  snapshot: UniversalSnapshot
): Promise<{ archetypes: StackArchetype[]; originId: string }> {
  const archetypes = classifyArchetypes(snapshot);
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const rootProv = await upsertEvidence(client, scanId, 'header_audit', {
      origin: snapshot.origin,
      archetypes,
      headers: snapshot.headers,
    });

    const originId = await upsertObject(
      client,
      scanId,
      'Origin',
      snapshot.origin,
      { archetypes },
      rootProv
    );

    // 1. Vibe-Coded BaaS Ingestion (Client Secrets + Direct DB Calls)
    for (const secret of snapshot.clientSecrets) {
      const prov = await upsertEvidence(client, scanId, 'js_bundle', secret);
      const assetId = await upsertObject(client, scanId, 'Asset', secret.scriptUrl, {}, prov);
      const secretId = await upsertObject(
        client,
        scanId,
        'ClientSecret',
        `${secret.kind}:${secret.redactedValue}`,
        { kind: secret.kind, redactedValue: secret.redactedValue },
        prov
      );
      await upsertLink(client, scanId, assetId, secretId, 'EMBEDS', prov);
    }

    for (const baas of snapshot.baasTargets) {
      const prov = await upsertEvidence(client, scanId, 'js_bundle', baas);
      const assetId = await upsertObject(client, scanId, 'Asset', baas.scriptUrl, {}, prov);
      const baasId = await upsertObject(
        client,
        scanId,
        'BaaSProject',
        `${baas.provider}:${baas.endpoint}`,
        { provider: baas.provider, rlsHeaderObserved: baas.rlsHeaderObserved },
        prov
      );
      await upsertLink(client, scanId, assetId, baasId, 'DIRECT_DB_CALL', prov);

      if (baas.rlsHeaderObserved) {
        const rlsId = await upsertObject(client, scanId, 'Control', 'RLS_ENFORCED', {}, prov);
        await upsertLink(client, scanId, rlsId, baasId, 'PROTECTS', prov);
      }
    }

    // 2. Legacy Monolith Ingestion (HTML Forms, Session Cookies, Outdated Libraries)
    for (const form of snapshot.htmlForms) {
      const prov = await upsertEvidence(client, scanId, 'dom_form', form);
      const formId = await upsertObject(
        client,
        scanId,
        'HtmlForm',
        `${form.method.toUpperCase()}:${form.action}`,
        { method: form.method.toUpperCase(), action: form.action },
        prov
      );
      await upsertLink(client, scanId, originId, formId, 'HOSTS', prov);

      if (form.hasCsrfInput) {
        const csrfId = await upsertObject(client, scanId, 'Control', 'CSRF_TOKEN', {}, prov);
        await upsertLink(client, scanId, csrfId, formId, 'PROTECTS', prov);
      }
    }

    for (const cookie of snapshot.cookies) {
      const prov = await upsertEvidence(client, scanId, 'cookie_audit', cookie);
      const cookieId = await upsertObject(
        client,
        scanId,
        'SessionCookie',
        cookie.name,
        {
          secure: cookie.secure,
          httpOnly: cookie.httpOnly,
          sameSite: cookie.sameSite,
        },
        prov
      );
      await upsertLink(client, scanId, originId, cookieId, 'HOSTS', prov);
    }

    for (const lib of snapshot.detectedLibraries) {
      const prov = await upsertEvidence(client, scanId, 'js_bundle', lib);
      const libId = await upsertObject(
        client,
        scanId,
        'LibraryVersion',
        `${lib.name}@${lib.version}`,
        { name: lib.name, version: lib.version, scriptUrl: lib.scriptUrl },
        prov
      );
      await upsertLink(client, scanId, originId, libId, 'LOADS', prov);
    }

    await client.query('COMMIT');
    return { archetypes, originId };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import type { Database } from '../db/db.js';
import type { GraphStore } from '../graph/store.js';
import {
  ScopeSentryAdapter,
  validateRawAssets,
  type AssetSourceAdapter,
  type RawAsset,
} from '../asm/adapters.js';
import { graphAssetSink, importAssets } from '../asm/import.js';

/**
 * ASM routes.
 *
 *   POST /api/asm/import   - import assets from a source into the asset graph
 *   GET  /api/asm/adapters - list available adapters (verified vs contract-only)
 *
 * Member-authenticated. Import is a data import, never a scan: it writes
 * rows into the asset graph and makes no network calls to the assets
 * themselves. A ScopeSentry API key, when one is used, is request-scoped
 * only: it arrives in the request body for a one-shot import and is never
 * persisted and never logged. Import merges per company (dedup key is
 * (kind, value, companyId)), but the asset graph is per-task, so the route
 * takes both companyId and taskId. Registered in server.ts, not here.
 */

export interface AsmRouteDeps {
  db: Database;
  graph: GraphStore;
}

const jsonFileImportSchema = z.object({
  adapter: z.literal('json-file'),
  companyId: z.string().min(1).max(500),
  taskId: z.string().uuid(),
  /** Inline assets only (the JSON-file `{assets: [...]}` shape, capped). */
  assets: z.array(z.unknown()).max(500),
});

const scopeSentryImportSchema = z.object({
  adapter: z.literal('scopesentry'),
  companyId: z.string().min(1).max(500),
  taskId: z.string().uuid(),
  baseUrl: z.string().min(1).max(2000),
  apiKey: z.string().min(1).max(2000),
  project: z.string().min(1).max(500),
  listPath: z.string().min(1).max(500).optional(),
});

const importSchema = z.discriminatedUnion('adapter', [
  jsonFileImportSchema,
  scopeSentryImportSchema,
]);

export async function asmRoutes(app: FastifyInstance, deps: AsmRouteDeps): Promise<void> {
  const { db, graph } = deps;
  const authenticate = buildAuthenticate(db);

  app.get('/api/asm/adapters', { preHandler: authenticate }, async () => {
    return {
      adapters: [
        {
          name: 'json-file',
          verified: true,
          description: 'Inline JSON assets of shape {assets: [...]} — fully testable offline.',
        },
        {
          name: 'scopesentry',
          verified: false,
          description:
            'ScopeSentry-style ASM API (base URL + X-API-Key header, paged list by project). ' +
            'Contract-only: endpoint paths and response shapes are assumed, not verified ' +
            'against a live deployment — the adapter fails loudly on an unexpected shape.',
        },
      ],
    };
  });

  app.post('/api/asm/import', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = importSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const task = await graph.getTask(body.data.taskId);
    if (!task || task.userId !== user.id) {
      return reply.status(404).send({ error: 'Task not found' });
    }

    let adapter: AssetSourceAdapter;
    if (body.data.adapter === 'json-file') {
      // Inline assets only: the backend never reads a caller-named
      // path off its own disk. Rows are validated up front, then
      // handed to the import as a one-shot adapter.
      let assets: RawAsset[];
      try {
        assets = validateRawAssets(body.data.assets);
      } catch (err) {
        return reply.status(400).send({ error: (err as Error).message });
      }
      adapter = { name: 'json-file', listAssets: async () => assets };
    } else {
      try {
        adapter = new ScopeSentryAdapter({
          baseUrl: body.data.baseUrl,
          apiKey: body.data.apiKey,
          project: body.data.project,
          listPath: body.data.listPath,
        });
      } catch (err) {
        return reply.status(400).send({ error: (err as Error).message });
      }
    }

    const result = await importAssets({
      adapter,
      companyId: body.data.companyId,
      userId: user.id,
      assetStore: graphAssetSink(graph, task.id),
    });
    return reply.send({ ...result, companyId: body.data.companyId, taskId: task.id });
  });
}

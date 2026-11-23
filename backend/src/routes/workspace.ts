import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import * as path from 'node:path';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import type { Database } from '../db/db.js';
import {
  MAX_FILE_BYTES,
  WorkspaceError,
  WorkspaceFiles,
  normalizeRelPath,
} from '../workspace/files.js';
import { MemoryWorkspaceMetaStore, type WorkspaceMetaStore } from '../workspace/meta.js';

/**
 * Workspace routes.
 *
 *   GET    /api/workspace            - list files (optional ?dir=) + recent uploads
 *   GET    /api/workspace/file?path= - download one file (attachment)
 *   POST   /api/workspace/upload     - {path, name, contentBase64, taskId?}
 *   DELETE /api/workspace/file?path= - delete a file or an empty directory
 *   GET    /api/workspace/usage      - bytes used vs the quota
 *
 * Member-authenticated; scoped to request.user.id, a traversal attempt
 * reads as 403. Uploads are JSON with a base64 body (no multipart
 * dependency). The per-file cap is 10 MiB and the per-user quota 100 MiB;
 * the route body limit is 16 MiB to leave room for base64 overhead.
 *
 * Files live on the backend host's disk, which is ephemeral on the hosted
 * deployment: a redeploy wipes them. Every response says so
 * (ephemeral: true). Registered in server.ts, not here.
 */

export interface WorkspaceRouteDeps {
  db: Database;
  /** Defaults to a memory store; the coordinator passes the Postgres store. */
  meta?: WorkspaceMetaStore;
  /** Defaults to a WorkspaceFiles rooted at WORKSPACE_ROOT / data/workspace. */
  files?: WorkspaceFiles;
}

const EPHEMERAL_NOTE =
  'Files live on the backend host’s disk, which is ephemeral — a redeploy may wipe them. ' +
  'Keep anything that must survive in the database or in object storage, not here.';

const listQuerySchema = z.object({
  dir: z.string().optional(),
});

const fileQuerySchema = z.object({
  path: z.string().min(1).max(1000),
});

const uploadSchema = z.object({
  /** Directory inside the workspace the file goes in ('' = root). */
  path: z.string().max(1000).optional(),
  /** Plain file name, no separators, no traversal. */
  name: z
    .string()
    .min(1)
    .max(200)
    .regex(/^[^/\\]+$/, 'name must be a plain file name'),
  /** File contents, base64-encoded. */
  contentBase64: z.string().min(1),
  /** Optional task the file belongs to (recorded in the metadata row). */
  taskId: z.string().uuid().optional(),
});

function decodeBase64(value: string): Buffer {
  const compact = value.replace(/\s/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(compact) || compact.length % 4 !== 0) {
    throw new WorkspaceError('forbidden', 'contentBase64 is not valid base64');
  }
  return Buffer.from(compact, 'base64');
}

function workspaceErrorStatus(err: WorkspaceError): number {
  switch (err.code) {
    case 'not-found':
      return 404;
    case 'forbidden':
      return 403;
    case 'too-large':
    case 'quota':
      return 413;
  }
}

/** Safe filename for Content-Disposition: no quotes or control chars. */
function safeAttachmentName(relPath: string): string {
  return path
    .posix
    .basename(relPath)
    .replace(/["\r\n]/g, '')
    .slice(0, 200) || 'file';
}

export async function workspaceRoutes(app: FastifyInstance, deps: WorkspaceRouteDeps): Promise<void> {
  const { db } = deps;
  const files = deps.files ?? new WorkspaceFiles();
  const meta = deps.meta ?? new MemoryWorkspaceMetaStore();
  const authenticate = buildAuthenticate(db);

  app.get('/api/workspace', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const query = listQuerySchema.safeParse(request.query);
    if (!query.success) {
      return reply.status(400).send({ error: query.error.issues[0]?.message ?? 'Invalid query' });
    }
    try {
      const dir = query.data.dir ? normalizeRelPath(query.data.dir) : '';
      const [listed, recent, usage] = await Promise.all([
        files.listFiles(user.id, dir || undefined),
        meta.listRecent(user.id, 20),
        files.usageBytes(user.id),
      ]);
      return reply.send({
        dir,
        files: listed,
        recent,
        usageBytes: usage,
        quotaBytes: files.quotaBytes,
        perFileCapBytes: files.perFileCapBytes,
        ephemeral: true,
        note: EPHEMERAL_NOTE,
      });
    } catch (err) {
      if (err instanceof WorkspaceError) {
        return reply.status(workspaceErrorStatus(err)).send({ error: err.message });
      }
      throw err;
    }
  });

  app.get('/api/workspace/file', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const query = fileQuerySchema.safeParse(request.query);
    if (!query.success) {
      return reply.status(400).send({ error: query.error.issues[0]?.message ?? 'Invalid query' });
    }
    try {
      const rel = normalizeRelPath(query.data.path);
      const { buffer, mime } = await files.readFile(user.id, rel);
      reply.header('Content-Type', mime);
      reply.header('Content-Disposition', `attachment; filename="${safeAttachmentName(rel)}"`);
      reply.header('Content-Length', String(buffer.length));
      return reply.send(buffer);
    } catch (err) {
      if (err instanceof WorkspaceError) {
        return reply.status(workspaceErrorStatus(err)).send({ error: err.message });
      }
      throw err;
    }
  });

  app.post(
    '/api/workspace/upload',
    {
      preHandler: authenticate,
      // 10 MiB file + base64 overhead (~33%).
      bodyLimit: MAX_FILE_BYTES + Math.ceil(MAX_FILE_BYTES / 3) + 1024 * 1024,
    },
    async (request, reply) => {
      const user = requireUser(request);
      const body = uploadSchema.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
      }
      try {
        const dir = body.data.path ? normalizeRelPath(body.data.path) : '';
        const rel = dir ? `${dir}/${body.data.name}` : body.data.name;
        const buffer = decodeBase64(body.data.contentBase64);
        const written = await files.writeFile(user.id, rel, buffer);
        const record = await meta.record({
          userId: user.id,
          taskId: body.data.taskId ?? null,
          relPath: written.path,
          sizeBytes: written.size,
          kind: 'upload',
        });
        const usage = await files.usageBytes(user.id);
        return reply.status(201).send({
          file: record,
          usageBytes: usage,
          quotaBytes: files.quotaBytes,
          ephemeral: true,
          note: EPHEMERAL_NOTE,
        });
      } catch (err) {
        if (err instanceof WorkspaceError) {
          return reply.status(workspaceErrorStatus(err)).send({ error: err.message });
        }
        throw err;
      }
    },
  );

  app.delete('/api/workspace/file', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const query = fileQuerySchema.safeParse(request.query);
    if (!query.success) {
      return reply.status(400).send({ error: query.error.issues[0]?.message ?? 'Invalid query' });
    }
    try {
      const rel = normalizeRelPath(query.data.path);
      await files.deleteFile(user.id, rel);
      // Best-effort: a missing metadata row is not a failed delete.
      await meta.removeByPath(user.id, rel).catch(() => undefined);
      return reply.send({ deleted: rel });
    } catch (err) {
      if (err instanceof WorkspaceError) {
        return reply.status(workspaceErrorStatus(err)).send({ error: err.message });
      }
      throw err;
    }
  });

  app.get('/api/workspace/usage', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const usage = await files.usageBytes(user.id);
    return {
      usageBytes: usage,
      quotaBytes: files.quotaBytes,
      perFileCapBytes: files.perFileCapBytes,
      ephemeral: true,
      note: EPHEMERAL_NOTE,
    };
  });
}

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import type { Database } from '../db/db.js';
import type { GraphStore } from '../graph/store.js';
import type { Company, CompanyScope, CompanyStore } from '../companies/store.js';
import {
  linkTaskToCompany,
  type TaskCompanyLinkStore,
} from '../companies/tasks.js';

/**
 * Company routes.
 *
 *   POST   /api/companies            - create a company (name + scope)
 *   GET    /api/companies            - my companies, newest first
 *   PATCH  /api/companies/:id        - rename / re-scope a company
 *   DELETE /api/companies/:id        - delete, refused while tasks link to it
 *   POST   /api/companies/:id/tasks  - link one of my tasks to the company
 *   GET    /api/companies/:id/tasks  - tasks linked to the company
 *
 * Member-authenticated; scoped to the caller, another user's company reads
 * as 404. A duplicate name for the same user is a 409, not a second row.
 * Auth is optional only for tests; when omitted the route fails closed
 * with 401. Registered in server.ts, not here.
 */

export interface CompanyRouteDeps {
  db: Database;
  companies: CompanyStore;
  links: TaskCompanyLinkStore;
  graph: GraphStore;
  authenticate?: (request: FastifyRequest, reply: FastifyReply) => Promise<void> | void;
}

const scopeSchema = z.object({
  domains: z.array(z.string().max(253)).max(500).default([]),
  notes: z.string().max(5000).optional(),
});

const createCompanySchema = z.object({
  name: z.string().min(1).max(200),
  scope: scopeSchema.optional(),
});

const renameCompanySchema = z.object({
  name: z.string().min(1).max(200).optional(),
  scope: scopeSchema.nullable().optional(),
});

const linkTaskSchema = z.object({
  taskId: z.string().min(1),
});

function publicCompany(c: Company): Company {
  return {
    id: c.id,
    userId: c.userId,
    name: c.name,
    scope: { domains: [...c.scope.domains], ...(c.scope.notes ? { notes: c.scope.notes } : {}) } as CompanyScope,
    createdAt: c.createdAt,
  };
}

export async function companyRoutes(app: FastifyInstance, deps: CompanyRouteDeps): Promise<void> {
  const { db, companies, links, graph } = deps;
  const authenticate =
    deps.authenticate ??
    buildAuthenticate(db);

  app.post('/api/companies', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = createCompanySchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    try {
      const company = await companies.create({
        userId: user.id,
        name: body.data.name,
        scope: body.data.scope ?? null,
      });
      return reply.status(201).send({ company: publicCompany(company) });
    } catch (err) {
      if ((err as Error).message === 'company_name_exists') {
        return reply.status(409).send({ error: 'A company with that name already exists' });
      }
      if ((err as Error).message === 'company_name_required') {
        return reply.status(400).send({ error: 'Company name is required' });
      }
      throw err;
    }
  });

  app.get('/api/companies', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const all = await companies.list(user.id);
    return { companies: all.map(publicCompany) };
  });

  app.patch('/api/companies/:id', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const body = renameCompanySchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    try {
      const updated = await companies.rename({
        id,
        userId: user.id,
        ...(body.data.name !== undefined ? { name: body.data.name } : {}),
        ...(body.data.scope !== undefined ? { scope: body.data.scope } : {}),
      });
      if (!updated) return reply.status(404).send({ error: 'Company not found' });
      return reply.send({ company: publicCompany(updated) });
    } catch (err) {
      if ((err as Error).message === 'company_name_exists') {
        return reply.status(409).send({ error: 'A company with that name already exists' });
      }
      throw err;
    }
  });

  app.delete('/api/companies/:id', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    try {
      const removed = await companies.remove(id, user.id, (companyId) =>
        links.hasTasks(companyId, user.id),
      );
      if (!removed) return reply.status(404).send({ error: 'Company not found' });
      return reply.send({ deleted: true, company: publicCompany(removed) });
    } catch (err) {
      if ((err as Error).message === 'company_has_linked_tasks') {
        return reply.status(409).send({
          error: 'Company still has linked tasks — unlink them before deleting it',
        });
      }
      throw err;
    }
  });

  app.post('/api/companies/:id/tasks', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const body = linkTaskSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const company = await companies.get(id, user.id);
    if (!company) return reply.status(404).send({ error: 'Company not found' });
    try {
      const { link, created } = await linkTaskToCompany(
        links,
        (taskId) => graph.getTask(taskId),
        body.data.taskId,
        id,
        user.id,
      );
      const task = await graph.getTask(body.data.taskId);
      return reply.status(created ? 201 : 200).send({ link, task });
    } catch (err) {
      const message = (err as Error).message;
      if (message === 'task_not_found' || message === 'task_not_owned') {
        return reply.status(404).send({ error: 'Task not found' });
      }
      throw err;
    }
  });

  app.get('/api/companies/:id/tasks', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const company = await companies.get(id, user.id);
    if (!company) return reply.status(404).send({ error: 'Company not found' });
    const taskIds = await links.tasksForCompany(id, user.id);
    // A task id whose task no longer resolves is skipped, never
    // surfaced as a broken row (task_id has no foreign key).
    const tasks = (
      await Promise.all(taskIds.map((taskId) => graph.getTask(taskId)))
    ).filter((t): t is NonNullable<typeof t> => t !== null && t.userId === user.id);
    return { companyId: id, tasks };
  });
}

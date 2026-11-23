import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import type { Database } from '../db/db.js';
import type { SkillRegistry } from '../skills/registry.js';
import type { SkillGapStore } from '../skills/gaps.js';
import { SKILL_ROLES, type SkillRole } from '../skills/loader.js';

/**
 * Skill routes.
 *
 *   GET  /api/skills?role=<planner|worker|main>
 *        - loaded skill packs (metadata only: name, description,
 *        when-to-use, roles, tools). The `role` filter lists only the
 *        skills that lane may see.
 *   GET  /api/skills/:name
 *        - one skill, metadata plus its playbook body. Built-in
 *        registry skills only: user-added skills are stored for a future
 *        editor UI and their bodies are never served raw from any route.
 *   POST /api/skills/:name/load {role, taskId?}
 *        - mark a skill loaded for a task's run and return the prompt
 *        text to inject. The run is keyed by taskId when given, so
 *        two tasks never share a loaded set. Loading unlocks the
 *        tools the skill gates, for that run only.
 *   GET  /api/skill-gaps
 *        - the caller's capability backlog, newest first.
 *   POST /api/skill-gaps {taskId, capability, context?}
 *        - record a gap the agent hit. Deduped by (taskId,
 *        capability): re-recording returns the existing row with
 *        `deduped: true`.
 *
 * Member-authenticated; gap reads and writes are scoped to the caller.
 * Registered in server.ts, not here.
 */

export interface SkillRouteDeps {
  db: Database;
  registry: SkillRegistry;
  gaps: SkillGapStore;
}

const loadSkillSchema = z.object({
  role: z.enum(['planner', 'worker', 'main']),
  taskId: z.string().min(1).max(200).optional(),
});

const recordGapSchema = z.object({
  taskId: z.string().min(1).max(200),
  capability: z.string().min(1).max(200),
  context: z.string().max(2000).optional(),
});

function skillMeta(skill: {
  name: string;
  description: string;
  whenToUse: string;
  roles: readonly string[];
  tools: readonly string[];
}) {
  return {
    name: skill.name,
    description: skill.description,
    whenToUse: skill.whenToUse,
    roles: [...skill.roles],
    tools: [...skill.tools],
  };
}

export async function skillsRoutes(app: FastifyInstance, deps: SkillRouteDeps): Promise<void> {
  const { db, registry, gaps } = deps;
  const authenticate = buildAuthenticate(db);

  app.get('/api/skills', { preHandler: authenticate }, async (request) => {
    requireUser(request);
    const query = request.query as { role?: string };
    if (query.role !== undefined) {
      if (!(SKILL_ROLES as readonly string[]).includes(query.role)) {
        throw Object.assign(new Error(`invalid_role: ${query.role}`), { statusCode: 400 });
      }
      return { skills: registry.visibleTo(query.role as SkillRole).map(skillMeta) };
    }
    return { skills: registry.list().map(skillMeta) };
  });

  app.get('/api/skills/:name', { preHandler: authenticate }, async (request, reply) => {
    requireUser(request);
    const { name } = request.params as { name: string };
    const skill = registry.get(name);
    if (!skill) {
      return reply.status(404).send({ error: 'Skill not found' });
    }
    return { skill: { ...skillMeta(skill), body: skill.body } };
  });

  app.post('/api/skills/:name/load', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { name } = request.params as { name: string };
    const body = loadSkillSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const skill = registry.get(name);
    if (!skill) {
      return reply.status(404).send({ error: 'Skill not found' });
    }
    try {
      const prompt = registry.loadSkillForRun(body.data.role, name, body.data.taskId ?? null);
      return { skill: name, role: body.data.role, userId: user.id, prompt };
    } catch (err) {
      const message = (err as Error).message;
      if (message.startsWith('skill_not_visible_to_role')) {
        return reply.status(403).send({ error: message });
      }
      throw err;
    }
  });

  app.get('/api/skill-gaps', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const rows = await gaps.listGaps(user.id);
    return { gaps: rows };
  });

  app.post('/api/skill-gaps', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = recordGapSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    try {
      const result = await gaps.recordGap({
        taskId: body.data.taskId,
        userId: user.id,
        capability: body.data.capability,
        context: body.data.context ?? null,
      });
      return reply.status(201).send({ gap: result.record, deduped: result.deduped });
    } catch (err) {
      const message = (err as Error).message;
      if (
        message.startsWith('skill_gap_capability') ||
        message.startsWith('skill_gap_context')
      ) {
        return reply.status(400).send({ error: message });
      }
      throw err;
    }
  });
}

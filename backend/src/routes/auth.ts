import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { hashPassword, verifyPassword, signSession, generateApiKey } from '../auth/auth.js';
import { verifyClerkToken } from '../auth/clerk.js';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import type { RouteDeps } from './health.js';

const registerSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(8).max(128),
});

const loginSchema = registerSchema;

const apiKeySchema = z.object({
  name: z.string().min(1).max(100).default('default'),
});

const clerkLinkSchema = z.object({
  email: z.string().email().max(254),
});

function publicUser(u: { id: string; email: string; plan: string; createdAt: string }) {
  return { id: u.id, email: u.email, plan: u.plan, createdAt: u.createdAt };
}

export async function authRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  const { db } = deps;
  const authenticate = buildAuthenticate(db);

  app.post('/api/auth/register', async (request, reply) => {
    const body = registerSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    try {
      const user = await db.createUser(body.data.email, await hashPassword(body.data.password));
      const token = signSession(user);
      return reply.status(201).send({ user: publicUser(user), token });
    } catch (err) {
      if (err instanceof Error && err.message === 'email_taken') {
        return reply.status(409).send({ error: 'Email already registered' });
      }
      throw err;
    }
  });

  app.post('/api/auth/login', async (request, reply) => {
    const body = loginSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const user = await db.getUserByEmail(body.data.email);
    if (!user || !(await verifyPassword(body.data.password, user.passwordHash))) {
      return reply.status(401).send({ error: 'Invalid email or password' });
    }
    return reply.send({ user: publicUser(user), token: signSession(user) });
  });

  /**
   * POST /api/auth/clerk/link — first call after a Clerk (Google) sign-in.
   * The Clerk token itself is the credential (verified against Clerk's
   * JWKS); the body's email comes from the Clerk profile on the client
   * and is bound to the token's `sub`, which is the actual identity.
   * Find-or-create: an existing BugSeek account with that email gets the
   * Clerk identity attached; otherwise a fresh Clerk-backed user is made.
   */
  app.post('/api/auth/clerk/link', async (request, reply) => {
    const auth = request.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      return reply.status(401).send({ error: 'Clerk session token required' });
    }
    const claims = await verifyClerkToken(auth.slice(7));
    if (!claims) {
      return reply.status(401).send({ error: 'Invalid Clerk token' });
    }
    const body = clerkLinkSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const byClerk = await db.getUserByClerkId(claims.clerkUserId);
    if (byClerk) return reply.send({ user: publicUser(byClerk), linked: true });
    const byEmail = await db.getUserByEmail(body.data.email);
    if (byEmail) {
      await db.linkClerkUser(byEmail.id, claims.clerkUserId);
      return reply.send({ user: publicUser(byEmail), linked: true });
    }
    const user = await db.createClerkUser(body.data.email, claims.clerkUserId);
    return reply.status(201).send({ user: publicUser(user), linked: true });
  });

  /**
   * GET /api/admin/users — the operator's user list (emails, plans, last
   * login). Gated to the single ADMIN_EMAIL account; everyone else 403s.
   */
  app.get('/api/admin/users', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const adminEmail = (process.env['ADMIN_EMAIL'] ?? '').trim().toLowerCase();
    if (!adminEmail || user.email.toLowerCase() !== adminEmail) {
      return reply.status(403).send({ error: 'Admin access only' });
    }
    const users = await db.listUsers(200);
    return {
      users: users.map((u) => ({
        id: u.id,
        email: u.email,
        plan: u.plan,
        createdAt: u.createdAt,
        lastLoginAt: u.lastLoginAt ?? null,
        viaClerk: Boolean(u.clerkUserId),
      })),
    };
  });

  app.get('/api/auth/me', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const full = await db.getUserById(user.id);
    if (!full) throw Object.assign(new Error('User not found'), { statusCode: 404 });
    return { user: publicUser(full) };
  });

  app.post('/api/auth/api-keys', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = apiKeySchema.safeParse(request.body ?? {});
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const { key, keyHash, keyPrefix } = generateApiKey();
    const rec = await db.createApiKey(user.id, body.data.name, keyHash, keyPrefix);
    // The raw key is returned ONCE — it cannot be retrieved again.
    return reply.status(201).send({
      id: rec.id,
      name: rec.name,
      keyPrefix: rec.keyPrefix,
      key,
      createdAt: rec.createdAt,
    });
  });

  app.get('/api/auth/api-keys', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const keys = await db.listApiKeys(user.id);
    return {
      keys: keys.map((k) => ({
        id: k.id,
        name: k.name,
        keyPrefix: k.keyPrefix,
        createdAt: k.createdAt,
        lastUsedAt: k.lastUsedAt,
        revokedAt: k.revokedAt,
      })),
    };
  });

  app.delete('/api/auth/api-keys/:id', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const ok = await db.revokeApiKey(id, user.id);
    if (!ok) return reply.status(404).send({ error: 'API key not found' });
    return reply.send({ revoked: true });
  });
}

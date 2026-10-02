/* Clerk webhook + admin list test: Svix-signed deliveries against the
   in-memory DB, signature rejection, login stamping, admin gating. */
import { createHmac, randomBytes } from 'node:crypto';

async function main() {
  const SECRET = `whsec_${randomBytes(32).toString('base64')}`;
  process.env['CLERK_WEBHOOK_SECRET'] = SECRET;
  process.env['ADMIN_EMAIL'] = 'boss@example.com';

  const { MemoryDatabase } = await import('../src/db/db.js');
  const { webhookRoutes } = await import('../src/routes/webhooks.js');
  const { authRoutes } = await import('../src/routes/auth.js');
  const { signSession } = await import('../src/auth/auth.js');
  const Fastify = (await import('fastify')).default;

  let failures = 0;
  const check = (name: string, ok: boolean) => {
    console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`);
    if (!ok) failures++;
  };

  const db = new MemoryDatabase();
  const app = Fastify();
  await authRoutes(app as never, { db, queue: {} as never, provider: {} as never });
  await app.register(async (instance) => {
    await webhookRoutes(instance as never, { db, queue: {} as never, provider: {} as never });
  });

  const key = Buffer.from(SECRET.slice('whsec_'.length), 'base64');
  function deliver(body: string, opts: { tamper?: boolean; secret?: string } = {}) {
    const id = `msg_${Math.random().toString(36).slice(2, 10)}`;
    const ts = String(Math.floor(Date.now() / 1000));
    const k = opts.secret ? Buffer.from(opts.secret.slice(6), 'base64') : key;
    const sig = createHmac('sha256', k).update(`${id}.${ts}.${body}`).digest('base64');
    return app.inject({
      method: 'POST',
      url: '/api/webhooks/clerk',
      headers: {
        'content-type': 'application/json',
        'svix-id': id,
        'svix-timestamp': ts,
        'svix-signature': `v1,${sig}`,
      },
      payload: opts.tamper ? body.replace('newhunter', 'attacker') : body,
    });
  }

  const userCreated = JSON.stringify({
    type: 'user.created',
    data: {
      id: 'user_wh_1',
      primary_email_address_id: 'em_1',
      email_addresses: [{ id: 'em_1', email_address: 'newhunter@example.com' }],
    },
  });

  const r1 = await deliver(userCreated);
  check('user.created accepted (200)', r1.statusCode === 200);
  const saved = await db.getUserByClerkId('user_wh_1');
  check('email saved in our DB', saved?.email === 'newhunter@example.com');
  check('sign-up stamps lastLoginAt', typeof saved?.lastLoginAt === 'string');

  const r2 = await deliver(userCreated, { tamper: true });
  check('tampered body rejected (400)', r2.statusCode === 400);

  const r3 = await deliver(userCreated, { secret: `whsec_${randomBytes(32).toString('base64')}` });
  check('wrong secret rejected (400)', r3.statusCode === 400);

  const before = saved?.lastLoginAt ?? '';
  await new Promise((r) => setTimeout(r, 1100));
  const sessionCreated = JSON.stringify({ type: 'session.created', data: { user_id: 'user_wh_1' } });
  const r4 = await deliver(sessionCreated);
  const after = await db.getUserByClerkId('user_wh_1');
  check('session.created accepted', r4.statusCode === 200);
  check('sign-in re-stamps lastLoginAt', (after?.lastLoginAt ?? '') > before);

  /* admin list gating */
  const boss = await db.createUser('boss@example.com', 'hash');
  const bossToken = signSession({ id: boss.id, email: boss.email, plan: boss.plan } as never);
  const admin = await app.inject({
    method: 'GET',
    url: '/api/admin/users',
    headers: { authorization: `Bearer ${bossToken}` },
  });
  const adminBody = admin.json() as { users: Array<{ email: string; viaClerk: boolean; lastLoginAt: string | null }> };
  check('admin can list users', admin.statusCode === 200 && adminBody.users.length >= 2);
  check(
    'list includes the Clerk user email + login stamp',
    adminBody.users.some((u) => u.email === 'newhunter@example.com' && u.viaClerk && u.lastLoginAt !== null),
  );

  const pleb = await db.createUser('pleb@example.com', 'hash');
  const plebToken = signSession({ id: pleb.id, email: pleb.email, plan: pleb.plan } as never);
  const denied = await app.inject({
    method: 'GET',
    url: '/api/admin/users',
    headers: { authorization: `Bearer ${plebToken}` },
  });
  check('non-admin gets 403', denied.statusCode === 403);

  await app.close();
  console.log(failures === 0 ? 'ALL WEBHOOK TESTS PASSED' : `${failures} FAILURES`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

/* Clerk auth test: real RS256 verification against a local JWKS server,
   plus the link → authenticated-request flow on the in-memory DB. */
import http from 'node:http';
import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';

async function main() {
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = publicKey.export({ format: 'jwk' }) as { n?: string; e?: string };
const KID = 'test-key-1';

const jwksServer = http.createServer((_req, res) => {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ keys: [{ kty: 'RSA', kid: KID, n: jwk.n, e: jwk.e, alg: 'RS256', use: 'sig' }] }));
});
await new Promise<void>((r) => jwksServer.listen(0, '127.0.0.1', r));
const port = (jwksServer.address() as { port: number }).port;
const FRONTEND_API = `http://127.0.0.1:${port}`;
process.env['CLERK_FRONTEND_API'] = FRONTEND_API;

// Import AFTER env is set (the verifier singleton reads env lazily, but
// keep the ordering explicit and safe).
const { createClerkVerifier } = await import('../src/auth/clerk.js');
const { MemoryDatabase } = await import('../src/db/db.js');
const { authRoutes } = await import('../src/routes/auth.js');
const Fastify = (await import('fastify')).default;

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
function makeToken(payload: Record<string, unknown>, key: KeyObject = privateKey): string {
  const h = b64({ alg: 'RS256', kid: KID, typ: 'JWT' });
  const p = b64(payload);
  const sig = cryptoSign('RSA-SHA256', Buffer.from(`${h}.${p}`), key).toString('base64url');
  return `${h}.${p}.${sig}`;
}
const now = Math.floor(Date.now() / 1000);
const validPayload = { iss: FRONTEND_API, sub: 'user_clerk_1', sid: 'sess_1', iat: now, exp: now + 3600 };

let failures = 0;
const check = (name: string, ok: boolean) => {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`);
  if (!ok) failures++;
};

/* ── verifier ── */
const verifier = createClerkVerifier({ frontendApi: FRONTEND_API });
const good = await verifier.verify(makeToken(validPayload));
check('valid token verifies', good?.clerkUserId === 'user_clerk_1');
check('expired rejected', (await verifier.verify(makeToken({ ...validPayload, exp: now - 60 }))) === null);
check('wrong issuer rejected', (await verifier.verify(makeToken({ ...validPayload, iss: 'https://evil.example' }))) === null);
const [h, , s] = makeToken(validPayload).split('.');
const tampered = `${h}.${b64({ ...validPayload, sub: 'user_attacker' })}.${s}`;
check('tampered payload rejected', (await verifier.verify(tampered)) === null);
const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
check('wrong key rejected', (await verifier.verify(makeToken(validPayload, other.privateKey))) === null);
check('garbage rejected', (await verifier.verify('not-a-jwt')) === null);

/* ── link + middleware flow ── */
const db = new MemoryDatabase();
const app = Fastify();
await authRoutes(app as never, { db, queue: {} as never, provider: {} as never });
const token = makeToken(validPayload);

const link = await app.inject({
  method: 'POST',
  url: '/api/auth/clerk/link',
  headers: { authorization: `Bearer ${token}` },
  payload: { email: 'hunter@example.com' },
});
check('link creates user (201)', link.statusCode === 201);
const linkedUser = (link.json() as { user: { id: string } }).user;

const me = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { authorization: `Bearer ${token}` } });
check('clerk token authenticates /me', me.statusCode === 200 && (me.json() as { user: { id: string } }).user.id === linkedUser.id);

const relink = await app.inject({
  method: 'POST',
  url: '/api/auth/clerk/link',
  headers: { authorization: `Bearer ${token}` },
  payload: { email: 'hunter@example.com' },
});
check('relink is idempotent (200, same user)', relink.statusCode === 200 && (relink.json() as { user: { id: string } }).user.id === linkedUser.id);

const bad = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { authorization: 'Bearer junk' } });
check('garbage token gets 401', bad.statusCode === 401);

/* link onto a pre-existing password account with the same email */
const existing = await db.createUser('veteran@example.com', 'hash');
const token2 = makeToken({ ...validPayload, sub: 'user_clerk_2' });
const link2 = await app.inject({
  method: 'POST',
  url: '/api/auth/clerk/link',
  headers: { authorization: `Bearer ${token2}` },
  payload: { email: 'veteran@example.com' },
});
check(
  'link attaches to existing account',
  link2.statusCode === 200 && (link2.json() as { user: { id: string } }).user.id === existing.id,
);
const me2 = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { authorization: `Bearer ${token2}` } });
check('existing account now Clerk-authenticates', me2.statusCode === 200);

await app.close();
jwksServer.close();
console.log(failures === 0 ? 'ALL CLERK TESTS PASSED' : `${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

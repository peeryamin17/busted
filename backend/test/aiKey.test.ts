import Fastify from 'fastify';
import { MemoryDatabase } from '../src/db/db.js';
import { aiKeyRoutes, getUserDecryptedAiKey } from '../src/routes/aiKey.js';
import { swarmRoutes } from '../src/routes/multiagent.js';
import { encryptSecret, decryptSecret, maskApiKey } from '../src/lib/crypto.js';
import { MockProvider } from '../src/llm/mock.js';
import { generateSessionToken, hashSessionToken } from '../src/auth/session.js';

let failures = 0;
function check(name: string, ok: boolean, extra?: unknown) {
  if (ok) console.log('PASS', name);
  else {
    failures++;
    console.error('FAIL', name, extra ?? '');
  }
}

async function main() {
  process.env['KEY_ENCRYPTION_SECRET'] = 'test-secret-must-be-min-16-characters!';

  // 1. Crypto unit checks
  const rawKey = 'AIzaSyA1234567890abcdefghijklmnopqrstuvwxyz';
  const encrypted = encryptSecret(rawKey);
  check('encryptSecret returns non-empty string with colons', encrypted.includes(':'));
  const decrypted = decryptSecret(encrypted);
  check('decryptSecret returns original key', decrypted === rawKey);
  check('maskApiKey produces expected pattern', maskApiKey(rawKey) === 'AIza••••wxyz');
  check('maskApiKey handles short strings safely', maskApiKey('short') === '••••••••');

  let tamperFailed = false;
  try {
    const parts = encrypted.split(':');
    parts[2] = Buffer.from('tampered-ciphertext').toString('base64');
    decryptSecret(parts.join(':'));
  } catch {
    tamperFailed = true;
  }
  check('decryptSecret rejects tampered ciphertext', tamperFailed);

  // 2. Route checks
  const db = new MemoryDatabase();
  const user = await db.createUser('user@example.com', 'unused-hash');
  // keep user on 'free' plan
  const token = generateSessionToken();
  await db.createSession(
    user.id,
    hashSessionToken(token),
    new Date(Date.now() + 3600_000).toISOString(),
  );
  const cookie = `bs_session=${token}`;

  const app = Fastify();
  const deps = { db, queue: {} as never, provider: new MockProvider() as never };
  await aiKeyRoutes(app as never, deps);
  await swarmRoutes(app as never, deps);

  // Unauthenticated calls
  const unauthGet = await app.inject({ method: 'GET', url: '/api/me/ai-key' });
  check('unauthenticated GET /api/me/ai-key → 401', unauthGet.statusCode === 401);

  // Initial state: not connected
  const initialGet = await app.inject({
    method: 'GET',
    url: '/api/me/ai-key',
    headers: { cookie },
  });
  check('initial GET /api/me/ai-key → 200, connected: false', initialGet.statusCode === 200);
  const initialBody = JSON.parse(initialGet.body);
  check('initial connected is false', initialBody.connected === false);

  // Swarm without BYOK on free plan → 403
  const authz = {
    type: 'ownership',
    statement: 'I own this domain and authorize testing.',
    confirmed: true,
  };

  const preSwarm = await app.inject({
    method: 'POST',
    url: '/api/swarm/scans',
    headers: { cookie },
    payload: {
      targetUrl: 'https://demo.owasp-juice.shop',
      authorization: authz,
    },
  });
  check('free plan without BYOK → 403', preSwarm.statusCode === 403);

  // POST with short/invalid key → 400
  const shortPost = await app.inject({
    method: 'POST',
    url: '/api/me/ai-key',
    headers: { cookie },
    payload: { apiKey: 'too-short' },
  });
  check('short apiKey → 400', shortPost.statusCode === 400);

  // POST with valid key (using mock test key prefix)
  const savePost = await app.inject({
    method: 'POST',
    url: '/api/me/ai-key',
    headers: { cookie },
    payload: { apiKey: 'AIzaTestValidKey1234567890', provider: 'gemini' },
  });
  check('valid key save → 200', savePost.statusCode === 200);
  const saveBody = JSON.parse(savePost.body);
  check('saveBody connected is true', saveBody.connected === true);
  check('saveBody hint is masked', saveBody.hint === 'AIza••••7890');

  // Verify GET returns connected with hint
  const afterGet = await app.inject({
    method: 'GET',
    url: '/api/me/ai-key',
    headers: { cookie },
  });
  const afterBody = JSON.parse(afterGet.body);
  check('after save connected is true', afterBody.connected === true);
  check('after save hint matches', afterBody.hint === 'AIza••••7890');

  // Verify getUserDecryptedAiKey
  const decryptedKey = await getUserDecryptedAiKey(db, user.id);
  check('decrypted key matches saved raw key', decryptedKey === 'AIzaTestValidKey1234567890');

  // Swarm WITH BYOK key on free plan → unlocks swarm and costs 0 credits!
  const swarmWithByok = await app.inject({
    method: 'POST',
    url: '/api/swarm/scans',
    headers: { cookie },
    payload: {
      targetUrl: 'https://demo.owasp-juice.shop',
      authorization: authz,
    },
  });
  check(
    'free plan WITH BYOK key → 200/202',
    swarmWithByok.statusCode === 200 || swarmWithByok.statusCode === 202,
    {
      status: swarmWithByok.statusCode,
      body: swarmWithByok.body,
    },
  );

  // Direct x-gemini-api-key header authentication without cookie or account
  const directHeaderSwarm = await app.inject({
    method: 'POST',
    url: '/api/swarm/scans',
    headers: { 'x-gemini-api-key': 'AIzaTestValidKey1234567890' },
    payload: {
      targetUrl: 'https://demo.owasp-juice.shop',
      authorization: authz,
    },
  });
  check(
    'direct x-gemini-api-key header → 200/202',
    directHeaderSwarm.statusCode === 200 || directHeaderSwarm.statusCode === 202,
  );

  // --- BYOK provider picker: Qwen + Ollama ---------------------------------
  // Unknown provider → 400 naming the provider
  const badProvider = await app.inject({
    method: 'POST',
    url: '/api/me/ai-key',
    headers: { cookie },
    payload: { apiKey: 'mock-qwen-key-1234567890', provider: 'anthropic' },
  });
  check('unknown provider → 400', badProvider.statusCode === 400);

  // Qwen with a mock key + Beijing region → 200, baseUrl stored
  const qwenSave = await app.inject({
    method: 'POST',
    url: '/api/me/ai-key',
    headers: { cookie },
    payload: { apiKey: 'mock-qwen-key-1234567890', provider: 'qwen', region: 'cn' },
  });
  check('qwen mock key save → 200', qwenSave.statusCode === 200, qwenSave.body);
  const qwenBody = JSON.parse(qwenSave.body);
  check('qwen save provider is qwen', qwenBody.provider === 'qwen');
  check(
    'qwen save baseUrl is Beijing endpoint',
    qwenBody.baseUrl === 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    qwenBody.baseUrl,
  );
  check('qwen save verified is true', qwenBody.verified === true);
  const qwenGet = JSON.parse(
    (
      await app.inject({ method: 'GET', url: '/api/me/ai-key', headers: { cookie } })
    ).body,
  );
  check('GET after qwen save reports region cn', qwenGet.region === 'cn');
  check('GET after qwen save reports baseUrl', qwenGet.baseUrl === qwenBody.baseUrl);
  check(
    'qwen decrypted key matches',
    (await getUserDecryptedAiKey(db, user.id)) === 'mock-qwen-key-1234567890',
  );

  // Qwen with a non-aliyuncs custom URL → 400 (SSRF guard)
  const qwenEvil = await app.inject({
    method: 'POST',
    url: '/api/me/ai-key',
    headers: { cookie },
    payload: {
      apiKey: 'mock-qwen-key-1234567890',
      provider: 'qwen',
      region: 'custom',
      baseUrl: 'https://evil.example.com/compatible-mode/v1',
    },
  });
  check('qwen custom URL off allowlist → 400', qwenEvil.statusCode === 400, qwenEvil.body);

  // Qwen with an http (non-https) custom URL → 400
  const qwenHttp = await app.inject({
    method: 'POST',
    url: '/api/me/ai-key',
    headers: { cookie },
    payload: {
      apiKey: 'mock-qwen-key-1234567890',
      provider: 'qwen',
      region: 'custom',
      baseUrl: 'http://dashscope.aliyuncs.com/compatible-mode/v1',
    },
  });
  check('qwen custom URL http → 400', qwenHttp.statusCode === 400);

  // Qwen with a valid custom workspace URL → 200
  const qwenCustom = await app.inject({
    method: 'POST',
    url: '/api/me/ai-key',
    headers: { cookie },
    payload: {
      apiKey: 'mock-qwen-key-1234567890',
      provider: 'qwen',
      region: 'custom',
      baseUrl: 'https://my-workspace.dashscope.aliyuncs.com/compatible-mode/v1',
    },
  });
  check('qwen valid custom URL → 200', qwenCustom.statusCode === 200, qwenCustom.body);
  check(
    'qwen custom save reports region custom',
    JSON.parse(qwenCustom.body).region === 'custom',
  );

  // Ollama: no key needed, stored unverified, hint 'local'
  const ollamaSave = await app.inject({
    method: 'POST',
    url: '/api/me/ai-key',
    headers: { cookie },
    payload: { provider: 'ollama' },
  });
  check('ollama save without key → 200', ollamaSave.statusCode === 200, ollamaSave.body);
  const ollamaBody = JSON.parse(ollamaSave.body);
  check('ollama save verified is false', ollamaBody.verified === false);
  check('ollama save hint is local', ollamaBody.hint === 'local');
  const ollamaGet = JSON.parse(
    (
      await app.inject({ method: 'GET', url: '/api/me/ai-key', headers: { cookie } })
    ).body,
  );
  check('GET after ollama save provider is ollama', ollamaGet.provider === 'ollama');
  check('GET after ollama save verified is false', ollamaGet.verified === false);
  check(
    'ollama decrypted key is null (no key to use)',
    (await getUserDecryptedAiKey(db, user.id)) === null,
  );

  // Gemini still works after the provider changes (regression)
  const geminiAgain = await app.inject({
    method: 'POST',
    url: '/api/me/ai-key',
    headers: { cookie },
    payload: { apiKey: 'AIzaTestValidKey1234567890', provider: 'gemini' },
  });
  check('gemini save after qwen/ollama → 200', geminiAgain.statusCode === 200);
  check(
    'gemini save clears baseUrl',
    JSON.parse(geminiAgain.body).baseUrl === null,
  );

  // DELETE key
  const delRes = await app.inject({
    method: 'DELETE',
    url: '/api/me/ai-key',
    headers: { cookie },
  });
  check('DELETE /api/me/ai-key → 200', delRes.statusCode === 200);
  const delBody = JSON.parse(delRes.body);
  check('delBody connected is false', delBody.connected === false);

  // Check state after delete
  const postDelGet = await app.inject({
    method: 'GET',
    url: '/api/me/ai-key',
    headers: { cookie },
  });
  check('GET after delete connected is false', JSON.parse(postDelGet.body).connected === false);
  const postDelKey = await getUserDecryptedAiKey(db, user.id);
  check('decrypted key after delete is null', postDelKey === null);

  if (failures > 0) {
    console.error(`FAILED: ${failures} test(s) failed`);
    process.exit(1);
  }
  console.log('ALL AI KEY TESTS PASSED');
}

main().catch((err) => {
  console.error('Test runner failed:', err);
  process.exit(1);
});

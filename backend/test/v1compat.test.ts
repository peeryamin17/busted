/* Integration test for the /api/v1 compat layer with stubbed db/provider. */
import Fastify from 'fastify';
import { v1CompatRoutes } from '../src/routes/v1compat.js';

const findings: any[] = [];
const db: any = {
  kind: 'stub',
  async getApiKeyByHash() {
    return { userId: 'u1', revokedAt: null };
  },
  async getUserById() {
    return { id: 'u1', email: 't@e.com', plan: 'pro' };
  },
  async touchApiKey() { /* stub */ },
  async createScan(input: any) {
    return { id: 'scan-1', ...input, status: 'completed', progress: {}, createdAt: new Date().toISOString() };
  },
  async addFinding(f: any) {
    findings.push(f);
    return { ...f, id: 'f1', createdAt: new Date().toISOString() };
  },
};
const provider: any = {
  name: 'mock',
  async complete() {
    return {
      text: JSON.stringify({ chains: [{ id: 'c1', verdict: 'plausible', confidence: 'medium', note: 'Looks plausible; verify manually.' }] }),
      parseJson<T>() { return JSON.parse(this.text) as T; },
      usage: { inputTokens: 100, outputTokens: 50 },
    };
  },
};

async function main() {
  const app = Fastify();
  await v1CompatRoutes(app as any, { db, queue: {} as any, provider });

  const h = await app.inject({ method: 'GET', url: '/api/v1/health' });
  console.log('health:', h.statusCode, h.body.slice(0, 80));

  const noAuth = await app.inject({ method: 'POST', url: '/api/v1/scans', payload: {} });
  console.log('no-auth scans:', noAuth.statusCode);

  const ingest = await app.inject({
    method: 'POST', url: '/api/v1/scans',
    headers: { 'x-api-key': 'bs_test' },
    payload: {
      targetUrl: 'https://example.com', mode: 'passive',
      tech: [{ name: 'nginx' }],
      findings: [{
        category: 'headers', title: 'Missing security headers: content-security-policy',
        description: 'No CSP set. Contact admin hunter2@example.com', severity: 'medium',
        confidence: 'high', trapProbability: 0.9, location: 'https://example.com/',
        evidence: 'missing: content-security-policy', reproSteps: ['curl -I https://example.com'],
        remediation: 'Add CSP', references: [],
      }],
    },
  });
  console.log('ingest:', ingest.statusCode, ingest.body.slice(0, 60));
  const f = findings[0];
  console.log('stored title:', f.title);
  console.log('stored trap:', f.trapProbability, 'suspect:', f.honeypotSuspect);
  console.log('cvss:', f.cvssScore, f.cvssVector?.slice(0, 20));

  const chains = await app.inject({
    method: 'POST', url: '/api/v1/chains/analyze',
    headers: { 'x-api-key': 'bs_test' },
    payload: {
      targetUrl: 'https://example.com',
      chains: [{ id: 'c1', title: 'XSS→session hijack', description: 'desc', findingIds: ['f1'] }],
      findings: [{ id: 'f1', title: 'Reflected input', severity: 'high', evidence: 'q=<canary>' }],
    },
  });
  console.log('chains:', chains.statusCode, chains.body.slice(0, 160));

  const bad = await app.inject({
    method: 'POST', url: '/api/v1/scans', headers: { 'x-api-key': 'bs_test' },
    payload: { targetUrl: 'not a url' },
  });
  console.log('bad url:', bad.statusCode);

  const acct = await app.inject({ method: 'GET', url: '/api/v1/account', headers: { 'x-api-key': 'bs_test' } });
  const acctBody = JSON.parse(acct.body);
  console.log('account:', acct.statusCode, acct.body.slice(0, 120));
  if (acct.statusCode !== 200 || acctBody.email !== 't@e.com' || acctBody.plan !== 'pro' || acctBody.operator !== false) {
    throw new Error('account endpoint mismatch (non-operator)');
  }
  process.env['ADMIN_EMAIL'] = 't@e.com';
  const op = await app.inject({ method: 'GET', url: '/api/v1/account', headers: { 'x-api-key': 'bs_test' } });
  const opBody = JSON.parse(op.body);
  console.log('account as operator:', op.statusCode, op.body.slice(0, 120));
  if (op.statusCode !== 200 || opBody.operator !== true) {
    throw new Error('account endpoint mismatch (operator)');
  }
  const noKey = await app.inject({ method: 'GET', url: '/api/v1/account' });
  console.log('account no-auth:', noKey.statusCode);
  if (noKey.statusCode !== 401) throw new Error('account endpoint must require auth');
  console.log('ALL V1COMPAT TESTS PASSED');
  await app.close();
}
main().catch((e) => { console.error('FAIL', e); process.exit(1); });

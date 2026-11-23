/**
 * Bloodhound self-check, run with `npm run check:bloodhound`.
 *
 * No test runner exists in this repo, so this is a plain executable
 * module: esbuild bundles it and node runs it. Every check uses synthetic
 * values that are NOT real credentials (deterministic filler drawn from a
 * fixed alphabet). Any check failure throws, so the npm script exits
 * non-zero. Nothing here calls a provider API.
 */
import { buildMarkdownReport } from '../lib/report';
import {
  fingerprintSecret,
  isKnownPublicHash,
  shannonEntropy,
} from '../lib/regexes';
import type { Finding, ScanResult } from '../lib/types';
import {
  scanHighEntropyStrings,
  scanSecretKeyNames,
  scanSecrets,
} from './secretScanner';
import {
  attachTrailsToFindings,
  buildTrails,
  sightingsFromFindings,
  trafficUsesFromEntries,
} from './keyTrail';

/* Deterministic filler: cycles a fixed alphabet, never a real secret. */
const ALPH = 'K7mQ2xR9vT4wY8bN3pL6sD1fH5j';
const tok = (n: number): string =>
  Array.from({ length: n }, (_, i) => ALPH[i % ALPH.length]).join('');

let passed = 0;
const failures: string[] = [];

function check(name: string, cond: boolean): void {
  if (cond) {
    passed++;
  } else {
    failures.push(name);
  }
}

/* ------------------------------------------------------------------ */
/* 1. Provider patterns: each sample is found, redacted, fingerprinted */
/* ------------------------------------------------------------------ */

const SAMPLES: Array<{ provider: string; sample: string; match?: string }> = [
  { provider: 'aws-access-key', sample: `AKIA${tok(16).toUpperCase()}` },
  { provider: 'aws-session-token', sample: `FQoGZXIvYXdz${tok(48)}` },
  { provider: 'gcp-service-account', sample: '"type": "service_account", "private_key": "x"', match: '"type": "service_account"' },
  { provider: 'gcp-oauth-client-secret', sample: `GOCSPX-${tok(28)}` },
  { provider: 'azure-storage-connection', sample: `DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=${tok(86)}==` },
  { provider: 'azure-servicebus-connection', sample: `Endpoint=sb://myns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=${tok(43)}=` },
  { provider: 'openai-api-key', sample: `sk-${tok(48)}` },
  { provider: 'anthropic-api-key', sample: `sk-ant-${tok(40)}` },
  { provider: 'stripe-live-key', sample: `sk_live_${tok(24)}` },
  { provider: 'square-access-token', sample: `sq0atp-${tok(22)}` },
  { provider: 'sendgrid-api-key', sample: `SG.${tok(22)}.${tok(43)}` },
  { provider: 'mailchimp-api-key', sample: `${tok(32).toLowerCase().replace(/[^0-9a-f]/g, 'a')}-us12` },
  { provider: 'twilio-api-key', sample: `SK${tok(32).toLowerCase().replace(/[^0-9a-f]/g, 'b')}` },
  { provider: 'npm-token', sample: `npm_${tok(36)}` },
  { provider: 'google-api-key', sample: `AIza${tok(35)}` },
  { provider: 'slack-token', sample: `xoxb-${tok(12)}-${tok(12)}` },
  { provider: 'slack-token', sample: `xapp-${tok(12)}-${tok(24)}` },
  { provider: 'discord-bot-token', sample: `${tok(24)}.${tok(6)}.${tok(27)}` },
  { provider: 'discord-webhook', sample: `https://discord.com/api/webhooks/987654321098765432/${tok(68)}` },
  { provider: 'telegram-bot-token', sample: `110201543:${tok(35)}` },
  { provider: 'github-token', sample: `ghp_${tok(36)}` },
  { provider: 'github-token', sample: `github_pat_${tok(22)}` },
  { provider: 'private-key', sample: '-----BEGIN RSA PRIVATE KEY-----' },
  { provider: 'mongodb-uri', sample: 'mongodb+srv://user:pass@cluster0.dbhost.net/db' },
  { provider: 'postgres-uri', sample: 'postgres://user:pass@db.dbhost.net:5432/app' },
  { provider: 'mysql-uri', sample: 'mysql://user:pass@db.dbhost.net:3306/app' },
  { provider: 'redis-uri', sample: 'rediss://:pass@cache.dbhost.net:6379/0' },
  {
    provider: 'jwt',
    sample: `eyJ${tok(20)}.${tok(30)}.${tok(30)}`,
  },
];

for (const { provider, sample, match } of SAMPLES) {
  const findings = scanSecrets([{ label: 'test bundle.js', code: `const v = "${sample}";` }]);
  const hit = findings.find((f) => f.secretProvider === provider);
  check(`pattern ${provider} detects sample`, hit !== undefined);
  if (hit) {
    // The fingerprint is computed from the regex MATCH, which for a few
    // patterns (e.g. gcp-service-account) is a substring of the sample.
    const matchedText = match ?? sample;
    check(
      `pattern ${provider} evidence hides full value`,
      !hit.evidence?.includes(matchedText),
    );
    check(
      `pattern ${provider} fingerprint is first4…last4 only`,
      hit.fingerprint !== undefined &&
        hit.fingerprint.startsWith(`${provider}:`) &&
        hit.fingerprint.includes(matchedText.slice(0, 4)) &&
        hit.fingerprint.includes(matchedText.slice(-4)) &&
        !hit.fingerprint.includes(matchedText.slice(4, -4)),
    );
  }
}

// Placeholder values are skipped, not reported.
check(
  'placeholder values skipped',
  scanSecrets([{ label: 't', code: 'const api_key = "test-key-1234567890abcdefghij";' }]).length === 0,
);

/* ------------------------------------------------------------------ */
/* 2. Fingerprint + entropy helpers                                    */
/* ------------------------------------------------------------------ */

check(
  'fingerprint format',
  fingerprintSecret('AKIAZQ9W8X7C6V5B4N3M', 'aws-access-key') === 'aws-access-key:AKIA…4N3M',
);
check(
  'fingerprint hides middle',
  !fingerprintSecret('AKIAZQ9W8X7C6V5B4N3M', 'aws-access-key').includes('ZQ9W8X7C6V5'),
);
check(
  'known public hash recognised',
  isKnownPublicHash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
);

const randomish = '9fK2xQ7vLm4pR8sT1wY3bN6cD0eF5gH8jK2mQv4zX7';
check('high-entropy string scores >= 4.5', shannonEntropy(randomish) >= 4.5);
const entropyFindings = scanHighEntropyStrings(
  `const k = "${randomish}";`,
  'test bundle.js',
);
check('high-entropy string flagged', entropyFindings.length === 1);
check(
  'entropy finding carries score + fingerprint, no value',
  entropyFindings[0]?.entropyScore !== undefined &&
    (entropyFindings[0]?.entropyScore ?? 0) >= 4.5 &&
    !JSON.stringify(entropyFindings[0]).includes(randomish),
);

const lowEntropy = scanHighEntropyStrings(
  'const a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; const b = "hello-world-this-is-just-a-label";',
  'test bundle.js',
);
check('low-entropy / repeated strings ignored', lowEntropy.length === 0);

const imageBase64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
check(
  'data-URI image base64 ignored',
  scanHighEntropyStrings(`const img = "data:image/png;base64,${imageBase64}";`, 'test bundle.js')
    .length === 0,
);
check(
  'URL fragment ignored',
  scanHighEntropyStrings(
    `fetch("https://cdn.example.com/assets/${randomish}/file.js");`,
    'test bundle.js',
  ).length === 0,
);

/* ------------------------------------------------------------------ */
/* 3. Storage / cookie key NAMES (values never read)                   */
/* ------------------------------------------------------------------ */

const keyNameFindings = scanSecretKeyNames(
  {
    local: [
      { key: 'stripe_secret_key', valueLength: 40, shape: 'long-opaque' },
      { key: 'theme', valueLength: 4, shape: 'text' },
    ],
    session: [],
  },
  ['api_key', 'session_id'],
  'https://example.com/',
);
check(
  'secret-shaped storage key flagged by name only',
  keyNameFindings.some((f) => f.location?.includes('stripe_secret_key')),
);
check(
  'secret-shaped cookie name flagged by name only',
  keyNameFindings.some((f) => f.location?.includes('cookie "api_key"')),
);
check(
  'innocuous key names not flagged',
  !keyNameFindings.some((f) => f.location?.includes('"theme"')),
);
check(
  'key-name findings carry no fingerprint',
  keyNameFindings.every((f) => f.fingerprint === undefined),
);

/* ------------------------------------------------------------------ */
/* 4. Key trails                                                       */
/* ------------------------------------------------------------------ */

const fp = fingerprintSecret(`ghp_${tok(36)}`, 'github-token');
const trailFindings: Finding[] = [
  {
    id: 'secret-github-token-1',
    category: 'secrets',
    title: 'GitHub token exposed in JavaScript',
    description: 'd',
    severity: 'high',
    confidence: 'high',
    location: 'https://example.com/app.js',
    evidence: 'redacted',
    remediation: 'r',
    secretProvider: 'github-token',
    fingerprint: fp,
    trail: ['discovered in https://example.com/app.js'],
  },
  {
    id: 'secret-github-token-2',
    category: 'secrets',
    title: 'GitHub token exposed in JavaScript',
    description: 'd',
    severity: 'high',
    confidence: 'high',
    location: 'source map https://example.com/app.js.map → original sources',
    evidence: 'redacted',
    remediation: 'r',
    secretProvider: 'github-token',
    fingerprint: fp,
    trail: ['discovered in source map'],
  },
];
const uses = trafficUsesFromEntries([
  {
    url: 'https://example.com/api/search?api_key=1&q=x',
    host: 'example.com',
    path: '/api/search',
    method: 'GET',
    paramNames: ['api_key', 'q'],
  },
  {
    url: 'https://unrelated.example.org/api?api_key=1',
    host: 'unrelated.example.org',
    path: '/api',
    method: 'GET',
    paramNames: ['api_key'],
  },
]);
// Extraction is host-agnostic (both entries carry a key-like param name);
// host correlation happens in buildTrails, not here.
check('key-like query params extracted from traffic', uses.length === 2);
check('non-key param not extracted', uses.every((u) => u.name === 'api_key'));

const trails = buildTrails(sightingsFromFindings(trailFindings), uses);
check('same fingerprint merges into one trail', trails.length === 1);
check(
  'trail has 2 discovery steps + 1 same-host traffic step',
  trails[0]?.steps.length === 3,
);
check(
  'traffic step is name-based, valueMatched false',
  trails[0]?.steps[2]?.valueMatched === false &&
    (trails[0]?.steps[2]?.text ?? '').includes('name-based correlation'),
);
check(
  'unrelated host traffic not correlated',
  !(trails[0]?.steps.some((s) => s.text.includes('unrelated.example.org')) ?? false),
);
attachTrailsToFindings(trailFindings, trails);
check(
  'trail attached to findings',
  (trailFindings[0].trail?.length ?? 0) === 3,
);

/* ------------------------------------------------------------------ */
/* 5. Report renders fingerprint + trail, never the full value        */
/* ------------------------------------------------------------------ */

const secretValue = `ghp_${tok(36)}`;
const reportFinding: Finding = {
  id: 'secret-github-token-9',
  category: 'secrets',
  title: 'GitHub token exposed in JavaScript',
  description: 'A GitHub token was found.',
  severity: 'high',
  confidence: 'high',
  location: 'https://example.com/app.js',
  evidence: 'ghp_… (redacted)',
  remediation: 'Revoke it.',
  secretProvider: 'github-token',
  fingerprint: fingerprintSecret(secretValue, 'github-token'),
  trail: [
    'discovered in https://example.com/app.js',
    'sent as query param "api_key" to GET example.com/api/search (name-based correlation — the key value was never observed in transit)',
  ],
};
const result: ScanResult = {
  targetUrl: 'https://example.com/',
  scannedAt: new Date().toISOString(),
  durationMs: 100,
  tech: [],
  findings: [reportFinding],
};
const md = buildMarkdownReport(result);
check('report renders fingerprint', md.includes('Fingerprint:'));
check('report renders trail', md.includes('Trail:'));
check('report never contains full secret', !md.includes(secretValue));

/* ------------------------------------------------------------------ */

if (failures.length > 0) {
  throw new Error(
    `bloodhound self-check FAILED (${passed} passed, ${failures.length} failed): ${failures.join('; ')}`,
  );
}
console.log(`bloodhound self-check: ${passed} checks passed, 0 failed`);

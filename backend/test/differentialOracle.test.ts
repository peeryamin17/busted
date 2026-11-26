/**
 * Unit tests for the differential-response oracle
 * (multiagent/differentialOracle.ts) and its depth-ladder rung.
 * All live probes are mocked, no network, no real target, no LLM.
 *
 * Run:  npx tsx test/differentialOracle.test.ts   (from backend/)
 */
import {
  SIMILARITY_THRESHOLD,
  buildCanaryPair,
  checkOracleInput,
  compareResponses,
  evaluatePair,
  isBolaShapedUrl,
  isForbiddenPayload,
  jaccardSimilarity,
  normalizeResponse,
  tokenize,
} from '../src/multiagent/differentialOracle.js';
import {
  classifyFinding,
  validateFindingWithLadder,
  type DepthProber,
  type DepthProbeResponse,
} from '../src/multiagent/depthLadder.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const FIXED_NOW = '2026-11-27T00:00:00.000Z';
const baseOpts = { now: () => FIXED_NOW };

function resp(partial: Partial<DepthProbeResponse>): DepthProbeResponse {
  return { ok: true, status: 200, headers: {}, body: '', ...partial };
}

function tokens(...words: string[]): string {
  return words.join(' ');
}

async function main() {
  // ── 1. Normalisation strips echoed ids, tokens and timestamps ──
  {
    const a = `<html>req 550e8400-e29b-41d4-a716-446655440000 csrf "csrf":"abc123" at 2026-11-27T00:00:00.000Z epoch 1764200000 hex 0123456789abcdef0123 results here</html>`;
    const b = `<html>req 123e4567-e89b-12d3-a456-426614174000 csrf "csrf":"zzz999" at 2026-11-27T00:05:00.000Z epoch 1764200300 hex fedcba9876543210fedc results here</html>`;
    const sim = jaccardSimilarity(tokenize(normalizeResponse(a)), tokenize(normalizeResponse(b)));
    check('normalise: rotated ids/tokens/timestamps compare identical', sim === 1, sim);
    const c = compareResponses(a, b, '1 AND 1=1', '1 AND 1=2');
    check('normalise: rotated volatile values → inconclusive, no signal', c.verdict === 'inconclusive' && !c.signal, c);
    check('normalise: strips the canary itself', !normalizeResponse(`echo bs0123456789abcdef end`, ['bs0123456789abcdef']).includes('bs0123456789abcdef'));
    check('normalise: strips a requestId value', normalizeResponse(`{"requestId":"abc-123","ok":true}`).includes('"requestId":""'));
  }

  // ── 2. Jaccard threshold behaviour at 0.95 ──
  {
    const same = compareResponses('alpha beta gamma', 'alpha beta gamma', 'x', 'y');
    check('jaccard: identical → similarity 1, inconclusive', same.similarity === 1 && same.verdict === 'inconclusive', same);
    const different = compareResponses(
      tokens('apple', 'banana', 'cherry', 'date', 'elderberry'),
      tokens('red', 'green', 'blue', 'yellow', 'purple'),
      'x', 'y',
    );
    check('jaccard: clearly different → similarity 0, confirmed', different.similarity === 0 && different.verdict === 'confirmed', different);
    const atThreshold = compareResponses(
      tokens(...Array.from({ length: 19 }, (_, i) => `t${i + 1}`)),
      tokens(...Array.from({ length: 19 }, (_, i) => `t${i + 1}`), 'lastone'),
      'x', 'y',
    );
    check('jaccard: exactly 0.95 (19/20) → no signal', atThreshold.similarity === 0.95 && atThreshold.verdict === 'inconclusive', atThreshold);
    const belowThreshold = compareResponses(
      tokens(...Array.from({ length: 20 }, (_, i) => `t${i + 1}`)),
      tokens(...Array.from({ length: 18 }, (_, i) => `t${i + 1}`), 'new1', 'new2'),
      'x', 'y',
    );
    check('jaccard: 18/22 below 0.95 → signal', belowThreshold.similarity < SIMILARITY_THRESHOLD && belowThreshold.verdict === 'confirmed', belowThreshold);
    check('jaccard: threshold constant is 0.95', SIMILARITY_THRESHOLD === 0.95);
  }

  // ── 3. Canary producers emit only inert payloads ──
  {
    const sqli = buildCanaryPair('sqli-boolean', 'bs0123456789abcdef');
    check('producer: sqli control is inert true-condition', sqli.control === '1 AND 1=1', sqli.control);
    check('producer: sqli attack is inert false-condition', sqli.attack === '1 AND 1=2', sqli.attack);
    const ssti = buildCanaryPair('ssti', 'bs0123456789abcdef');
    check('producer: ssti control is plain arithmetic text', ssti.control === '7*7', ssti.control);
    check('producer: ssti attack is inert arithmetic only', ssti.attack === '{{7*7}}', ssti.attack);
    check('producer: ssti expected result is 49', ssti.expectedSignal === '49', ssti.expectedSignal);
    const xss = buildCanaryPair('xss-marker', 'bs0123456789abcdef');
    check('producer: xss attack is the canary itself', xss.attack === 'bs0123456789abcdef', xss.attack);
    check('producer: xss control is a plain marker', xss.control === 'plainmarker', xss.control);
    for (const p of [sqli.control, sqli.attack, ssti.control, ssti.attack, xss.control, xss.attack]) {
      check(`producer: payload is inert (${p})`, !isForbiddenPayload(p) && !/;|UNION|SELECT|__class__|<script|alert\(/i.test(p), p);
    }
  }

  // ── 4. Guardrails: forbidden payloads rejected before sending ──
  {
    check('guardrail: UNION SELECT extraction rejected', isForbiddenPayload('1 UNION SELECT password FROM users'));
    check('guardrail: stacked query rejected', isForbiddenPayload('1; DROP TABLE users'));
    check('guardrail: comment-based bypass rejected', isForbiddenPayload("1' -- "));
    check('guardrail: SSTI breakout rejected', isForbiddenPayload('{{7*7.__class__}}'));
    check('guardrail: script payload rejected', isForbiddenPayload('<script>alert(1)</script>'));
    check('guardrail: mutation rejected', isForbiddenPayload("1'; UPDATE users SET admin=1 --"));
    check('guardrail: checkOracleInput refuses forbidden payload', checkOracleInput('http://127.0.0.1:9/search?q=x', ['1 UNION SELECT password FROM users']).allowed === false);
    check('guardrail: checkOracleInput allows canary pair', checkOracleInput('http://127.0.0.1:9/search?q=x', ['1 AND 1=1', '1 AND 1=2']).allowed === true);
  }

  // ── 5. Guardrails: BOLA-shaped input refused, not probed ──
  {
    check('guardrail: /api/users/42 is BOLA-shaped', isBolaShapedUrl('http://127.0.0.1:9/api/users/42'));
    check('guardrail: ?userId=42 is BOLA-shaped', isBolaShapedUrl('http://127.0.0.1:9/search?userId=42'));
    check('guardrail: plain search URL is not BOLA-shaped', !isBolaShapedUrl('http://127.0.0.1:9/search?q=hello'));
    check('guardrail: checkOracleInput refuses BOLA target', checkOracleInput('http://127.0.0.1:9/api/users/42', ['1 AND 1=1', '1 AND 1=2']).allowed === false);
    let calls = 0;
    const counting: DepthProber = async () => { calls += 1; return resp({ body: '' }); };
    const v = await validateFindingWithLadder(
      { category: 'sqli', title: 'Boolean-based SQL injection', location: 'http://127.0.0.1:9/api/users/42' },
      counting, baseOpts,
    );
    check('guardrail: BOLA target → zero probes, unproven', calls === 0 && v.depth === 'unproven', { calls, depth: v.depth });
    check('guardrail: BOLA refusal recorded as stop reason', !!v.stopReason?.includes('refused'), v.stopReason);
  }

  // ── 6. Kind signals: SSTI result and XSS marker ──
  {
    const ssti = buildCanaryPair('ssti', 'bs0123456789abcdef');
    const evaluated = evaluatePair('ssti', ssti, '<html>result 7*7</html>', '<html>result 49</html>');
    check('ssti: evaluated 49 → confirmed', evaluated.verdict === 'confirmed' && evaluated.kindSignal, evaluated);
    const notEvaluated = evaluatePair('ssti', ssti, '<html>result 7*7</html>', '<html>result {{7*7}}</html>');
    check('ssti: raw expression echoed, no 49 → inconclusive', notEvaluated.verdict === 'inconclusive', notEvaluated);
    const xss = buildCanaryPair('xss-marker', 'bs0123456789abcdef');
    const reflected = evaluatePair('xss-marker', xss, '<html>results for plainmarker</html>', '<html>results for bs0123456789abcdef</html>');
    check('xss-marker: canary in attack only → confirmed', reflected.verdict === 'confirmed' && reflected.kindSignal, reflected);
    const bothHaveIt = evaluatePair('xss-marker', xss, '<html>bs0123456789abcdef</html>', '<html>bs0123456789abcdef</html>');
    check('xss-marker: canary in both → inconclusive, no signal', bothHaveIt.verdict === 'inconclusive', bothHaveIt);
  }

  // ── 7. Ladder: classification + SQLi differential confirm/escalate ──
  {
    check('classify: sqli', classifyFinding({ category: 'sqli', title: 'Boolean-based SQL injection' }) === 'sqli');
    check('classify: ssti', classifyFinding({ category: 'ssti', title: 'Server-side template injection' }) === 'ssti');
    const differential: DepthProber = async (req) => {
      const u = new URL(req.url);
      const values = [...u.searchParams.values()];
      if (values.includes('1 AND 1=2')) return resp({ body: '<html>no results found</html>' });
      if (values.includes('1 AND 1=1')) return resp({ body: '<html>results apple banana cherry date elderberry fig grape</html>' });
      return resp({ body: '<html>results apple banana cherry date elderberry fig grape</html>' });
    };
    const v = await validateFindingWithLadder(
      { category: 'sqli', title: 'Boolean-based SQL injection', location: 'http://127.0.0.1:9/search?q=hello' },
      differential, baseOpts,
    );
    check('sqli: true/false differ on two params → verified/escalated', v.status === 'verified' && v.depth === 'escalated' && v.poe === 3, v);
    check('sqli: differential evidence kinds recorded', v.evidence.some((e) => e.kind === 'differential-sqli') && v.evidence.some((e) => e.kind === 'differential-sqli-second-context'), v.evidence.map((e) => e.kind));
    check('sqli: cross-context impact', v.impact === 'cross-context', v.impact);
  }
  {
    // Identical responses after normalisation → inconclusive, unproven.
    const identical: DepthProber = async () => resp({ body: '<html>same page for everyone</html>' });
    const v = await validateFindingWithLadder(
      { category: 'sqli', title: 'Boolean-based SQL injection', location: 'http://127.0.0.1:9/search?q=hello' },
      identical, baseOpts,
    );
    check('sqli: identical responses → hint/unproven', v.status === 'hint' && v.depth === 'unproven', v);
  }
  {
    // SSTI: template evaluates the arithmetic in both parameters.
    const sstiTarget: DepthProber = async (req) => {
      const u = new URL(req.url);
      const values = [...u.searchParams.values()];
      if (values.includes('{{7*7}}')) return resp({ body: '<html>result 49</html>' });
      return resp({ body: '<html>result 7*7</html>' });
    };
    const v = await validateFindingWithLadder(
      { category: 'ssti', title: 'Server-side template injection', location: 'http://127.0.0.1:9/search?q=hello' },
      sstiTarget, baseOpts,
    );
    check('ssti: 49 evaluated on two params → verified/escalated', v.status === 'verified' && v.depth === 'escalated' && v.poe === 3, v);
    check('ssti: differential evidence kinds recorded', v.evidence.some((e) => e.kind === 'differential-ssti') && v.evidence.some((e) => e.kind === 'differential-ssti-second-context'), v.evidence.map((e) => e.kind));
  }
  {
    // SSTI confirmed on one param only → confirmed, not escalated.
    const oneParam: DepthProber = async (req) => {
      const u = new URL(req.url);
      if (u.searchParams.get('q') === '{{7*7}}') return resp({ body: '<html>result 49</html>' });
      return resp({ body: '<html>result 7*7</html>' });
    };
    const v = await validateFindingWithLadder(
      { category: 'ssti', title: 'Server-side template injection', location: 'http://127.0.0.1:9/search?q=hello' },
      oneParam, baseOpts,
    );
    check('ssti: one param only → hint/confirmed (POE 2 stays hint)', v.status === 'hint' && v.depth === 'confirmed' && v.poe === 2, v);
  }

  // ── 8. Probe errors → inconclusive, never a pass or fail ──
  {
    const controlFails: DepthProber = async (req) => {
      if (req.label.includes('control')) return { ok: false, body: '', error: 'connection reset' };
      return resp({ body: '<html>no results found</html>' });
    };
    const v = await validateFindingWithLadder(
      { category: 'sqli', title: 'Boolean-based SQL injection', location: 'http://127.0.0.1:9/search?q=hello' },
      controlFails, baseOpts,
    );
    check('probe error: control request failure → hint/unproven', v.status === 'hint' && v.depth === 'unproven', v);
    const attackFails: DepthProber = async (req) => {
      if (req.label.includes('attack')) return { ok: false, body: '', error: 'connection reset' };
      return resp({ body: '<html>results here</html>' });
    };
    const v2 = await validateFindingWithLadder(
      { category: 'sqli', title: 'Boolean-based SQL injection', location: 'http://127.0.0.1:9/search?q=hello' },
      attackFails, baseOpts,
    );
    check('probe error: attack request failure → hint/unproven', v2.status === 'hint' && v2.depth === 'unproven', v2);
    const throwing: DepthProber = async () => { throw new Error('network exploded'); };
    const v3 = await validateFindingWithLadder(
      { category: 'ssti', title: 'Server-side template injection', location: 'http://127.0.0.1:9/search?q=hello' },
      throwing, baseOpts,
    );
    check('probe error: throwing prober degrades to hint', v3.status === 'hint' && v3.depth === 'unproven', v3);
  }

  if (failures > 0) { console.error(`${failures} differential-oracle test(s) failed`); process.exit(1); }
  console.log('ALL DIFFERENTIAL-ORACLE TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('differential-oracle test crashed', e); process.exit(1); });

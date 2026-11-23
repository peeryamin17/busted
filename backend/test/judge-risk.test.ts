/**
 * Unit tests for the fallback judge (src/guardrails/judge.ts) and the
 * deterministic risk score (src/guardrails/risk.ts). No network, no DB,
 * no live LLM, the judge is exercised through a fake provider.
 *
 * Run:  npx tsx test/judge-risk.test.ts   (from backend/)
 */
import {
  JUDGE_QUESTIONS,
  buildJudgePrompt,
  judgeToolCall,
} from '../src/guardrails/judge.js';
import { bandForScore, riskScore, type RiskInput } from '../src/guardrails/risk.js';
import {
  makeCompletion,
  type LLMCompletionRequest,
  type LLMProvider,
} from '../src/llm/provider.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

/** Fake provider: answers from a canned JSON string, records the request. */
function fakeProvider(text: string, opts?: { throws?: Error }): LLMProvider & { seen: LLMCompletionRequest[] } {
  const seen: LLMCompletionRequest[] = [];
  return {
    name: 'fake-judge',
    seen,
    async complete(req: LLMCompletionRequest) {
      seen.push(req);
      if (opts?.throws) throw opts.throws;
      return makeCompletion(text, { inputTokens: 10, outputTokens: 10 });
    },
  };
}

const JUDGE_OK = JSON.stringify({
  answers: [false, false, false, false, false, false, false, false],
  reason: 'Plain read-only fetch against the primary host.',
});

const baseInput = {
  tool: 'http_fetch',
  args: { url: 'https://example.com/' },
  targetHost: 'example.com',
  scopeSummary: 'full-domain example.com',
};

async function main() {
  // ── 1. Judge: all-false → allow ──
  {
    const r = await judgeToolCall(fakeProvider(JUDGE_OK), baseInput);
    check('judge: all-false → allow', r.verdict === 'allow', r);
    check('judge: all-false → eight false answers', r.answers.length === 8 && r.answers.every((a) => a === false), r);
    check('judge: all-false → reason kept', r.reason.includes('Plain read-only fetch'), r);
  }

  // ── 2. Judge: any single true answer → ask (each question on its own) ──
  {
    for (let i = 0; i < 8; i++) {
      const answers = Array(8).fill(false);
      answers[i] = true;
      const r = await judgeToolCall(
        fakeProvider(JSON.stringify({ answers, reason: `question ${i + 1} is yes` })),
        baseInput
      );
      check(`judge: only question ${i + 1} true → ask`, r.verdict === 'ask', r);
      check(`judge: only question ${i + 1} true → answers kept`, r.answers[i] === true, r);
    }
  }

  // ── 3. Judge: malformed JSON → ask ──
  {
    const r = await judgeToolCall(fakeProvider('this is not json at all'), baseInput);
    check('judge: malformed JSON → ask', r.verdict === 'ask', r);
    check('judge: malformed JSON → reason says so', /parse|JSON/i.test(r.reason), r);
  }

  // ── 4. Judge: provider throws → ask ──
  {
    const r = await judgeToolCall(
      fakeProvider(JUDGE_OK, { throws: new Error('provider exploded') }),
      baseInput
    );
    check('judge: provider throws → ask', r.verdict === 'ask', r);
  }

  // ── 5. Judge: non-boolean / wrong-shape answers → ask ──
  {
    const nonBoolean = await judgeToolCall(
      fakeProvider(JSON.stringify({ answers: [false, 'maybe', false, false, false, false, false, false], reason: 'unsure' })),
      baseInput
    );
    check('judge: non-boolean answer → ask', nonBoolean.verdict === 'ask', nonBoolean);

    const shortList = await judgeToolCall(
      fakeProvider(JSON.stringify({ answers: [false, false, false], reason: 'short' })),
      baseInput
    );
    check('judge: too few answers → ask', shortList.verdict === 'ask', shortList);

    const missing = await judgeToolCall(
      fakeProvider(JSON.stringify({ reason: 'no answers field' })),
      baseInput
    );
    check('judge: missing answers → ask', missing.verdict === 'ask', missing);

    const nullAnswers = await judgeToolCall(
      fakeProvider(JSON.stringify({ answers: null, reason: 'null' })),
      baseInput
    );
    check('judge: null answers → ask', nullAnswers.verdict === 'ask', nullAnswers);
  }

  // ── 6. Judge prompt: all 8 questions + ONLY JSON instruction ──
  {
    const prompt = buildJudgePrompt(baseInput);
    for (const q of JUDGE_QUESTIONS) {
      check(`judge prompt: contains question "${q.slice(0, 40)}…"`, prompt.system.includes(q));
    }
    check('judge prompt: exactly 8 questions', JUDGE_QUESTIONS.length === 8);
    check('judge prompt: "answer ONLY JSON" instruction', /answer ONLY JSON/i.test(prompt.system), prompt.system);
    check('judge prompt: user part names the tool', prompt.user.includes('http_fetch'), prompt.user);
    check('judge prompt: user part names the target host', prompt.user.includes('example.com'), prompt.user);
  }

  // ── 7. Judge prompt redacts secrets in args ──
  {
    const prompt = buildJudgePrompt({
      tool: 'http_fetch',
      args: { url: 'https://example.com/', password: 'hunter2-secret-value' },
      targetHost: 'example.com',
    });
    check('judge prompt: secret value redacted from args', !prompt.user.includes('hunter2-secret-value'), prompt.user);
  }

  // ── 8. Judge call shape: routine tier, small token budget ──
  {
    const provider = fakeProvider(JUDGE_OK);
    await judgeToolCall(provider, baseInput);
    check('judge: exactly one provider call', provider.seen.length === 1, provider.seen.length);
    const req = provider.seen[0]!;
    check("judge: tier 'routine'", req.tier === 'routine', req);
    check('judge: maxTokens ≤ 400', typeof req.maxTokens === 'number' && req.maxTokens <= 400, req);
    check('judge: temperature 0.1', req.temperature === 0.1, req);
    check('judge: system + user messages', req.messages.length === 2 && req.messages[0]!.role === 'system' && req.messages[1]!.role === 'user', req.messages);
  }

  // ── 9. Risk ordering ──
  {
    const reconPrimary = riskScore({ actionClass: 'read-only-fetch', url: 'https://example.com/', targetHost: 'example.com', scopePosition: 'primary' });
    const reconAuth = riskScore({ actionClass: 'read-only-fetch', url: 'https://example.com/login', targetHost: 'example.com', scopePosition: 'primary' });
    const authProbeNewHost = riskScore({ actionClass: 'auth-probe', url: 'https://new-host.example.net/login', targetHost: 'example.com', scopePosition: 'edge', isNewHost: true, touchesCredentials: true });
    check('risk: read-only recon on primary host is low (<30)', reconPrimary.score < 30 && reconPrimary.band === 'low', reconPrimary);
    check('risk: same action on auth endpoint scores higher', reconAuth.score > reconPrimary.score, { reconPrimary, reconAuth });
    check('risk: auth probe on new unpinned host scores highest', authProbeNewHost.score > reconAuth.score, { reconAuth, authProbeNewHost });
    check('risk: auth probe on new unpinned host is critical (≥80)', authProbeNewHost.score >= 80 && authProbeNewHost.band === 'critical', authProbeNewHost);
  }

  // ── 10. Risk monotonicity: adding a factor never lowers the score ──
  {
    const base: RiskInput = { actionClass: 'read-only-fetch', url: 'https://example.com/', targetHost: 'example.com', scopePosition: 'primary' };
    const baseScore = riskScore(base).score;
    const additions: Array<[string, RiskInput]> = [
      ['auth endpoint', { ...base, isAuthEndpoint: true }],
      ['touches credentials', { ...base, touchesCredentials: true }],
      ['mutates', { ...base, mutates: true }],
      ['subdomain scope', { ...base, scopePosition: 'subdomain' }],
      ['edge scope', { ...base, scopePosition: 'edge' }],
      ['out of scope', { ...base, scopePosition: 'out-of-scope' }],
      ['new unpinned host', { ...base, isNewHost: true }],
      ['auth probe class', { ...base, actionClass: 'auth-probe' }],
      ['form submit class', { ...base, actionClass: 'form-submit' }],
      ['destructive class', { ...base, actionClass: 'destructive' }],
      ['everything at once', { ...base, actionClass: 'auth-probe', isAuthEndpoint: true, touchesCredentials: true, mutates: true, scopePosition: 'out-of-scope', isNewHost: true }],
    ];
    for (const [label, input] of additions) {
      const s = riskScore(input).score;
      check(`risk monotonic: +${label} never lowers (${baseScore} → ${s})`, s >= baseScore, { baseScore, s });
    }
    // Pairwise: every single-flag addition on a mid-risk input also holds.
    const mid: RiskInput = { actionClass: 'form-submit', url: 'https://example.com/submit', targetHost: 'example.com', scopePosition: 'subdomain' };
    const midScore = riskScore(mid).score;
    for (const [label, input] of [
      ['auth endpoint', { ...mid, isAuthEndpoint: true }],
      ['credentials', { ...mid, touchesCredentials: true }],
      ['new host', { ...mid, isNewHost: true }],
      ['out of scope', { ...mid, scopePosition: 'out-of-scope' as const }],
    ] as Array<[string, RiskInput]>) {
      check(`risk monotonic (mid): +${label} never lowers`, riskScore(input).score >= midScore, { midScore, s: riskScore(input).score });
    }
  }

  // ── 11. Band boundaries ──
  {
    check('band: 29 → low', bandForScore(29) === 'low');
    check('band: 30 → medium', bandForScore(30) === 'medium');
    check('band: 59 → medium', bandForScore(59) === 'medium');
    check('band: 60 → high', bandForScore(60) === 'high');
    check('band: 79 → high', bandForScore(79) === 'high');
    check('band: 80 → critical', bandForScore(80) === 'critical');
    check('band: 0 → low', bandForScore(0) === 'low');
    check('band: 100 → critical', bandForScore(100) === 'critical');
    // riskScore's band always agrees with its score.
    const samples: RiskInput[] = [
      { actionClass: 'read-only-fetch', scopePosition: 'primary' },
      { actionClass: 'form-submit', scopePosition: 'subdomain' },
      { actionClass: 'auth-probe', scopePosition: 'primary' },
      { actionClass: 'destructive', scopePosition: 'out-of-scope' },
    ];
    for (const input of samples) {
      const r = riskScore(input);
      check(`band: riskScore band matches score (${r.score} → ${r.band})`, r.band === bandForScore(r.score), r);
    }
  }

  // ── 12. Destructive class never below 70 ──
  {
    const plain = riskScore({ actionClass: 'destructive', scopePosition: 'primary' });
    check('risk: destructive on primary host ≥ 70', plain.score >= 70, plain);
    const mutating = riskScore({ actionClass: 'read-only-fetch', scopePosition: 'primary', mutates: true });
    check('risk: mutating action ≥ 70', mutating.score >= 70, mutating);
    const destructive = riskScore({ actionClass: 'destructive', scopePosition: 'out-of-scope' });
    check('risk: destructive out of scope caps at 100', destructive.score === 100, destructive);
  }

  // ── 13. Auth probes / credential touches are high (≥70) ──
  {
    const probe = riskScore({ actionClass: 'auth-probe', scopePosition: 'primary' });
    check('risk: auth probe ≥ 70', probe.score >= 70, probe);
    const creds = riskScore({ actionClass: 'read-only-fetch', scopePosition: 'primary', touchesCredentials: true });
    check('risk: credential-touching action ≥ 70', creds.score >= 70, creds);
    const outOfScope = riskScore({ actionClass: 'read-only-fetch', scopePosition: 'out-of-scope' });
    check('risk: out-of-scope ≥ 80', outOfScope.score >= 80 && outOfScope.band === 'critical', outOfScope);
    const newHost = riskScore({ actionClass: 'read-only-fetch', scopePosition: 'primary', isNewHost: true });
    check('risk: new unpinned host ≥ 80', newHost.score >= 80 && newHost.band === 'critical', newHost);
  }

  // ── 14. Reasons are non-empty and name the deciding factor ──
  {
    const recon = riskScore({ actionClass: 'read-only-fetch', scopePosition: 'primary' });
    check('risk reasons: non-empty for a low-risk action', recon.reasons.length > 0, recon);
    check('risk reasons: low-risk mentions primary host', recon.reasons.some((r) => /primary in-scope host/i.test(r)), recon);

    const auth = riskScore({ actionClass: 'read-only-fetch', url: 'https://example.com/login', targetHost: 'example.com', scopePosition: 'primary' });
    check('risk reasons: auth endpoint mentioned', auth.reasons.some((r) => /auth\/login\/admin\/session endpoint/i.test(r)), auth);

    const oos = riskScore({ actionClass: 'read-only-fetch', scopePosition: 'out-of-scope' });
    check('risk reasons: out-of-scope mentioned', oos.reasons.some((r) => /outside the authorised scope/i.test(r)), oos);

    const creds = riskScore({ actionClass: 'read-only-fetch', scopePosition: 'primary', touchesCredentials: true });
    check('risk reasons: credentials mentioned', creds.reasons.some((r) => /credentials or session/i.test(r)), creds);

    const destructive = riskScore({ actionClass: 'destructive', scopePosition: 'primary' });
    check('risk reasons: destructive mentioned', destructive.reasons.some((r) => /destructive/i.test(r)), destructive);
  }

  // ── 15. URL inference: auth path + host derivation without explicit flags ──
  {
    const inferred = riskScore({ actionClass: 'read-only-fetch', url: 'https://example.com/admin/settings', targetHost: 'example.com' });
    check('risk: /admin URL inferred as auth endpoint', inferred.score > riskScore({ actionClass: 'read-only-fetch', url: 'https://example.com/', targetHost: 'example.com' }).score, inferred);
    const sub = riskScore({ actionClass: 'read-only-fetch', url: 'https://api.example.com/', targetHost: 'example.com' });
    check('risk: subdomain host inferred from URL', sub.score > riskScore({ actionClass: 'read-only-fetch', url: 'https://example.com/', targetHost: 'example.com' }).score, sub);
    check('risk: score always within 0–100', [inferred, sub].every((r) => r.score >= 0 && r.score <= 100));
  }

  if (failures > 0) { console.error(`${failures} judge-risk test(s) failed`); process.exit(1); }
  console.log('ALL JUDGE-RISK TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('judge-risk test crashed', e); process.exit(1); });

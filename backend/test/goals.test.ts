/**
 * Tests for goal decomposition (multiagent/goals.ts).
 * Mock provider shape mirrors swarm.test.ts / gemini.test.ts: a canned
 * LLMProvider returning fixed JSON, plus a throwing variant.
 */
import { makeCompletion, type LLMCompletion, type LLMCompletionRequest, type LLMProvider } from '../src/llm/provider.js';
import { decomposeGoal } from '../src/multiagent/goals.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

class CannedProvider implements LLMProvider {
  readonly name = 'canned';
  lastRequest: LLMCompletionRequest | null = null;
  constructor(private readonly text: string) {}
  async complete(req: LLMCompletionRequest): Promise<LLMCompletion> {
    this.lastRequest = req;
    return makeCompletion(this.text, { inputTokens: 100, outputTokens: 50 });
  }
}

class ThrowingProvider implements LLMProvider {
  readonly name = 'throwing';
  async complete(): Promise<LLMCompletion> {
    throw new Error('provider exploded');
  }
}

const GOAL = 'Test https://example.com for XSS and auth flaws';
const TARGET = 'https://example.com';

async function main() {
  // 1. Happy path: goals + allow + deny returned as-is.
  {
    const provider = new CannedProvider(JSON.stringify({
      goals: [
        'confirm whether reflected XSS exists on the search page',
        'confirm whether login is vulnerable to credential stuffing',
        'list every endpoint that accepts user input without authentication',
      ],
      allow: ['https://example.com', 'https://example.com/search'],
      deny: ['https://example.com/admin', 'do not submit payment forms'],
    }));
    const out = await decomposeGoal(provider, { goalText: GOAL, targetUrl: TARGET });
    check('goals: returns decomposed goals', out.goals.length === 3, out.goals);
    check('goals: first goal is a deliverable', out.goals[0] === 'confirm whether reflected XSS exists on the search page');
    check('goals: allow returned', out.allow.length === 2 && out.allow[0] === 'https://example.com', out.allow);
    check('goals: deny returned', out.deny.length === 2 && out.deny[0] === 'https://example.com/admin', out.deny);
    const req = provider.lastRequest;
    check('goals: routine tier', req?.tier === 'routine', req?.tier);
    check('goals: maxTokens 600', req?.maxTokens === 600, req?.maxTokens);
    check('goals: temperature 0.2', req?.temperature === 0.2, req?.temperature);
    check('goals: prompt names the target', req?.messages.some((m) => m.content.includes(TARGET)) === true);
    check('goals: prompt forbids recon/attack steps', req?.messages.some((m) => m.content.includes('Do NOT decompose into recon steps')) === true);
  }

  // 2. Malformed JSON → single-goal fallback, never throws.
  {
    const out = await decomposeGoal(new CannedProvider('this is not json {'), { goalText: GOAL, targetUrl: TARGET });
    check('goals: malformed JSON falls back to single goal', out.goals.length === 1 && out.goals[0] === GOAL, out.goals);
    check('goals: malformed JSON → empty allow/deny', out.allow.length === 0 && out.deny.length === 0);
  }

  // 3. Empty goals array → fallback.
  {
    const out = await decomposeGoal(
      new CannedProvider(JSON.stringify({ goals: [], allow: ['https://example.com'], deny: [] })),
      { goalText: GOAL, targetUrl: TARGET },
    );
    check('goals: empty goals fall back to single goal', out.goals.length === 1 && out.goals[0] === GOAL, out.goals);
  }

  // 4. Caps enforced: 7 goals in → 6 out; long goal truncated to 200 chars;
  //    empty/non-string entries dropped.
  {
    const longGoal = 'x'.repeat(250);
    const provider = new CannedProvider(JSON.stringify({
      goals: ['g1', 'g2', 'g3', 'g4', 'g5', 'g6', 'g7', '', '   ', 42, longGoal],
      allow: [],
      deny: [],
    }));
    const out = await decomposeGoal(provider, { goalText: GOAL, targetUrl: TARGET });
    check('goals: 7 goals capped to 6', out.goals.length === 6, out.goals);
    check('goals: cap keeps the first 6', out.goals[5] === 'g6' && !out.goals.includes('g7'));
    const outLong = await decomposeGoal(
      new CannedProvider(JSON.stringify({ goals: [longGoal], allow: [], deny: [] })),
      { goalText: GOAL, targetUrl: TARGET },
    );
    check('goals: long goal truncated to 200 chars', outLong.goals[0].length === 200, outLong.goals[0].length);
    const outDirty = await decomposeGoal(
      new CannedProvider(JSON.stringify({ goals: ['', '  ', 42, null, 'real goal'], allow: [], deny: [] })),
      { goalText: GOAL, targetUrl: TARGET },
    );
    check('goals: empty/non-string entries dropped', outDirty.goals.length === 1 && outDirty.goals[0] === 'real goal', outDirty.goals);
  }

  // 5. Provider error → fallback, never throws.
  {
    const out = await decomposeGoal(new ThrowingProvider(), { goalText: GOAL, targetUrl: TARGET });
    check('goals: provider error falls back to single goal', out.goals.length === 1 && out.goals[0] === GOAL, out.goals);
  }

  // 6. Missing allow/deny keys → empty constraints, not a fallback.
  {
    const out = await decomposeGoal(
      new CannedProvider(JSON.stringify({ goals: ['one deliverable'] })),
      { goalText: GOAL, targetUrl: TARGET },
    );
    check('goals: missing allow/deny → empty arrays', out.goals.length === 1 && out.allow.length === 0 && out.deny.length === 0, out);
  }

  // 7. JSON wrapped in ```json fences still parses (makeCompletion tolerance).
  {
    const out = await decomposeGoal(
      new CannedProvider('```json\n{"goals":["fenced deliverable"],"allow":[],"deny":[]}\n```'),
      { goalText: GOAL, targetUrl: TARGET },
    );
    check('goals: fenced JSON parses', out.goals.length === 1 && out.goals[0] === 'fenced deliverable', out.goals);
  }

  // 8. Non-object JSON (e.g. a bare string) → fallback.
  {
    const out = await decomposeGoal(new CannedProvider('"just a string"'), { goalText: GOAL, targetUrl: TARGET });
    check('goals: non-object JSON falls back', out.goals.length === 1 && out.goals[0] === GOAL, out.goals);
  }

  if (failures > 0) { console.error(`${failures} goals test(s) failed`); process.exit(1); }
  console.log('ALL GOALS TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('goals test crashed', e); process.exit(1); });

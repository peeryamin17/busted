/**
 * Unit tests for the timing oracle (multiagent/timingOracle.ts) and its
 * depth-ladder rung. All live probes are mocked with a fake clock, no
 * network, no real target, no real sleeps, no LLM.
 *
 * Run:  npx tsx test/timingOracle.test.ts   (from backend/)
 */
import {
  TIMING_DELAYS_MS,
  buildTimingPair,
  checkScaling,
  checkTimingInput,
  evaluateTimingLadder,
  evaluateTimingStep,
  isTimingPayload,
  mad,
  majorityAgree,
  median,
  robustSigma,
} from '../src/multiagent/timingOracle.js';
import { isForbiddenPayload } from '../src/multiagent/differentialOracle.js';
import {
  TIMING_MAX_PROBES,
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

function sleepSeconds(value: string): number | null {
  const m = value.match(/SLEEP\((\d)\)/);
  return m ? Number(m[1]) : null;
}

function isAttack(value: string): boolean {
  return value.includes('IF(1=1,');
}

// A fake clock the mock prober advances by the simulated latency, so
// the rung measures exact timings without any real sleep.
let fakeNow = 0;
const clock = () => fakeNow;

// Mock target that sleeps on the attack payload and answers at once
// on the control. `sleepParams` limits which params sleep (default all).
function timingTarget(sleepParams?: Set<string>): DepthProber {
  return async (req) => {
    const u = new URL(req.url);
    for (const [param, value] of u.searchParams) {
      if (isAttack(value) && (!sleepParams || sleepParams.has(param))) {
        const n = sleepSeconds(value) ?? 0;
        fakeNow += 100 + n * 1000;
        return resp({ body: '<html>results here</html>' });
      }
    }
    fakeNow += 100;
    return resp({ body: '<html>results here</html>' });
  };
}

const timingFinding = {
  category: 'sqli',
  title: 'Time-based blind SQL injection',
  location: 'http://127.0.0.1:9/search?q=hello',
};

async function main() {
  // ── 1. Median and MAD ignore one slow outlier ──
  {
    const baseline = [100, 102, 98, 101, 5000];
    check('median: one 5000ms outlier leaves median at 101', median(baseline) === 101, median(baseline));
    check('mad: one outlier leaves MAD at 1', mad(baseline) === 1, mad(baseline));
    check('robust sigma: stays small despite the outlier', robustSigma(baseline) < 50, robustSigma(baseline));
    check('robust sigma: floor keeps it off zero for identical timings', robustSigma([100, 100, 100]) === 25, robustSigma([100, 100, 100]));
    const step = evaluateTimingStep({ delayMs: 1000, baselineMs: baseline, delayedMs: [1120, 1090, 1110] });
    check('outlier baseline: delayed samples still signal', step.signal && step.agreeing === 3, step);
  }

  // ── 2. Majority consistency ──
  {
    check('majority: 2 of 3 agree', majorityAgree([true, true, false]));
    check('majority: 1 of 3 does not agree', !majorityAgree([true, false, false]));
    check('majority: empty never agrees', !majorityAgree([]));
    const twoOfThree = evaluateTimingStep({ delayMs: 1000, baselineMs: [100, 102, 98], delayedMs: [1100, 1050, 120] });
    check('step: 2-of-3 over threshold signals', twoOfThree.signal && twoOfThree.agreeing === 2, twoOfThree);
    const oneOfThree = evaluateTimingStep({ delayMs: 1000, baselineMs: [100, 102, 98], delayedMs: [1100, 120, 110] });
    check('step: 1-of-3 over threshold does not signal', !oneOfThree.signal && oneOfThree.agreeing === 1, oneOfThree);
  }

  // ── 3. Ladder scaling ──
  {
    check('scaling: 1000/2000/4000 grows', checkScaling([1000, 2000, 4000]));
    check('scaling: flat diffs do not grow', !checkScaling([2500, 2500, 2500]));
    check('scaling: shrinking diffs fail', !checkScaling([4000, 2000, 1000]));
    check('scaling: one step cannot scale', !checkScaling([1000]));
    const base = [100, 102, 98];
    const growing = TIMING_DELAYS_MS.map((d) =>
      evaluateTimingStep({ delayMs: d, baselineMs: base, delayedMs: [100 + d + 10, 100 + d, 100 + d - 5] }));
    const grown = evaluateTimingLadder(growing);
    check('ladder: diffs growing with delay confirm', grown.verdict === 'confirmed', grown);
    const flatBig = TIMING_DELAYS_MS.map((d) =>
      evaluateTimingStep({ delayMs: d, baselineMs: base, delayedMs: [2600, 2620, 2580] }));
    check('ladder: every step signals on a big flat offset', flatBig.every((s) => s.signal), flatBig);
    const flat = evaluateTimingLadder(flatBig);
    check('ladder: big flat offset is inconclusive, no scaling', flat.verdict === 'inconclusive', flat);
    const flatSmall = TIMING_DELAYS_MS.map((d) =>
      evaluateTimingStep({ delayMs: d, baselineMs: base, delayedMs: [400, 410, 390] }));
    const small = evaluateTimingLadder(flatSmall);
    check('ladder: small constant offset is inconclusive', small.verdict === 'inconclusive' && !flatSmall.some((s) => s.signal), small);
  }

  // ── 4. Too few samples, probe errors, timeouts ──
  {
    const empty = evaluateTimingStep({ delayMs: 1000, baselineMs: [100, 102, 98], delayedMs: [] });
    check('step: no delayed samples is inconclusive', !empty.signal && empty.samples === 0, empty);
    const oneBaseline = evaluateTimingStep({ delayMs: 1000, baselineMs: [100], delayedMs: [1100, 1150, 1200] });
    check('step: one baseline sample is inconclusive', !oneBaseline.signal, oneBaseline);
    const noSteps = evaluateTimingLadder([]);
    check('ladder: no steps is inconclusive', noSteps.verdict === 'inconclusive', noSteps);
    fakeNow = 0;
    const attackFails: DepthProber = async (req) => {
      if (req.label.includes('attack')) return { ok: false, body: '', error: 'connection reset' };
      fakeNow += 100;
      return resp({ body: '<html>results here</html>' });
    };
    const v = await validateFindingWithLadder(timingFinding, attackFails, { ...baseOpts, clock });
    check('probe error: attack failures leave no samples, hint/unproven', v.status === 'hint' && v.depth === 'unproven', v);
    fakeNow = 0;
    const timeouts: DepthProber = async () => ({ ok: false, body: '', error: 'request timed out' });
    const v2 = await validateFindingWithLadder(timingFinding, timeouts, { ...baseOpts, clock });
    check('probe error: every probe timing out is inconclusive', v2.status === 'hint' && v2.depth === 'unproven', v2);
    const throwing: DepthProber = async () => { throw new Error('network exploded'); };
    const v3 = await validateFindingWithLadder(timingFinding, throwing, { ...baseOpts, clock });
    check('probe error: throwing prober degrades to hint', v3.status === 'hint' && v3.depth === 'unproven', v3);
  }

  // ── 5. Identical timings ──
  {
    const identical = evaluateTimingStep({ delayMs: 1000, baselineMs: [100, 100, 100], delayedMs: [100, 100, 100] });
    check('step: identical timings do not signal', !identical.signal && identical.diffMs === 0, identical);
    const ladder = evaluateTimingLadder(TIMING_DELAYS_MS.map((d) =>
      evaluateTimingStep({ delayMs: d, baselineMs: [100, 100, 100], delayedMs: [100, 100, 100] })));
    check('ladder: identical timings are inconclusive', ladder.verdict === 'inconclusive', ladder);
    fakeNow = 0;
    const flat: DepthProber = async () => { fakeNow += 100; return resp({ body: '<html>same page</html>' }); };
    const v = await validateFindingWithLadder(timingFinding, flat, { ...baseOpts, clock });
    check('rung: identical timings are hint/unproven', v.status === 'hint' && v.depth === 'unproven', v);
  }

  // ── 6. Guardrails: payloads are inert delay triggers only ──
  {
    const forbidden = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'exec', 'execute', ';', '--', '/*', 'alert(', 'eval(', 'document.', '__class__', 'os.', 'subprocess', 'import '];
    for (const d of TIMING_DELAYS_MS) {
      const pair = buildTimingPair(d);
      check(`guardrail: ${d}ms control matches the allowlist`, isTimingPayload(pair.control), pair.control);
      check(`guardrail: ${d}ms attack matches the allowlist`, isTimingPayload(pair.attack), pair.attack);
      for (const p of [pair.control, pair.attack]) {
        check(`guardrail: payload has no extraction/execution pattern (${p})`, !forbidden.some((f) => p.toLowerCase().includes(f)) && !isForbiddenPayload(p), p);
      }
      check(`guardrail: ${d}ms pair differs only in the boolean`, pair.control.replace('1=2', '1=1') === pair.attack, pair);
    }
    check('guardrail: stacked query refused', !isTimingPayload('1 AND SLEEP(2); DROP TABLE users'));
    check('guardrail: plain select refused', !isTimingPayload('1 AND 1=1 UNION SELECT password FROM users'));
    check('guardrail: BOLA target refused', checkTimingInput('http://127.0.0.1:9/api/users/42', ['1 AND IF(1=1,SLEEP(2),0)']).allowed === false);
    check('guardrail: plain search URL allowed', checkTimingInput('http://127.0.0.1:9/search?q=hello', ['1 AND IF(1=1,SLEEP(2),0)']).allowed === true);
    check('guardrail: bad delay rejected', (() => { try { buildTimingPair(1500); return false; } catch { return true; } })());
    let calls = 0;
    const counting: DepthProber = async () => { calls += 1; return resp({ body: '' }); };
    const v = await validateFindingWithLadder(
      { category: 'sqli', title: 'Time-based blind SQL injection', location: 'http://127.0.0.1:9/api/users/42' },
      counting, baseOpts,
    );
    check('guardrail: BOLA target sends zero probes, unproven', calls === 0 && v.depth === 'unproven', { calls, depth: v.depth });
    check('guardrail: BOLA refusal recorded as stop reason', !!v.stopReason?.includes('refused'), v.stopReason);
  }

  // ── 7. Ladder rung: confirm and escalate on a sleeping target ──
  {
    check('classify: time-based blind SQLi is timing, not sqli', classifyFinding({ category: 'sqli', title: 'Time-based blind SQL injection' }) === 'timing');
    check('classify: plain boolean SQLi stays sqli', classifyFinding({ category: 'sqli', title: 'Boolean-based SQL injection' }) === 'sqli');
    check('classify: timing category classifies', classifyFinding({ category: 'timing', title: 'Response timing side channel' }) === 'timing');
    fakeNow = 0;
    let calls = 0;
    const target = timingTarget();
    const counting: DepthProber = async (req) => { calls += 1; return target(req); };
    const v = await validateFindingWithLadder(timingFinding, counting, { ...baseOpts, clock });
    check('timing: sleeping target on two params is verified/escalated', v.status === 'verified' && v.depth === 'escalated' && v.poe === 3, v);
    check('timing: evidence kinds recorded', v.evidence.some((e) => e.kind === 'timing') && v.evidence.some((e) => e.kind === 'timing-second-context'), v.evidence.map((e) => e.kind));
    check('timing: cross-context impact', v.impact === 'cross-context', v.impact);
    check('timing: full ladder uses 24 probes, inside its budget', calls === 24 && calls <= TIMING_MAX_PROBES, { calls, budget: TIMING_MAX_PROBES });
  }
  {
    // Sleeps on the first parameter only: confirmed, not escalated.
    fakeNow = 0;
    let calls = 0;
    const target = timingTarget(new Set(['q']));
    const counting: DepthProber = async (req) => { calls += 1; return target(req); };
    const v = await validateFindingWithLadder(timingFinding, counting, { ...baseOpts, clock });
    check('timing: one param only is hint/confirmed (POE 2 stays hint)', v.status === 'hint' && v.depth === 'confirmed' && v.poe === 2, v);
    check('timing: one-param run still spends the full 24-probe ladder', calls === 24, { calls });
  }
  {
    // Timing-only: the verdict does not move when response bodies change.
    fakeNow = 0;
    let m = 0;
    const flatBodies: DepthProber = async (req) => {
      m += 1;
      const u = new URL(req.url);
      let slept = false;
      for (const value of u.searchParams.values()) {
        if (isAttack(value)) { fakeNow += 100 + (sleepSeconds(value) ?? 0) * 1000; slept = true; break; }
      }
      if (!slept) fakeNow += 100;
      return resp({ body: `<html>variant ${m} completely different content ${'y'.repeat(m * 7)}</html>` });
    };
    const v = await validateFindingWithLadder(timingFinding, flatBodies, { ...baseOpts, clock });
    check('timing-only: varying bodies do not change the verdict', v.status === 'verified' && v.depth === 'escalated', v);
  }
  {
    // Default clock path (performance.now, no injected clock): an instant
    // mock answers at once, so every sample is ~0ms and nothing signals.
    const instant: DepthProber = async () => resp({ body: '<html>fast</html>' });
    const started = Date.now();
    const v = await validateFindingWithLadder(timingFinding, instant, baseOpts);
    check('default clock: instant responses are hint/unproven', v.status === 'hint' && v.depth === 'unproven', v);
    check('default clock: instant run finishes fast', Date.now() - started < 5000, Date.now() - started);
  }

  if (failures > 0) { console.error(`${failures} timing-oracle test(s) failed`); process.exit(1); }
  console.log('ALL TIMING-ORACLE TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('timing-oracle test crashed', e); process.exit(1); });

import type { OracleVerdict } from '../reports/poe.js';
import { isBolaShapedUrl, isForbiddenPayload } from './differentialOracle.js';

// Timing oracle: latency only. It measures how long responses take, it
// never reads response bodies for content and never extracts data.
//
// Two ideas carry the verdict, both exist so one slow outlier or one
// slow response cannot fake a signal:
//   robust sigma: baseline timings are summarised with median and median
//     absolute deviation, not mean and standard deviation.
//   majority consistency: a step only signals when most repeated
//     measurements agree, never on a single sample.
//   ladder scaling: delays grow 1s, 2s, 4s. A genuine timing signal
//     grows with the injected delay; a constant offset does not.
// A probe error, a timeout, or a majority that does not agree lands
// inconclusive, never a pass or a fail.

export const TIMING_DELAYS_MS = [1000, 2000, 4000];

/** Repeated measurements per side of each delay step. */
export const TIMING_REPEATS = 3;

/** Floor on the robust sigma, so jitter-free timings cannot divide by zero. */
export const SIGMA_FLOOR_MS = 25;

/** A step signals only when the median delay grows by at least this factor. */
export const SCALING_FACTOR = 1.5;

export function median(values: number[]): number {
  if (values.length === 0) return NaN;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

export function mad(values: number[], med: number = median(values)): number {
  if (values.length === 0) return NaN;
  return median(values.map((v) => Math.abs(v - med)));
}

/** Robust sigma: 1.4826 times the MAD, floored so it is never zero. */
export function robustSigma(values: number[]): number {
  if (values.length === 0) return NaN;
  return Math.max(1.4826 * mad(values), SIGMA_FLOOR_MS);
}

/** True when strictly more than half the flags agree. Empty never agrees. */
export function majorityAgree(flags: boolean[]): boolean {
  if (flags.length === 0) return false;
  return flags.filter(Boolean).length * 2 > flags.length;
}

/**
 * Scaling check over median diffs in delay order: diffs must not shrink
 * step to step (10 percent slack for jitter) and the last must be at
 * least SCALING_FACTOR times the first.
 */
export function checkScaling(diffsMs: number[]): boolean {
  if (diffsMs.length < 2) return false;
  for (let i = 1; i < diffsMs.length; i++) {
    if (diffsMs[i] < diffsMs[i - 1] * 0.9) return false;
  }
  return diffsMs[diffsMs.length - 1] >= diffsMs[0] * SCALING_FACTOR;
}

export interface TimingPair {
  control: string;
  attack: string;
  delayMs: number;
}

/**
 * Inert delay trigger pair for one delay step. The control and attack
 * differ only in the boolean: the attack sleeps when the condition is
 * true, the control returns at once when it is false. No data is read,
 * no rows are selected, nothing is stacked or executed.
 */
export function buildTimingPair(delayMs: number): TimingPair {
  const seconds = delayMs / 1000;
  if (!Number.isInteger(seconds) || seconds < 1 || seconds > 9) {
    throw new Error(`timing delay must be whole seconds 1-9, got ${delayMs}ms`);
  }
  return {
    control: `1 AND IF(1=2,SLEEP(${seconds}),0)`,
    attack: `1 AND IF(1=1,SLEEP(${seconds}),0)`,
    delayMs,
  };
}

// The only payload shapes the oracle ever sends: the exact control and
// attack forms from buildTimingPair, nothing else.
const TIMING_PAYLOAD_RE = /^1 AND IF\(1=[12],SLEEP\([1-9]\),0\)$/;

export function isTimingPayload(payload: string): boolean {
  return TIMING_PAYLOAD_RE.test(payload);
}

export interface OracleInputCheck {
  allowed: boolean;
  reason?: string;
}

/** Guardrail gate: refuse BOLA targets and any payload outside the allowlist. */
export function checkTimingInput(url: string, payloads: string[]): OracleInputCheck {
  if (isBolaShapedUrl(url)) {
    return { allowed: false, reason: 'BOLA-shaped target (another user object id) - refused, not probed' };
  }
  for (const p of payloads) {
    if (!isTimingPayload(p) || isForbiddenPayload(p)) {
      return { allowed: false, reason: `forbidden payload refused before sending: ${p.slice(0, 80)}` };
    }
  }
  return { allowed: true };
}

export interface TimingStepInput {
  delayMs: number;
  baselineMs: number[];
  delayedMs: number[];
}

export interface TimingStepOutcome {
  delayMs: number;
  baselineMedian: number;
  delayedMedian: number;
  diffMs: number;
  sigmaMs: number;
  agreeing: number;
  samples: number;
  signal: boolean;
  reason: string;
}

/**
 * Verdict for one delay step. A delayed sample counts when it beats the
 * baseline median by at least max(3 robust sigma, half the injected
 * delay). The step signals only when a majority of samples count.
 * Fewer than 2 samples on either side is inconclusive, never a signal.
 */
export function evaluateTimingStep(input: TimingStepInput): TimingStepOutcome {
  const { delayMs, baselineMs, delayedMs } = input;
  const baselineMedian = median(baselineMs) || 0;
  const delayedMedian = median(delayedMs) || 0;
  const sigmaMs = robustSigma(baselineMs) || 0;
  if (baselineMs.length < 2 || delayedMs.length < 2) {
    return {
      delayMs,
      baselineMedian,
      delayedMedian,
      diffMs: 0,
      sigmaMs,
      agreeing: 0,
      samples: delayedMs.length,
      signal: false,
      reason: `too few timing samples (baseline ${baselineMs.length}, delayed ${delayedMs.length}, need at least 2 each)`,
    };
  }
  const threshold = Math.max(3 * sigmaMs, 0.5 * delayMs);
  const flags = delayedMs.map((t) => t - baselineMedian >= threshold);
  const agreeing = flags.filter(Boolean).length;
  const signal = majorityAgree(flags);
  const diffMs = delayedMedian - baselineMedian;
  return {
    delayMs,
    baselineMedian,
    delayedMedian,
    diffMs,
    sigmaMs,
    agreeing,
    samples: delayedMs.length,
    signal,
    reason: signal
      ? `${agreeing}/${delayedMs.length} repeats ${Math.round(diffMs)}ms over baseline median (sigma ${Math.round(sigmaMs)}ms, threshold ${Math.round(threshold)}ms)`
      : `only ${agreeing}/${delayedMs.length} repeats over threshold ${Math.round(threshold)}ms (median diff ${Math.round(diffMs)}ms)`,
  };
}

export interface TimingLadderOutcome {
  verdict: OracleVerdict;
  steps: TimingStepOutcome[];
  reason: string;
}

/**
 * Verdict for the whole ladder. Confirmed needs at least 2 signalling
 * steps whose median diffs scale with the injected delay. Anything
 * else is inconclusive: too few signalling steps, or diffs that do not
 * grow, which is a constant offset, not a timing signal.
 */
export function evaluateTimingLadder(steps: TimingStepOutcome[]): TimingLadderOutcome {
  const signalling = steps.filter((s) => s.signal);
  const diffs = (list: TimingStepOutcome[]): string =>
    list.map((s) => `${Math.round(s.diffMs)}`).join('/');
  if (signalling.length < 2) {
    return {
      verdict: 'inconclusive',
      steps,
      reason: `only ${signalling.length} of ${steps.length} delay steps signalled, need at least 2`,
    };
  }
  if (!checkScaling(signalling.map((s) => s.diffMs))) {
    return {
      verdict: 'inconclusive',
      steps,
      reason: `delay steps signalled but latency did not scale with delay (median diffs ${diffs(signalling)}ms)`,
    };
  }
  return {
    verdict: 'confirmed',
    steps,
    reason: `latency scaled with delay (median diffs ${diffs(signalling)}ms over ${signalling.length} steps, majority of repeats agree)`,
  };
}

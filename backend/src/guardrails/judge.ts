import type { LLMMessage, LLMProvider } from '../llm/provider.js';
import { redactText } from './redact.js';

/**
 * Fallback judge for proposed tool calls that match NO approval rule.
 *
 * Closed-question mode: the judge answers a FIXED set of yes/no risk
 * questions about the call. The verdict is 'allow' ONLY when every answer
 * is false and the response parses cleanly. Anything else, any true
 * answer, any parse failure, any provider error or timeout, any ambiguity
 *, fails closed to 'ask', never 'allow'.
 *
 * Cost: the judge runs on the cheapest ('routine') tier with a small token
 * budget, because it only adjudicates calls the deterministic rules did
 * not already decide.
 */

export const JUDGE_MAX_TOKENS = 300;
export const JUDGE_TEMPERATURE = 0.1;
/** A hung provider must not stall the approval gate: fail to 'ask'. */
export const JUDGE_TIMEOUT_MS = 30_000;

/**
 * The fixed closed questions. The order is part of the contract:
 * answers[i] in the judge's JSON reply answers JUDGE_QUESTIONS[i].
 * Keep this list in sync with the prompt built by buildJudgePrompt.
 */
export const JUDGE_QUESTIONS: readonly string[] = [
  'Does the call mutate server state?',
  'Does the call send credentials or secrets?',
  'Does the call touch an auth or session endpoint?',
  'Does the call exfiltrate data off the target?',
  'Does the call go outside the authorised scope?',
  'Is the call destructive or irreversible?',
  'Does the call attempt to bypass a control (auth, rate limit, WAF)?',
  'Does the call target a non-target host?',
] as const;

export interface JudgeInput {
  /** Tool name, e.g. 'http_fetch', the shape workers plan with. */
  tool: string;
  /** Tool arguments. Values are redacted before they reach the prompt. */
  args?: Record<string, unknown>;
  /** Host the call targets, if known. */
  targetHost?: string;
  /** Short human-readable summary of the authorised scope. */
  scopeSummary?: string;
}

export interface JudgePrompt {
  system: string;
  user: string;
}

export interface JudgeResult {
  verdict: 'allow' | 'ask';
  /** One boolean per question in JUDGE_QUESTIONS, in order. */
  answers: boolean[];
  /** Short human-readable reason (from the judge, or the failure). */
  reason: string;
}

/**
 * Build the judge prompt. Pure, no provider, no I/O, so tests and the
 * approval gate can inspect exactly what the judge is asked.
 */
export function buildJudgePrompt(input: JudgeInput): JudgePrompt {
  const numbered = JUDGE_QUESTIONS.map((q, i) => `${i + 1}. ${q}`).join('\n');
  const system =
    'You are a security gatekeeper deciding whether a proposed tool call in an authorised security test may run without human approval.\n\n' +
    'Answer each of the following questions with YES or NO, in order:\n' +
    `${numbered}\n\n` +
    'Answer ONLY JSON in exactly this shape, with no other text:\n' +
    '{"answers": [boolean, boolean, boolean, boolean, boolean, boolean, boolean, boolean], "reason": "one short sentence explaining the riskiest answer, or why the call is safe"}';

  const argsSummary = redactText(JSON.stringify(redactArgs(input.args ?? {})), 1000);
  const user =
    `Proposed tool call:\n` +
    `tool: ${input.tool}\n` +
    `args (redacted): ${argsSummary}\n` +
    `target host: ${input.targetHost ?? 'unknown'}\n` +
    `authorised scope: ${input.scopeSummary ?? 'unknown'}`;

  return { system, user };
}

const SENSITIVE_ARG_KEYS =
  /password|passwd|pwd|secret|token|api[-_]?key|auth|cookie|session|private[-_]?key|client[-_]?secret/i;

/**
 * Strip values held under sensitive keys (password, token, api key, …)
 * before args are summarised. Key-based redaction covers the shapes a
 * value-pattern scan misses (e.g. JSON `"password": "…"`, where the
 * closing quote and colon sit between the key and the value). The
 * summarised string still passes through redactText for pattern-shaped
 * secrets held under innocuous keys.
 */
function redactArgs(args: Record<string, unknown>): unknown {
  const walk = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(walk);
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out[k] = SENSITIVE_ARG_KEYS.test(k) ? '[REDACTED]' : walk(v);
      }
      return out;
    }
    return value;
  };
  return walk(args);
}

function toMessages(prompt: JudgePrompt): LLMMessage[] {
  return [
    { role: 'system', content: prompt.system },
    { role: 'user', content: prompt.user },
  ];
}

/** Fail-closed result used for every ambiguous or failed judgement. */
function askResult(reason: string): JudgeResult {
  return {
    verdict: 'ask',
    // Unknown safety: report every question as risky rather than safe.
    answers: JUDGE_QUESTIONS.map(() => true),
    reason,
  };
}

/**
 * Adjudicate a proposed tool call with the LLM fallback judge.
 *
 * 'allow' requires a clean parse AND all eight answers false. Every other
 * outcome, a true answer, malformed JSON, a non-boolean or missing answer,
 * a provider error, a timeout, returns 'ask'.
 */
export async function judgeToolCall(
  provider: LLMProvider,
  input: JudgeInput
): Promise<JudgeResult> {
  if (!input.tool || typeof input.tool !== 'string') {
    return askResult('No tool name supplied — failing closed to human approval.');
  }

  const prompt = buildJudgePrompt(input);
  let completion;
  try {
    const call = provider.complete({
      messages: toMessages(prompt),
      maxTokens: JUDGE_MAX_TOKENS,
      temperature: JUDGE_TEMPERATURE,
      tier: 'routine',
    });
    const timeout = new Promise<never>((_, reject) => {
      setTimeout(
        () => reject(new Error(`Judge LLM call timed out after ${JUDGE_TIMEOUT_MS / 1000}s`)),
        JUDGE_TIMEOUT_MS
      );
    });
    completion = await Promise.race([call, timeout]);
  } catch (err) {
    return askResult(
      `Judge provider failed (${(err as Error).message}) — failing closed to human approval.`
    );
  }

  let parsed: unknown;
  try {
    parsed = completion.parseJson<{ answers: unknown; reason: unknown }>();
  } catch (err) {
    return askResult(
      `Judge response did not parse as JSON (${(err as Error).message}) — failing closed to human approval.`
    );
  }

  const answers = (parsed as { answers?: unknown })?.answers;
  if (!Array.isArray(answers) || answers.length !== JUDGE_QUESTIONS.length) {
    return askResult(
      `Judge returned ${Array.isArray(answers) ? answers.length : 'no'} answers, expected ${JUDGE_QUESTIONS.length} — failing closed to human approval.`
    );
  }
  if (!answers.every((a) => typeof a === 'boolean')) {
    return askResult(
      'Judge returned a non-boolean answer — failing closed to human approval.'
    );
  }

  const reasonRaw = (parsed as { reason?: unknown })?.reason;
  const reason =
    typeof reasonRaw === 'string' && reasonRaw.trim().length > 0
      ? reasonRaw.trim().slice(0, 500)
      : 'Judge gave no reason.';

  if ((answers as boolean[]).some((a) => a === true)) {
    const risky = (answers as boolean[])
      .map((a, i) => (a ? JUDGE_QUESTIONS[i] : null))
      .filter((q): q is string => q !== null);
    return {
      verdict: 'ask',
      answers: answers as boolean[],
      reason: `Judge flagged risk: ${risky.join('; ')}. ${reason}`.slice(0, 500),
    };
  }

  return { verdict: 'allow', answers: answers as boolean[], reason };
}

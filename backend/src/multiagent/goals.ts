import type { LLMProvider } from '../llm/provider.js';

/**
 * Goal decomposition.
 *
 * One LLM call turns the operator's free-text goal into:
 *   - `goals`: FINAL DELIVERABLES, testable outcomes that count as "done"
 *     (e.g. "confirm whether reflected XSS exists on the search page").
 *   - `allow` / `deny`: OPERATION CONSTRAINTS, what the swarm may and may
 *     not touch (e.g. "only test https://example.com", "do not touch /admin").
 *
 * Deliberately NOT decomposed into recon steps or attack steps, deciding
 * how to test is the workers' job, later. Decomposition failure must
 * degrade, never kill a scan: any parse failure, empty result, or provider
 * error falls back to a single goal equal to the operator's goal text.
 */

export interface GoalDecompositionInput {
  goalText: string;
  targetUrl: string;
}

export interface GoalDecomposition {
  goals: string[];
  allow: string[];
  deny: string[];
}

const MAX_GOALS = 6;
const MAX_CONSTRAINTS = 12;
const MAX_ITEM_CHARS = 200;

const GOAL_SYSTEM = `You are the GOAL DECOMPOSER for the BugSeek AI security-testing swarm.
You turn an operator's testing goal into a small set of final deliverables
plus the operation constraints the swarm must obey.

HARD RULES:
- "goals" are FINAL DELIVERABLES: testable outcomes that count as done
  (e.g. "confirm whether reflected XSS exists on the search page",
  "list every endpoint that accepts user input without authentication").
  Each goal must be verifiable from evidence, not a procedure.
- Do NOT decompose into recon steps or attack steps. Never list actions
  like "run a port scan", "crawl the site", "try payload X", "check headers".
  How the goal is tested is the workers' job, not yours.
- "allow" lists what IS in scope (hosts, paths, features the swarm may test).
- "deny" lists what is OFF-LIMITS (hosts, paths, actions the swarm must
  never touch). When in doubt, put a boundary in "deny", not "allow".
- All testing is authorized, in-scope, rate-limited, non-destructive.
- Return ONLY valid JSON — no prose, no markdown fences.`;

export async function decomposeGoal(
  provider: LLMProvider,
  input: GoalDecompositionInput,
): Promise<GoalDecomposition> {
  const goalText = input.goalText.trim();
  // Degraded fallback: the scan proceeds with the operator's goal as-is.
  const fallback: GoalDecomposition = {
    goals: goalText ? [goalText.slice(0, MAX_ITEM_CHARS)] : [input.goalText],
    allow: [],
    deny: [],
  };
  try {
    const completion = await provider.complete({
      messages: [
        { role: 'system', content: GOAL_SYSTEM },
        {
          role: 'user',
          content:
            `<!--GOAL-DECOMPOSITION-REQUEST-->\n` +
            `TARGET: ${input.targetUrl}\n` +
            `GOAL: ${input.goalText}\n\n` +
            `Decompose the goal into final deliverables and operation constraints.\n` +
            `Return JSON: {"goals":["..."],"allow":["..."],"deny":["..."]}\n` +
            `Rules: at most ${MAX_GOALS} goals; each goal a single verifiable outcome, ` +
            `not a recon or attack step. "allow"/"deny" are scope boundaries only.`,
        },
      ],
      maxTokens: 600,
      temperature: 0.2,
      tier: 'routine',
    });
    const parsed = completion.parseJson<{ goals?: unknown; allow?: unknown; deny?: unknown }>();
    const goals = cleanItems(parsed?.goals, MAX_GOALS);
    if (goals.length === 0) return fallback;
    return {
      goals,
      allow: cleanItems(parsed?.allow, MAX_CONSTRAINTS),
      deny: cleanItems(parsed?.deny, MAX_CONSTRAINTS),
    };
  } catch {
    // Any failure (provider error, malformed JSON, wrong shape) degrades
    // to the fallback, decomposition must never kill a scan.
    return fallback;
  }
}

/** Keep only non-empty trimmed strings, truncated to the char cap. */
function cleanItems(raw: unknown, cap: number): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item !== 'string') continue;
    const trimmed = item.trim().slice(0, MAX_ITEM_CHARS);
    if (trimmed.length > 0) out.push(trimmed);
    if (out.length >= cap) break;
  }
  return out;
}

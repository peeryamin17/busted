import {
  classifyFinding,
  isLadderTestable,
  untestedVerification,
  validateFindingWithLadder,
  type DepthProber,
  type LadderFindingInput,
} from './depthLadder.js';
import type {
  DepthEvidence,
  DepthLevel,
  Finding,
  FindingVerification,
  VerificationStatus,
} from '../types.js';

/**
 * Retester loop.
 *
 * A dedicated, lightweight re-run of ONE finding's proof, separate from the
 * main swarm. It re-runs only the finding's own proof, the same
 * benign-canary, read-only depth ladder
 * (`validateFindingWithLadder` in depthLadder.ts) with a fresh canary, plus
 * one plain baseline request to the finding's location. It never invents a
 * finding, never mutates state, and never probes outside the finding's
 * authorised target/scope: the route that calls this re-checks authorisation
 * and scope first, and the prober it is handed is built on guardedFetch, so
 * every request still passes the scope / rate-limit / SSRF guards.
 *
 * Verdicts:
 * - 'reproduced', the fresh canary reproduces the proof. Upgrades a hint
 *   to verified.
 * - 'fixed', positive evidence the proof no longer reproduces: the ladder
 *   ran cleanly to completion and the canary no longer reflects / the
 *   neighbour is no longer reachable / the read-only query returns no data,
 *   AND the finding was verified before. 'fixed' is a NEW verification
 *   status alongside 'verified'/'hint': reports must treat it as resolved,
 *   not as a hint. (See the note on `RetestVerification`, `types.ts` still
 *   needs the one-line `VerificationStatus` update for this to typecheck
 *   end-to-end; until then the widened type lives here.)
 * - 'inconclusive', the retest could not run or could not tell: no live
 *   probe for the category, target unreachable, rate-limited, server
 *   errors, a blocked baseline, or the ladder stopping early. A retest
 *   that cannot run is NEVER 'fixed', 'fixed' requires the proof to have
 *   been re-runnable and to have failed. Inconclusive changes nothing: the
 *   finding keeps its existing verification untouched.
 *
 * A retest costs at most 7 probes: 1 baseline + the ladder's max 6.
 */

export const RETEST_METHOD = 'retester v1 (benign canary, read-only)';

export type RetestVerdict = 'reproduced' | 'fixed' | 'inconclusive';

export interface RetestResult {
  findingId: string;
  verdict: RetestVerdict;
  /** Ladder depth when the proof reproduced ('confirmed' | 'escalated'); 'unproven' when fixed. */
  depth?: DepthLevel;
  /** Human-readable statement of what the retest proved (or why it could not tell). */
  impactSummary: string;
  /** Baseline receipt first, then the ladder's rung evidence (if any). */
  evidence: DepthEvidence[];
  /** The fresh canary the retest ran with (ours, safe to show). */
  canaryToken?: string;
  testedAt: string; // ISO
  method: typeof RETEST_METHOD;
}

/** The finding shape the retester needs, a ladder input plus id + prior verification. */
export interface RetestFindingInput extends LadderFindingInput {
  id: string;
  verification?: FindingVerification;
}

/**
 * A finding verification as the retester writes it back: the ladder's
 * `FindingVerification` plus the new 'fixed' status.
 *
 * NOTE (coordinator): add 'fixed' to `VerificationStatus` in `types.ts`
 * (one line) and this alias collapses to `FindingVerification`. Until then,
 * `applyRetestVerdict` returns this widened type and the persistence layer
 * stores it as JSONB, which accepts the new status today.
 */
export type RetestVerification = FindingVerification;

const GRAPHQL_TYPENAME = JSON.stringify({ query: '{ __typename }' });

/** What the single baseline request to the finding's location established. */
type BaselineOutcome =
  | 'reachable' // Endpoint answers; the ladder decides reproduced vs fixed.
  | 'gone' // 404/410, the endpoint that once served the vulnerable response is gone.
  | 'no-data' // GraphQL only: HTTP 200 but the read-only query returns no data.
  | 'unreachable' // No HTTP response at all (network error), cannot tell.
  | 'rate-limited' // HTTP 429, cannot tell.
  | 'server-error' // HTTP 5xx, cannot tell.
  | 'forbidden' // HTTP 403, auth/WAF now in the way; ambiguous, cannot claim fixed.
  | 'ambiguous'; // Any other 4xx, cannot tell.

interface BaselineCheck {
  outcome: BaselineOutcome;
  status?: number;
  evidence: DepthEvidence;
}

function baselineEvidence(
  url: URL,
  isGraphql: boolean,
  status: number | undefined,
  observed: string,
): DepthEvidence {
  return {
    rung: 'confirm',
    kind: 'retest-baseline',
    request: isGraphql
      ? `POST ${url.pathname} { __typename } (read-only query)`
      : `GET ${url.pathname}${url.search}`,
    observed,
    ...(status !== undefined ? { status } : {}),
  };
}

/**
 * One plain, read-only request to the finding's location: is the endpoint
 * still there, and reachable? For GraphQL the baseline is the same read-only
 * `{ __typename }` query the ladder uses (a plain GET to a GraphQL endpoint
 * routinely answers 400/405, which would say nothing). Never throws: a
 * failed request is 'unreachable', not a crash.
 */
async function probeBaseline(
  url: URL,
  kind: ReturnType<typeof classifyFinding>,
  prober: DepthProber,
): Promise<BaselineCheck> {
  const isGraphql = kind === 'graphql';
  let res: Awaited<ReturnType<DepthProber>>;
  try {
    res = await prober({
      method: isGraphql ? 'POST' : 'GET',
      url: url.toString(),
      ...(isGraphql
        ? { headers: { 'content-type': 'application/json' }, body: GRAPHQL_TYPENAME }
        : {}),
      label: 'retest-baseline',
    });
  } catch (err) {
    return {
      outcome: 'unreachable',
      evidence: baselineEvidence(
        url,
        isGraphql,
        undefined,
        `baseline request failed before any HTTP response (${(err as Error).message.slice(0, 120)}) — target unreachable`,
      ),
    };
  }
  const status = res.status;
  // No HTTP response (fetch/network/guardrail failure surfaced as an error
  // with no status), the target cannot be reached, so nothing can be said.
  if (status === undefined || res.error) {
    return {
      outcome: 'unreachable',
      status,
      evidence: baselineEvidence(
        url,
        isGraphql,
        status,
        `baseline request produced no HTTP response (${(res.error ?? 'unknown error').slice(0, 120)}) — target unreachable`,
      ),
    };
  }
  if (status === 429) {
    return {
      outcome: 'rate-limited',
      status,
      evidence: baselineEvidence(url, isGraphql, status, 'HTTP 429: target rate-limited the baseline request'),
    };
  }
  if (status >= 500) {
    return {
      outcome: 'server-error',
      status,
      evidence: baselineEvidence(url, isGraphql, status, `HTTP ${status}: target returned a server error`),
    };
  }
  if (status === 404 || status === 410) {
    return {
      outcome: 'gone',
      status,
      evidence: baselineEvidence(url, isGraphql, status, `HTTP ${status}: the endpoint that once served the vulnerable response is gone`),
    };
  }
  if (status === 403) {
    return {
      outcome: 'forbidden',
      status,
      evidence: baselineEvidence(url, isGraphql, status, 'HTTP 403: target refused the baseline request (auth or WAF in the way)'),
    };
  }
  if (status >= 200 && status < 400) {
    if (isGraphql) {
      let hasData = false;
      try {
        const parsed: unknown = JSON.parse(res.body);
        hasData =
          !!parsed && typeof parsed === 'object' && 'data' in (parsed as Record<string, unknown>);
      } catch {
        /* non-JSON, no data */
      }
      if (!hasData) {
        return {
          outcome: 'no-data',
          status,
          evidence: baselineEvidence(
            url,
            isGraphql,
            status,
            'HTTP 200: the read-only GraphQL query returned no data',
          ),
        };
      }
    }
    return {
      outcome: 'reachable',
      status,
      evidence: baselineEvidence(url, isGraphql, status, `HTTP ${status}: endpoint still answers`),
    };
  }
  return {
    outcome: 'ambiguous',
    status,
    evidence: baselineEvidence(url, isGraphql, status, `HTTP ${status}: unexpected baseline response`),
  };
}

/** Resolve the finding's location (or the target) to an http(s) URL. Mirrors the ladder's resolver. */
function resolveFindingUrl(finding: LadderFindingInput, targetUrl?: string): URL | null {
  const candidates = [finding.location, targetUrl].filter(Boolean) as string[];
  for (const c of candidates) {
    try {
      const u = new URL(c);
      if (u.protocol === 'http:' || u.protocol === 'https:') return u;
    } catch {
      // Not absolute, try resolving a path against the target origin.
      if (targetUrl && c.startsWith('/')) {
        try {
          return new URL(c, targetUrl);
        } catch {
          /* fall through */
        }
      }
    }
  }
  return null;
}

/**
 * Re-run one finding's proof with a fresh canary. Never throws: any prober
 * error or unexpected exception degrades to 'inconclusive' with the reason
 * in `impactSummary`, so a retest failure can never drop, corrupt, or
 * falsely "fix" a finding.
 */
export async function retestFinding(input: {
  finding: RetestFindingInput;
  targetUrl: string;
  prober: DepthProber;
  now?: () => string;
}): Promise<RetestResult> {
  const { finding, targetUrl, prober } = input;
  const now = input.now ?? (() => new Date().toISOString());
  const testedAt = now();
  const inconclusive = (reason: string, evidence: DepthEvidence[] = []): RetestResult => ({
    findingId: finding.id,
    verdict: 'inconclusive',
    impactSummary: `Retest inconclusive: ${reason}`,
    evidence,
    testedAt,
    method: RETEST_METHOD,
  });
  try {
    if (!isLadderTestable(finding)) {
      return inconclusive(
        `no read-only live probe exists for category "${finding.category}" — the retester only re-runs XSS, IDOR, CORS and GraphQL proofs.`,
      );
    }
    const url = resolveFindingUrl(finding, targetUrl);
    if (!url) {
      return inconclusive(
        'no usable URL could be resolved from the finding location — the retester needs a target URL to probe.',
      );
    }
    const kind = classifyFinding(finding);

    // 1. Baseline: is the endpoint still there at all, and reachable? A
    // retest that cannot reach the target cannot say anything, least of
    // all that the finding is fixed.
    const baseline = await probeBaseline(url, kind, prober);
    if (baseline.outcome === 'unreachable') {
      return inconclusive(
        'the target could not be reached — an unreachable target is not evidence of a fix.',
        [baseline.evidence],
      );
    }
    if (baseline.outcome === 'rate-limited') {
      return inconclusive(
        'the target rate-limited the retest (HTTP 429) — the proof could not be re-run.',
        [baseline.evidence],
      );
    }
    if (baseline.outcome === 'server-error') {
      return inconclusive(
        `the target returned HTTP ${baseline.status ?? '5xx'} — the proof could not be re-run against an erroring endpoint.`,
        [baseline.evidence],
      );
    }
    if (baseline.outcome === 'forbidden' || baseline.outcome === 'ambiguous') {
      return inconclusive(
        `the target answered HTTP ${baseline.status} to the baseline request — the proof could not be re-run, and a blocked request is not evidence of a fix.`,
        [baseline.evidence],
      );
    }

    // 2. Re-run the finding's own proof with a fresh canary.
    const ladder = await validateFindingWithLadder(finding, prober, { targetUrl, now });
    const evidence = [baseline.evidence, ...ladder.evidence];
    if (ladder.status === 'verified') {
      return {
        findingId: finding.id,
        verdict: 'reproduced',
        depth: ladder.depth,
        impactSummary: `Retest reproduced the finding with a fresh benign canary. ${ladder.impactSummary}`,
        evidence,
        canaryToken: ladder.canaryToken,
        testedAt,
        method: RETEST_METHOD,
      };
    }

    // 3. The ladder could not reproduce. A stop reason means the run itself
    // was cut short (rate limit, lockout, error storm, guardrail refusal,
    // probe budget), that is "could not tell", never "fixed".
    if (ladder.stopReason) {
      return inconclusive(
        `the re-run stopped early (${ladder.stopReason}) — the proof could not be re-run to completion.`,
        evidence,
      );
    }

    // 4. No stop reason: the probes ran cleanly and the proof did not
    // reproduce. That is positive evidence the fix landed, but only for a
    // finding that was verified before. A hint that still does not
    // reproduce tells us nothing new.
    if (finding.verification?.status !== 'verified') {
      return inconclusive(
        'the re-run did not reproduce the proof, but the finding was never verified — an unproven hint that stays unproven is not evidence of a fix.',
        evidence,
      );
    }
    const goneNote =
      baseline.outcome === 'gone'
        ? ` The endpoint that once served the vulnerable response now returns HTTP ${baseline.status}.`
        : baseline.outcome === 'no-data'
          ? ' The read-only GraphQL query that once returned data now returns none.'
          : ' The baseline request still answers, but the fresh canary no longer reproduces the original proof.';
    return {
      findingId: finding.id,
      verdict: 'fixed',
      depth: 'unproven',
      impactSummary: `Retest: the proof no longer reproduces.${goneNote} The finding was verified before and the same benign-canary proof now fails, so it is treated as fixed.`,
      evidence,
      canaryToken: ladder.canaryToken,
      testedAt,
      method: RETEST_METHOD,
    };
  } catch (err) {
    // Backstop: retestFinding never throws, whatever the prober did.
    return inconclusive(
      `retester error: ${(err as Error).message.slice(0, 200)} — the retest could not run.`,
    );
  }
}

/**
 * Apply a retest verdict to a finding's verification. Pure function, no
 * I/O, no persistence; the route persists the returned object.
 *
 * - 'reproduced' → { status: 'verified', depth: the retest's depth }.
 *   Upgrades a hint to verified; re-confirms an already-verified finding.
 * - 'fixed' → { status: 'fixed', depth: 'unproven', impact: 'not-measured' }.
 *   Moves the finding to fixed. 'fixed' is a NEW status value alongside
 *   'verified'/'hint': reports must treat it as RESOLVED, not as a hint —
 *   a 'fixed' finding must not appear under "Hints (unverified)" (see
 *   reports/verification.ts: `hintFindings` currently treats anything that
 *   is not 'verified' as a hint, so it needs a 'fixed' exclusion when
 *   `types.ts` gains the status).
 * - 'inconclusive' → the finding's existing verification, unchanged (same
 *   object). A retest that could not run must never downgrade or upgrade a
 *   finding. If the finding had no verification at all, a hint stating the
 *   retest was inconclusive is returned instead.
 */
export function applyRetestVerdict(finding: Finding, result: RetestResult): RetestVerification {
  if (result.verdict === 'inconclusive') {
    if (finding.verification) return finding.verification;
    return untestedVerification(
      `retest inconclusive: ${result.impactSummary} No prior verification existed, so the finding stays an unconfirmed hint.`,
      () => result.testedAt,
    );
  }
  if (result.verdict === 'reproduced') {
    const depth = result.depth ?? 'confirmed';
    return {
      status: 'verified',
      depth,
      impact: depth === 'escalated' ? 'cross-context' : 'single-context',
      impactSummary: result.impactSummary,
      ...(result.canaryToken ? { canaryToken: result.canaryToken } : {}),
      evidence: result.evidence,
      testedAt: result.testedAt,
      method: RETEST_METHOD,
    };
  }
  // 'fixed'
  return {
    status: 'fixed',
    depth: 'unproven',
    impact: 'not-measured',
    impactSummary: result.impactSummary,
    ...(result.canaryToken ? { canaryToken: result.canaryToken } : {}),
    evidence: result.evidence,
    testedAt: result.testedAt,
    method: RETEST_METHOD,
  };
}

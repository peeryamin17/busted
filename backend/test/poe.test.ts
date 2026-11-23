/**
 * Unit tests for POE 0-4 + the verbatim-quote receipt check
 * (src/reports/poe.ts). No network, no DB, no LLM.
 *
 * Run:  npx tsx test/poe.test.ts   (from backend/)
 */
import {
  DATA_ESCALATION_KINDS,
  assignPoe,
  extractQuotes,
  isVerified,
  receiptCheck,
} from '../src/reports/poe.js';
import type { FindingVerification } from '../src/types.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

function verification(partial: Partial<FindingVerification>): FindingVerification {
  return {
    status: 'hint',
    depth: 'unproven',
    impact: 'not-measured',
    impactSummary: 'not measured',
    evidence: [],
    testedAt: '2026-11-23T00:00:00.000Z',
    method: 'depth-ladder v1 (benign canary, read-only proofs)',
    ...partial,
  };
}

async function main() {
  // ── 1. POE mapping: unproven → 0 ──
  {
    check('poe: no verification → 0', assignPoe({}).poe === 0);
    check(
      'poe: unproven depth → 0',
      assignPoe({ verification: verification({ depth: 'unproven' }) }).poe === 0,
    );
  }

  // ── 2. POE mapping: confirmed → 2 ──
  {
    const v = verification({
      status: 'verified',
      depth: 'confirmed',
      impact: 'single-context',
      evidence: [
        { rung: 'confirm', kind: 'xss-reflection', request: 'GET /search?q=<canary>', observed: 'canary reflected' },
      ],
    });
    const r = assignPoe({ verification: v });
    check('poe: confirmed → 2', r.poe === 2, r);
  }

  // ── 3. POE mapping: escalated with a data kind → 3 (every data kind) ──
  {
    for (const kind of DATA_ESCALATION_KINDS) {
      const v = verification({
        status: 'verified',
        depth: 'escalated',
        impact: 'cross-context',
        evidence: [
          { rung: 'confirm', kind: 'xss-reflection', request: 'GET /a', observed: 'canary reflected' },
          { rung: 'escalate', kind, request: 'GET /b', observed: 'second context reproduced' },
        ],
      });
      check(`poe: escalated + ${kind} → 3`, assignPoe({ verification: v }).poe === 3);
    }
  }

  // ── 4. POE mapping: escalated WITHOUT a data kind → 2 ──
  {
    const v = verification({
      status: 'verified',
      depth: 'escalated',
      impact: 'cross-context',
      evidence: [
        { rung: 'confirm', kind: 'xss-reflection', request: 'GET /a', observed: 'canary reflected' },
        // Escalation rung that repeats the same shape, no data, no second context.
        { rung: 'escalate', kind: 'xss-reflection', request: 'GET /b', observed: 'canary reflected again' },
      ],
    });
    const r = assignPoe({ verification: v });
    check('poe: escalated without data kind → 2', r.poe === 2, r);
    // Explicit evidenceKinds override: same finding, kinds supplied by caller.
    check(
      'poe: evidenceKinds override respected',
      assignPoe({ verification: v }, ['graphql-introspection']).poe === 3,
    );
    check(
      'poe: evidenceKinds override without data kind → 2',
      assignPoe({ verification: v }, ['xss-reflection']).poe === 2,
    );
  }

  // ── 5. POE 4 is never auto-assigned ──
  {
    const depths = ['unproven', 'confirmed', 'escalated'] as const;
    const kinds = [...DATA_ESCALATION_KINDS, 'xss-reflection', 'idor-neighbor-shape', 'cors-canary-origin'];
    let sawFour = false;
    for (const depth of depths) {
      for (const kind of kinds) {
        const v = verification({
          status: 'verified',
          depth,
          evidence: [{ rung: 'escalate', kind, request: 'GET /x', observed: 'observed' }],
        });
        if (assignPoe({ verification: v }).poe === 4) sawFour = true;
      }
    }
    check('poe: never 4 across depths × kinds', !sawFour);
  }

  // ── 6. extractQuotes ──
  {
    const quotes = extractQuotes([
      {
        rung: 'escalate',
        kind: 'graphql-introspection',
        request: 'POST /graphql',
        observed: 'introspection returned schema with type "QueryRootType" and field "adminUsers"',
      },
      {
        rung: 'confirm',
        kind: 'xss-reflection',
        request: 'GET /search',
        observed: 'canary reflected near "short" and "QueryRootType" again',
      },
    ]);
    check('quotes: extracts ≥8-char quotes', quotes.includes('QueryRootType') && quotes.includes('adminUsers'), quotes);
    check('quotes: drops <8-char quotes', !quotes.includes('short'), quotes);
    check('quotes: deduped', quotes.filter((q) => q === 'QueryRootType').length === 1, quotes);
    check('quotes: exactly 8 chars counts', extractQuotes([
      { rung: 'confirm', kind: 'x', request: '', observed: 'saw "12345678" here' },
    ]).includes('12345678'));
    check('quotes: 7 chars ignored', extractQuotes([
      { rung: 'confirm', kind: 'x', request: '', observed: 'saw "1234567" here' },
    ]).length === 0);
    const many = extractQuotes([
      { rung: 'confirm', kind: 'x', request: '', observed: Array.from({ length: 12 }, (_, i) => `"quote-number-${i}"`).join(' ') },
    ]);
    check('quotes: capped at 10', many.length === 10, many.length);
  }

  // ── 7. receiptCheck ──
  {
    const pass = receiptCheck(['QueryRootType'], ['<html>schema type "QueryRootType" listed</html>']);
    check('receipt: quote verbatim in body → pass', pass.pass && pass.matchedQuote === 'QueryRootType', pass);
    check('receipt: quote absent → fail', receiptCheck(['QueryRootType'], ['<html>no schema here</html>']).pass === false);
    check('receipt: quote is a substring, not a fuzzy match', receiptCheck(['QueryRootTyp'], ['"QueryRootType"']).pass === true);
    check('receipt: partial quote does not match', receiptCheck(['QueryRootTypeX'], ['"QueryRootType"']).pass === false);
    check('receipt: no proof bodies → fail', receiptCheck(['QueryRootType'], []).pass === false);
    check('receipt: empty quotes → fail', receiptCheck([], ['"QueryRootType"']).pass === false);
    check('receipt: short quote ignored → empty quotes → fail',
      receiptCheck(extractQuotes([
        { rung: 'confirm', kind: 'x', request: '', observed: 'only "tiny" here' },
      ]), ['only "tiny" here']).pass === false);
  }

  // ── 8. isVerified end-to-end ──
  {
    const escalated = verification({
      status: 'verified',
      depth: 'escalated',
      impact: 'cross-context',
      evidence: [
        { rung: 'confirm', kind: 'graphql-readonly-query', request: 'POST /graphql { __typename }', observed: 'returned data' },
        {
          rung: 'escalate',
          kind: 'graphql-introspection',
          request: 'POST /graphql { __schema }',
          observed: 'introspection returned the schema, type "QueryRootType" present',
        },
      ],
    });
    const proofBodies = ['{"data":{"__schema":{"queryType":{"name":"QueryRootType"}}}}'];
    const ok = isVerified({ verification: escalated }, proofBodies);
    check('isVerified: poe 3 + receipt + verified status → verified', ok.verified && ok.poe === 3 && ok.receipt === true, ok);

    const confirmed = verification({
      status: 'verified',
      depth: 'confirmed',
      impact: 'single-context',
      evidence: [
        { rung: 'confirm', kind: 'xss-reflection', request: 'GET /search', observed: 'canary reflected in "searchResultsPage"' },
      ],
    });
    const poe2 = isVerified({ verification: confirmed }, ['canary reflected in "searchResultsPage"']);
    check('isVerified: poe 2 + receipt → NOT verified', poe2.verified === false && poe2.poe === 2, poe2);

    const noReceipt = isVerified({ verification: escalated }, ['{"data":{"__schema":{"queryType":{"name":"SomethingElse"}}}}']);
    check('isVerified: poe 3 + no receipt → NOT verified', noReceipt.verified === false && noReceipt.poe === 3 && noReceipt.receipt === false, noReceipt);

    const hintStatus = verification({
      status: 'hint',
      depth: 'escalated',
      impact: 'cross-context',
      evidence: [
        { rung: 'escalate', kind: 'graphql-introspection', request: 'POST /graphql', observed: 'type "QueryRootType" present' },
      ],
    });
    const hint = isVerified({ verification: hintStatus }, proofBodies);
    check('isVerified: poe 3 + receipt but ladder status hint → NOT verified', hint.verified === false, hint);

    const none = isVerified({}, proofBodies);
    check('isVerified: no verification → NOT verified, poe 0', none.verified === false && none.poe === 0, none);
  }

  if (failures > 0) { console.error(`${failures} poe test(s) failed`); process.exit(1); }
  console.log('ALL POE TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('poe test crashed', e); process.exit(1); });

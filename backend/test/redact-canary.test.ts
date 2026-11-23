/**
 * Regression tests: BugSeek's own benign canary tokens must survive
 * redaction (src/guardrails/redact.ts).
 *
 * A canary (`bs` + 16 hex chars) often contains a digit run long
 * enough to match the phone / card-number patterns. When the redactor
 * mangled it (`bs6a12ded[REDACTED:phone]`), the verbatim receipt check
 * failed non-deterministically, only canaries whose hex happened to
 * contain a long digit run were hit, so the retester gate looked
 * flaky when it was not.
 *
 * Run:  npx tsx test/redact-canary.test.ts   (from backend/)
 */
import { redactText } from '../src/guardrails/redact.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) {
    failures++;
    console.error(`FAIL: ${name}`, extra ?? '');
  } else console.log(`ok: ${name}`);
}

function main(): void {
  // The exact canary from the flaky failure: 9 consecutive digits.
  const digitHeavy = 'bs6a12ded794735159';
  check(
    'redact: digit-heavy canary survives verbatim',
    redactText(`results for ${digitHeavy}`, 1000) === `results for ${digitHeavy}`,
    redactText(`results for ${digitHeavy}`, 1000),
  );
  // 11 consecutive digits (the other failing canary).
  const digitHeavier = 'bs79230608520e37ef';
  check(
    'redact: 11-digit-run canary survives verbatim',
    redactText(`<html>${digitHeavier}</html>`, 1000) === `<html>${digitHeavier}</html>`,
  );
  // 13+ digits: the card-number pattern must not eat it either.
  const cardLike = 'bs1234567890123456';
  check(
    'redact: card-length digit run in a canary survives',
    redactText(cardLike, 1000) === cardLike,
  );
  // Several canaries in one body, all restored.
  const two = `first bsaaaaaaaaaaaaaaaa and second ${digitHeavy} end`;
  check('redact: multiple canaries all restored', redactText(two, 1000) === two);
  // Real PII next to a canary is still redacted; the canary is not.
  const mixed = `call 5551234567 about ${digitHeavy}`;
  const mixedOut = redactText(mixed, 1000);
  check('redact: phone next to a canary is still redacted', mixedOut.includes('[REDACTED:phone]'), mixedOut);
  check('redact: canary next to a phone survives', mixedOut.includes(digitHeavy), mixedOut);
  // A literal "CANARY5" in target text is not mistaken for a placeholder.
  const literal = 'the CANARY5 token is not ours';
  check('redact: literal CANARY5 untouched', redactText(literal, 1000) === literal, redactText(literal, 1000));
  // A 16-hex string WITHOUT the bs prefix is not a canary: it redacts
  // as before when it looks like a phone number.
  const bare = 'call 1234567890123456 now';
  check('redact: bare digit run still redacts', redactText(bare, 1000).includes('[REDACTED:'), redactText(bare, 1000));
  // Idempotent: redacting twice changes nothing.
  const once = redactText(`results for ${digitHeavy} and 5551234567`, 1000);
  check('redact: idempotent', redactText(once, 1000) === once, redactText(once, 1000));
  // Truncation still works with a canary present.
  const long = `${digitHeavy} ` + 'x'.repeat(100);
  const trunc = redactText(long, 20);
  check('redact: truncation still applies', trunc.length <= 20 + '…[truncated]'.length && trunc.endsWith('…[truncated]'), trunc);

  // New secret shapes (Batch 2) are redacted even next to a canary,
  // while the canary itself still survives.
  const shaped = `canary ${digitHeavy} plus ghp_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIj end`;
  const shapedOut = redactText(shaped, 1000);
  check('redact: ghp_ token next to a canary is redacted', !shapedOut.includes('ghp_'), shapedOut);
  check('redact: canary next to a ghp_ token survives', shapedOut.includes(digitHeavy), shapedOut);
  const aq = `key AQ.AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv and ${digitHeavy}`;
  const aqOut = redactText(aq, 1000);
  check('redact: AQ. token next to a canary is redacted', !aqOut.includes('AQ.'), aqOut);
  check('redact: canary next to an AQ. token survives', aqOut.includes(digitHeavy), aqOut);
  const proj = `sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv near ${digitHeavy}`;
  const projOut = redactText(proj, 1000);
  check('redact: sk-proj- token next to a canary is redacted', !projOut.includes('sk-proj-'), projOut);
  check('redact: canary next to a sk-proj- token survives', projOut.includes(digitHeavy), projOut);

  if (failures > 0) {
    console.error(`${failures} REDACT-CANARY TEST(S) FAILED`);
    process.exit(1);
  }
  console.log('ALL REDACT-CANARY TESTS PASSED');
}

main();

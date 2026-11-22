import type { Finding } from '../types.js';

/**
 * White-box section support for reports (Thread 3).
 *
 * Findings produced by code-intake (POST /api/code-intake) carry category
 * 'whitebox'. Report builders split them out of the general findings list
 * and render them under their own "White-box analysis" heading, with the
 * method note below so the limits are visible in the report itself: ZIP
 * findings are regex pattern matches over source text; JAR/WAR findings
 * are constant-pool string scans, not decompilation.
 */
export const WHITEBOX_CATEGORY = 'whitebox';

export function splitWhiteBoxFindings(findings: Finding[]): {
  whiteBox: Finding[];
  rest: Finding[];
} {
  const whiteBox = findings.filter((f) => f.category === WHITEBOX_CATEGORY);
  const rest = findings.filter((f) => f.category !== WHITEBOX_CATEGORY);
  return { whiteBox, rest };
}

export const WHITEBOX_SECTION_NOTE =
  'Findings in this section come from static white-box analysis of code supplied by the user — not from live testing. ' +
  'ZIP findings are regex pattern matches over source text (well-known secret formats and dangerous-API-use patterns). ' +
  'JAR/WAR findings are constant-pool string scans of .class files, not decompilation: method bodies and control flow ' +
  'are not reconstructed, so a referenced API is not proof it is called with attacker-controlled data. ' +
  'Treat every match as a lead to verify in the code, not as a confirmed vulnerability.';

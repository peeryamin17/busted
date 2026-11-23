/**
 * Runs the secret regex patterns over collected JavaScript sources.
 * All reported evidence is redacted; placeholder/test values are skipped.
 *
 * Every pattern finding carries `secretProvider` + a redacted
 * fingerprint (provider + first 4 + last 4 chars), so one key can be
 * correlated across locations without storing its full value.
 * `scanHighEntropyStrings` catches provider-less keys via Shannon
 * entropy, with a false-positive filter (known public hashes, data-URI
 * / image base64, URL fragments, repeated characters, placeholders).
 * `scanSecretKeyNames` flags secret-shaped key names in web storage
 * and cookies, names only, values never read.
 *
 * Sources: inline scripts, fetched JS bundles (fed in as ScriptSources
 * by the background worker), and source-mapped original sources. No
 * found key is ever validated against a provider API.
 */
import {
  ENTROPY_MAX_FINDINGS_PER_SOURCE,
  ENTROPY_MIN_LENGTH,
  ENTROPY_THRESHOLD,
  SECRET_PATTERNS,
  fingerprintSecret,
  isKnownPublicHash,
  isPlaceholder,
  isRepeatedChar,
  redactSecret,
  shannonEntropy,
} from '../lib/regexes';
import type { Finding, StorageEntry } from '../lib/types';

export interface ScriptSource {
  /** Human-readable label, e.g. "inline <script> #3" or the script URL. */
  label: string;
  code: string;
}

let findingSeq = 0;
const MAX_MATCHES_PER_PATTERN = 5;

/** Quoted runs of token-shaped characters, candidates for entropy scoring. */
const QUOTED_RUN_RE = /["'`]([A-Za-z0-9+/=_-]{20,})["'`]/g;

/** A URL tail immediately before a candidate means it is a path segment, not a key. */
const URL_TAIL_RE = /https?:\/\/[^\s"'`]*$/;

function spansOverlap(aStart: number, aEnd: number, spans: Array<{ start: number; end: number }>): boolean {
  return spans.some((s) => aStart < s.end && aEnd > s.start);
}

/**
 * Generic high-entropy detection over one source. `patternSpans` are the
 * [start, end) ranges already matched by SECRET_PATTERNS so the same key
 * is not reported twice (once as a known provider, once as generic).
 * Returns findings only, the candidate values themselves are never kept.
 */
export function scanHighEntropyStrings(
  code: string,
  label: string,
  patternSpans: Array<{ start: number; end: number }> = [],
): Finding[] {
  const findings: Finding[] = [];
  const re = new RegExp(QUOTED_RUN_RE.source, QUOTED_RUN_RE.flags);
  let match: RegExpExecArray | null;

  while ((match = re.exec(code)) !== null && findings.length < ENTROPY_MAX_FINDINGS_PER_SOURCE) {
    if (match.index === re.lastIndex) re.lastIndex++;
    const candidate = match[1];
    const start = match.index + 1; // skip the opening quote
    const end = start + candidate.length;
    if (candidate.length < ENTROPY_MIN_LENGTH) continue;
    if (spansOverlap(start, end, patternSpans)) continue;
    if (isPlaceholder(candidate) || isKnownPublicHash(candidate)) continue;
    if (isRepeatedChar(candidate)) continue;
    // A data-URI / image payload is encoded content, not a credential.
    const before = code.slice(Math.max(0, match.index - 80), match.index);
    if (/data:[a-z]+\/[a-z0-9.+-]+;base64/i.test(before)) continue;
    if (URL_TAIL_RE.test(before)) continue;
    // Long base64 that is clearly an image: decodes to a known image magic.
    if (looksLikeImageBase64(candidate)) continue;

    const entropy = shannonEntropy(candidate);
    if (entropy < ENTROPY_THRESHOLD) continue;

    findings.push({
      id: `secret-generic-entropy-${findingSeq++}`,
      category: 'secrets',
      title: 'High-entropy string that may be an API key',
      description:
        `A ${candidate.length}-character string with Shannon entropy ${entropy.toFixed(2)} bits/char ` +
        'was found in client-side JavaScript. Random-looking strings of this shape are often API keys or ' +
        'tokens, but this check cannot tell a key from an encoded blob or hash — manual review is required. ' +
        'Confirm by tracing where the value comes from in source control; if it is a live credential, rotate it. ' +
        'Do not paste it into any third-party "key checker" — validity is judged by format and context only, never by calling a provider API.',
      severity: 'medium',
      confidence: 'medium',
      location: label,
      evidence:
        `entropy ${entropy.toFixed(2)} bits/char over ${candidate.length} chars — value never stored`,
      remediation:
        'If this is a real credential, rotate it and move it server-side; the frontend should only hold public identifiers.',
      secretProvider: 'generic-high-entropy',
      fingerprint: fingerprintSecret(candidate, 'generic-high-entropy'),
      entropyScore: Math.round(entropy * 100) / 100,
      trail: [`discovered in ${label}`],
    });
  }

  return findings;
}

/** Cheap image-magic check on the first decoded bytes of a base64 candidate. */
function looksLikeImageBase64(candidate: string): boolean {
  try {
    const head = atob(candidate.slice(0, 24).replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = [...head].map((c) => c.charCodeAt(0));
    // PNG, JPEG, GIF, WEBP
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return true;
    if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return true;
    if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) return true;
    if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46) return true;
    return false;
  } catch {
    return false;
  }
}

export function scanSecrets(sources: ScriptSource[]): Finding[] {
  const findings: Finding[] = [];

  for (const src of sources) {
    const patternSpans: Array<{ start: number; end: number }> = [];

    for (const pattern of SECRET_PATTERNS) {
      // Re-instantiate so `lastIndex` state never leaks between scans.
      const flags = pattern.regex.flags.includes('g')
        ? pattern.regex.flags
        : pattern.regex.flags + 'g';
      const re = new RegExp(pattern.regex.source, flags);

      let match: RegExpExecArray | null;
      let reported = 0;
      while ((match = re.exec(src.code)) !== null && reported < MAX_MATCHES_PER_PATTERN) {
        // Guard against zero-width matches looping forever.
        if (match.index === re.lastIndex) re.lastIndex++;

        const matched = match[0];
        patternSpans.push({ start: match.index, end: match.index + matched.length });
        if (isPlaceholder(matched)) continue;
        reported++;

        findings.push({
          id: `secret-${pattern.id}-${findingSeq++}`,
          category: 'secrets',
          title: `${pattern.name} exposed in JavaScript`,
          description: pattern.description,
          severity: pattern.severity,
          confidence:
            pattern.severity === 'critical' || pattern.severity === 'high'
              ? 'high'
              : 'medium',
          location: src.label,
          evidence: redactSecret(matched),
          remediation: pattern.remediation,
          secretProvider: pattern.id,
          fingerprint: fingerprintSecret(matched, pattern.id),
          trail: [`discovered in ${src.label}`],
        });
      }
    }

    // Generic high-entropy pass over the same source (deduped vs patterns).
    findings.push(...scanHighEntropyStrings(src.code, src.label, patternSpans));
  }

  return findings;
}

/* ------------------------------------------------------------------ */
/* Secret-shaped key NAMES in storage / cookies (names only)           */
/* ------------------------------------------------------------------ */

const SECRET_KEY_NAME_RE =
  /(api[_-]?key|api[_-]?secret|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|db[_-]?pass(word)?|aws[_-]?secret|stripe[_-]?secret|sendgrid|twilio|github[_-]?token|firebase[_-]?key|bearer)/i;

const MAX_KEY_NAME_FINDINGS = 10;

function keyNameMatch(key: string): string | null {
  const m = key.match(SECRET_KEY_NAME_RE);
  return m ? m[1].toLowerCase().replace(/[_-]/g, '-') : null;
}

/**
 * Flag storage entries / cookie names whose KEY NAME looks secret-bearing.
 * Only names are inspected, storage values are never read here (the
 * content script already reduced them to key + shape) and cookie values
 * are never requested. A matching name alone is weak evidence, so these
 * findings are medium/low confidence and carry no fingerprint.
 */
export function scanSecretKeyNames(
  storage: { local: StorageEntry[]; session: StorageEntry[] } | undefined,
  cookieNames: string[],
  pageUrl: string,
): Finding[] {
  const findings: Finding[] = [];
  const push = (f: Finding): void => {
    if (findings.length < MAX_KEY_NAME_FINDINGS) findings.push(f);
  };

  for (const [storeName, entries] of [
    ['localStorage', storage?.local ?? []] as const,
    ['sessionStorage', storage?.session ?? []] as const,
  ]) {
    for (const e of entries) {
      const hit = keyNameMatch(e.key);
      if (!hit) continue;
      push({
        id: `secret-keyname-${findingSeq++}`,
        category: 'secrets',
        title: `Secret-shaped key name in ${storeName} ("${e.key}")`,
        description:
          `The ${storeName} key "${e.key}" is named like a credential (${hit}). The value was not read — ` +
          `only the name and its shape (${e.shape}, ${e.valueLength} chars) were observed — but a secret-shaped ` +
          'name in web storage is worth checking: any script on the page can read it, so if the value is a live ' +
          'credential it is one XSS away from theft.',
        severity: 'medium',
        confidence: 'medium',
        location: `${storeName} key "${e.key}" on ${pageUrl}`,
        evidence: `key name only — value never captured (shape: ${e.shape})`,
        remediation:
          'Confirm what this key holds. If it is a live credential, rotate it and move it to an HttpOnly cookie or keep it in memory only.',
        secretProvider: `key-name:${hit}`,
        trail: [`stored under key "${e.key}" in ${storeName}`],
      });
    }
  }

  for (const name of cookieNames) {
    const hit = keyNameMatch(name);
    if (!hit) continue;
    push({
      id: `secret-keyname-${findingSeq++}`,
      category: 'secrets',
      title: `Secret-shaped cookie name ("${name}")`,
      description:
        `A cookie named "${name}" looks secret-bearing (${hit}). Only the name was observed — cookie values ` +
        'are never read for this check. A credential-shaped cookie name is a weak signal on its own, but combined ' +
        'with a matching key found in JavaScript it helps trace where the credential travels.',
      severity: 'low',
      confidence: 'low',
      location: `cookie "${name}" on ${pageUrl}`,
      evidence: 'cookie name only — value never captured',
      remediation:
        'Confirm the cookie does not carry a live credential in a JavaScript-readable (non-HttpOnly) cookie.',
      secretProvider: `key-name:${hit}`,
      trail: [`stored as cookie "${name}"`],
    });
  }

  return findings;
}

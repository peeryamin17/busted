/**
 * Defensive "aftermath" report section (Thread 5, DEFENSIVE).
 *
 * For each attack class, states whether the site detected it, blocked it,
 * logged it, alerted on it, or was blind, with concrete remediation per
 * gap. This is a NEW section builder; existing report files are untouched
 * and the coordinator wires this section into the report assembly.
 *
 * Honest limits, printed in the section itself: "logged" and "alerted"
 * can only be confirmed from server-side logs or the runtime detection
 * layer. When the input says "unknown" for those, the report says the
 * site may have logged the attempt without any visible trace, it does
 * NOT claim a blind spot that may not exist.
 */

export type DefenseSignal = 'observed' | 'not-observed' | 'unknown';

export interface DefensiveClassInput {
  attackClass:
    | 'key-exposure'
    | 'brute-force'
    | 'exploitation'
    | 'waf-evasion'
    | 'request-smuggling'
    | 'post-exploitation'
    | 'lateral-movement';
  detected: DefenseSignal;
  blocked: DefenseSignal;
  logged: DefenseSignal;
  alerted: DefenseSignal;
  /** Plain-language summary of what was (and was not) seen. */
  summary: string;
}

export interface DefensiveReportInput {
  targetUrl: string;
  scannedAt: string; // ISO
  classes: DefensiveClassInput[];
}

export const CLASS_LABELS: Record<DefensiveClassInput['attackClass'], string> = {
  'key-exposure': 'Key exposure',
  'brute-force': 'Brute force / credential stuffing',
  exploitation: 'Exploitation attempts (benign canaries)',
  'waf-evasion': 'WAF / filter evasion (encoding classes)',
  'request-smuggling': 'Request smuggling (conditions check)',
  'post-exploitation': 'Post-exploitation paths (internal/debug endpoints)',
  'lateral-movement': 'Lateral movement (SSRF / metadata / env exposure)',
};

/** Concrete remediation per gap, per class. */
export const REMEDIATION: Record<DefensiveClassInput['attackClass'], string[]> = {
  'key-exposure': [
    'Rotate every exposed key and scope the replacement to least privilege.',
    'Add a pre-deploy secret scan so keys never ship in bundles or source maps again.',
    'Restrict keys at the provider (HTTP referrers, API restrictions, project scoping) where supported.',
  ],
  'brute-force': [
    'Enable rate limiting on the login endpoint and progressive delays after failed attempts.',
    'Add account lockout or CAPTCHA after a small number of failures.',
    'Alert on failed-login velocity (the runtime detection layer watches this from inside).',
  ],
  exploitation: [
    'Ensure output encoding on every reflection point and keep CSP enforced.',
    'Add WAF rules for the payload classes that passed through unencoded.',
  ],
  'waf-evasion': [
    'Normalise double-encoded and Unicode input at the edge before rule matching.',
    'Add rules for the encoding classes that passed, then re-run the probe to confirm the tune.',
  ],
  'request-smuggling': [
    'Reject requests carrying both Content-Length and Transfer-Encoding, and duplicate Content-Length headers, at the edge.',
    'Test smuggling only on isolated staging with a dedicated tool — never shared production.',
  ],
  'post-exploitation': [
    'Put internal/debug endpoints behind authentication and network restrictions (allow-list, VPN, or removal from production).',
    'Actuator/env endpoints must never be internet-reachable.',
  ],
  'lateral-movement': [
    'Allow-list the destinations of every URL-accepting parameter.',
    'Block link-local/metadata ranges (169.254.0.0/16, 10/8, 172.16/12, 192.168/16) at the egress proxy.',
    'Strip env dumps from error pages, bundles, and source maps; narrow BaaS keys to least privilege with row-level security.',
  ],
};

export function signalCell(s: DefenseSignal): string {
  if (s === 'observed') return 'Yes';
  if (s === 'not-observed') return 'No';
  return 'Unknown';
}

export function classVerdict(c: DefensiveClassInput): string {
  if (c.blocked === 'observed') return 'Defended — the attack class was blocked';
  if (c.detected === 'observed' && c.blocked === 'not-observed') {
    return 'Seen but not stopped — the site reacted without blocking';
  }
  if (c.detected === 'not-observed' && c.blocked === 'not-observed') {
    return 'Blind spot — no defense was observed for this class';
  }
  return 'Inconclusive — not enough signal to judge this class';
}

/** Minimal shape a finding needs for derivation (backend findings have no tags column). */
export interface DefenseFindingLike {
  title: string;
  description?: string;
  category?: string;
  tags?: string[];
}

const CLASS_BY_TAG: Record<string, DefensiveClassInput['attackClass']> = {
  'defense-key-exposure': 'key-exposure',
  'defense-brute-force': 'brute-force',
  'defense-exploitation': 'exploitation',
  'defense-waf': 'waf-evasion',
  'defense-smuggling-conditions': 'request-smuggling',
  'defense-post-exploitation': 'post-exploitation',
  'defense-lateral-movement': 'lateral-movement',
};

/**
 * Title prefixes the defense probes generate (stable strings from
 * src/active/defenseProbes.ts). Used only when tags are absent, backend
 * findings lose tags at ingestion because the findings table has no tags
 * column. If a probe title changes, this mapping must change with it.
 */
const CLASS_BY_TITLE: Array<{ re: RegExp; cls: DefensiveClassInput['attackClass'] }> = [
  { re: /key-exposure|exposed key|secret-shaped value/i, cls: 'key-exposure' },
  { re: /brute-force/i, cls: 'brute-force' },
  { re: /canary payload/i, cls: 'exploitation' },
  { re: /\bWAF\b/i, cls: 'waf-evasion' },
  { re: /request smuggling/i, cls: 'request-smuggling' },
  { re: /internal\/debug endpoint/i, cls: 'post-exploitation' },
  { re: /lateral-movement|SSRF sink|environment variable names|own-key scope/i, cls: 'lateral-movement' },
];

const ENGAGED_RE = /engaged|blocked every|contained/i;
const BYPASSED_RE = /let through|passed the defenses/i;
const NOTHING_REACTED_RE = /no .* protection observed|no .* defense/i;
const NOT_TESTED_RE = /skipped|not applicable|not run/i;
const CLEAN_RE = /no .* found|no .* reachable|no .* to assess|no .* signals observed/i;
const EXPOSED_RE = /reachable without authentication|exposed|surface found|response body|signals present/i;

function classOf(f: DefenseFindingLike): DefensiveClassInput['attackClass'] | null {
  for (const t of f.tags ?? []) {
    const cls = CLASS_BY_TAG[t];
    if (cls) return cls;
  }
  for (const { re, cls } of CLASS_BY_TITLE) {
    if (re.test(f.title)) return cls;
  }
  return null;
}

/**
 * Derive defensive classes from defense-verification findings. Signals are
 * deliberately coarse, they come from what the probes could observe from
 * outside: a defense visibly engaging, a payload class passing through, or
 * nothing reacting at all. `logged`/`alerted` are always `unknown` here;
 * only server-side logs or the runtime detection layer can confirm those.
 * Returns [] when no defense-verification findings are present, so callers
 * simply omit the section.
 */
export function defensiveClassesFromFindings(findings: DefenseFindingLike[]): DefensiveClassInput[] {
  const byClass = new Map<DefensiveClassInput['attackClass'], DefenseFindingLike[]>();
  for (const f of findings) {
    const cls = classOf(f);
    if (cls) {
      const list = byClass.get(cls) ?? [];
      list.push(f);
      byClass.set(cls, list);
    }
  }
  const out: DefensiveClassInput[] = [];
  for (const [attackClass, list] of byClass) {
    const tags = list.flatMap((f) => f.tags ?? []);
    const titles = list.map((f) => f.title).join(' ');
    const engaged = tags.includes('defense-engaged') || ENGAGED_RE.test(titles);
    const bypassed = BYPASSED_RE.test(titles);
    const notTested = NOT_TESTED_RE.test(titles);
    const nothingReacted =
      (tags.includes('defense-blind') || NOTHING_REACTED_RE.test(titles)) && !engaged && !bypassed;
    const clean = !engaged && !bypassed && !notTested && CLEAN_RE.test(titles);
    const exposed = !engaged && EXPOSED_RE.test(titles);
    let detected: DefenseSignal;
    let blocked: DefenseSignal;
    if (engaged && !bypassed) {
      detected = 'observed';
      blocked = 'observed';
    } else if (bypassed) {
      // A filter exists and reacted to some classes, but these passed it.
      detected = 'observed';
      blocked = 'not-observed';
    } else if (notTested) {
      // Skipped / not applicable / no input supplied: not tested, not a verdict.
      detected = 'unknown';
      blocked = 'unknown';
    } else if (clean) {
      // Probed and nothing was there to exploit, defended for this class.
      detected = 'not-observed';
      blocked = 'observed';
    } else if (exposed || nothingReacted) {
      detected = 'not-observed';
      blocked = 'not-observed';
    } else {
      // Exposure found (e.g. key scope review, SSRF surface map) without
      // a clear engaged/blind signal: we detected it; it was not blocked.
      detected = 'observed';
      blocked = 'not-observed';
    }
    const summarySource = list.find((f) => f.description)?.description ?? list[0]?.title ?? '';
    out.push({
      attackClass,
      detected,
      blocked,
      logged: 'unknown',
      alerted: 'unknown',
      summary: summarySource.length > 300 ? `${summarySource.slice(0, 297)}…` : summarySource,
    });
  }
  return out;
}

/** Build the defensive section as Markdown lines (coordinator appends them to the report). */
export function buildDefensiveSection(input: DefensiveReportInput): string {
  const lines: string[] = [
    '## Did your site notice? — defensive aftermath',
    '',
    `Target: ${input.targetUrl} · probed ${input.scannedAt}. Each attack class below was tested with safe, authorized probes ` +
      `(inert canaries, at most 5 canary logins, read-only GETs — nothing was exploited). ` +
      '"Logged" and "alerted" can only be confirmed from server-side logs or the BugSeek runtime detection layer; ' +
      '"Unknown" there means "not visible from outside", not "did not happen".',
    '',
    '| Attack class | Detected | Blocked | Logged | Alerted | Verdict |',
    '|---|---|---|---|---|---|',
  ];

  const gaps: DefensiveClassInput[] = [];
  for (const c of input.classes) {
    lines.push(
      `| ${CLASS_LABELS[c.attackClass]} | ${signalCell(c.detected)} | ${signalCell(c.blocked)} | ` +
        `${signalCell(c.logged)} | ${signalCell(c.alerted)} | ${classVerdict(c)} |`,
    );
    if (c.blocked === 'not-observed' || c.detected === 'not-observed') gaps.push(c);
  }
  lines.push('');

  for (const c of input.classes) {
    lines.push(`### ${CLASS_LABELS[c.attackClass]}`, '');
    lines.push(`${c.summary}`, '');
  }

  if (gaps.length > 0) {
    lines.push('### What to fix first', '');
    for (const c of gaps) {
      lines.push(`**${CLASS_LABELS[c.attackClass]}** — ${classVerdict(c)}.`);
      for (const fix of REMEDIATION[c.attackClass]) lines.push(`- ${fix}`);
      lines.push('');
    }
  } else {
    lines.push(
      '### What to fix first',
      '',
      'No blind spots were observed in this run: every tested class was blocked or produced no exposure. ' +
        'Re-run after each deploy and each WAF rule change — defenses rot silently.',
      '',
    );
  }

  return lines.join('\n');
}

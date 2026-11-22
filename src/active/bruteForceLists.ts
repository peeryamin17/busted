/**
 * Curated credential lists for the guardrailed brute-force module
 * (src/active/bruteForce.ts).
 *
 * These lists are PUBLIC KNOWLEDGE — well-known default credentials shipped
 * in every scanner wordlist, and the weakest passwords in common use. They
 * are NOT secrets, breached data, or leaked credentials.
 *
 * HARD LIMITS (enforced by the module, not just by convention):
 *  - Default credentials only, per detected technology — never credential
 *    stuffing with breached or leaked lists.
 *  - Weak passwords: at most 15 entries, tried against ONE username only
 *    (no password spraying across many accounts).
 *  - Total attempts per scan are hard-capped by the module (~20).
 *  - No high-throughput guessing, no OTP/session-token guessing, and no
 *    rate-limit evasion of any kind (no IP rotation, header spoofing, or
 *    distributed workers).
 *
 * Keep this file short and reviewable: anyone auditing what the scanner
 * tries should only need to read this file.
 */

export type LoginTech = 'wordpress' | 'tomcat' | 'jenkins' | 'router' | 'generic';

/**
 * Well-known default credential pairs per detected technology, ordered by
 * likelihood. Each pair is a factory/default account for that product.
 */
export const TECH_DEFAULT_CREDENTIALS: Record<
  LoginTech,
  ReadonlyArray<readonly [string, string]>
> = {
  generic: [
    ['admin', 'admin'],
    ['admin', 'password'],
    ['administrator', 'administrator'],
    ['root', 'root'],
    ['admin', '123456'],
  ],
  wordpress: [
    ['admin', 'password'],
    ['admin', 'admin'],
    ['admin', 'wordpress'],
  ],
  tomcat: [
    ['tomcat', 'tomcat'],
    ['manager', 'manager'],
    ['admin', 'admin'],
    ['role1', 'role1'],
    ['both', 'both'],
  ],
  jenkins: [
    ['admin', 'admin'],
    ['admin', 'password'],
    ['jenkins', 'jenkins'],
  ],
  router: [
    ['admin', 'admin'],
    ['admin', 'password'],
    ['admin', '1234'],
    ['root', 'admin'],
    ['user', 'password'],
  ],
};

/**
 * Short weak-password list (15 entries — do not grow without review).
 * Tried against ONE username only (WEAK_PASSWORD_TARGET_USER). This is a
 * weak-password check, not a dictionary attack and not password spraying.
 */
export const WEAK_PASSWORDS: readonly string[] = [
  'password',
  '123456',
  '12345678',
  'admin',
  'letmein',
  'qwerty',
  '123456789',
  '12345',
  '1234567',
  'password1',
  'admin123',
  'welcome',
  'changeme',
  'passw0rd',
  '123123',
];

/** The single username the weak-password list is tried against. */
export const WEAK_PASSWORD_TARGET_USER = 'admin';

export interface AttemptPlanEntry {
  username: string;
  password: string;
  /** Human-readable list label, e.g. 'tomcat defaults' or 'weak passwords'. */
  list: string;
}

/**
 * Build the ordered, de-duplicated attempt plan for a scan.
 *
 * Order: detected-technology defaults first, then generic defaults, then
 * the weak-password list against the single target username. Pairs already
 * covered by another module (e.g. authChecker's default-credential probes)
 * are skipped so no pair is tried twice in one scan. The plan never
 * exceeds `maxAttempts`.
 */
export function buildAttemptPlan(
  tech: LoginTech,
  covered: ReadonlyArray<readonly [string, string]>,
  maxAttempts: number,
): AttemptPlanEntry[] {
  const seen = new Set(covered.map(([u, p]) => `${u}\n${p}`));
  const plan: AttemptPlanEntry[] = [];
  const push = (username: string, password: string, list: string): void => {
    if (plan.length >= maxAttempts) return;
    const key = `${username}\n${password}`;
    if (seen.has(key)) return;
    seen.add(key);
    plan.push({ username, password, list });
  };

  for (const [u, p] of TECH_DEFAULT_CREDENTIALS[tech]) {
    push(u, p, `${tech} defaults`);
  }
  if (tech !== 'generic') {
    for (const [u, p] of TECH_DEFAULT_CREDENTIALS.generic) {
      push(u, p, 'generic defaults');
    }
  }
  for (const pw of WEAK_PASSWORDS) {
    push(WEAK_PASSWORD_TARGET_USER, pw, 'weak passwords');
  }
  return plan;
}

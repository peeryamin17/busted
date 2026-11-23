/**
 * Shared backend types for BugSeek AI Phase 2.
 *
 * NOTE on backward compatibility with the Phase 1 extension
 * (bugseek/src/lib/types.ts): the backend `Finding` type keeps every Phase 1
 * field name and meaning. New fields are additive only (cvssScore,
 * cvssVector, trapProbability, honeypotSuspect, reproSteps, references), so
 * old clients keep working. The extension sibling may add fields but MUST NOT
 * rename or change the meaning of existing ones — see docs/schemas.md.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export type Confidence = 'high' | 'medium' | 'low';

/**
 * Exploit-depth verification (depth ladder, multiagent/depthLadder.ts).
 *
 * The ladder VALIDATES findings specialists already produced; it never
 * invents findings. `status: 'verified'` means the vulnerability was
 * reproduced with a benign canary probe and read-only evidence — it is NOT
 * proof of exploitability to full impact, and no chain is ever executed.
 * `status: 'hint'` means the claim could not be reproduced (or could not be
 * tested live) and must be treated as an unconfirmed hint.
 */
export type DepthLevel = 'unproven' | 'confirmed' | 'escalated';

/** Impact measured from OBSERVED depth, never from a model guess. */
export type DepthImpact = 'not-measured' | 'single-context' | 'cross-context';

export type VerificationStatus = 'verified' | 'hint' | 'fixed';

export interface DepthEvidence {
  /** Which rung of the ladder this evidence supports. */
  rung: 'confirm' | 'escalate';
  /** What was probed, e.g. 'xss-reflection', 'idor-neighbor-shape'. */
  kind: string;
  /** The (redacted) request that was made — read-only by construction. */
  request: string;
  /** What was observed — redacted excerpt, or status/shape metadata only. */
  observed: string;
  status?: number;
}

export interface FindingVerification {
  status: VerificationStatus;
  depth: DepthLevel;
  impact: DepthImpact;
  /** Human-readable statement of what the observed depth does/does not prove. */
  impactSummary: string;
  /** The benign canary token used, if a live probe ran (ours — safe to show). */
  canaryToken?: string;
  evidence: DepthEvidence[];
  /** Why the ladder stopped early, if it did (rate limit, error storm, scope refusal…). */
  stopReason?: string;
  /**
   * Proof-of-exploitation level 0–4 (Phase B proof gate): 0 unverified
   * claim, 1 error/timing variation, 2 structural manipulation, 3 data
   * extracted / cross-context, 4 critical impact (never auto-assigned).
   * A finding counts as 'verified' only at POE ≥ 3 with a verbatim
   * receipt in bound proof (see reports/poe.ts).
   */
  poe?: number;
  /** Whether the verbatim-quote receipt check passed against bound proof. */
  receiptChecked?: boolean;
  testedAt: string; // ISO
  method: string;
}

export type ScanMode = 'passive' | 'active';

export type ScanStatus =
  | 'queued'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type PlanTier = 'free' | 'hunter' | 'pro' | 'enterprise';

export type AuthzType = 'bug-bounty' | 'pentest-contract' | 'ownership';

/**
 * Scope boundaries the agent MUST NOT cross (plan §8: scope enforcement).
 * `mode` mirrors the extension's scope confirmation step:
 * - 'full-domain': the target host + subdomains (if includeSubdomains)
 * - 'subdomain': only the exact target host
 * - 'page': only the exact target URL (no crawling)
 */
export interface ScopePolicy {
  mode: 'full-domain' | 'subdomain' | 'page';
  includeSubdomains: boolean;
  excludedHosts: string[];
  excludedPaths: string[];
  maxRequestsPerSecond: number;
}

export interface AuthorizationRecord {
  id: string;
  userId: string;
  type: AuthzType;
  programName?: string;
  referenceUrl?: string;
  /** User's explicit statement of authorization, stored verbatim. */
  statement: string;
  confirmedAt: string; // ISO
}

export interface TechEntry {
  name: string;
  version?: string;
}

export interface ScanProgress {
  completedSteps: number;
  totalSteps: number;
  currentStep?: string;
}

export interface Scan {
  id: string;
  userId: string;
  targetUrl: string;
  mode: ScanMode;
  status: ScanStatus;
  scope: ScopePolicy;
  /** Authorization record id — REQUIRED for active scans (plan §8). */
  authorizationId?: string;
  techStack: TechEntry[];
  progress: ScanProgress;
  error?: string;
  createdAt: string; // ISO
  startedAt?: string; // ISO
  finishedAt?: string; // ISO
}

/**
 * Canonical server-side finding.
 *
 * LEGAL GUARDRAIL (plan §8 — data handling): `evidence` MUST be redacted
 * before persistence. The backend runs every finding through
 * `redactEvidence()` (guardrails/redact.ts) which masks secrets, tokens,
 * credentials and PII. Findings reference the vulnerability; they never
 * reproduce sensitive data itself.
 */
export interface Finding {
  id: string;
  scanId: string;
  /**
   * Superset of the Phase 1 FindingCategory. Phase 1 values
   * ('secrets' | 'cookies' | 'headers' | 'tech' | 'dom' | 'sinks') remain
   * valid; active-testing categories are additive.
   */
  category: string;
  title: string;
  description: string;
  severity: Severity;
  /** CVSS v3.1 base-score estimate (see reports/cvss.ts). */
  cvssScore?: number;
  cvssVector?: string;
  confidence: Confidence;
  /**
   * Honeypot/trap suspicion, 0..1 (plan §4.5). Findings with
   * trapProbability >= 0.6 are flagged via `honeypotSuspect` and presented
   * as "possible trap — verify manually", not as confirmed vulnerabilities.
   */
  trapProbability: number;
  honeypotSuspect: boolean;
  /** Where the finding was observed. Never contains raw secrets. */
  location?: string;
  /** Truncated, REDACTED evidence snippet. */
  evidence?: string;
  reproSteps: string[];
  remediation: string;
  /**
   * AI-generated concrete code fix (Phase 3, developer persona). Always
   * labeled as unverified in reports — a wrong auto-fix is worse than none.
   */
  suggestedFix?: string;
  /**
   * Exploit-depth verification from the swarm depth ladder (see
   * FindingVerification in this file). Present on swarm findings: 'verified'
   * means reproduced with a benign canary probe; 'hint' means unproven or
   * untestable. Absent on findings from older scans / other sources.
   */
  verification?: FindingVerification;
  references: string[];
  createdAt: string; // ISO
}

export interface ScanProgressEvent {
  seq: number;
  at: string; // ISO
  kind: 'status' | 'step' | 'finding' | 'log' | 'guardrail';
  message: string;
  data?: unknown;
}

export interface UserRecord {
  id: string;
  email: string;
  passwordHash: string;
  plan: PlanTier;
  createdAt: string; // ISO
  /** Google `sub` when the account signs in with Google. */
  googleSub?: string;
  /** Display name from the Google profile. */
  name?: string;
  /** Avatar URL from the Google profile. */
  avatarUrl?: string;
  /** Most recent login; ISO string. */
  lastLoginAt?: string;
  /** Encrypted BYOK AI key (AES-256-GCM). */
  encryptedAiKey?: string;
  /** AI provider (e.g. 'gemini'). */
  aiProvider?: string;
  /** Provider-specific base URL (e.g. the DashScope region endpoint for Qwen). */
  aiBaseUrl?: string;
  /** Safe masked hint for UI display. */
  aiKeyHint?: string;
  /** Timestamp when AI key was last updated. */
  aiKeyUpdatedAt?: string;
}

/** Server-side website session. Only the token's SHA-256 hash is stored. */
export interface SessionRecord {
  id: string;
  userId: string;
  tokenHash: string;
  createdAt: string; // ISO
  expiresAt: string; // ISO
  /** Last authenticated request (drives the inactivity sign-out). */
  lastSeenAt: string; // ISO
}

export interface ApiKeyRecord {
  id: string;
  userId: string;
  name: string;
  keyHash: string;
  /** e.g. "bs_a1b2" — safe to display, used for key identification. */
  keyPrefix: string;
  createdAt: string; // ISO
  lastUsedAt?: string; // ISO
  revokedAt?: string; // ISO
}

/** One-time extension link code; only the SHA-256 hash is stored. */
export interface PairingCodeRecord {
  id: string;
  userId: string;
  codeHash: string;
  createdAt: string; // ISO
  expiresAt: string; // ISO
  usedAt?: string; // ISO
}

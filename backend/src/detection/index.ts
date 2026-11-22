/**
 * Runtime detection layer — public surface (Thread 5, DEFENSIVE).
 *
 * Dogfooded on BugSeek's own backend first: the rules watch the events
 * this backend records (failed logins, API-key uses, probe traffic).
 * See events.ts for the intake wiring the coordinator still needs to add,
 * and analyze.ts for the on-demand analysis entry point.
 */
export { analyzeEvents, type AnalyzeOptions } from './analyze.js';
export {
  clearSecurityEvents,
  hashAccountId,
  hashAttemptedPassword,
  listSecurityEvents,
  recordSecurityEvent,
  securityEventCount,
} from './events.js';
export {
  apiKeyAnomalyRule,
  failedLoginVelocityRule,
  manyAccountsFewIpsRule,
  passwordSprayRule,
  probePatternRule,
  runAllRules,
  userAgentDiversityRule,
  type RuleOptions,
} from './rules.js';
export type {
  ApiKeyBaseline,
  DetectionCandidate,
  DetectionPattern,
  DetectionRecord,
  DetectionSeverity,
  SecurityEvent,
  SecurityEventType,
} from './types.js';

import type {
  Confidence,
  Finding,
  FindingVerification,
  ScopePolicy,
  Severity,
  TechEntry,
} from '../types.js';
import type { LLMProvider } from '../llm/provider.js';
import type { AgentTool, ToolExecutionContext } from '../agent/tools.js';
import type { GraphStore } from '../graph/store.js';
import type { CoverageStore } from '../coverage/ledger.js';
import type { EvidenceSnapshot, EvidenceStore } from '../evidence/snapshots.js';
import type { ApprovalStore } from '../approvals/store.js';
import type { ApprovalRuleStore } from '../approvals/rules.js';
import type { PinStore } from '../guardrails/pins.js';
import type { NoiseProfileName } from '../egress/noise.js';

/**
 * Optional task context for a swarm run. When present, the head
 * agent records its work into the task's exploration graph, coverage
 * ledger and evidence store as it runs; when absent (CLI, tests, older
 * callers) the swarm behaves exactly as before. Recording never breaks
 * a scan, every graph/coverage/evidence write is guarded in head.ts.
 *
 * adds the supervision wiring (all optional, absent = ungated
 * behaviour as before): the approval queue + rules, the pin store, the
 * task owner's id, a per-run pin-check callback built by the route, and
 * a per-run cache of gate verdicts so an identical tool call is judged
 * once per run instead of once per worker.
 */
export interface SwarmTaskContext {
  taskId: string;
  graph: GraphStore;
  coverage: CoverageStore;
  evidence: EvidenceStore;
  approvals?: ApprovalStore;
  approvalRules?: ApprovalRuleStore;
  pins?: PinStore;
  userId?: string;
  pinCheck?: (url: URL) => { decision: 'allowed' | 'ask' | 'blocked'; reason: string };
  gateCache?: Map<string, 'allowed' | 'denied'>;
}

/**
 * Multi-agent system ("super agent"), shared types.
 *
 * Architecture:
 *   HeadAgent (head.ts)
 *     1. Runs the recon specialist first (fast, deterministic-heavy).
 *     2. PLANS which specialist workers to spawn, adapted to the tech stack
 *        and recon findings (e.g. GraphQL endpoint seen → graphql worker).
 *     3. Spawns workers with bounded concurrency; workers share ONE
 *        ToolExecutionContext (single rate limiter + scope guardrail), so N
 *        workers can never DDoS the target.
 *     4. Collects WorkerReports → dedupes → head-level trap review →
 *        attack chaining → final synthesis.
 *   Specialist workers (worker.ts + specialists.ts): each runs its own
 *   PLAN → ACT → OBSERVE → REFLECT loop with a specialist system prompt, a
 *   restricted tool subset, and its own budgets, then reports home.
 *
 * Cost control (the user is a cost-sensitive student): planning and triage
 * reflection use the cheap 'routine' tier; the expensive 'reasoning' tier is
 * reserved for escalated reflection (triage says "candidate finding") and the
 * head's final synthesis.
 */

export type SpecialistId =
  | 'recon'
  | 'secrets'
  | 'headers'
  | 'cors'
  | 'xss'
  | 'idor'
  | 'auth'
  | 'graphql'
  | 'sourcemap';

export interface SpecialistDef {
  id: SpecialistId;
  name: string;
  /** What this worker is an expert in (1-2 lines, used in prompts). */
  expertise: string;
  /** Specialist system prompt for PLAN + REFLECT. */
  systemPrompt: string;
  /** Tool names this worker may use (subset of the registry). */
  tools: string[];
  /** Max LLM-planned actions for this worker. */
  maxActions: number;
  /** Max reasoning-tier escalations per worker (cost cap). */
  maxEscalations: number;
}

export interface WorkerFinding {
  severity: Severity;
  confidence: Confidence;
  category: string;
  title: string;
  description: string;
  location: string;
  evidence: string;
  rawEvidence?: string;
  suggestedFix?: string;
  /** Depth-ladder result (head.ts Phase 4.6): 'verified' vs 'hint'. */
  verification?: FindingVerification;
  reproSteps: string[];
  remediation: string;
  references: string[];
  trapProbability: number;
  chainWith: string[];
  provenanceIds?: string[];
}

export interface WorkerReport {
  specialistId: SpecialistId;
  specialistName: string;
  summary: string;
  findings: WorkerFinding[];
  testsRun: number;
  testsPlanned: number;
  escalations: number;
  llmCalls: number;
  tokensUsed: { input: number; output: number };
  errors: string[];
  durationMs: number;
  notes: string[];
  /** One entry per LLM call: provider, model, exact finite token counts. */
  llmProviders?: Array<{
    providerId: string;
    model: string;
    inputTokens: number;
    outputTokens: number;
  }>;
}

export interface MultiAgentLimits {
  /** Max specialists to spawn (after recon). */
  maxWorkers: number;
  /** How many workers run at the same time. */
  maxConcurrency: number;
  /** Hard cap on total LLM tokens for the whole run (input+output). */
  maxTotalTokens: number;
  /** Hard wall-clock cap for the whole run. */
  maxDurationMs: number;
  /** Requests/sec across ALL workers (shared limiter). */
  requestsPerSecond: number;
  /** Skip private-target refusal (self-hosted labs like Juice Shop). */
  allowPrivateTargets: boolean;
  /**
   * Noise-governor profile for this run. When set, the head
   * attaches one NoiseGovernor to the shared tool context; when absent
   * (tests, CLI) requests run ungoverned, as before.
   */
  noiseProfile?: NoiseProfileName;
}

export interface MultiAgentOptions {
  targetUrl: string;
  scope: ScopePolicy;
  provider: LLMProvider;
  techStack?: TechEntry[];
  limits?: Partial<MultiAgentLimits>;
  /** Force a specific specialist set (skips head planning). */
  specialists?: SpecialistId[];
  onEvent?: (e: MultiAgentEvent) => void;
  shouldContinue?: () => 'run' | 'paused' | 'cancelled';
  osdk?: import('../ontology/osdk.js').BugSeekOSDK;
  scanId?: string;
  discoveredEndpoints?: string[];
  /** Plain-language goal for the run. */
  goalText?: string;
  /** task context, graph, coverage and evidence recording. */
  task?: SwarmTaskContext;
}

export type MultiAgentEventKind =
  | 'head_plan'
  | 'worker_start'
  | 'worker_progress'
  | 'worker_done'
  | 'head_review'
  | 'head_synthesis'
  | 'guardrail'
  | 'approval_needed'
  | 'done';

export interface MultiAgentEvent {
  kind: MultiAgentEventKind;
  message: string;
  data?: unknown;
}

export interface MultiAgentOutcome {
  targetUrl: string;
  /**
   * Findings with the ladder's verification attached. `proofSnapshots`
   * carries the content-addressed evidence snapshots the
   * ladder collected for the finding, the route persists them against
   * the finding's DB id so the proof survives after the live traffic
   * is gone. Absent when the ladder ran no probes for the finding.
   */
  findings: Array<
    Omit<Finding, 'id' | 'scanId' | 'createdAt'> & { proofSnapshots?: EvidenceSnapshot[] }
  >;
  workerReports: WorkerReport[];
  headSummary: string;
  testsRun: number;
  llmCalls: number;
  tokensUsed: { input: number; output: number };
  durationMs: number;
  errors: string[];
}

export interface WorkerContext {
  provider: LLMProvider;
  tools: AgentTool[];
  toolCtx: ToolExecutionContext;
  targetUrl: string;
  scope: ScopePolicy;
  techStack: TechEntry[];
  priorFindings: string[];
  discoveredEndpoints?: string[];
  deadline: number;
  tokenBudget: { input: number; output: number; max: number };
  shouldContinue?: () => 'run' | 'paused' | 'cancelled';
  onEvent?: (e: MultiAgentEvent) => void;
  /** task context, carries the approval queue the gate consults. */
  task?: SwarmTaskContext;
}

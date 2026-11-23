import type { LLMProvider } from '../llm/provider.js';
import type { AgentTool } from '../agent/tools.js';
import type {
  SpecialistDef,
  WorkerContext,
  WorkerFinding,
  WorkerReport,
} from './types.js';
import { assessHoneypotSignals, type BaselineProfile, type ProbeObservation } from './honeypot.js';
import { codeOwnedTail, dataEnvelope, frameToolOutput } from '../llm/boundary.js';
import { gateToolCall } from '../approvals/gate.js';
import { DEFAULT_APPROVAL_TIMEOUT_MS } from '../approvals/service.js';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function completeWithTimeout(
  provider: LLMProvider,
  req: Parameters<LLMProvider['complete']>[0],
  // Long enough for a slow model plus a cascade to the next candidate:
  // one candidate can take ~30s per API version before it fails over.
  // The swarm runs async with polling, so a slow call blocks nothing.
  timeoutMs = 120_000,
) {
  let timer: NodeJS.Timeout;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`LLM call timed out after ${Math.round(timeoutMs / 1000)}s`));
    }, timeoutMs);
  });
  try {
    return await Promise.race([provider.complete(req), timeoutPromise]);
  } finally {
    clearTimeout(timer!);
  }
}

/** The boundary tail (see src/llm/boundary.ts) replaces the old ad-hoc injection-defense text. */

interface PlannedTest {
  id: string;
  name: string;
  tool: string;
  args: Record<string, unknown>;
  priority: number;
  rationale: string;
}

interface Triage {
  triage: 'candidate' | 'no-finding';
  reason: string;
}

interface Verdict {
  verdict: 'finding' | 'honeypot' | 'no-finding';
  trapProbability: number;
  severity?: WorkerFinding['severity'];
  confidence?: WorkerFinding['confidence'];
  category?: string;
  title?: string;
  description?: string;
  location?: string;
  evidence?: string;
  reproSteps?: string[];
  remediation?: string;
  references?: string[];
  chainWith?: string[];
  reasoning?: string;
}

function scopeSummary(ctx: WorkerContext): string {
  const s = ctx.scope;
  return `mode=${s.mode}, includeSubdomains=${s.includeSubdomains}, excludedHosts=${JSON.stringify(s.excludedHosts)}, excludedPaths=${JSON.stringify(s.excludedPaths)}`;
}

function toolCatalog(tools: AgentTool[]): string {
  return tools.map((t) => `- ${t.name}: ${t.description}`).join('\n');
}

/**
 * Run one specialist worker: PLAN → (ACT → OBSERVE → TRIAGE → [ESCALATE]) loop.
 *
 * Cost design: planning and triage use the cheap 'routine' tier. The
 * expensive 'reasoning' tier is spent only when triage flags a candidate
 * finding (bounded by the specialist's maxEscalations), plus a shared global
 * token budget enforced by the head.
 */
export async function runWorker(
  def: SpecialistDef,
  ctx: WorkerContext,
): Promise<WorkerReport> {
  const started = Date.now();
  const { provider } = ctx;
  // Least privilege: the worker can only touch its specialist tool subset,
  // regardless of what the model tries to plan.
  const tools = ctx.tools.filter((t) => def.tools.includes(t.name));
  const report: WorkerReport = {
    specialistId: def.id,
    specialistName: def.name,
    summary: '',
    findings: [],
    testsRun: 0,
    testsPlanned: 0,
    escalations: 0,
    llmCalls: 0,
    tokensUsed: { input: 0, output: 0 },
    errors: [],
    durationMs: 0,
    notes: [],
  };
  const emit = ctx.onEvent;
  const event = (kind: 'worker_progress' | 'guardrail', message: string, data?: unknown) =>
    emit?.({ kind, message, data });

  const spend = (input?: number, output?: number): boolean => {
    const inCount = Number.isFinite(input) ? Number(input) : 0;
    const outCount = Number.isFinite(output) ? Number(output) : 0;
    report.llmCalls += 1;
    report.tokensUsed.input += inCount;
    report.tokensUsed.output += outCount;
    ctx.tokenBudget.input += inCount;
    ctx.tokenBudget.output += outCount;
    if (ctx.tokenBudget.input + ctx.tokenBudget.output > ctx.tokenBudget.max) {
      event('guardrail', `${def.name}: global token budget exhausted — stopping`);
      return false;
    }
    return true;
  };

  const checkContinue = async (): Promise<boolean> => {
    if (Date.now() > ctx.deadline) {
      event('guardrail', `${def.name}: time budget exhausted — stopping`);
      return false;
    }
    for (;;) {
      const state = ctx.shouldContinue?.() ?? 'run';
      if (state === 'run') return true;
      if (state === 'cancelled') {
        report.notes.push('cancelled by user');
        return false;
      }
      await sleep(1000);
    }
  };

  // ── PLAN (routine tier) ─────────────────────────────────────────────
  event('worker_progress', `${def.name}: planning`, undefined);
  let plan: PlannedTest[] = [];
  try {
    const completion = await completeWithTimeout(provider, {
      messages: [
        { role: 'system', content: `${def.systemPrompt}\n\nMODE: PLANNING` },
        {
          role: 'user',
          content:
            `TARGET: ${ctx.targetUrl}\n` +
            `TECH STACK: ${ctx.techStack.map((t) => t.version ? `${t.name} ${t.version}` : t.name).join(', ') || 'unknown'}\n` +
            `SCOPE: ${scopeSummary(ctx)}\n` +
            `MAX_ACTIONS: ${def.maxActions}\n` +
            `${dataEnvelope('discovered-surface', ctx.discoveredEndpoints?.slice(0, 30).join(', ') || 'root URL')}\n` +
            `${dataEnvelope('prior-worker-notes', ctx.priorFindings.join(' | ') || 'none')}\n\n` +
            `Tools you may use:\n${toolCatalog(tools)}\n\n` +
            `Produce your test plan as a JSON array.`,
        },
      ],
      maxTokens: 2000,
      temperature: 0.2,
      tier: 'routine',
    });
    if (!spend(completion.usage?.inputTokens, completion.usage?.outputTokens)) {
      report.durationMs = Date.now() - started;
      return report;
    }
    const parsed = completion.parseJson<PlannedTest[]>();
    if (!Array.isArray(parsed)) throw new Error(`Plan is not a valid JSON array: ${completion.text.slice(0, 150)}`);
    plan = parsed
      .filter((t) => t && typeof t.tool === 'string')
      .sort((a, b) => (a.priority ?? 99) - (b.priority ?? 99))
      .slice(0, def.maxActions);
  } catch (err) {
    const errorMsg = (err as Error).message || String(err);
    console.error(`[worker] ${def.name} planning failed:`, errorMsg);
    report.errors.push(`planning failed: ${errorMsg}`);
    report.durationMs = Date.now() - started;
    // CRITICAL FIX: Do NOT silently swallow LLM API errors during planning.
    // Swallowing API errors here returns 0 tests and masks fatal LLM failures
    // (such as 400 bad argument, 401 unauthenticated, 403 quota) as a "clean" 100-score scan.
    throw new Error(`${def.name} planning failed: ${errorMsg}`);
  }
  report.testsPlanned = plan.length;
  event('worker_progress', `${def.name}: planned ${plan.length} tests`, plan.map((t) => t.name));

  // ── ACT → OBSERVE → TRIAGE → [ESCALATE] ─────────────────────────────
  for (const test of plan) {
    if (!(await checkContinue())) break;

    const tool = tools.find((t) => t.name === test.tool);
    if (!tool) {
      event('guardrail', `${def.name}: unknown tool "${test.tool}" — skipping`);
      continue;
    }

    // GATE, standing rules, then the LLM judge, then the
    // operator. A denied step is skipped, never silently retried, and
    // never re-requested: the per-run cache remembers the verdict.
    // Ungated runs (no task queue attached) proceed exactly as before.
    if (ctx.task?.approvals && ctx.task?.userId) {
      const remainingMs = ctx.deadline - Date.now();
      if (remainingMs <= 0) {
        event('guardrail', `${def.name}: time budget exhausted — stopping`);
        break;
      }
      const gate = await gateToolCall({
        provider,
        approvals: ctx.task.approvals,
        approvalRules: ctx.task.approvalRules,
        graph: ctx.task.graph,
        taskId: ctx.task.taskId,
        userId: ctx.task.userId,
        tool: test.tool,
        args: test.args ?? {},
        targetUrl: ctx.targetUrl,
        scope: ctx.scope,
        timeoutMs: Math.min(DEFAULT_APPROVAL_TIMEOUT_MS, remainingMs),
        cache: ctx.task.gateCache,
      });
      if (!gate.proceed) {
        report.notes.push(`step "${test.name}" skipped: ${gate.reason}`);
        event('guardrail', `${def.name}: skipped "${test.name}" — ${gate.reason}`);
        continue;
      }
    }

    // ACT
    let toolResult;
    try {
      toolResult = await tool.run(test.args ?? {}, ctx.toolCtx);
    } catch (err) {
      report.errors.push(`tool ${test.tool} threw: ${(err as Error).message}`);
      continue;
    }
    report.testsRun += 1;

    // Assess deterministic honeypot / canary / tarpit signals
    const defaultBaseline: BaselineProfile = {
      random404Status: 404,
      random404Length: 0,
      meanLatencyMs: 350,
      stdLatencyMs: 150,
    };
    const probeObs: ProbeObservation = {
      url: toolResult.finalUrl ?? String(test.args?.['url'] ?? ctx.targetUrl),
      status: toolResult.status ?? 200,
      bodyLength: (toolResult.bodySnippet ?? '').length,
      latencyMs: toolResult.timingMs ?? 0,
      headers: (toolResult.data && typeof toolResult.data === 'object' && 'headers' in (toolResult.data as Record<string, unknown>))
        ? ((toolResult.data as { headers: Record<string, string> }).headers ?? {})
        : {},
      bodySnippet: toolResult.bodySnippet ?? '',
    };
    const hpAssessment = assessHoneypotSignals(probeObs, defaultBaseline);
    const combinedSignals = [
      ...(toolResult.honeypotSignals ?? []),
      ...hpAssessment.signals,
    ];

    // OBSERVE (redacted, truncated — never raw bodies to the model)
    const observation = {
      test: test.name,
      tool: test.tool,
      ok: toolResult.ok,
      status: toolResult.status,
      finalUrl: toolResult.finalUrl,
      timingMs: toolResult.timingMs,
      data: toolResult.data,
      error: toolResult.error,
      bodyExcerpt: (toolResult.bodySnippet ?? '').slice(0, 600),
      honeypotSignals: combinedSignals,
    };

    // TRIAGE (routine tier — cheap filter)
    let triage: Triage;
    try {
      const triageCompletion = await completeWithTimeout(provider, {
        messages: [
          { role: 'system', content: `${def.systemPrompt}\n\n${codeOwnedTail()}\n\nMODE: TRIAGE. Return {"triage":"candidate"|"no-finding","reason":"..."}.` },
          { role: 'user', content: `TEST: ${test.name}\nOBSERVATION:\n${frameToolOutput(JSON.stringify(observation)).framed}` },
        ],
        maxTokens: 300,
        temperature: 0.1,
        tier: 'routine',
      });
      if (!spend(triageCompletion.usage.inputTokens, triageCompletion.usage.outputTokens)) break;
      triage = triageCompletion.parseJson<Triage>();
    } catch (err) {
      report.errors.push(`triage failed for "${test.name}": ${(err as Error).message}`);
      continue;
    }
    if (triage.triage !== 'candidate') continue;

    // ESCALATE (reasoning tier — only for candidates, capped)
    if (report.escalations >= def.maxEscalations) {
      report.notes.push(`escalation cap reached; candidate "${test.name}" recorded as note`);
      continue;
    }
    report.escalations += 1;
    try {
      const verdictCompletion = await completeWithTimeout(provider, {
        messages: [
          { role: 'system', content: `${def.systemPrompt}\n\n${codeOwnedTail()}\n\nMODE: FULL VERDICT. Return the full verdict JSON schema.` },
          {
            role: 'user',
            content:
              `TEST: ${test.name}\nTRIAGE REASON: ${triage.reason}\n` +
              `OBSERVATION:\n${frameToolOutput(JSON.stringify(observation)).framed}\n` +
              `PRIOR FINDINGS THIS SCAN: ${report.findings.map((f) => f.title).join(' | ') || 'none'}`,
          },
        ],
        maxTokens: 1200,
        temperature: 0.1,
        tier: 'reasoning',
      });
      if (!spend(verdictCompletion.usage.inputTokens, verdictCompletion.usage.outputTokens)) break;
      const raw = verdictCompletion.parseJson<Partial<Verdict>>();
      const verdict: Verdict = {
        verdict: ['finding', 'honeypot', 'no-finding'].includes(String(raw.verdict))
          ? (raw.verdict as Verdict['verdict'])
          : 'no-finding',
        trapProbability:
          typeof raw.trapProbability === 'number' && Number.isFinite(raw.trapProbability)
            ? Math.min(1, Math.max(0, raw.trapProbability))
            : 0,
        severity: ['critical', 'high', 'medium', 'low', 'info'].includes(String(raw.severity))
          ? (raw.severity as Verdict['severity'])
          : 'info',
        confidence: ['high', 'medium', 'low'].includes(String(raw.confidence))
          ? (raw.confidence as Verdict['confidence'])
          : 'low',
        category: typeof raw.category === 'string' ? raw.category.slice(0, 50) : def.id,
        title: typeof raw.title === 'string' ? raw.title.slice(0, 300) : test.name,
        description: typeof raw.description === 'string' ? raw.description.slice(0, 5000) : '',
        location: typeof raw.location === 'string' ? raw.location.slice(0, 500) : undefined,
        evidence: typeof raw.evidence === 'string' ? raw.evidence.slice(0, 5000) : undefined,
        reproSteps: Array.isArray(raw.reproSteps) ? raw.reproSteps.filter((s): s is string => typeof s === 'string').slice(0, 20) : [],
        remediation: typeof raw.remediation === 'string' ? raw.remediation.slice(0, 5000) : '',
        references: Array.isArray(raw.references) ? raw.references.filter((s): s is string => typeof s === 'string').slice(0, 20) : [],
        chainWith: Array.isArray(raw.chainWith) ? raw.chainWith.filter((s): s is string => typeof s === 'string').slice(0, 20) : [],
        reasoning: typeof raw.reasoning === 'string' ? raw.reasoning.slice(0, 2000) : '',
      };
      if (verdict.verdict === 'finding') {
        const rawEvidence = JSON.stringify({
          test: test.name,
          tool: test.tool,
          status: toolResult.status,
          finalUrl: toolResult.finalUrl,
          timingMs: toolResult.timingMs,
          data: toolResult.data,
          bodyExcerpt: (toolResult.bodySnippet ?? '').slice(0, 600),
          honeypotSignals: toolResult.honeypotSignals ?? [],
        });
        report.findings.push({
          severity: verdict.severity ?? 'info',
          confidence: verdict.confidence ?? 'low',
          category: verdict.category ?? def.id,
          title: verdict.title ?? test.name,
          description: verdict.description ?? triage.reason,
          location: verdict.location ?? String(test.args?.['url'] ?? ctx.targetUrl),
          evidence: (verdict.evidence ?? '').slice(0, 500),
          rawEvidence,
          reproSteps: verdict.reproSteps ?? [],
          remediation: verdict.remediation ?? '',
          references: verdict.references ?? [],
          trapProbability: Math.min(1, Math.max(verdict.trapProbability ?? 0, hpAssessment.trapProbability)),
          chainWith: verdict.chainWith ?? [],
        });
        if (hpAssessment.isLikelyTrap) {
          report.notes.push(
            `High trap probability (${hpAssessment.trapProbability}) on ${test.name}: ${hpAssessment.signals.join('; ')}`
          );
        }
      } else if (verdict.verdict === 'honeypot') {
        report.notes.push(`possible trap dismissed: ${verdict.title ?? test.name} (${verdict.reasoning ?? ''})`.slice(0, 300));
      }
    } catch (err) {
      report.errors.push(`verdict failed for "${test.name}": ${(err as Error).message}`);
    }
  }

  report.durationMs = Date.now() - started;
  report.summary =
    `${def.name}: ran ${report.testsRun}/${report.testsPlanned} tests, ` +
    `${report.findings.length} findings, ${report.escalations} escalations, ` +
    `${report.llmCalls} LLM calls (${report.tokensUsed.input + report.tokensUsed.output} tokens).`;
  return report;
}

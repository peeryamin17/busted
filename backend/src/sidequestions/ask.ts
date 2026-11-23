/**
 * Frozen-context Q and A: one provider call against a frozen snapshot of
 * a task. No tools, no live loop. Snapshot text is redacted and capped
 * at 8000 chars; findings are dropped whole, never cut in half.
 */
import type { LLMProvider } from '../llm/provider.js';
import type { GraphNode, TaskRecord } from '../graph/types.js';
import { redactText } from '../guardrails/redact.js';
import type { RecordSideQuestionInput, SideQuestionRecord, SideQuestionStore } from './store.js';

/** Hard cap on the rendered snapshot, in characters. */
export const SNAPSHOT_MAX_CHARS = 8000;

/** Marker appended whenever the snapshot was cut down to fit the cap. */
export const SNAPSHOT_TRUNCATION_MARKER = '…[truncated]';

/** A question must be non-empty and fit in one prompt-sized message. */
export const MAX_QUESTION_CHARS = 2000;

export interface SnapshotFinding {
  title: string;
  severity: string;
  category?: string;
  location?: string;
  description?: string;
}

export interface SnapshotCoverage {
  tested: string[];
  untested: string[];
}

export interface BuildSnapshotInput {
  task: TaskRecord;
  nodes?: GraphNode[];
  findings?: SnapshotFinding[];
  /** Coverage as pre-rendered text, or as tested/untested risk classes. */
  coverage?: string | SnapshotCoverage | null;
}

export interface SideQuestionResult {
  answer: string;
  /** Provider name, e.g. 'gemini', the model family that answered. */
  model: string;
  snapshotChars: number;
  tokens: number;
}

export function assertValidQuestion(question: unknown): string {
  if (typeof question !== 'string' || !question.trim()) {
    throw new Error('side_question_empty');
  }
  const trimmed = question.trim();
  if (trimmed.length > MAX_QUESTION_CHARS) {
    throw new Error('side_question_too_long');
  }
  return trimmed;
}

/** Scrub one line for the snapshot: secrets masked, capped per line so one long field cannot eat the budget. */
function cleanLine(text: string, maxLength = 400): string {
  return redactText(text.replace(/\s+/g, ' ').trim(), maxLength);
}

function renderCoverage(coverage: string | SnapshotCoverage | null | undefined): string | null {
  if (coverage == null) return null;
  if (typeof coverage === 'string') {
    const trimmed = coverage.trim();
    return trimmed ? cleanLine(trimmed, 500) : null;
  }
  const tested = coverage.tested.length ? coverage.tested.join(', ') : 'none recorded';
  const untested = coverage.untested.length ? coverage.untested.join(', ') : 'none recorded';
  return `Tested: ${tested}. Untested (not clean — simply unexamined): ${untested}.`;
}

/**
 * Render a task's context into a single bounded text snapshot.
 *
 * Sections: goal + target + status, intent nodes, fact nodes, hint
 * nodes, findings (title, severity, category, location, short
 * description), coverage. Finding-kind graph nodes are not repeated
 * here, the findings list is the authoritative source. When the
 * rendered text would exceed SNAPSHOT_MAX_CHARS, whole findings are
 * dropped from the end (newest last) until it fits, and the marker
 * is appended; if the header alone overflows, the header itself is
 * cut at the cap with the marker. The result is always at most
 * SNAPSHOT_MAX_CHARS long, and the marker is present exactly when
 * content was dropped.
 */
export function buildSnapshot(input: BuildSnapshotInput): string {
  const { task, nodes = [], findings = [] } = input;
  const lines: string[] = [];
  lines.push('Task snapshot — frozen context captured for one side question.');
  lines.push('This context is a snapshot, not live state. Answer only from what is written here.');
  lines.push(`Goal: ${cleanLine(task.goalText, 1000)}`);
  lines.push(`Target: ${cleanLine(task.targetUrl, 500)}`);
  lines.push(`Status: ${task.status}`);
  if (task.todolist.length > 0) {
    const steps = task.todolist.map((t) => `${t.text} [${t.status}]`).join('; ');
    lines.push(`Plan: ${cleanLine(steps, 1000)}`);
  }

  const intents = nodes.filter((n) => n.kind === 'intent');
  if (intents.length > 0) {
    lines.push('Intents:');
    for (const n of intents) {
      lines.push(`- ${cleanLine(n.label)}${n.status ? ` [${n.status}]` : ''}`);
    }
  }
  const facts = nodes.filter((n) => n.kind === 'fact');
  if (facts.length > 0) {
    lines.push('Facts:');
    for (const n of facts) {
      const detail = n.detail ? `: ${cleanLine(n.detail)}` : '';
      lines.push(`- ${cleanLine(n.label)}${detail}`);
    }
  }
  const hints = nodes.filter((n) => n.kind === 'hint');
  if (hints.length > 0) {
    lines.push('Notes:');
    for (const n of hints) {
      lines.push(`- ${cleanLine(n.label)}`);
    }
  }

  const coverage = renderCoverage(input.coverage);
  if (coverage) lines.push(`Coverage: ${coverage}`);

  const header = lines.join('\n');

  // Render each finding as a self-contained block, then add blocks
  // while the whole snapshot still fits. A block is added whole or
  // not at all, never cut mid-finding.
  const blocks = findings.map((f) => {
    const parts = [`- [${f.severity}] ${cleanLine(f.title)}`];
    if (f.category) parts[0] += ` (${cleanLine(f.category, 100)})`;
    if (f.location) parts.push(`  Location: ${cleanLine(f.location)}`);
    if (f.description) parts.push(`  ${cleanLine(f.description)}`);
    return parts.join('\n');
  });

  const shown: string[] = [];
  let omitted = 0;
  // Reserve room for the full truncation line (marker + omitted count),
  // not just the marker, the line is what gets appended at the end.
  const truncationLineLength = (n: number) =>
    `\n${SNAPSHOT_TRUNCATION_MARKER} (${n} finding(s) omitted to fit the snapshot budget)`.length;
  for (const block of blocks) {
    const candidate =
      header +
      `\nFindings (${shown.length + 1} of ${findings.length}):` +
      (shown.length > 0 ? `\n${shown.join('\n')}` : '') +
      `\n${block}`;
    const willOmit = omitted > 0 || shown.length + 1 < findings.length;
    const reserve = willOmit ? truncationLineLength(findings.length) + 2 : 0;
    if (candidate.length + reserve <= SNAPSHOT_MAX_CHARS) {
      shown.push(block);
    } else {
      omitted++;
    }
  }
  // Any finding that did not fit counts as omitted, including ones
  // never attempted because the budget was already spent.
  omitted += findings.length - shown.length - omitted;

  let snapshot = header;
  if (findings.length > 0) {
    snapshot += `\nFindings (${shown.length} of ${findings.length}):`;
    if (shown.length > 0) snapshot += `\n${shown.join('\n')}`;
  }
  if (omitted > 0) {
    snapshot += `\n${SNAPSHOT_TRUNCATION_MARKER} (${omitted} finding(s) omitted to fit the snapshot budget)`;
  }
  if (snapshot.length > SNAPSHOT_MAX_CHARS) {
    snapshot = snapshot.slice(0, SNAPSHOT_MAX_CHARS - SNAPSHOT_TRUNCATION_MARKER.length) + SNAPSHOT_TRUNCATION_MARKER;
  }
  return snapshot;
}

/**
 * Ask one side question against a frozen snapshot.
 *
 * Exactly ONE provider.complete call: a system message stating the
 * context is a frozen snapshot and the answer must not invent
 * findings beyond it, plus the snapshot and the question as the user
 * message. Temperature 0.2, side questions are lookups, not
 * brainstorming. The provider interface exposes no tools, so no
 * tool call can happen during the answer; the model can only read
 * the snapshot it was given. Returns the answer with the provider
 * name, the snapshot size, and the total token count for the call.
 */
export async function askSideQuestion(args: {
  provider: LLMProvider;
  snapshot: string;
  question: string;
}): Promise<SideQuestionResult> {
  const question = assertValidQuestion(args.question);
  const completion = await args.provider.complete({
    messages: [
      {
        role: 'system',
        content:
          'You are answering a side question about a security assessment task. ' +
          'The context below is a FROZEN SNAPSHOT of the task — a fixed summary captured at one moment, not live state. ' +
          'Answer only from what the snapshot contains. Do not invent findings, evidence, or coverage beyond it; ' +
          'if the snapshot does not contain the answer, say so plainly instead of guessing. ' +
          'Keep the answer short and concrete.',
      },
      {
        role: 'user',
        content: `Snapshot:\n${args.snapshot}\n\nQuestion: ${question}`,
      },
    ],
    temperature: 0.2,
    maxTokens: 1024,
    tier: 'routine',
  });
  return {
    answer: completion.text,
    model: args.provider.name,
    snapshotChars: args.snapshot.length,
    tokens: completion.usage.inputTokens + completion.usage.outputTokens,
  };
}

/** Persist one answered side question against its task (append-only history). */
export async function recordSideQuestion(
  store: SideQuestionStore,
  input: RecordSideQuestionInput,
): Promise<SideQuestionRecord> {
  assertValidQuestion(input.question);
  if (!input.answer.trim()) throw new Error('side_question_answer_empty');
  return store.create(input);
}

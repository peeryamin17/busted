/**
 * Cross-task lesson extraction from a completed task's own record.
 * Deterministic rules, no LLM call. Every lesson carries evidence; a
 * lesson with no evidence is never produced. Lesson text is redacted.
 * Shadow mode: lessons are stored, never injected into prompts.
 */
import { redactText } from '../guardrails/redact.js';
import type { CoverageEntry } from '../coverage/ledger.js';
import type { TodoItem } from '../graph/types.js';

export type LessonKind = 'worked' | 'failed' | 'pattern';

export const LESSON_KINDS: readonly LessonKind[] = ['worked', 'failed', 'pattern'];

/** One extracted lesson, before storage (the store assigns the id). */
export interface Lesson {
  id?: string;
  taskId: string;
  userId: string;
  kind: LessonKind;
  title: string;
  detail: string;
  evidence: string[];
  createdAt?: string;
}

/** A finding as extraction sees it (subset of the Finding record). */
export interface LessonFindingInput {
  category: string;
  title: string;
  /** Verified at POE ≥ 3 with a passing receipt (see reports/poe.ts). */
  verified?: boolean;
  severity?: string;
}

/** A retest verdict as extraction sees it (subset of RetestRecord). */
export interface LessonRetestInput {
  findingId: string;
  verdict: 'reproduced' | 'fixed' | 'inconclusive';
}

export interface ExtractLessonsInput {
  task: {
    id: string;
    userId: string;
    /** Must be terminal (done/timeout/failed), see below. */
    status: string;
    goalText?: string;
    targetUrl?: string;
  };
  todolist: TodoItem[];
  findings: LessonFindingInput[];
  retests?: LessonRetestInput[];
  coverage?: CoverageEntry[];
}

const TERMINAL_STATUSES = ['done', 'timeout', 'failed'];

function clean(text: string, maxLength: number): string {
  // redactText truncates at its own default; the explicit length keeps
  // lesson detail usable while still scrubbing secrets and PII.
  return redactText(text, maxLength);
}

function lesson(
  taskId: string,
  userId: string,
  kind: LessonKind,
  title: string,
  detail: string,
  evidence: string[],
): Lesson {
  return {
    taskId,
    userId,
    kind,
    title: clean(title, 300),
    detail: clean(detail, 2000),
    evidence: evidence.map((e) => clean(e, 300)),
  };
}

/**
 * Extract lessons from a completed task.
 *
 *   - 'worked': each done todolist step; each verified finding.
 *   - 'failed': each skipped todolist step; each inconclusive retest.
 *   - 'pattern': a finding category seen ≥2 times in this task, or a
 *     risk class with ≥2 'finding' coverage entries. (Extraction is
 *     per-task only, so patterns come from within-task repetition,
 *     cross-task repetition is what the store's listing is for.)
 *
 * Throws `task_not_completed` when the task has not reached a terminal
 * status, lessons are only extracted from finished work, never from
 * a run still in flight.
 */
export function extractLessons(input: ExtractLessonsInput): Lesson[] {
  const { task, todolist, findings } = input;
  if (!TERMINAL_STATUSES.includes(task.status)) {
    throw new Error('task_not_completed');
  }
  const retests = input.retests ?? [];
  const coverage = input.coverage ?? [];
  const out: Lesson[] = [];
  const target = task.targetUrl ?? task.goalText ?? task.id;

  for (const step of todolist) {
    if (step.status === 'done') {
      out.push(
        lesson(
          task.id,
          task.userId,
          'worked',
          `Completed step: ${step.text}`,
          `The step "${step.text}" completed during the task on ${target}. ` +
            `Repeating this step's approach on similar targets is a known-good move.`,
          [`todolist:${step.id}`],
        ),
      );
    } else if (step.status === 'skipped') {
      out.push(
        lesson(
          task.id,
          task.userId,
          'failed',
          `Skipped step: ${step.text}`,
          `The step "${step.text}" was skipped during the task on ${target}. ` +
            `Skipped steps are unfinished work, not clean results — a future run ` +
            `should either attempt the step or record why it does not apply.`,
          [`todolist:${step.id}`],
        ),
      );
    }
  }

  for (const finding of findings) {
    if (finding.verified) {
      out.push(
        lesson(
          task.id,
          task.userId,
          'worked',
          `Verified ${finding.category}: ${finding.title}`,
          `A ${finding.category} finding ("${finding.title}") was verified ` +
            `with a passing receipt on ${target}. The probe that produced it ` +
            `is a proven technique for this class.`,
          [`finding:${finding.category}:${finding.title}`],
        ),
      );
    }
  }

  for (const retest of retests) {
    if (retest.verdict === 'inconclusive') {
      out.push(
        lesson(
          task.id,
          task.userId,
          'failed',
          `Inconclusive retest: ${retest.findingId}`,
          `Re-testing finding ${retest.findingId} on ${target} came back ` +
            `inconclusive — neither reproduced nor fixed. An inconclusive ` +
            `retest settles nothing; the finding stays unverified.`,
          [`retest:${retest.findingId}`],
        ),
      );
    }
  }

  // Within-task repetition: the same category twice is a pattern, not
  // two unrelated one-offs.
  const byCategory = new Map<string, LessonFindingInput[]>();
  for (const finding of findings) {
    const list = byCategory.get(finding.category) ?? [];
    list.push(finding);
    byCategory.set(finding.category, list);
  }
  for (const [category, list] of [...byCategory.entries()].sort((a, b) =>
    a[0].localeCompare(b[0]),
  )) {
    if (list.length < 2) continue;
    out.push(
      lesson(
        task.id,
        task.userId,
        'pattern',
        `Repeated ${category} findings (${list.length}) on one task`,
        `The task on ${target} produced ${list.length} ${category} findings. ` +
          `When one target yields the same class repeatedly, the class is ` +
          `worth checking early on similar targets.`,
        list.map((f) => `finding:${f.category}:${f.title}`),
      ),
    );
  }

  const findingsByClass = new Map<string, number>();
  for (const entry of coverage) {
    if (entry.outcome === 'finding') {
      findingsByClass.set(entry.riskClass, (findingsByClass.get(entry.riskClass) ?? 0) + 1);
    }
  }
  for (const [riskClass, count] of [...findingsByClass.entries()].sort((a, b) =>
    a[0].localeCompare(b[0]),
  )) {
    if (count < 2) continue;
    out.push(
      lesson(
        task.id,
        task.userId,
        'pattern',
        `Repeated ${riskClass} coverage hits (${count}) on one task`,
        `Coverage for the task on ${target} recorded ${count} finding ` +
          `outcomes in risk class ${riskClass}.`,
        [`coverage:${riskClass}`],
      ),
    );
  }

  return out;
}

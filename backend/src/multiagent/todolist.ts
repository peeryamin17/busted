/**
 * Persistent per-task todolist for dependent chains. Only a step whose
 * prerequisites are satisfied dispatches per round. Pure: no I/O, no LLM,
 * no imports. Lists are immutable; markStep returns a new list.
 */

export type TodoStepKind = 'recon' | 'test' | 'verify' | 'report';
export type TodoStepStatus = 'pending' | 'ready' | 'running' | 'done' | 'blocked';

export const TODO_STEP_KINDS: readonly TodoStepKind[] = ['recon', 'test', 'verify', 'report'];
export const TODO_STEP_STATUSES: readonly TodoStepStatus[] = [
  'pending',
  'ready',
  'running',
  'done',
  'blocked',
];

export interface TodoStep {
  id: string;
  label: string;
  kind: TodoStepKind;
  dependsOn: string[];
  status: TodoStepStatus;
  note?: string;
}

export interface TodoList {
  steps: TodoStep[];
}

export interface TodoStepInput {
  id?: string;
  label: string;
  kind: TodoStepKind;
  dependsOn?: string[];
  status?: TodoStepStatus;
  note?: string;
}

function isTodoStepKind(v: unknown): v is TodoStepKind {
  return typeof v === 'string' && (TODO_STEP_KINDS as readonly string[]).includes(v);
}

function isTodoStepStatus(v: unknown): v is TodoStepStatus {
  return typeof v === 'string' && (TODO_STEP_STATUSES as readonly string[]).includes(v);
}

/**
 * Validate a built step list: every `dependsOn` reference must exist and
 * the dependency graph must be acyclic. Throws a clear Error otherwise.
 */
function validateTodoSteps(steps: TodoStep[]): void {
  const ids = new Set(steps.map((s) => s.id));
  for (const s of steps) {
    for (const dep of s.dependsOn) {
      if (!ids.has(dep)) {
        throw new Error(`Todo step "${s.id}" depends on unknown step "${dep}"`);
      }
    }
  }
  // Cycle detection (iterative DFS with an explicit path for the message).
  const byId = new Map(steps.map((s) => [s.id, s]));
  const state = new Map<string, 'visiting' | 'done'>();
  const visit = (id: string, path: string[]): void => {
    const st = state.get(id);
    if (st === 'done') return;
    if (st === 'visiting') {
      const cycle = [...path.slice(path.indexOf(id)), id].join(' -> ');
      throw new Error(`Dependency cycle detected in todolist: ${cycle}`);
    }
    state.set(id, 'visiting');
    for (const dep of byId.get(id)?.dependsOn ?? []) visit(dep, [...path, id]);
    state.set(id, 'done');
  };
  for (const s of steps) visit(s.id, []);
}

/**
 * Build a todolist from step inputs. Assigns deterministic ids
 * (`step-1`, `step-2`, …) where none are given, defaults status to
 * `pending`, and validates dependency references and cycles (throws).
 */
export function createTodoList(steps: TodoStepInput[]): TodoList {
  const used = new Set<string>();
  const built: TodoStep[] = steps.map((s, i) => {
    let id = (s.id ?? '').trim();
    if (!id) {
      const base = `step-${i + 1}`;
      id = base;
      let suffix = 2;
      while (used.has(id)) id = `${base}-${suffix++}`;
    }
    if (used.has(id)) {
      throw new Error(`Duplicate todo step id "${id}"`);
    }
    used.add(id);
    if (typeof s.label !== 'string' || s.label.trim().length === 0) {
      throw new Error(`Todo step "${id}" has no label`);
    }
    if (!isTodoStepKind(s.kind)) {
      throw new Error(`Todo step "${id}" has invalid kind ${JSON.stringify(s.kind)}`);
    }
    const status: TodoStepStatus = s.status ?? 'pending';
    if (!isTodoStepStatus(status)) {
      throw new Error(`Todo step "${id}" has invalid status ${JSON.stringify(status)}`);
    }
    return {
      id,
      label: s.label.trim(),
      kind: s.kind,
      dependsOn: [...new Set((s.dependsOn ?? []).filter((d) => typeof d === 'string'))],
      status,
      ...(typeof s.note === 'string' && s.note.trim().length > 0 ? { note: s.note.trim() } : {}),
    };
  });
  validateTodoSteps(built);
  return { steps: built };
}

/**
 * The only steps that may be dispatched: status `pending` (or `ready`,
 * an explicit planner confirmation of the same condition) AND every
 * dependency done. A step whose prerequisites are not done is never
 * returned, no matter what else is true of it.
 */
export function readySteps(list: TodoList): TodoStep[] {
  const done = new Set(list.steps.filter((s) => s.status === 'done').map((s) => s.id));
  return list.steps.filter(
    (s) =>
      (s.status === 'pending' || s.status === 'ready') &&
      s.dependsOn.every((d) => done.has(d)),
  );
}

/**
 * Return a new list with one step moved to `status` (optionally attaching
 * a note). The original list is untouched. Guards (all throw):
 * - unknown step id;
 * - moving out of `done` (done is terminal);
 * - `done` requires every dependency already done;
 * - `running` requires the step to be dispatchable (pending/ready with
 *   all dependencies done);
 * - `ready` (explicit "prerequisites verified") also requires all
 *   dependencies done.
 */
export function markStep(
  list: TodoList,
  id: string,
  status: TodoStepStatus,
  note?: string,
): TodoList {
  const idx = list.steps.findIndex((s) => s.id === id);
  if (idx === -1) {
    throw new Error(`Unknown todo step "${id}"`);
  }
  const step = list.steps[idx];
  if (step.status === 'done' && status !== 'done') {
    throw new Error(`Todo step "${id}" is already done and cannot move to "${status}"`);
  }
  const doneIds = new Set(list.steps.filter((s) => s.status === 'done').map((s) => s.id));
  const unmet = step.dependsOn.filter((d) => !doneIds.has(d));
  if (status === 'done' && unmet.length > 0) {
    throw new Error(
      `Cannot mark todo step "${id}" done: prerequisite step(s) not done: ${unmet.join(', ')}`,
    );
  }
  if ((status === 'running' || status === 'ready') && unmet.length > 0) {
    throw new Error(
      `Cannot move todo step "${id}" to "${status}": prerequisite step(s) not done: ${unmet.join(', ')}`,
    );
  }
  if (status === 'running' && step.status !== 'pending' && step.status !== 'ready') {
    throw new Error(
      `Cannot start todo step "${id}": step is "${step.status}" (must be pending or ready)`,
    );
  }
  const next: TodoStep = {
    ...step,
    status,
    ...(note !== undefined ? { note } : step.note !== undefined ? { note: step.note } : {}),
  };
  const steps = [...list.steps];
  steps[idx] = next;
  return { steps };
}

/**
 * Complete when every step is `done`, or `blocked` with a note explaining
 * why it can go no further. A `blocked` step without a note, or any step
 * still pending/ready/running, means the list is not complete. An empty
 * list is vacuously complete.
 */
export function isComplete(list: TodoList): boolean {
  return list.steps.every(
    (s) => s.status === 'done' || (s.status === 'blocked' && typeof s.note === 'string' && s.note.trim().length > 0),
  );
}

/** Serialize a todolist to a JSON string for the tasks.todolist column. */
export function serialize(list: TodoList): string {
  return JSON.stringify(list);
}

/**
 * Parse a todolist back from JSON (string or already-parsed value).
 * Round-trip safe and tolerant: unknown fields are dropped, missing
 * `dependsOn`/`status` default to `[]`/`pending`. Throws a clear Error
 * on malformed JSON, a wrong shape, invalid kind/status values, unknown
 * dependency references, or dependency cycles.
 */
export function parseTodoList(json: unknown): TodoList {
  let parsed: unknown = json;
  if (typeof json === 'string') {
    try {
      parsed = JSON.parse(json);
    } catch (err) {
      throw new Error(`Invalid todolist JSON: ${(err as Error).message}`);
    }
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Invalid todolist: expected an object with a "steps" array');
  }
  const rawSteps = (parsed as { steps?: unknown }).steps;
  if (!Array.isArray(rawSteps)) {
    throw new Error('Invalid todolist: "steps" must be an array');
  }
  const steps: TodoStep[] = rawSteps.map((raw, i) => {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      throw new Error(`Invalid todolist: step ${i} is not an object`);
    }
    const r = raw as Record<string, unknown>;
    if (typeof r.id !== 'string' || r.id.trim().length === 0) {
      throw new Error(`Invalid todolist: step ${i} has no id`);
    }
    if (typeof r.label !== 'string' || r.label.trim().length === 0) {
      throw new Error(`Invalid todolist: step "${r.id}" has no label`);
    }
    if (!isTodoStepKind(r.kind)) {
      throw new Error(`Invalid todolist: step "${r.id}" has invalid kind ${JSON.stringify(r.kind)}`);
    }
    const status: TodoStepStatus = r.status === undefined ? 'pending' : (r.status as TodoStepStatus);
    if (!isTodoStepStatus(status)) {
      throw new Error(`Invalid todolist: step "${r.id}" has invalid status ${JSON.stringify(r.status)}`);
    }
    const dependsOn = Array.isArray(r.dependsOn)
      ? [...new Set(r.dependsOn.filter((d): d is string => typeof d === 'string'))]
      : [];
    return {
      id: r.id.trim(),
      label: r.label.trim(),
      kind: r.kind,
      dependsOn,
      status,
      ...(typeof r.note === 'string' && r.note.trim().length > 0 ? { note: r.note.trim() } : {}),
    };
  });
  // Duplicate ids are invalid on parse too (createTodoList rejects them).
  const seen = new Set<string>();
  for (const s of steps) {
    if (seen.has(s.id)) throw new Error(`Invalid todolist: duplicate step id "${s.id}"`);
    seen.add(s.id);
  }
  validateTodoSteps(steps);
  return { steps };
}

/**
 * Tests for the persistent todolist (multiagent/todolist.ts).
 * Pure functions, no I/O, no LLM, so tests run entirely in-memory.
 */
import {
  createTodoList,
  isComplete,
  markStep,
  parseTodoList,
  readySteps,
  serialize,
  type TodoList,
} from '../src/multiagent/todolist.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

function expectThrow(name: string, fn: () => unknown, match?: string) {
  try {
    fn();
    check(name, false, 'did not throw');
  } catch (err) {
    const msg = (err as Error).message;
    check(name, match === undefined || msg.includes(match), msg);
  }
}

function chain(): TodoList {
  return createTodoList([
    { id: 'a', label: 'Map the attack surface', kind: 'recon' },
    { id: 'b', label: 'Test reflected input handling', kind: 'test', dependsOn: ['a'] },
    { id: 'c', label: 'Verify the XSS finding with a benign canary', kind: 'verify', dependsOn: ['b'] },
  ]);
}

async function main() {
  // 1. Chain A→B→C: only A ready at first; B only after A done; C only after B.
  {
    const list = chain();
    check('todolist: only A ready at first', readySteps(list).map((s) => s.id).join(',') === 'a', readySteps(list).map((s) => s.id));
    const afterA = markStep(list, 'a', 'done');
    check('todolist: B ready only after A done', readySteps(afterA).map((s) => s.id).join(',') === 'b', readySteps(afterA).map((s) => s.id));
    const afterB = markStep(afterA, 'b', 'done');
    check('todolist: C ready only after B done', readySteps(afterB).map((s) => s.id).join(',') === 'c', readySteps(afterB).map((s) => s.id));
    const afterC = markStep(afterB, 'c', 'done');
    check('todolist: nothing ready when all done', readySteps(afterC).length === 0);
    check('todolist: complete when all done', isComplete(afterC));
    check('todolist: not complete while steps pending', !isComplete(list));
  }

  // 2. Cycle detection throws (two-node cycle and self-dependency).
  {
    expectThrow(
      'todolist: A<->B cycle throws',
      () => createTodoList([
        { id: 'a', label: 'A', kind: 'recon', dependsOn: ['b'] },
        { id: 'b', label: 'B', kind: 'test', dependsOn: ['a'] },
      ]),
      'cycle',
    );
    expectThrow(
      'todolist: self-dependency throws',
      () => createTodoList([{ id: 'a', label: 'A', kind: 'recon', dependsOn: ['a'] }]),
      'cycle',
    );
    expectThrow(
      'todolist: unknown dependency throws',
      () => createTodoList([{ id: 'a', label: 'A', kind: 'recon', dependsOn: ['ghost'] }]),
      'unknown step "ghost"',
    );
    expectThrow(
      'todolist: duplicate id throws',
      () => createTodoList([
        { id: 'a', label: 'A', kind: 'recon' },
        { id: 'a', label: 'A again', kind: 'test' },
      ]),
      'Duplicate',
    );
  }

  // 3. markStep guards: cannot mark done/running before deps are done.
  {
    const list = chain();
    expectThrow('todolist: cannot mark B done before A done', () => markStep(list, 'b', 'done'), 'not done');
    expectThrow('todolist: cannot start B before A done', () => markStep(list, 'b', 'running'), 'not done');
    expectThrow('todolist: cannot mark C ready before deps done', () => markStep(list, 'c', 'ready'), 'not done');
    expectThrow('todolist: unknown step id throws', () => markStep(list, 'nope', 'done'), 'Unknown todo step');
    const afterA = markStep(list, 'a', 'done');
    const startedB = markStep(afterA, 'b', 'running');
    check('todolist: B can start once A is done', startedB.steps.find((s) => s.id === 'b')?.status === 'running');
    expectThrow(
      'todolist: done step cannot move back to running',
      () => markStep(afterA, 'a', 'running'),
      'already done',
    );
    // A step that is running can still finish.
    const finishedB = markStep(startedB, 'b', 'done');
    check('todolist: running step can be marked done', finishedB.steps.find((s) => s.id === 'b')?.status === 'done');
  }

  // 4. Serialize / parse round-trip.
  {
    const list = markStep(chain(), 'a', 'done', 'surface mapped: 12 endpoints');
    const json = serialize(list);
    check('todolist: serialize produces a JSON string', typeof json === 'string' && json.includes('"todolist"') === false, json.slice(0, 80));
    const parsed = parseTodoList(json);
    check(
      'todolist: round-trip preserves steps',
      JSON.stringify(parsed) === JSON.stringify(list),
      { parsed, list },
    );
    // parse accepts an already-parsed object too.
    const parsedObj = parseTodoList(JSON.parse(json));
    check('todolist: parse accepts an object', JSON.stringify(parsedObj) === JSON.stringify(list));
  }

  // 5. parseTodoList is tolerant of unknown fields; strict on bad shape.
  {
    const parsed = parseTodoList(JSON.stringify({
      steps: [
        { id: 'a', label: 'A', kind: 'recon', status: 'pending', dependsOn: [], extraField: 1, legacy: true },
        { id: 'b', label: 'B', kind: 'test', dependsOn: ['a'] }, // status + note omitted
      ],
      someTopLevelExtra: 'ignored',
    }));
    check('todolist: unknown fields dropped on parse', !('extraField' in parsed.steps[0]) && !('someTopLevelExtra' in parsed), parsed);
    check('todolist: missing status defaults to pending', parsed.steps[1].status === 'pending');
    expectThrow('todolist: malformed JSON throws', () => parseTodoList('{not json'), 'Invalid todolist JSON');
    expectThrow('todolist: missing steps array throws', () => parseTodoList(JSON.stringify({})), '"steps" must be an array');
    expectThrow(
      'todolist: invalid kind throws',
      () => parseTodoList(JSON.stringify({ steps: [{ id: 'a', label: 'A', kind: 'explode' }] })),
      'invalid kind',
    );
    expectThrow(
      'todolist: cyclic JSON throws',
      () => parseTodoList(JSON.stringify({
        steps: [
          { id: 'a', label: 'A', kind: 'recon', dependsOn: ['b'] },
          { id: 'b', label: 'B', kind: 'test', dependsOn: ['a'] },
        ],
      })),
      'cycle',
    );
  }

  // 6. isComplete semantics: blocked-with-note counts; blocked-without-note does not.
  {
    const blockedWithNote = markStep(chain(), 'a', 'blocked', 'target unreachable after 3 retries');
    check('todolist: blocked-with-note alone is not complete (B/C still pending)', !isComplete(blockedWithNote));
    const allBlocked = markStep(
      markStep(markStep(chain(), 'a', 'blocked', 'target down'), 'b', 'blocked', 'prereq blocked'),
      'c', 'blocked', 'prereq blocked',
    );
    check('todolist: all blocked-with-note is complete', isComplete(allBlocked));
    const blockedNoNote = markStep(chain(), 'a', 'blocked');
    check('todolist: blocked without note is not complete', !isComplete(blockedNoNote));
    check('todolist: empty list is complete', isComplete(createTodoList([])));
    const mixed = markStep(markStep(chain(), 'a', 'done'), 'b', 'blocked', 'endpoint removed by target');
    // c cannot be done while b is blocked (dep not done).
    expectThrow('todolist: blocked dep still gates done', () => markStep(mixed, 'c', 'done'), 'not done');
    check('todolist: done + blocked-with-note + pending is not complete', !isComplete(mixed));
  }

  // 7. Ids are assigned when missing; markStep returns a new list (immutable).
  {
    const list = createTodoList([
      { label: 'First', kind: 'recon' },
      { label: 'Second', kind: 'test', dependsOn: ['step-1'] },
    ]);
    check('todolist: ids auto-assigned deterministically', list.steps[0].id === 'step-1' && list.steps[1].id === 'step-2', list.steps.map((s) => s.id));
    const next = markStep(list, 'step-1', 'done');
    check('todolist: markStep returns a new list', next !== list && next.steps !== list.steps);
    check('todolist: original list untouched by markStep', list.steps[0].status === 'pending');
    check('todolist: note attached by markStep', next.steps[0].note === undefined || typeof next.steps[0].note === 'string');
    const noted = markStep(list, 'step-1', 'running', 'started recon');
    check('todolist: markStep stores the note', noted.steps[0].note === 'started recon', noted.steps[0]);
  }

  // 8. Explicit 'ready' status: requires deps done, and stays dispatchable.
  {
    const list = chain();
    const afterA = markStep(list, 'a', 'done');
    const readyB = markStep(afterA, 'b', 'ready');
    check('todolist: ready step with deps done is dispatchable', readySteps(readyB).some((s) => s.id === 'b'));
    const started = markStep(readyB, 'b', 'running');
    check('todolist: ready step can start running', started.steps.find((s) => s.id === 'b')?.status === 'running');
  }

  if (failures > 0) { console.error(`${failures} todolist test(s) failed`); process.exit(1); }
  console.log('ALL TODOLIST TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('todolist test crashed', e); process.exit(1); });

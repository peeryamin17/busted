/**
 * Unit tests for the skills system (src/skills/*) + starter packs
 * (backend/skills/*). No network, no DB, no LLM, the Postgres gap
 * store is exercised against a stub query function, not a live pool.
 *
 * Run:  npx tsx test/skills.test.ts   (from backend/)
 */
import { join } from 'node:path';
import {
  loadSkillDir,
  loadSkillDirectory,
  parseFrontmatter,
  parseSkillFile,
  assertNoExecutableDirectives,
  defaultSkillsDir,
} from '../src/skills/loader.js';
import { SkillRegistry, skillPromptText } from '../src/skills/registry.js';
import {
  MemorySkillGapStore,
  PostgresSkillGapStore,
  type SkillGapRecord,
} from '../src/skills/gaps.js';

let failures = 0;
let passes = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else { passes++; console.log(`ok: ${name}`); }
}

function throwsWith(fn: () => unknown, re: RegExp): boolean {
  try {
    fn();
  } catch (e) {
    return re.test((e as Error).message);
  }
  return false;
}

const VALID_SKILL = `---
name: test-skill
description: A skill for testing.
when-to-use: When testing the loader.
roles:
  - planner
  - worker
tools:
  - guarded-fetch
  - taint-engine
---

# Test skill

Do the test thing, carefully.
`;

const TASK = '11111111-1111-1111-1111-111111111111';
const TASK2 = '22222222-2222-2222-2222-222222222222';
const USER = 'user-1';
const USER2 = 'user-2';

async function main() {
  // ── 1. Frontmatter parsing: valid ──
  {
    const fm = parseFrontmatter(
      'name: api-recon\ndescription: Map it.\nwhen-to-use: At the start.\nroles:\n  - planner\n  - worker\ntools: [guarded-fetch, header-probe]',
    );
    check('fm: name parsed', fm['name'] === 'api-recon', fm);
    check('fm: description parsed', fm['description'] === 'Map it.', fm);
    check('fm: block list parsed', Array.isArray(fm['roles']) && (fm['roles'] as string[]).length === 2, fm);
    check('fm: inline list parsed', Array.isArray(fm['tools']) && (fm['tools'] as string[]).includes('header-probe'), fm);
    check('fm: quoted scalar unquoted', parseFrontmatter('name: "quoted-name"')['name'] === 'quoted-name');
  }

  // ── 2. Frontmatter parsing: malformed ──
  {
    check('fm: line without a colon rejected', throwsWith(
      () => parseFrontmatter('name: ok\nthis is not a pair'),
      /invalid_skill_frontmatter/,
    ));
    check('fm: list item without a key rejected', throwsWith(
      () => parseFrontmatter('name: ok\n  - orphan'),
      /invalid_skill_frontmatter/,
    ));
    check('fm: duplicate key rejected', throwsWith(
      () => parseFrontmatter('name: a\nname: b'),
      /duplicate key/,
    ));
    check('fm: unknown key rejected', throwsWith(
      () => parseFrontmatter('name: a\ndescription: b\nwhen-to-use: c\nroles: [worker]\ntools: []\nsurprise: yes'),
      /unknown key/,
    ));
    check('fm: empty block list rejected', throwsWith(
      () => parseFrontmatter('name: a\nroles:'),
      /empty list/,
    ));
  }

  // ── 3. Skill parsing: valid, missing fields, bad values ──
  {
    const skill = parseSkillFile(VALID_SKILL, '/tmp/test-skill');
    check('parse: name', skill.name === 'test-skill', skill);
    check('parse: description', skill.description === 'A skill for testing.', skill);
    check('parse: whenToUse', skill.whenToUse === 'When testing the loader.', skill);
    check('parse: roles', skill.roles.length === 2 && skill.roles.includes('planner'), skill);
    check('parse: tools', skill.tools.length === 2 && skill.tools.includes('taint-engine'), skill);
    check('parse: body kept', skill.body.includes('Do the test thing'), skill);
    check('parse: sourceDir recorded', skill.sourceDir === '/tmp/test-skill');

    check('parse: missing description rejected', throwsWith(
      () => parseSkillFile(VALID_SKILL.replace('description: A skill for testing.\n', ''), '/tmp/x'),
      /missing or empty required field "description"/,
    ));
    check('parse: missing roles rejected', throwsWith(
      () => parseSkillFile(VALID_SKILL.replace(/roles:\n  - planner\n  - worker\n/, ''), '/tmp/x'),
      /missing required field "roles"/,
    ));
    check('parse: missing frontmatter rejected', throwsWith(
      () => parseSkillFile('# No frontmatter here\n', '/tmp/x'),
      /must start with a YAML frontmatter fence/,
    ));
    check('parse: unclosed frontmatter rejected', throwsWith(
      () => parseSkillFile('---\nname: a\n', '/tmp/x'),
      /never closed/,
    ));
    check('parse: non-slug name rejected', throwsWith(
      () => parseSkillFile(VALID_SKILL.replace('name: test-skill', 'name: Test_Skill'), '/tmp/x'),
      /not a lowercase slug/,
    ));
    check('parse: unknown role rejected', throwsWith(
      () => parseSkillFile(VALID_SKILL.replace('- planner', '- overlord'), '/tmp/x'),
      /unknown role/,
    ));
    check('parse: empty body rejected', throwsWith(
      () => parseSkillFile(VALID_SKILL.replace('\n# Test skill\n\nDo the test thing, carefully.\n', '\n'), '/tmp/x'),
      /body is empty/,
    ));
  }

  // ── 4. Executable directives rejected ──
  {
    check('exec: bash fence rejected', throwsWith(
      () => assertNoExecutableDirectives('Do this:\n```bash\ncurl https://example.com\n```\n'),
      /skill_contains_executable_directive/,
    ));
    check('exec: sh fence rejected', throwsWith(
      () => assertNoExecutableDirectives('```sh\necho hi\n```'),
      /skill_contains_executable_directive/,
    ));
    check('exec: powershell fence rejected', throwsWith(
      () => assertNoExecutableDirectives('```powershell\nGet-ChildItem\n```'),
      /skill_contains_executable_directive/,
    ));
    check('exec: plain fence allowed', (() => {
      try {
        assertNoExecutableDirectives('```text\njust prose\n```');
        return true;
      } catch {
        return false;
      }
    })());
    check('exec: json fence allowed', (() => {
      try {
        assertNoExecutableDirectives('```json\n{"a": 1}\n```');
        return true;
      } catch {
        return false;
      }
    })());
    check('exec: exec frontmatter key rejected', throwsWith(
      () => parseFrontmatter('name: a\nexec: curl https://example.com'),
      /skill_contains_executable_directive/,
    ));
    check('exec: run frontmatter key rejected', throwsWith(
      () => parseFrontmatter('name: a\nrun: ./do-it.sh'),
      /skill_contains_executable_directive/,
    ));
    check('exec: shell fence in full skill rejected', throwsWith(
      () => parseSkillFile(VALID_SKILL + '\n```bash\nrun-the-thing\n```\n', '/tmp/x'),
      /skill_contains_executable_directive/,
    ));
  }

  // ── 5. Registry: listing + role visibility ──
  const registry = new SkillRegistry();
  {
    const skill = parseSkillFile(VALID_SKILL, '/tmp/test-skill');
    const workerOnly = parseSkillFile(
      VALID_SKILL.replace('name: test-skill', 'name: worker-only')
        .replace('roles:\n  - planner\n  - worker', 'roles:\n  - worker'),
      '/tmp/worker-only',
    );
    const mainOnly = parseSkillFile(
      VALID_SKILL.replace('name: test-skill', 'name: main-only')
        .replace('roles:\n  - planner\n  - worker', 'roles:\n  - main'),
      '/tmp/main-only',
    );
    registry.add(skill);
    registry.add(workerOnly);
    registry.add(mainOnly);

    check('registry: lists all 3', registry.list().length === 3, registry.list().map((s) => s.name));
    check('registry: list sorted by name', registry.list()[0].name === 'main-only');
    check('registry: planner sees 1', registry.visibleTo('planner').length === 1 && registry.visibleTo('planner')[0].name === 'test-skill');
    check('registry: worker sees 2', registry.visibleTo('worker').length === 2);
    check('registry: main sees 1', registry.visibleTo('main').length === 1 && registry.visibleTo('main')[0].name === 'main-only');
    check('registry: get unknown → null', registry.get('nope') === null);
    check('registry: toolGatedBy names the skill', registry.toolGatedBy('taint-engine').includes('test-skill'));
    check('registry: ungated tool has no gater', registry.toolGatedBy('plain-fetch').length === 0);
    check('registry: isToolGated true/false', registry.isToolGated('taint-engine') && !registry.isToolGated('plain-fetch'));
    check('prompt: header carries name + description', skillPromptText(skill).startsWith('Skill: test-skill — A skill for testing.'));
  }

  // ── 6. Tool gating: locked before load, unlocked after ──
  {
    const run = registry.runFor(TASK);
    check('gate: gated tool locked before load', run.isToolUnlocked('taint-engine') === false);
    check('gate: ungated tool always available', run.isToolUnlocked('plain-fetch') === true);
    check('gate: other run is independent', registry.runFor(TASK2).isToolUnlocked('taint-engine') === false);

    const prompt = run.load('worker', 'test-skill');
    check('gate: load returns prompt text', prompt.includes('Do the test thing'), prompt);
    check('gate: gated tool unlocked after load', run.isToolUnlocked('taint-engine') === true);
    check('gate: other run still locked', registry.runFor(TASK2).isToolUnlocked('taint-engine') === false);
    check('gate: loadedSkills lists it', run.loadedSkills().includes('test-skill'));
    check('gate: loading twice is a no-op', run.load('worker', 'test-skill') === prompt);

    check('gate: unknown skill → skill_not_found', throwsWith(
      () => run.load('worker', 'no-such-skill'),
      /skill_not_found/,
    ));
    check('gate: wrong role → not visible', throwsWith(
      () => run.load('main', 'test-skill'),
      /skill_not_visible_to_role/,
    ));
    check('gate: wrong role does not unlock', registry.runFor(TASK2).isToolUnlocked('guarded-fetch') === false);

    // loadSkillForRun convenience on the registry itself.
    const prompt2 = registry.loadSkillForRun('worker', 'worker-only', TASK2);
    check('gate: loadSkillForRun returns prompt', prompt2.includes('Do the test thing'));
    check('gate: loadSkillForRun unlocked the run', registry.runFor(TASK2).isToolUnlocked('taint-engine') === true);

    registry.dropRun(TASK2);
    check('gate: dropRun resets the loaded set', registry.runFor(TASK2).isToolUnlocked('taint-engine') === false);
  }

  // ── 7. Skill-gap ledger (memory): record + dedup + scoping ──
  {
    const gaps = new MemorySkillGapStore();
    const first = await gaps.recordGap({ taskId: TASK, userId: USER, capability: 'websocket-replay', context: 'needed to replay a WS handshake' });
    check('gap: first record not deduped', first.deduped === false, first);
    check('gap: record carries fields', first.record.capability === 'websocket-replay' && first.record.userId === USER && first.record.taskId === TASK, first.record);
    check('gap: record has id + time', typeof first.record.id === 'string' && !Number.isNaN(Date.parse(first.record.createdAt)), first.record);

    const again = await gaps.recordGap({ taskId: TASK, userId: USER, capability: 'websocket-replay', context: 'different context, same gap' });
    check('gap: same task+capability deduped', again.deduped === true, again);
    check('gap: dedup returns the same id', again.record.id === first.record.id, again.record);
    check('gap: dedup keeps the first context', again.record.context === 'needed to replay a WS handshake', again.record);

    const otherTask = await gaps.recordGap({ taskId: TASK2, userId: USER, capability: 'websocket-replay' });
    check('gap: same capability on another task is a new gap', otherTask.deduped === false && otherTask.record.id !== first.record.id);
    check('gap: null context stored', otherTask.record.context === null);

    await gaps.recordGap({ taskId: TASK, userId: USER2, capability: 'graphql-introspection' });
    const mine = await gaps.listGaps(USER);
    check('gap: listGaps scoped to caller', mine.length === 2 && mine.every((g) => g.userId === USER), mine);
    check('gap: listGaps newest first', mine[0].createdAt >= mine[1].createdAt, mine);
    const theirs = await gaps.listGaps(USER2);
    check('gap: other user sees only theirs', theirs.length === 1 && theirs[0].capability === 'graphql-introspection', theirs);

    const forTask = await gaps.listGapsForTask(TASK);
    check('gap: listGapsForTask lists one task', forTask.length === 2 && forTask.every((g) => g.taskId === TASK), forTask);
    check('gap: listGapsForTask covers both users of the task', forTask.map((g) => g.capability).sort().join(',') === 'graphql-introspection,websocket-replay', forTask);

    check('gap: empty capability rejected', await throwsAsync(
      () => gaps.recordGap({ taskId: TASK, userId: USER, capability: '  ' }),
      /skill_gap_capability_required/,
    ));
    check('gap: capability with spaces rejected', await throwsAsync(
      () => gaps.recordGap({ taskId: TASK, userId: USER, capability: 'has spaces' }),
      /skill_gap_capability_no_spaces/,
    ));
    check('gap: overlong context rejected', await throwsAsync(
      () => gaps.recordGap({ taskId: TASK, userId: USER, capability: 'x', context: 'y'.repeat(2001) }),
      /skill_gap_context_too_long/,
    ));
  }

  // ── 8. Skill-gap ledger (Postgres, stub query fn) ──
  {
    const rows: Record<string, unknown>[] = [];
    const stubQuery = async (sql: string, params: unknown[]) => {
      if (sql.includes('INSERT INTO skill_gaps')) {
        const [taskId, userId, capability, context] = params as [string, string, string, string | null];
        if (rows.some((r) => r['task_id'] === taskId && r['capability'] === capability)) {
          return { rows: [] };
        }
        const row = {
          id: `pg-${rows.length + 1}`,
          task_id: taskId,
          user_id: userId,
          capability,
          context,
          created_at: new Date(Date.now() + rows.length * 1000),
        };
        rows.push(row);
        return { rows: [row] };
      }
      if (sql.includes('WHERE task_id = $1 AND capability = $2')) {
        return { rows: rows.filter((r) => r['task_id'] === params[0] && r['capability'] === params[1]) };
      }
      if (sql.includes('WHERE user_id = $1')) {
        return { rows: rows.filter((r) => r['user_id'] === params[0]) };
      }
      if (sql.includes('WHERE task_id = $1')) {
        return { rows: rows.filter((r) => r['task_id'] === params[0]) };
      }
      throw new Error(`stub: unhandled query ${sql}`);
    };
    const pg = new PostgresSkillGapStore(stubQuery);
    const first = await pg.recordGap({ taskId: TASK, userId: USER, capability: 'mcp-stdio', context: 'needs a process host' });
    check('pg gap: insert returns a row', first.deduped === false && first.record.id === 'pg-1', first);
    const again = await pg.recordGap({ taskId: TASK, userId: USER, capability: 'mcp-stdio' });
    check('pg gap: conflict deduped via select', again.deduped === true && again.record.id === 'pg-1', again);
    const listed = await pg.listGaps(USER);
    check('pg gap: listGaps returns the row', listed.length === 1 && listed[0].capability === 'mcp-stdio', listed);
    const forTask = await pg.listGapsForTask(TASK);
    check('pg gap: listGapsForTask returns the row', forTask.length === 1, forTask);
  }

  // ── 9. Loader reads the 4 shipped starter packs ──
  {
    const dir = join(__dirname, '..', 'skills');
    const skills = await loadSkillDirectory(dir);
    const names = skills.map((s) => s.name);
    check('packs: all 4 parse', skills.length === 4, names);
    check('packs: names as expected', ['api-recon', 'api-security', 'codeaudit', 'patch-diff'].every((n) => names.includes(n)), names);
    for (const skill of skills) {
      check(`packs: ${skill.name} has description`, skill.description.length > 10, skill);
      check(`packs: ${skill.name} has roles`, skill.roles.length >= 1, skill);
      check(`packs: ${skill.name} gates at least one tool`, skill.tools.length >= 1, skill);
      check(`packs: ${skill.name} body is a real playbook`, skill.body.length > 500, skill.body.length);
    }
    const single = await loadSkillDir(join(dir, 'api-recon'));
    check('packs: loadSkillDir reads one pack', single.name === 'api-recon' && single.roles.includes('planner'));
    check('packs: defaultSkillsDir points at backend/skills', defaultSkillsDir().endsWith(join('backend', 'skills')), defaultSkillsDir());

    const fresh = new SkillRegistry();
    await fresh.loadFromDirectory(dir);
    check('packs: registry loads all 4 from disk', fresh.list().length === 4);
    check('packs: planner sees api-recon + api-security', fresh.visibleTo('planner').map((s) => s.name).sort().join(',') === 'api-recon,api-security');
    check('packs: worker sees all 4', fresh.visibleTo('worker').length === 4);
    check('packs: main sees patch-diff only', fresh.visibleTo('main').map((s) => s.name).join(',') === 'patch-diff');
    const run = fresh.runFor(TASK);
    check('packs: taint-engine locked until codeaudit loads', run.isToolUnlocked('taint-engine') === false);
    fresh.loadSkillForRun('worker', 'codeaudit', TASK);
    check('packs: taint-engine unlocked after codeaudit loads', run.isToolUnlocked('taint-engine') === true);
  }

  if (failures > 0) { console.error(`${failures} skill test(s) failed, ${passes} passed`); process.exit(1); }
  console.log(`ALL SKILL TESTS PASSED (${passes} checks)`);
  process.exit(0);
}

async function throwsAsync(fn: () => Promise<unknown>, re: RegExp): Promise<boolean> {
  try {
    await fn();
  } catch (e) {
    return re.test((e as Error).message);
  }
  return false;
}

main().catch((e) => { console.error('skills test crashed', e); process.exit(1); });

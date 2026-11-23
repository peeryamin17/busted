/**
 * Unit tests for the workspace file manager (src/workspace/files.ts,
 * src/workspace/meta.ts) and its path confinement.
 * No network, no DB, no LLM. Files live in a temp dir used as
 * WORKSPACE_ROOT and removed after the run.
 *
 * Run:  npx tsx test/workspace.test.ts   (from backend/)
 */
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  WorkspaceError,
  WorkspaceFiles,
  guessMime,
  normalizeRelPath,
} from '../src/workspace/files.js';
import { MemoryWorkspaceMetaStore } from '../src/workspace/meta.js';

let failures = 0;
let checks = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  checks++;
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

async function expectCode(
  name: string,
  code: string,
  fn: () => Promise<unknown>,
): Promise<void> {
  try {
    await fn();
    check(name, false, 'did not throw');
  } catch (err) {
    check(
      name,
      err instanceof WorkspaceError && err.code === code,
      err instanceof Error ? `${err.constructor.name}: ${err.message}` : err,
    );
  }
}

const ALICE = 'user-alice';
const BOB = 'user-bob';

async function main() {
  const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'bugseek-workspace-'));
  try {
    const files = new WorkspaceFiles({ root: tmpRoot });
    // Small caps so the quota / per-file tests run without writing 100 MiB.
    // Separate instances: the per-file cap and the quota need different
    // overrides, and both share the same root (so BOB's files accumulate).
    const capped = new WorkspaceFiles({ root: tmpRoot, maxFileBytes: 10, maxUserBytes: 100 });
    const quotaCapped = new WorkspaceFiles({ root: tmpRoot, maxFileBytes: 1000, maxUserBytes: 100 });

    // ── 1. Traversal is rejected, and the error never leaks the host path ──
    {
      const bad = [
        '../escape.txt',
        '/abs/path.txt',
        'a/../../b.txt',
        'a//b.txt',
        'a/./b.txt',
        'a\0b.txt',
        'a\\b.txt',
        '..',
      ];
      for (const p of bad) {
        await expectCode(`traversal: ${JSON.stringify(p)} → forbidden`, 'forbidden', () =>
          files.resolveUserPath(ALICE, p),
        );
      }
      // The message must not contain the temp root (an absolute host path).
      try {
        await files.resolveUserPath(ALICE, '../escape.txt');
        check('traversal: error message hides host path', false, 'did not throw');
      } catch (err) {
        check(
          'traversal: error message hides host path',
          err instanceof WorkspaceError && !err.message.includes(tmpRoot),
          err instanceof Error ? err.message : err,
        );
      }
      // The root itself and a plain nested path resolve fine.
      const root = await files.resolveUserPath(ALICE);
      check('resolve: empty path is the user root', root.endsWith(ALICE), root);
      const nested = await files.resolveUserPath(ALICE, 'reports/scan.md');
      check('resolve: nested path stays inside the root', nested.startsWith(root + path.sep), nested);
      check('resolve: trailing slash tolerated', (await files.resolveUserPath(ALICE, 'reports/')).endsWith('reports'));
    }

    // ── 2. A symlink pointing outside the root is refused ──
    {
      const outside = path.join(tmpRoot, 'outside.txt');
      await fs.writeFile(outside, 'secret');
      const aliceRoot = path.join(tmpRoot, ALICE);
      await fs.mkdir(aliceRoot, { recursive: true });
      await fs.symlink(outside, path.join(aliceRoot, 'link.txt'));
      await expectCode('symlink: read through an escaping link → forbidden', 'forbidden', () =>
        files.readFile(ALICE, 'link.txt'),
      );
      await expectCode('symlink: write through an escaping link → forbidden', 'forbidden', () =>
        files.writeFile(ALICE, 'link.txt', Buffer.from('x')),
      );
      // A symlink to a file inside the root is fine.
      await files.writeFile(ALICE, 'real.txt', Buffer.from('inside'));
      await fs.symlink(path.join(aliceRoot, 'real.txt'), path.join(aliceRoot, 'inner-link.txt'));
      const read = await files.readFile(ALICE, 'inner-link.txt');
      check('symlink: link staying inside the root reads fine', read.buffer.toString() === 'inside', read.buffer.toString());
      // A symlinked parent directory pointing outside is refused too.
      await fs.symlink(tmpRoot, path.join(aliceRoot, 'escape-dir'));
      await expectCode('symlink: parent dir escaping the root → forbidden', 'forbidden', () =>
        files.readFile(ALICE, 'escape-dir/outside.txt'),
      );
    }

    // ── 3. Write + read round-trip, mime guess ──
    {
      const written = await files.writeFile(ALICE, 'notes/hello.txt', Buffer.from('hello workspace'));
      check('write: returns the normalised path', written.path === 'notes/hello.txt', written);
      check('write: returns the size', written.size === 15, written);
      const read = await files.readFile(ALICE, 'notes/hello.txt');
      check('read: round-trips the bytes', read.buffer.toString() === 'hello workspace');
      check('read: mime guessed from extension', read.mime === 'text/plain', read.mime);
      check('read: size matches', read.size === 15);
      check('mime: markdown', guessMime('a.md') === 'text/markdown');
      check('mime: json', guessMime('a.json') === 'application/json');
      check('mime: unknown extension falls back', guessMime('a.xyz') === 'application/octet-stream');
      const usage = await files.usageBytes(ALICE);
      check('usage: counts written bytes', usage >= 15, usage);
      await expectCode('read: missing file → not-found', 'not-found', () =>
        files.readFile(ALICE, 'notes/nope.txt'),
      );
      await expectCode('read: a directory → forbidden', 'forbidden', () =>
        files.readFile(ALICE, 'notes'),
      );
    }

    // ── 4. Per-file cap enforced (small override, no big writes) ──
    {
      await expectCode('cap: 11 bytes over a 10-byte cap → too-large', 'too-large', () =>
        capped.writeFile(BOB, 'big.txt', Buffer.alloc(11, 'x')),
      );
      const ok = await capped.writeFile(BOB, 'small.txt', Buffer.alloc(10, 'x'));
      check('cap: exactly at the cap writes fine', ok.size === 10, ok);
    }

    // ── 5. Quota enforced (small override, no big writes) ──
    {
      // BOB already holds small.txt (10 bytes) under the 100-byte quota.
      const a = await quotaCapped.writeFile(BOB, 'q1.bin', Buffer.alloc(60, 'a'));
      check('quota: first write inside quota', a.size === 60, a);
      await expectCode('quota: write past 100 bytes → quota', 'quota', () =>
        quotaCapped.writeFile(BOB, 'q2.bin', Buffer.alloc(60, 'b')),
      );
      check('quota: usage still under the cap after refusal', (await quotaCapped.usageBytes(BOB)) <= 100);
      // Overwriting with a smaller file frees quota instead of double-counting.
      await quotaCapped.writeFile(BOB, 'q1.bin', Buffer.alloc(5, 'a'));
      check('quota: overwrite shrinks usage', (await quotaCapped.usageBytes(BOB)) === 15, await quotaCapped.usageBytes(BOB));
    }

    // ── 6. List scoping: users cannot see each other ──
    {
      const aliceFiles = await files.listFiles(ALICE);
      const bobFiles = await files.listFiles(BOB);
      check('list: alice sees her own files', aliceFiles.some((f) => f.path === 'notes/hello.txt'), aliceFiles.map((f) => f.path));
      check('list: bob does not see alice’s files', !bobFiles.some((f) => f.path === 'notes/hello.txt'), bobFiles.map((f) => f.path));
      await expectCode('list: bob cannot read alice’s file', 'forbidden', () =>
        files.readFile(BOB, `../${ALICE}/notes/hello.txt`),
      );
      await expectCode('list: cross-user resolve is traversal', 'forbidden', () =>
        files.resolveUserPath(BOB, `../${ALICE}/notes/hello.txt`),
      );
      // Directories first, then alphabetical within each group.
      const listed = await files.listFiles(ALICE);
      const firstFileIdx = listed.findIndex((f) => !f.isDirectory);
      const lastDirIdx = listed.map((f) => f.isDirectory).lastIndexOf(true);
      check('list: directories come before files', firstFileIdx === -1 || lastDirIdx < firstFileIdx, listed);
      check('list: entries carry name/path/size/mtime', listed.every((f) => typeof f.name === 'string' && typeof f.path === 'string' && typeof f.size === 'number' && typeof f.mtime === 'string'));
      const sub = await files.listFiles(ALICE, 'notes');
      check('list: ?dir= scopes to that directory', sub.length === 1 && sub[0].path === 'notes/hello.txt', sub);
      check('list: missing directory lists as empty', (await files.listFiles(ALICE, 'no-such-dir')).length === 0);
    }

    // ── 7. Delete: file, empty dir, non-empty dir refused ──
    {
      await files.writeFile(ALICE, 'doomed/deep.txt', Buffer.from('x'));
      await expectCode('delete: non-empty dir refused', 'forbidden', () =>
        files.deleteFile(ALICE, 'doomed'),
      );
      await files.deleteFile(ALICE, 'doomed/deep.txt');
      await files.deleteFile(ALICE, 'doomed');
      check('delete: empty dir deletes after its contents', (await files.listFiles(ALICE, 'doomed')).length === 0);
      await expectCode('delete: missing file → not-found', 'not-found', () =>
        files.deleteFile(ALICE, 'doomed/deep.txt'),
      );
      await expectCode('delete: refusing the workspace root', 'forbidden', () =>
        files.deleteFile(ALICE, ''),
      );
      check('delete: file gone from listing', !(await files.listFiles(ALICE)).some((f) => f.path === 'doomed/deep.txt'));
    }

    // ── 8. Metadata store round-trip (memory implementation) ──
    {
      const meta = new MemoryWorkspaceMetaStore();
      const TASK = '22222222-2222-2222-2222-222222222222';
      const first = await meta.record({
        userId: ALICE, taskId: TASK, relPath: 'reports/scan.md', sizeBytes: 120, kind: 'report',
      });
      const second = await meta.record({
        userId: ALICE, taskId: null, relPath: 'uploads/code.zip', sizeBytes: 500, kind: 'intake',
      });
      check('meta: record returns an id', typeof first.id === 'string' && first.id.length > 0, first);
      check('meta: record keeps the kind', first.kind === 'report' && second.kind === 'intake');
      const got = await meta.get(first.id);
      check('meta: get returns the row', got?.relPath === 'reports/scan.md', got);
      check('meta: get of unknown id → null', (await meta.get('no-such-id')) === null);
      const recent = await meta.listRecent(ALICE);
      check('meta: recent is newest first', recent[0].id === second.id && recent[1].id === first.id, recent.map((r) => r.relPath));
      check('meta: recent is scoped to the user', (await meta.listRecent(BOB)).length === 0);
      const forTask = await meta.listForTask(TASK);
      check('meta: listForTask returns only that task’s files', forTask.length === 1 && forTask[0].id === first.id, forTask);
      check('meta: removeByPath removes the row', (await meta.removeByPath(ALICE, 'reports/scan.md')) === true);
      check('meta: removed row is gone', (await meta.get(first.id)) === null);
      check('meta: removing again → false', (await meta.removeByPath(ALICE, 'reports/scan.md')) === false);
      let threw = false;
      try {
        await meta.record({ userId: ALICE, relPath: 'x.txt', sizeBytes: 1, kind: 'bogus' as never });
      } catch {
        threw = true;
      }
      check('meta: invalid kind rejected', threw);
    }

    // ── 9. Normalisation helper ──
    {
      check('normalize: strips a trailing slash', normalizeRelPath('a/b/') === 'a/b');
      let threw = false;
      try {
        normalizeRelPath('a/../b');
      } catch {
        threw = true;
      }
      check('normalize: rejects ..', threw);
    }

    if (failures > 0) {
      console.error(`${failures} of ${checks} workspace test(s) failed`);
      process.exit(1);
    }
    console.log(`ALL WORKSPACE TESTS PASSED (${checks} checks)`);
    process.exit(0);
  } finally {
    await fs.rm(tmpRoot, { recursive: true, force: true });
  }
}

main().catch((e) => { console.error('workspace test crashed', e); process.exit(1); });

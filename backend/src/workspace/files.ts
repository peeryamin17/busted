/**
 * Workspace file manager: per-user files on the site (task working files,
 * code-intake uploads, exported reports).
 *
 * Layout: one directory per user under the workspace root. Every operation
 * goes through resolveUserPath, which confines a relative path to that
 * user's root: absolute paths, .. segments, NUL bytes, and empty segments
 * are rejected, and any symlink resolving outside the root is refused.
 *
 * Limits: 10 MiB per file, 100 MiB per user. All failures throw
 * WorkspaceError with a code, never a raw fs error, never a message
 * containing an absolute host path.
 *
 * Files live on the backend host's disk, which is ephemeral on the hosted
 * deployment: a redeploy wipes them. The metadata table survives in
 * Postgres, the bytes may not. Routes answer ephemeral: true. Anything
 * that must survive a redeploy belongs in the database or object storage.
 */
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

/** Per-file cap, matching the code-intake archive limit (10 MB). */
export const MAX_FILE_BYTES = 10 * 1024 * 1024;

/** Per-user quota across everything in that user's workspace. */
export const MAX_USER_BYTES = 100 * 1024 * 1024;

export type WorkspaceErrorCode = 'not-found' | 'forbidden' | 'too-large' | 'quota';

/**
 * The only error type this module throws. `message` carries the
 * relative path only, never an absolute host path.
 */
export class WorkspaceError extends Error {
  readonly code: WorkspaceErrorCode;

  constructor(code: WorkspaceErrorCode, message: string) {
    super(message);
    this.name = 'WorkspaceError';
    this.code = code;
  }
}

export interface WorkspaceFilesOptions {
  /** Defaults to WORKSPACE_ROOT, else `<cwd>/data/workspace`. */
  root?: string;
  /** Per-file cap in bytes (default MAX_FILE_BYTES). */
  maxFileBytes?: number;
  /** Per-user quota in bytes (default MAX_USER_BYTES). */
  maxUserBytes?: number;
}

export function defaultWorkspaceRoot(): string {
  return process.env.WORKSPACE_ROOT ?? path.resolve(process.cwd(), 'data', 'workspace');
}

export interface WorkspaceFileEntry {
  /** File name within its directory. */
  name: string;
  /** POSIX relative path from the user's root, e.g. `reports/scan.md`. */
  path: string;
  /** Bytes; 0 for directories. */
  size: number;
  /** Last-modified time, ISO string. */
  mtime: string;
  isDirectory: boolean;
}

export interface WorkspaceReadResult {
  buffer: Buffer;
  /** MIME type guessed from the extension, else application/octet-stream. */
  mime: string;
  size: number;
}

const MIME_BY_EXT: Record<string, string> = {
  '.txt': 'text/plain',
  '.md': 'text/markdown',
  '.markdown': 'text/markdown',
  '.json': 'application/json',
  '.html': 'text/html',
  '.htm': 'text/html',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.mjs': 'text/javascript',
  '.ts': 'text/plain',
  '.pdf': 'application/pdf',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.zip': 'application/zip',
  '.jar': 'application/java-archive',
  '.csv': 'text/csv',
  '.xml': 'application/xml',
  '.log': 'text/plain',
  '.yaml': 'text/yaml',
  '.yml': 'text/yaml',
};

export function guessMime(relPath: string): string {
  return MIME_BY_EXT[path.extname(relPath).toLowerCase()] ?? 'application/octet-stream';
}

/** Human-readable byte count for error messages (no rounding to 0). */
function formatBytes(n: number): string {
  if (n >= 1024 * 1024) return `${Math.round(n / 1024 / 1024)} MB`;
  if (n >= 1024) return `${Math.round(n / 1024)} KiB`;
  return `${n} bytes`;
}

function assertUserId(userId: string): void {
  if (!userId || typeof userId !== 'string') {
    throw new WorkspaceError('forbidden', 'Missing user id');
  }
  if (
    userId.includes('/') ||
    userId.includes('\\') ||
    userId.includes('\0') ||
    userId === '.' ||
    userId === '..'
  ) {
    throw new WorkspaceError('forbidden', 'Invalid user id');
  }
}

/**
 * Split a user-supplied relative path into segments, rejecting
 * anything that could climb out of the user's root. A single trailing
 * slash is tolerated (`reports/` means `reports`); an empty path
 * means the user's root itself.
 */
function splitRelPath(relPath: string): string[] {
  if (typeof relPath !== 'string') {
    throw new WorkspaceError('forbidden', 'Path must be a string');
  }
  if (relPath.includes('\0')) {
    throw new WorkspaceError('forbidden', 'Path contains a NUL byte');
  }
  if (relPath.includes('\\')) {
    throw new WorkspaceError('forbidden', 'Path must use / separators');
  }
  if (path.isAbsolute(relPath) || relPath.startsWith('/')) {
    throw new WorkspaceError('forbidden', 'Absolute paths are not allowed');
  }
  if (relPath === '') return [];
  const trimmed = relPath.endsWith('/') ? relPath.slice(0, -1) : relPath;
  if (trimmed === '') return [];
  const segments = trimmed.split('/');
  for (const seg of segments) {
    if (seg === '' || seg === '.' || seg === '..') {
      throw new WorkspaceError('forbidden', `Path escapes the workspace: ${relPath}`);
    }
  }
  return segments;
}

/** Normalise a user-supplied relative path to POSIX form, or throw. */
export function normalizeRelPath(relPath: string): string {
  return splitRelPath(relPath).join('/');
}

export class WorkspaceFiles {
  private readonly root: string;
  private readonly maxFileBytes: number;
  private readonly maxUserBytes: number;

  constructor(options: WorkspaceFilesOptions = {}) {
    this.root = path.resolve(options.root ?? defaultWorkspaceRoot());
    this.maxFileBytes = options.maxFileBytes ?? MAX_FILE_BYTES;
    this.maxUserBytes = options.maxUserBytes ?? MAX_USER_BYTES;
  }

  get quotaBytes(): number {
    return this.maxUserBytes;
  }

  get perFileCapBytes(): number {
    return this.maxFileBytes;
  }

  /** Absolute path of one user's root (one path segment, no traversal). */
  userRoot(userId: string): string {
    assertUserId(userId);
    return path.join(this.root, userId);
  }

  /**
   * Resolve a user-supplied relative path to an absolute path inside
   * the user's root, or throw WorkspaceError. Also verifies that no
   * existing component of the path is a symlink escaping the root,
   * a symlink planted in a parent directory cannot smuggle a read or
   * write outside the workspace.
   */
  async resolveUserPath(userId: string, relPath?: string): Promise<string> {
    const userRoot = this.userRoot(userId);
    const segments = splitRelPath(relPath ?? '');
    const abs = path.resolve(userRoot, ...segments);
    // Lexical confinement: the resolved path must be the root itself
    // or live beneath it.
    if (abs !== userRoot && !abs.startsWith(userRoot + path.sep)) {
      throw new WorkspaceError('forbidden', `Path escapes the workspace: ${relPath ?? ''}`);
    }
    await this.assertNoEscape(userRoot, abs);
    return abs;
  }

  /**
   * Walk each existing component of `abs` below the user root; any
   * symlink whose real path leaves the (real) user root is refused.
   * When the root does not exist yet there is nothing on disk that
   * could escape, so the check is a no-op.
   */
  private async assertNoEscape(userRootAbs: string, abs: string): Promise<void> {
    let realRoot: string;
    try {
      realRoot = await fs.realpath(userRootAbs);
    } catch {
      return;
    }
    const rel = path.relative(userRootAbs, abs);
    if (!rel) return;
    let cur = userRootAbs;
    for (const seg of rel.split(path.sep)) {
      cur = path.join(cur, seg);
      let st: Awaited<ReturnType<typeof fs.lstat>>;
      try {
        st = await fs.lstat(cur);
      } catch {
        // Component does not exist yet, nothing deeper can either.
        return;
      }
      if (st.isSymbolicLink()) {
        const real = await fs.realpath(cur);
        if (real !== realRoot && !real.startsWith(realRoot + path.sep)) {
          throw new WorkspaceError(
            'forbidden',
            `Path escapes the workspace: ${path.relative(userRootAbs, abs)}`,
          );
        }
      }
    }
  }

  /** Total bytes stored for one user (0 when the user has no files). */
  async usageBytes(userId: string): Promise<number> {
    const root = this.userRoot(userId);
    const visited = new Set<string>();
    let total = 0;
    const walk = async (dir: string): Promise<void> => {
      let entries;
      try {
        entries = await fs.readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          await walk(full);
        } else if (entry.isFile()) {
          total += (await fs.stat(full).catch(() => null))?.size ?? 0;
        } else if (entry.isSymbolicLink()) {
          // Count a symlink's target only when it stays inside the
          // user's root, and only once (cycle guard).
          const real = await fs.realpath(full).catch(() => null);
          if (!real) continue;
          const realRoot = await fs.realpath(root).catch(() => null);
          if (!realRoot || (real !== realRoot && !real.startsWith(realRoot + path.sep))) continue;
          if (visited.has(real)) continue;
          visited.add(real);
          const st = await fs.stat(real).catch(() => null);
          if (st?.isFile()) total += st.size;
        }
      }
    };
    await walk(root);
    return total;
  }

  /**
   * Recursive listing of a directory (the user's root by default).
   * Directories first, then files, each group alphabetical. A missing
   * directory lists as empty; a path naming a file lists as empty.
   */
  async listFiles(userId: string, dir?: string): Promise<WorkspaceFileEntry[]> {
    const absDir = await this.resolveUserPath(userId, dir);
    const root = this.userRoot(userId);
    let st;
    try {
      st = await fs.stat(absDir);
    } catch {
      return [];
    }
    if (!st.isDirectory()) return [];
    const out: WorkspaceFileEntry[] = [];
    const walk = async (dirAbs: string): Promise<void> => {
      const entries = await fs.readdir(dirAbs, { withFileTypes: true });
      entries.sort((a, b) => {
        if (a.isDirectory() !== b.isDirectory()) return a.isDirectory() ? -1 : 1;
        return a.name.localeCompare(b.name);
      });
      for (const entry of entries) {
        const full = path.join(dirAbs, entry.name);
        const rel = path.relative(root, full).split(path.sep).join('/');
        if (entry.isDirectory()) {
          const dirStat = await fs.stat(full).catch(() => null);
          out.push({
            name: entry.name,
            path: rel,
            size: 0,
            mtime: (dirStat?.mtime ?? new Date(0)).toISOString(),
            isDirectory: true,
          });
          await walk(full);
        } else if (entry.isFile()) {
          const fileStat = await fs.stat(full).catch(() => null);
          if (!fileStat) continue;
          out.push({
            name: entry.name,
            path: rel,
            size: fileStat.size,
            mtime: fileStat.mtime.toISOString(),
            isDirectory: false,
          });
        }
        // Symlinks are not listed: they are never created by this
        // module, and listing a link would invite following it.
      }
    };
    await walk(absDir);
    return out;
  }

  /** Read one file. Throws 'not-found' when missing, 'forbidden' for a directory or an escaping symlink. */
  async readFile(userId: string, relPath: string): Promise<WorkspaceReadResult> {
    const abs = await this.resolveUserPath(userId, relPath);
    let st;
    try {
      st = await fs.stat(abs);
    } catch {
      throw new WorkspaceError('not-found', `File not found: ${normalizeRelPath(relPath)}`);
    }
    if (!st.isFile()) {
      throw new WorkspaceError('forbidden', `Not a file: ${normalizeRelPath(relPath)}`);
    }
    const buffer = await fs.readFile(abs);
    return { buffer, mime: guessMime(relPath), size: buffer.length };
  }

  /**
   * Write (or overwrite) one file, creating parent directories.
   * Enforces the per-file cap and the per-user quota; the write is
   * atomic, content goes to a temp file in the same directory and is
   * renamed into place, so a failed write never leaves a partial file.
   */
  async writeFile(
    userId: string,
    relPath: string,
    buffer: Buffer,
  ): Promise<{ path: string; size: number }> {
    const rel = normalizeRelPath(relPath);
    if (rel === '') {
      throw new WorkspaceError('forbidden', 'A file path is required');
    }
    if (buffer.length > this.maxFileBytes) {
      throw new WorkspaceError(
        'too-large',
        `File exceeds the per-file limit of ${formatBytes(this.maxFileBytes)}`,
      );
    }
    const abs = await this.resolveUserPath(userId, rel);
    await fs.mkdir(path.dirname(abs), { recursive: true });
    const existing = await fs.stat(abs).catch(() => null);
    const usage = await this.usageBytes(userId);
    const after = usage - (existing?.isFile() ? existing.size : 0) + buffer.length;
    if (after > this.maxUserBytes) {
      throw new WorkspaceError(
        'quota',
        `Write would exceed the workspace quota of ${formatBytes(this.maxUserBytes)}`,
      );
    }
    const tmp = path.join(path.dirname(abs), `.tmp-${randomUUID()}`);
    try {
      await fs.writeFile(tmp, buffer);
      await fs.rename(tmp, abs);
    } catch (err) {
      await fs.unlink(tmp).catch(() => undefined);
      if (err instanceof WorkspaceError) throw err;
      throw new WorkspaceError('forbidden', `Could not write file: ${rel}`);
    }
    return { path: rel, size: buffer.length };
  }

  /**
   * Delete a file, or an empty directory. A non-empty directory is
   * refused ('forbidden'), callers delete its contents first, so a
   * single call can never wipe a whole tree by accident.
   */
  async deleteFile(userId: string, relPath: string): Promise<void> {
    const rel = normalizeRelPath(relPath);
    if (rel === '') {
      throw new WorkspaceError('forbidden', 'Refusing to delete the workspace root');
    }
    const abs = await this.resolveUserPath(userId, rel);
    let st;
    try {
      st = await fs.lstat(abs);
    } catch {
      throw new WorkspaceError('not-found', `File not found: ${rel}`);
    }
    if (st.isDirectory()) {
      const children = await fs.readdir(abs);
      if (children.length > 0) {
        throw new WorkspaceError('forbidden', `Directory is not empty: ${rel}`);
      }
      await fs.rmdir(abs);
      return;
    }
    await fs.unlink(abs);
  }
}

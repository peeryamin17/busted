import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseImport, type ImportedFinding } from './importers.js';

/**
 * Bundled open-source engines (Phase 5) — the backend shells out to
 * WhatWeb / Nikto / Nuclei when their binaries exist on the host.
 *
 * Safety contract:
 *  - execFile with FIXED argument arrays — user input only ever lands in
 *    the single target-URL slot, never in a shell string.
 *  - Engines run ONLY from the authorised engines route (Hunter plan +
 *    recorded authorisation), against the one declared target URL.
 *  - Hard timeouts + output caps; Nikto is loud by design (thousands of
 *    checks) so it is bounded with -maxtime and called out in the UI.
 *  - Missing binary = clean { available: false }, never a crash.
 */

export type EngineId = 'whatweb' | 'nikto' | 'nuclei';

export interface EngineStatus {
  engine: EngineId;
  available: boolean;
  detail?: string;
}

const BINARIES: Record<EngineId, string> = {
  whatweb: 'whatweb',
  nikto: 'nikto',
  nuclei: 'nuclei',
};

function extraDirs(): string[] {
  return (process.env['BUGSEEK_ENGINE_PATHS'] ?? '')
    .split(':')
    .map((d) => d.trim())
    .filter(Boolean);
}

async function findBinary(name: string): Promise<string | null> {
  const dirs = [...(process.env['PATH'] ?? '').split(':'), ...extraDirs()];
  for (const dir of dirs) {
    if (!dir) continue;
    const p = path.join(dir, name);
    try {
      await fs.access(p, fs.constants.X_OK);
      return p;
    } catch {
      /* keep looking */
    }
  }
  return null;
}

export async function engineStatus(): Promise<EngineStatus[]> {
  const out: EngineStatus[] = [];
  for (const engine of Object.keys(BINARIES) as EngineId[]) {
    const bin = await findBinary(BINARIES[engine]);
    if (!bin) {
      out.push({ engine, available: false, detail: 'binary not installed on the backend host' });
      continue;
    }
    if (engine === 'nuclei') {
      const tplDir = process.env['NUCLEI_TEMPLATES_DIR'];
      out.push({
        engine,
        available: true,
        detail: tplDir ? `templates: ${tplDir}` : 'uses the default nuclei template path',
      });
    } else {
      out.push({ engine, available: true });
    }
  }
  return out;
}

interface RunSpec {
  timeoutMs: number;
  build: (bin: string, target: string, tmpDir: string) => Promise<{ args: string[]; readOutput: () => Promise<string> }>;
}

const SPECS: Record<EngineId, RunSpec> = {
  whatweb: {
    timeoutMs: 120_000,
    build: async (_bin, target, tmpDir) => {
      const logFile = path.join(tmpDir, 'whatweb.json');
      return {
        args: ['-a', '1', '--color=never', `--log-json=${logFile}`, target],
        readOutput: async () => {
          try {
            return await fs.readFile(logFile, 'utf8');
          } catch {
            return '[]';
          }
        },
      };
    },
  },
  nikto: {
    timeoutMs: 300_000,
    build: async (_bin, target, tmpDir) => {
      // Nikto 2.1.x has no JSON format — XML to a file is its structured
      // output (2.5+ JSON is handled by the same parser downstream).
      const outFile = path.join(tmpDir, 'nikto.xml');
      return {
        args: ['-h', target, '-Format', 'xml', '-output', outFile, '-nointeractive', '-timeout', '8', '-maxtime', '240'],
        readOutput: async () => {
          try {
            return await fs.readFile(outFile, 'utf8');
          } catch {
            return '';
          }
        },
      };
    },
  },
  nuclei: {
    timeoutMs: 300_000,
    build: async (_bin, target) => {
      const args = ['-u', target, '-jsonl', '-silent', '-nc', '-duc', '-timeout', '8', '-retries', '1', '-c', '10'];
      const tpl = process.env['NUCLEI_TEMPLATES_DIR'];
      if (tpl) args.push('-t', tpl);
      return { args, readOutput: async () => '' };
    },
  },
};

export async function runEngine(engine: EngineId, targetUrl: string): Promise<ImportedFinding[]> {
  const bin = await findBinary(BINARIES[engine]);
  if (!bin) throw Object.assign(new Error(`Engine ${engine} is not installed on the backend host`), { statusCode: 503 });

  const spec = SPECS[engine];
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), `bugseek-${engine}-`));
  try {
    const { args, readOutput } = await spec.build(bin, targetUrl, tmpDir);
    const stdout = await new Promise<string>((resolve, reject) => {
      // stdin MUST be 'ignore': nuclei (and friends) read targets from an
      // open stdin pipe and would block forever waiting for input.
      const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
      const chunks: Buffer[] = [];
      let size = 0;
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error(`${engine} timed out after ${Math.round(spec.timeoutMs / 1000)}s`));
      }, spec.timeoutMs);
      child.stdout.on('data', (c: Buffer) => {
        size += c.length;
        if (size > 16 * 1024 * 1024) {
          child.kill('SIGKILL');
          reject(new Error(`${engine} produced too much output`));
          return;
        }
        chunks.push(c);
      });
      child.on('error', (err) => {
        clearTimeout(timer);
        reject(new Error(`${engine} failed to start: ${err.message.slice(0, 200)}`));
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        const out = Buffer.concat(chunks).toString('utf8');
        // Engines exit non-zero when they FIND things — output is what matters.
        if (out) return resolve(out);
        if (code !== 0) return reject(new Error(`${engine} exited with code ${code} and no output`));
        resolve('');
      });
    });
    const fileOutput = await readOutput();
    const raw = fileOutput && fileOutput !== '[]' ? fileOutput : stdout;
    if (!raw.trim()) return [];
    return parseImport(engine === 'whatweb' ? 'whatweb' : engine, raw);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
  }
}

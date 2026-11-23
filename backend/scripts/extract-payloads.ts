/**
 * Extract curated payload packs from the PayloadsAllTheThings archive.
 *
 * Reads the zip directly (never copied into the repo) and writes three
 * kinds of data under backend/data/payloads/:
 *   packs/       small line lists for the depth ladder (capped at 20 KB each)
 *   playbooks/   chunked methodology excerpts for the skills layer
 *   signatures/  deterministic JSON lists (secrets, SCM paths, sinks)
 *
 * Output is deterministic: same zip in, byte-identical files out. Run it
 * again any time with:
 *
 *   npx tsx scripts/extract-payloads.ts [--zip <path>] [--out <dir>]
 *
 * Defaults: zip at ~/workspace/user/files/PayloadsAllTheThings-master.zip
 * (or $PAYLOADS_ZIP), output at backend/data/payloads.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import JSZip from 'jszip';

const ZIP_PREFIX = 'PayloadsAllTheThings-master/';
const LICENSE_LINE = 'MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings)';
const MAX_PACK_BYTES = 20 * 1024;
const PLAYBOOK_CHUNK_LINES = 120;

export interface ExtractOptions {
  zipPath: string;
  outDir: string;
}

interface ManifestEntry {
  id: string;
  kind: 'micro-pack' | 'playbook-chunk' | 'signature' | 'excluded';
  file: string | null;
  source: string;
  sourceSha256: string;
  sourceBytes: number;
  sourceLines: number;
  bytes: number | null;
  lines: number | null;
  budget: { maxRequestsPerEndpoint: number | null; note: string };
  chunkIndex?: number;
  chunkCount?: number;
  excludedReason?: string;
}

interface Manifest {
  generatedBy: string;
  version: 1;
  archive: { file: string; sha256: string; files: number; bytes: number };
  license: string;
  note: string;
  packs: ManifestEntry[];
}

interface MicroPackSpec {
  id: string;
  file: string;
  source: string;
  /** Max ladder requests per endpoint when this pack is used. */
  budget: number;
}

const MICRO_PACKS: MicroPackSpec[] = [
  { id: 'sqli-polyglots', file: 'sqli-polyglots.txt', source: 'SQL Injection/Intruder/SQLi_Polyglots.txt', budget: 10 },
  { id: 'generic-fuzz', file: 'generic-fuzz.txt', source: 'SQL Injection/Intruder/Generic_Fuzz.txt', budget: 10 },
  { id: 'nosql', file: 'nosql.txt', source: 'NoSQL Injection/Intruder/NoSQL.txt', budget: 10 },
  { id: 'crlf-injection', file: 'crlf-injection.txt', source: 'CRLF Injection/Files/crlfinjection.txt', budget: 10 },
  { id: 'ssti-fuzz', file: 'ssti-fuzz.txt', source: 'Server Side Template Injection/Intruder/ssti.fuzz', budget: 25 },
  { id: 'springboot-actuator', file: 'springboot-actuator.txt', source: 'Insecure Management Interface/Intruder/springboot_actuator.txt', budget: 25 },
  { id: 'open-redirect', file: 'open-redirect.txt', source: 'Open Redirect/Intruder/open_redirect_wordlist.txt', budget: 25 },
  { id: 'param-miner-headers', file: 'param-miner-headers.txt', source: 'Web Cache Deception/Intruders/param_miner_lowercase_headers.txt', budget: 50 },
  { id: 'xss-polyglot', file: 'xss-polyglot.md', source: 'XSS Injection/2 - XSS Polyglot.md', budget: 10 },
];

interface PlaybookSpec {
  id: string;
  source: string;
}

const PLAYBOOKS: PlaybookSpec[] = [
  { id: 'jwt', source: 'JSON Web Token/README.md' },
  { id: 'oauth', source: 'OAuth Misconfiguration/README.md' },
  { id: 'graphql', source: 'GraphQL Injection/README.md' },
  { id: 'idor', source: 'Insecure Direct Object References/README.md' },
  { id: 'mass-assignment', source: 'Mass Assignment/README.md' },
  { id: 'business-logic', source: 'Business Logic Errors/README.md' },
  { id: 'cors', source: 'CORS Misconfiguration/README.md' },
  { id: 'prototype-pollution', source: 'Prototype Pollution/README.md' },
  { id: 'dom-clobbering', source: 'DOM Clobbering/README.md' },
  { id: 'client-side-path-traversal', source: 'Client Side Path Traversal/README.md' },
  { id: 'xs-leak', source: 'XS-Leak/README.md' },
  { id: 'xss-csp-bypass', source: 'XSS Injection/4 - CSP Bypass.md' },
  { id: 'xss-angular', source: 'XSS Injection/5 - XSS in Angular.md' },
  { id: 'web-cache-deception', source: 'Web Cache Deception/README.md' },
  { id: 'reverse-proxy', source: 'Reverse Proxy Misconfigurations/README.md' },
  { id: 'request-smuggling', source: 'Request Smuggling/README.md' },
  { id: 'ssrf-cloud-instances', source: 'Server Side Request Forgery/SSRF-Cloud-Instances.md' },
];

const DOTDOTPWN: MicroPackSpec = {
  id: 'dotdotpwn',
  file: 'dotdotpwn.txt',
  source: 'Directory Traversal/Intruder/dotdotpwn.txt',
  budget: 0,
};

interface SinkDoc {
  id: string;
  language: string;
  source: string;
  /** Backticked spans matching this are kept as sinks. */
  keep: RegExp;
  /** Extra entries verified verbatim against the doc. */
  extra: { name: string; kind: string }[];
  /** Split one matched span into the sink names it actually names. */
  normalize?: (span: string) => string[];
}

const SINK_DOCS: SinkDoc[] = [
  {
    id: 'node', language: 'node', source: 'Insecure Deserialization/Node.md',
    keep: /serial|funcster/i, extra: [],
  },
  {
    id: 'java', language: 'java', source: 'Insecure Deserialization/Java.md',
    keep: /serial|yaml|viewstate|xstream|objectmapper|gson|jackson|ysoserial|readobject|xmldecoder|AC ED|rO0|H4sI/i,
    extra: [{ name: 'application/x-java-serialized-object', kind: 'marker' }],
  },
  {
    id: 'php', language: 'php', source: 'Insecure Deserialization/PHP.md',
    keep: /unserial|__wakeup|__unserialize|__destruct|eval|parse_str|create_function|__toString|__get|__set/i,
    extra: [],
  },
  {
    id: 'python', language: 'python', source: 'Insecure Deserialization/Python.md',
    keep: /pickle|yaml\.load|marshal|shelve|__reduce__|eval|exec|dill/i, extra: [],
  },
  {
    id: 'type-juggling', language: 'php', source: 'Type Juggling/README.md',
    // The doc names operators in '== or !=' spans and functions inside
    // example expressions, never as bare backticked names.
    keep: /^(==|===|!=|!==)( or (==|===|!=|!==))*$|strcmp\(|md5\(|sha1\(/,
    extra: [],
    normalize: (span) => {
      if (/^(==|===|!=|!==)( or (==|===|!=|!==))*$/.test(span)) return span.split(' or ');
      const out: string[] = [];
      if (span.includes('strcmp(')) out.push('strcmp()');
      if (span.includes('md5(')) out.push('md5()');
      if (span.includes('sha1(')) out.push('sha1()');
      return out;
    },
  },
];

const SCM_DOCS: { system: string; source: string }[] = [
  { system: 'git', source: 'Insecure Source Code Management/Git.md' },
  { system: 'svn', source: 'Insecure Source Code Management/Subversion.md' },
  { system: 'hg', source: 'Insecure Source Code Management/Mercurial.md' },
  { system: 'bzr', source: 'Insecure Source Code Management/Bazaar.md' },
];

function sha256(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

function splitLines(text: string): string[] {
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
}

/** Line count the way wc -l counts: newlines, not split elements. */
function countLines(text: string): number {
  if (text === '') return 0;
  const parts = splitLines(text);
  return parts[parts.length - 1] === '' ? parts.length - 1 : parts.length;
}

function cleanPackLines(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of splitLines(text)) {
    const line = raw.replace(/[\t ]+$/, '');
    if (line === '') continue;
    if (seen.has(line)) continue;
    seen.add(line);
    out.push(line);
  }
  return out;
}

function writeText(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text, 'utf8');
}

function writeJson(path: string, value: unknown): void {
  writeText(path, `${JSON.stringify(value, null, 2)}\n`);
}

function sinkKind(name: string): string {
  if (/^__/.test(name)) return 'magic-method';
  if (/^[=!<>]=?={0,2}$/.test(name)) return 'operator';
  if (/AC ED|rO0|H4sI|x-java-serialized-object/.test(name)) return 'marker';
  if (/\(\)$/.test(name)) return 'function';
  return 'library';
}

function isShortHexSegment(seg: string): boolean {
  return /^[0-9a-f]{1,8}$/.test(seg) && !['config', 'index', 'logs', 'heads'].includes(seg);
}

/** Cut a matched SCM path at the first short hex fragment (object hash shard). */
function trimScmPath(matched: string): string {
  const parts = matched.split('/').filter((p) => p !== '');
  const cut: string[] = [];
  for (const part of parts) {
    if (isShortHexSegment(part)) break;
    cut.push(part);
  }
  if (cut.length === 0) return matched;
  const leading = matched.startsWith('/') ? '/' : '';
  return leading + cut.join('/');
}

export async function runExtraction(opts: ExtractOptions): Promise<Manifest> {
  const zipBuf = readFileSync(opts.zipPath);
  const zip = await JSZip.loadAsync(zipBuf);
  const entries: ManifestEntry[] = [];

  const mustRead = async (rel: string): Promise<Buffer> => {
    const entry = zip.file(ZIP_PREFIX + rel);
    if (!entry) throw new Error(`missing from archive: ${rel}`);
    return entry.async('nodebuffer');
  };
  const mustReadText = async (rel: string): Promise<string> => {
    const buf = await mustRead(rel);
    return buf.toString('utf8').replace(/^\uFEFF/, '');
  };

  // Fresh output dirs so a re-run never leaves stale packs behind.
  for (const sub of ['packs', 'playbooks', 'signatures']) {
    rmSync(join(opts.outDir, sub), { recursive: true, force: true });
  }
  mkdirSync(opts.outDir, { recursive: true });

  // 1. Micro-packs.
  for (const spec of MICRO_PACKS) {
    const buf = await mustRead(spec.source);
    // Markdown packs ship verbatim (they are docs, not line lists); text
    // packs are deduped and blank-stripped.
    const text = spec.file.endsWith('.md')
      ? `${splitLines(buf.toString('utf8').replace(/^\uFEFF/, '')).join('\n')}\n`
      : `${cleanPackLines(buf.toString('utf8').replace(/^\uFEFF/, '')).join('\n')}\n`;
    const lines = splitLines(text);
    // The trailing newline leaves one empty split element; drop it.
    if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
    const bytes = Buffer.byteLength(text, 'utf8');
    if (bytes > MAX_PACK_BYTES) {
      throw new Error(`pack over cap: ${spec.id} is ${bytes} bytes (cap ${MAX_PACK_BYTES})`);
    }
    writeText(join(opts.outDir, 'packs', spec.file), text);
    entries.push({
      id: spec.id,
      kind: 'micro-pack',
      file: `packs/${spec.file}`,
      source: spec.source,
      sourceSha256: sha256(buf),
      sourceBytes: buf.length,
      sourceLines: splitLines(buf.toString('utf8')).length,
      bytes,
      lines: lines.length,
      budget: {
        maxRequestsPerEndpoint: spec.budget,
        note: `Ladder cap for this pack: at most ${spec.budget} requests per endpoint, routed through pinCheck, approvals and the noise governor.`,
      },
    });
  }

  // dotdotpwn is deliberately not imported: 1.87 MB of traversal variants
  // is a brute-force list, not a micro-pack. Recorded, not shipped.
  {
    const buf = await mustRead(DOTDOTPWN.source);
    entries.push({
      id: DOTDOTPWN.id,
      kind: 'excluded',
      file: null,
      source: DOTDOTPWN.source,
      sourceSha256: sha256(buf),
      sourceBytes: buf.length,
      sourceLines: splitLines(buf.toString('utf8')).length,
      bytes: null,
      lines: null,
      budget: { maxRequestsPerEndpoint: null, note: 'Not imported.' },
      excludedReason: '1.87 MB brute-force wordlist. Importing it wholesale would bloat the repo and turn the ladder into noisy brute-forcing. A small curated traversal subset can be added later if a specialist needs it.',
    });
  }

  // 2. Playbook chunks.
  for (const spec of PLAYBOOKS) {
    const buf = await mustRead(spec.source);
    const text = buf.toString('utf8').replace(/^\uFEFF/, '');
    const lines = splitLines(text);
    const totalChunks = Math.max(1, Math.ceil(lines.length / PLAYBOOK_CHUNK_LINES));
    for (let i = 0; i < totalChunks; i++) {
      const chunkLines = lines.slice(i * PLAYBOOK_CHUNK_LINES, (i + 1) * PLAYBOOK_CHUNK_LINES);
      // Drop trailing blank lines so chunks end on content.
      while (chunkLines.length > 0 && chunkLines[chunkLines.length - 1].trim() === '') chunkLines.pop();
      const header = `<!-- source: ${spec.source} | chunk ${i + 1}/${totalChunks} | ${LICENSE_LINE} -->`;
      const body = `${header}\n\n${chunkLines.join('\n')}\n`;
      const file = `${spec.id}-${String(i + 1).padStart(2, '0')}.md`;
      writeText(join(opts.outDir, 'playbooks', file), body);
      entries.push({
        id: `${spec.id}-chunk-${i + 1}`,
        kind: 'playbook-chunk',
        file: `playbooks/${file}`,
        source: spec.source,
        sourceSha256: sha256(buf),
        sourceBytes: buf.length,
        sourceLines: lines.length,
        bytes: Buffer.byteLength(body, 'utf8'),
        lines: chunkLines.length,
        budget: { maxRequestsPerEndpoint: null, note: 'Retrieval only — playbook text for the skills layer, never a live request.' },
        chunkIndex: i + 1,
        chunkCount: totalChunks,
      });
    }
  }

  // 3a. Secret signatures.
  const machineKeysBuf = await mustRead('API Key Leaks/Files/MachineKeys.txt');
  const machineKeysText = machineKeysBuf.toString('utf8');
  // Length classes only — the key values themselves are never stored.
  // A length counts as common when it covers at least 1% of rows; the
  // handful of truncated rows (4, 19, 34 chars, ...) are outliers.
  const keyLenCounts = { validation: new Map<number, number>(), decryption: new Map<number, number>() };
  let machineKeyRows = 0;
  for (const line of splitLines(machineKeysText)) {
    if (line.trim() === '') continue;
    const parts = line.split(',');
    if (parts.length < 2) continue;
    const [v, d] = parts;
    if (!/^[0-9A-Fa-f]+$/.test(v) || !/^[0-9A-Fa-f]+$/.test(d)) continue;
    machineKeyRows++;
    keyLenCounts.validation.set(v.length, (keyLenCounts.validation.get(v.length) ?? 0) + 1);
    keyLenCounts.decryption.set(d.length, (keyLenCounts.decryption.get(d.length) ?? 0) + 1);
  }
  const commonLengths = (counts: Map<number, number>): { lengths: number[]; outliers: number } => {
    const lengths: number[] = [];
    let outliers = 0;
    for (const [len, n] of [...counts.entries()].sort((a, b) => a[0] - b[0])) {
      if (n >= machineKeyRows / 100) lengths.push(len);
      else outliers += n;
    }
    return { lengths, outliers };
  };
  const validationCommon = commonLengths(keyLenCounts.validation);
  const decryptionCommon = commonLengths(keyLenCounts.decryption);
  if (validationCommon.lengths.length === 0 || decryptionCommon.lengths.length === 0) {
    throw new Error('no common MachineKeys lengths found; the file shape may have changed');
  }
  const hexRange = (lengths: number[]): string => {
    const lo = Math.min(...lengths);
    const hi = Math.max(...lengths);
    return lo === hi ? `${lo}` : `${lo},${hi}`;
  };
  const secrets = {
    note: 'Detection patterns only. No key material from the archive is stored here — MachineKeys.txt values were measured for length classes and then discarded.',
    machineKey: {
      source: 'API Key Leaks/IIS-Machine-Keys.md',
      configFiles: ['web.config', 'machine.config'],
      attributePatterns: [
        { id: 'machinekey-validationkey', pattern: `validationKey\\s*=\\s*"[0-9A-Fa-f]{${hexRange(validationCommon.lengths)}}"`, description: 'ASP.NET validationKey attribute holding a hex key' },
        { id: 'machinekey-decryptionkey', pattern: `decryptionKey\\s*=\\s*"[0-9A-Fa-f]{${hexRange(decryptionCommon.lengths)}}"`, description: 'ASP.NET decryptionKey attribute holding a hex key' },
        { id: 'machinekey-element', pattern: '<machineKey[^>]*validationKey\\s*=\\s*"[^"]+"[^>]*decryptionKey\\s*=\\s*"[^"]+"', description: 'A machineKey element carrying both keys' },
      ],
      observedHexLengths: {
        validationKey: { commonLengths: validationCommon.lengths, outlierRows: validationCommon.outliers },
        decryptionKey: { commonLengths: decryptionCommon.lengths, outlierRows: decryptionCommon.outliers },
        rowsMeasured: machineKeyRows,
        source: 'API Key Leaks/Files/MachineKeys.txt',
      },
    },
    hardcodedAssignment: {
      source: 'API Key Leaks/README.md',
      note: 'Generic shapes for the hardcoded-key cause described in the methodology section.',
      patterns: [
        { id: 'hardcoded-api-key', pattern: '\\b(api[_-]?key|apikey)\\s*[:=]\\s*[\'"][^\'"]{8,}[\'"]', flags: 'i', description: 'An API key assigned inline in source' },
        { id: 'hardcoded-secret', pattern: '\\b(client[_-]?secret|secret[_-]?key)\\s*[:=]\\s*[\'"][^\'"]{8,}[\'"]', flags: 'i', description: 'A client secret assigned inline in source' },
      ],
    },
  };
  for (const p of [...secrets.machineKey.attributePatterns, ...secrets.hardcodedAssignment.patterns]) {
    new RegExp(p.pattern, 'flags' in p ? (p as { flags: string }).flags : undefined);
  }
  writeJson(join(opts.outDir, 'signatures', 'secrets.json'), secrets);

  // 3b. SCM / config exposure paths.
  const scmPaths: { path: string; system: string; source: string; verbatim: boolean; note?: string }[] = [];
  const seenScm = new Set<string>();
  const addScm = (path: string, system: string, source: string, verbatim: boolean, note?: string): void => {
    const key = `${system}:${path}`;
    if (seenScm.has(key)) return;
    seenScm.add(key);
    scmPaths.push({ path, system, source, verbatim, ...(note ? { note } : {}) });
  };
  const scmRe = /(?:^|[\s"'`(])(\.(?:git|svn|hg|bzr)(?:\/[A-Za-z0-9._~%+\-]+)*)|(\/(?:\.git|\.svn|\.hg|\.bzr)(?:\/[A-Za-z0-9._~%+\-]+)*)/g;
  for (const doc of SCM_DOCS) {
    const text = await mustReadText(doc.source);
    for (const m of text.matchAll(scmRe)) {
      let p = (m[1] ?? m[2]).replace(/[.,;:)"']+$/, '').replace(/\/+$/, '');
      p = trimScmPath(p);
      if (p === '' || p === '.' || p === '/') continue;
      // Normalise the VCS dir to lowercase (.SVN in prose is the .svn dir).
      p = p.replace(/^\/?\.(git|svn|hg|bzr)/i, (seg) => seg.toLowerCase());
      addScm(p, doc.system, doc.source, true);
      // A probe usually wants the directory too, not just the example file.
      const lastSlash = p.lastIndexOf('/');
      if (lastSlash > 0 && p.slice(lastSlash + 1).includes('.')) {
        addScm(p.slice(0, lastSlash), doc.system, doc.source, true);
      }
    }
  }
  // Bazaar: the doc's bzr_dumper output lists the paths it fetches; they
  // live under .bzr/ on an exposed repo. Mercurial: the doc names no path,
  // only the rip-hg.pl tool, so only the bare directory is recorded.
  {
    const bzrText = await mustReadText('Insecure Source Code Management/Bazaar.md');
    for (const m of bzrText.matchAll(/\[\+\] GET (\S+)/g)) {
      const target = m[1];
      // Skip the bytes-literal revision hash, not a path.
      if (target.startsWith("b'") || /^[0-9a-f]{32,}$/.test(target)) continue;
      addScm(`.bzr/${target}`, 'bzr', 'Insecure Source Code Management/Bazaar.md', false, 'Path fetched by bzr_dumper in the doc; served under .bzr/ on an exposed repo.');
    }
    addScm('.hg', 'hg', 'Insecure Source Code Management/Mercurial.md', false, 'No probe path is stated in the doc; .hg is the directory its rip-hg.pl tool targets.');
    addScm('.bzr', 'bzr', 'Insecure Source Code Management/Bazaar.md', false, 'Bare repo directory; the doc only shows paths fetched beneath it.');
    addScm('.svn', 'svn', 'Insecure Source Code Management/Subversion.md', false, 'Bare repo directory; the doc shows files beneath it.');
  }
  scmPaths.sort((a, b) => (a.system < b.system ? -1 : a.system > b.system ? 1 : a.path < b.path ? -1 : 1));
  writeJson(join(opts.outDir, 'signatures', 'scm-exposure.json'), {
    note: 'URL paths to probe for exposed version-control metadata. verbatim paths appear word-for-word in the source doc; derived ones are marked and explained.',
    paths: scmPaths,
  });

  // 3c. Deserialization / type-juggling sinks.
  const sinkEntries: { name: string; kind: string; language: string; source: string }[] = [];
  const seenSink = new Set<string>();
  for (const doc of SINK_DOCS) {
    const text = await mustReadText(doc.source);
    for (const m of text.matchAll(/`([^`\n]{1,80})`/g)) {
      const span = m[1].trim();
      if (span === '' || /https?:|www\./.test(span)) continue;
      if (/^(import|from)\s/.test(span)) continue;
      if (!doc.keep.test(span)) continue;
      const names = doc.normalize ? doc.normalize(span) : [span];
      for (const name of names) {
        const key = `${doc.language}:${name}`;
        if (seenSink.has(key)) continue;
        seenSink.add(key);
        sinkEntries.push({ name, kind: sinkKind(name), language: doc.language, source: doc.source });
      }
    }
    for (const extra of doc.extra) {
      if (!text.includes(extra.name)) throw new Error(`curated sink not found verbatim in ${doc.source}: ${extra.name}`);
      const key = `${doc.language}:${extra.name}`;
      if (seenSink.has(key)) continue;
      seenSink.add(key);
      sinkEntries.push({ name: extra.name, kind: extra.kind, language: doc.language, source: doc.source });
    }
    if (!sinkEntries.some((s) => s.source === doc.source)) {
      throw new Error(`no sinks extracted from ${doc.source}; the keep pattern may be stale`);
    }
  }
  // A short marker that is a substring of a longer marker from the same
  // doc (AC ED inside "AC ED 00 05") is the same signal twice; keep the long one.
  const deduped = sinkEntries.filter((s) => {
    if (s.kind !== 'marker') return true;
    return !sinkEntries.some(
      (o) => o !== s && o.kind === 'marker' && o.source === s.source && o.name.length > s.name.length && o.name.includes(s.name),
    );
  });
  deduped.sort((a, b) => (a.language < b.language ? -1 : a.language > b.language ? 1 : a.name < b.name ? -1 : 1));
  writeJson(join(opts.outDir, 'signatures', 'deserialization-sinks.json'), {
    note: 'Unsafe deserialization sinks and loose-comparison operators named in the source docs. Data only — the static analyzer wires these in later.',
    sinks: deduped,
  });

  // Manifest entries for the three signature files.
  const sigSources: { id: string; file: string; sources: string[] }[] = [
    { id: 'secrets', file: 'signatures/secrets.json', sources: ['API Key Leaks/README.md', 'API Key Leaks/IIS-Machine-Keys.md', 'API Key Leaks/Files/MachineKeys.txt'] },
    { id: 'scm-exposure', file: 'signatures/scm-exposure.json', sources: ['Insecure Source Code Management/Git.md', 'Insecure Source Code Management/Subversion.md', 'Insecure Source Code Management/Mercurial.md', 'Insecure Source Code Management/Bazaar.md'] },
    { id: 'deserialization-sinks', file: 'signatures/deserialization-sinks.json', sources: SINK_DOCS.map((d) => d.source) },
  ];
  for (const sig of sigSources) {
    const first = await mustRead(sig.sources[0]);
    const text = readFileSync(join(opts.outDir, sig.file), 'utf8');
    entries.push({
      id: sig.id,
      kind: 'signature',
      file: sig.file,
      source: sig.sources.join(', '),
      sourceSha256: sha256(first),
      sourceBytes: first.length,
      sourceLines: splitLines(first.toString('utf8')).length,
      bytes: Buffer.byteLength(text, 'utf8'),
      lines: countLines(text),
      budget: { maxRequestsPerEndpoint: null, note: 'Deterministic check — no live requests. The scanner reads this data, it never fetches with it.' },
    });
  }
  entries.sort((a, b) => (a.id < b.id ? -1 : 1));

  const fileEntries = Object.values(zip.files).filter((f) => !f.dir);
  const manifest: Manifest = {
    generatedBy: 'scripts/extract-payloads.ts',
    version: 1,
    archive: {
      file: 'PayloadsAllTheThings-master.zip',
      sha256: sha256(zipBuf),
      files: fileEntries.length,
      bytes: zipBuf.length,
    },
    license: LICENSE_LINE,
    note: 'Curated subsets of the archive, not the full archive. Regenerate with: npx tsx scripts/extract-payloads.ts',
    packs: entries,
  };
  writeJson(join(opts.outDir, 'manifest.json'), manifest);

  writeText(join(opts.outDir, 'NOTICE.md'), [
    '# Payloads notices',
    '',
    'Curated subsets of PayloadsAllTheThings, used under its MIT license:',
    '',
    'MIT License — Copyright (c) 2019 Swissky',
    '',
    'Permission is hereby granted, free of charge, to any person obtaining a copy',
    'of this software and associated documentation files (the "Software"), to deal',
    'in the Software without restriction, including without limitation the rights',
    'to use, copy, modify, merge, publish, distribute, sublicense, and/or sell',
    'copies of the Software, and to permit persons to whom the Software is',
    'furnished to do so, subject to the inclusion of this copyright notice.',
    '',
    'These packs are curated subsets, not the full archive. The 1.87 MB',
    'dotdotpwn.txt wordlist was deliberately left out (see manifest.json).',
    'No key material from the archive is stored here: MachineKeys.txt values',
    'were measured for length classes only and then discarded.',
    '',
    `Source archive: PayloadsAllTheThings-master.zip (sha256 ${manifest.archive.sha256}).`,
    `Regenerate with: npx tsx scripts/extract-payloads.ts`,
    '',
  ].join('\n'));

  return manifest;
}

function defaultZipPath(): string {
  if (process.env.PAYLOADS_ZIP) return resolve(process.env.PAYLOADS_ZIP);
  return join(homedir(), 'workspace', 'user', 'files', 'PayloadsAllTheThings-master.zip');
}

function parseArgs(argv: string[]): ExtractOptions {
  const opts: ExtractOptions = {
    zipPath: defaultZipPath(),
    outDir: resolve(__dirname, '..', 'data', 'payloads'),
  };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--zip' && argv[i + 1]) opts.zipPath = resolve(argv[++i]);
    else if (argv[i] === '--out' && argv[i + 1]) opts.outDir = resolve(argv[++i]);
    else throw new Error(`unknown argument: ${argv[i]} (usage: extract-payloads.ts [--zip <path>] [--out <dir>])`);
  }
  if (!existsSync(opts.zipPath)) throw new Error(`zip not found: ${opts.zipPath}`);
  return opts;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const manifest = await runExtraction(opts);
  const packs = manifest.packs.filter((p) => p.kind !== 'excluded');
  const totalBytes = packs.reduce((n, p) => n + (p.bytes ?? 0), 0);
  console.log(`extracted ${packs.length} packs (${manifest.packs.filter((p) => p.kind === 'excluded').length} excluded) from ${manifest.archive.files} files in the archive`);
  console.log(`total output: ${totalBytes} bytes in ${opts.outDir}`);
  for (const p of packs) {
    console.log(`  ${p.id}: ${p.file} (${p.bytes} bytes, ${p.lines} lines)`);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('extract-payloads failed:', err instanceof Error ? err.message : err);
    process.exit(1);
  });
}

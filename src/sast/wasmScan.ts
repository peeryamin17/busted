/**
 * WebAssembly scan, lighter version (white-box, client-side).
 *
 * Finds `.wasm` modules the page loaded (resource-timing entries from
 * the content script) and fetches the same-origin ones, size-capped.
 * Validates the `\0asm` magic bytes, lists exports via
 * `WebAssembly.Module.exports()` on the fetched bytes, and scans the
 * module's embedded strings for secret patterns and URLs (same
 * patterns as the JS secret scanner).
 *
 * Limits, stated wherever results surface: no decompilation, no
 * function-body analysis, export names and embedded strings are the
 * whole signal. No execution, modules are compiled with
 * `new WebAssembly.Module` (validation only) and never instantiated.
 * No detection of WASM embedded as base64 inside JS, or loaded from
 * cross-origin URLs the extension cannot fetch (listed, not fetched).
 */
import { SECRET_PATTERNS, isPlaceholder, redactSecret } from '../lib/regexes';
import type { Finding } from '../lib/types';

export interface WasmModuleReport {
  url: string;
  sizeBytes: number;
  exports: string[];
  suspiciousStrings: Array<{ kind: string; sample: string }>;
  /** Why the module was not analysed, when applicable. */
  skippedReason?: string;
}

const MAX_MODULES = 3;
const MAX_MODULE_BYTES = 5 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 8000;
const MAX_SECRET_MATCHES = 5;
const WASM_MAGIC = [0x00, 0x61, 0x73, 0x6d]; // \0asm

let findingSeq = 0;

function hasWasmMagic(bytes: Uint8Array): boolean {
  return WASM_MAGIC.every((b, i) => bytes[i] === b);
}

/** Printable ASCII runs (>= 6 chars) out of raw bytes, the string table. */
function extractStrings(bytes: Uint8Array): string[] {
  const out: string[] = [];
  let run = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b >= 0x20 && b <= 0x7e) {
      run += String.fromCharCode(b);
    } else {
      if (run.length >= 6) out.push(run);
      run = '';
    }
  }
  if (run.length >= 6) out.push(run);
  return out;
}

async function fetchModule(url: string, pageOrigin: string): Promise<WasmModuleReport> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { url, sizeBytes: 0, exports: [], suspiciousStrings: [], skippedReason: 'unparseable URL' };
  }
  if (parsed.origin !== pageOrigin) {
    return { url, sizeBytes: 0, exports: [], suspiciousStrings: [], skippedReason: 'cross-origin — not fetched' };
  }
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    let res: Response;
    try {
      res = await fetch(url, { signal: ctrl.signal });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) {
      return { url, sizeBytes: 0, exports: [], suspiciousStrings: [], skippedReason: `HTTP ${res.status}` };
    }
    const buf = await res.arrayBuffer();
    if (buf.byteLength > MAX_MODULE_BYTES) {
      return { url, sizeBytes: buf.byteLength, exports: [], suspiciousStrings: [], skippedReason: 'exceeds 5 MB cap' };
    }
    const bytes = new Uint8Array(buf);
    if (!hasWasmMagic(bytes)) {
      return { url, sizeBytes: buf.byteLength, exports: [], suspiciousStrings: [], skippedReason: 'not a WASM module (bad magic bytes)' };
    }

    // Validation-only compile: lists exports without running any code.
    let exports: string[] = [];
    try {
      const mod = new WebAssembly.Module(buf);
      exports = WebAssembly.Module.exports(mod).map((e) => `${e.kind}:${e.name}`);
    } catch {
      return { url, sizeBytes: buf.byteLength, exports: [], suspiciousStrings: [], skippedReason: 'failed WebAssembly validation' };
    }

    const suspiciousStrings: WasmModuleReport['suspiciousStrings'] = [];
    const corpus = extractStrings(bytes).join('\n');
    for (const pattern of SECRET_PATTERNS) {
      const flags = pattern.regex.flags.includes('g')
        ? pattern.regex.flags
        : pattern.regex.flags + 'g';
      const re = new RegExp(pattern.regex.source, flags);
      let match: RegExpExecArray | null;
      let reported = 0;
      while ((match = re.exec(corpus)) !== null && reported < MAX_SECRET_MATCHES) {
        if (match.index === re.lastIndex) re.lastIndex++;
        if (isPlaceholder(match[0])) continue;
        reported++;
        suspiciousStrings.push({ kind: pattern.name, sample: redactSecret(match[0]) });
      }
    }
    // Embedded URLs (endpoints, exfil targets) are worth surfacing.
    for (const m of corpus.matchAll(/https?:\/\/[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{6,120}/g)) {
      if (suspiciousStrings.length >= MAX_SECRET_MATCHES + 5) break;
      suspiciousStrings.push({ kind: 'embedded URL', sample: m[0].slice(0, 120) });
    }

    return { url, sizeBytes: buf.byteLength, exports, suspiciousStrings };
  } catch {
    return { url, sizeBytes: 0, exports: [], suspiciousStrings: [], skippedReason: 'fetch failed' };
  }
}

/**
 * Scan the page's WASM modules (same-origin fetch, validation only).
 * Returns one inventory finding per analysed module plus secret findings.
 */
export async function scanWasmModules(
  wasmUrls: string[],
  pageUrl: string,
): Promise<{ findings: Finding[]; reports: WasmModuleReport[] }> {
  const findings: Finding[] = [];
  const pageOrigin = new URL(pageUrl).origin;
  const targets = [...new Set(wasmUrls)].slice(0, MAX_MODULES);
  const reports: WasmModuleReport[] = [];
  for (const url of targets) {
    reports.push(await fetchModule(url, pageOrigin));
  }

  for (const report of reports) {
    if (report.skippedReason) {
      findings.push({
        id: `wasm-skipped-${findingSeq++}`,
        category: 'whitebox',
        title: 'WebAssembly module detected but not analysed',
        description:
          `A WebAssembly module was loaded from ${report.url} but was not analysed: ${report.skippedReason}. ` +
          `Only same-origin modules under 5 MB are fetched, and modules are never executed — only validated for exports and scanned for embedded strings.`,
        severity: 'info',
        confidence: 'high',
        location: report.url,
        evidence: report.skippedReason,
        remediation: 'If the module is first-party, review its exports and embedded strings manually; WASM function bodies are outside this scan.',
      });
      continue;
    }
    findings.push({
      id: `wasm-${findingSeq++}`,
      category: 'whitebox',
      title: `WebAssembly module inventoried (${report.exports.length} export${report.exports.length === 1 ? '' : 's'})`,
      description:
        `A WebAssembly module (${Math.round(report.sizeBytes / 1024)} KB) was loaded from ${report.url}. ` +
        `Exports: ${report.exports.slice(0, 10).join(', ') || 'none'}${report.exports.length > 10 ? ` (+${report.exports.length - 10} more)` : ''}. ` +
        `This scan lists export names and embedded strings only — it does not decompile or analyse WASM function bodies, and the module was never executed.`,
      severity: 'info',
      confidence: 'high',
      location: report.url,
      evidence: `exports: ${report.exports.slice(0, 10).join(', ') || 'none'}`,
      remediation: 'Review exported function names for sensitive operations (crypto, network, storage). For full assurance, decompile the module with wasm2wat / Ghidra and review function bodies.',
    });
    for (const s of report.suspiciousStrings) {
      const isSecret = s.kind !== 'embedded URL';
      findings.push({
        id: `wasm-secret-${findingSeq++}`,
        category: isSecret ? 'secrets' : 'whitebox',
        title: isSecret
          ? `${s.kind} embedded in WebAssembly module`
          : 'URL embedded in WebAssembly module',
        description: isSecret
          ? `A ${s.kind} was found in the embedded strings of the WebAssembly module at ${report.url}. Secrets compiled into WASM are still extractable — anyone can download the module and read its strings.`
          : `The WebAssembly module at ${report.url} embeds the URL ${s.sample}. Check whether the module contacts this endpoint and what data it sends — WASM network calls bypass the page's JS-visible fetch surface.`,
        severity: isSecret ? 'high' : 'info',
        confidence: 'medium',
        location: report.url,
        evidence: s.sample,
        remediation: isSecret
          ? 'Rotate the credential and remove it from the module. Load secrets at runtime from a secure backend, never compile them in.'
          : 'Verify the endpoint is expected and that any data sent to it is authorized and minimal.',
      });
    }
  }

  return { findings, reports };
}

/**
 * Code-intake analyser — static analysis of user-uploaded code archives.
 *
 * Two modes, both purely static (nothing is executed, compiled, or run):
 *
 *  - ZIP (repo): walk source files (JS/TS/Java/Python/PHP/Go/Ruby/Rust/C#),
 *    run well-known secret patterns plus dangerous-API-use detection.
 *  - JAR/WAR (Java bytecode): unzip and scan `.class` files' CONSTANT
 *    POOLS — the raw UTF-8 strings embedded in the class file — for
 *    secrets, hardcoded credentials, JDBC URLs and dangerous API references
 *    (Runtime.exec, reflection, deserialization). This is a CONSTANT-POOL
 *    STRING SCAN, NOT DECOMPILATION: method bodies are never reconstructed,
 *    control flow is never followed, and a referenced API is not proof it
 *    is called with attacker-controlled data.
 *
 * Limits (zip-bomb / resource guards): 10 MB archive, 2,000 entries,
 * 2 MB per file, 20 MB total scanned text. Everything runs in memory —
 * nothing is written to disk, so there is no temp dir to clean up.
 *
 * No backend secret-detection patterns existed to reuse (guardrails/
 * redact.ts only redacts); the patterns here mirror the extension's
 * well-known-format approach from src/lib/regexes.ts.
 */
import JSZip from 'jszip';
import { redactText } from '../guardrails/redact.js';
import type { Confidence, Severity } from '../types.js';

export interface CodeIntakeFinding {
  category: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  location?: string;
  evidence?: string;
  remediation: string;
  references: string[];
}

export interface CodeIntakeResult {
  kind: 'zip' | 'jar';
  /** Method note surfaced in reports so the limits are never hidden. */
  method: string;
  filesScanned: number;
  entriesSkipped: number;
  findings: CodeIntakeFinding[];
  warnings: string[];
}

export const MAX_ARCHIVE_BYTES = 10 * 1024 * 1024;
const MAX_ENTRIES = 2000;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_SCANNED_BYTES = 20 * 1024 * 1024;
const MAX_FINDINGS_PER_PATTERN = 5;

const ZIP_METHOD =
  'Static regex scan of uploaded source files (well-known secret formats + dangerous-API-use patterns). No execution, no dependency resolution.';
const JAR_METHOD =
  'Constant-pool string scan of .class files plus text scan of embedded resources — NOT decompilation. ' +
  'Method bodies and control flow are not reconstructed; a referenced API is not proof it is called with attacker-controlled data.';

const SOURCE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
  '.java', '.py', '.php', '.go', '.rb', '.rs', '.cs', '.kt',
]);
// Config / resource files scanned for secrets only (no API patterns).
const SECRET_ONLY_EXTENSIONS = new Set([
  '.properties', '.env', '.yml', '.yaml', '.json', '.xml', '.toml', '.ini', '.cfg', '.conf',
]);

interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: Severity;
  description: string;
  remediation: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'aws-access-key',
    name: 'AWS access key ID',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'critical',
    description: 'A hardcoded AWS access key ID was found in uploaded code.',
    remediation: 'Rotate the key in IAM and remove it from source. Issue credentials from a secrets manager or the deployment environment instead.',
  },
  {
    id: 'aws-secret-key',
    name: 'AWS secret access key assignment',
    regex: /aws[_-]?secret[_-]?access[_-]?key["'\s:=]+[A-Za-z0-9/+=]{30,}/gi,
    severity: 'critical',
    description: 'An AWS secret access key appears to be assigned in uploaded code.',
    remediation: 'Rotate the key immediately and remove it from source. Never commit secret keys.',
  },
  {
    id: 'stripe-live-key',
    name: 'Stripe live secret key',
    regex: /\b[rs]k_live_[0-9A-Za-z]{16,}\b/g,
    severity: 'critical',
    description: 'A Stripe LIVE secret key was found in uploaded code.',
    remediation: 'Roll the key in the Stripe dashboard. Secret keys must only ever live server-side.',
  },
  {
    id: 'github-token',
    name: 'GitHub token',
    regex: /\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
    severity: 'critical',
    description: 'A GitHub personal access token was found in uploaded code.',
    remediation: 'Revoke the token on GitHub and remove it from source. Use scoped, short-lived tokens from a secrets manager.',
  },
  {
    id: 'google-api-key',
    name: 'Google API key',
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    severity: 'high',
    description: 'A Google Cloud API key was found in uploaded code.',
    remediation: 'Restrict the key (API restrictions / referrer restrictions) in Google Cloud Console, rotate it, and proxy sensitive calls through a backend.',
  },
  {
    id: 'slack-token',
    name: 'Slack token',
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    severity: 'high',
    description: 'A Slack token was found in uploaded code.',
    remediation: 'Revoke the token in the Slack admin console and remove it from source.',
  },
  {
    id: 'private-key',
    name: 'Private key material',
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'Private key material was found in uploaded code.',
    remediation: 'Treat the key as compromised: revoke/replace it everywhere it was used and remove it from source.',
  },
  {
    id: 'jdbc-url-with-credentials',
    name: 'JDBC URL with embedded credentials',
    regex: /jdbc:[a-z]+:\/\/[^\s"';&]*[?&](user|password)=[^\s"'&;]+/gi,
    severity: 'high',
    description: 'A JDBC connection URL with embedded credentials was found.',
    remediation: 'Move database credentials out of source into environment variables or a secrets manager; connect with credentials supplied at runtime.',
  },
  {
    id: 'generic-credential-assignment',
    name: 'Hardcoded credential assignment',
    regex: /(password|passwd|pwd|client[_-]?secret|api[_-]?key)\s*[:=]\s*["'][^"'\s]{8,}["']/gi,
    severity: 'high',
    description: 'A credential appears to be hardcoded in an assignment.',
    remediation: 'Remove the hardcoded value and load it from the environment or a secrets manager. Rotate it if it was ever committed.',
  },
];

interface DangerousApiPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: Severity;
  confidence: Confidence;
  description: string;
  remediation: string;
}

/** Per-language dangerous-API patterns (regex over source text). */
const DANGEROUS_API_PATTERNS: Array<DangerousApiPattern & { exts: string[] }> = [
  {
    id: 'java-runtime-exec', name: 'Runtime.exec / ProcessBuilder',
    regex: /\b(Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder\s*\()/g,
    severity: 'high', confidence: 'medium', exts: ['.java', '.kt'],
    description: 'Code invokes an OS command (Runtime.exec / ProcessBuilder). If any argument derives from untrusted input this is command injection.',
    remediation: 'Avoid shelling out. If unavoidable, use a fixed allow-list of commands and pass arguments as an array — never build a command string from input.',
  },
  {
    id: 'java-deserialization', name: 'Java deserialization (readObject)',
    regex: /\b(readObject\s*\(|new\s+ObjectInputStream\s*\()/g,
    severity: 'high', confidence: 'medium', exts: ['.java', '.kt'],
    description: 'Code deserializes Java objects. Deserializing untrusted bytes is a classic remote-code-execution vector.',
    remediation: 'Do not deserialize untrusted data. Use a safe format (JSON with a vetted parser) or an allow-list ObjectInputStream filter (JEP 290).',
  },
  {
    id: 'java-reflection', name: 'Java reflection (Class.forName / getMethod / invoke)',
    regex: /\b(Class\.forName|getDeclaredMethod|getMethod\s*\(.*\)\.invoke|\.invoke\s*\()/g,
    severity: 'medium', confidence: 'low', exts: ['.java', '.kt'],
    description: 'Code uses reflection. Reflection on attacker-influenced class/method names can bypass access controls.',
    remediation: 'Avoid reflection on untrusted names; validate any class/method name against a fixed allow-list first.',
  },
  {
    id: 'java-script-engine', name: 'ScriptEngine.eval',
    regex: /\bScriptEngine\b.{0,80}\beval\s*\(/gs,
    severity: 'high', confidence: 'medium', exts: ['.java', '.kt'],
    description: 'Code evaluates a script at runtime. Script input from untrusted sources is code injection.',
    remediation: 'Do not evaluate untrusted scripts. If scripting is required, run it in a sandboxed engine with no host access.',
  },
  {
    id: 'java-xxe', name: 'XML parsing without XXE hardening',
    regex: /\b(DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLReaderFactory\.createXMLReader)\s*\(/g,
    severity: 'medium', confidence: 'low', exts: ['.java', '.kt'],
    description: 'Code creates an XML parser. Without disabling external entities this is vulnerable to XXE (file disclosure / SSRF).',
    remediation: 'Set disallow-doctype-decl / external-general-entities false on the factory, or use a parser with XXE disabled by default.',
  },
  {
    id: 'java-weak-crypto', name: 'Weak crypto (DES / MD5 / SHA-1 / java.util.Random)',
    regex: /\b(Cipher\.getInstance\s*\(\s*"DES|MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1)"|new\s+Random\s*\()/g,
    severity: 'medium', confidence: 'medium', exts: ['.java', '.kt'],
    description: 'Code uses broken or predictable crypto primitives (DES, MD5, SHA-1, java.util.Random).',
    remediation: 'Use AES-GCM, SHA-256+, and java.security.SecureRandom.',
  },
  {
    id: 'java-sql-concat', name: 'SQL string concatenation (executeQuery)',
    regex: /\b(executeQuery|executeUpdate|execute\s*)\(\s*[^)]*\+/g,
    severity: 'medium', confidence: 'low', exts: ['.java', '.kt'],
    description: 'A SQL statement is built by string concatenation. If input flows into it this is SQL injection.',
    remediation: 'Use PreparedStatement with bound parameters for all user input.',
  },
  {
    id: 'js-eval', name: 'eval / Function constructor',
    regex: /\b(eval\s*\(|new\s+Function\s*\()/g,
    severity: 'high', confidence: 'medium', exts: ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'],
    description: 'Code evaluates a string as JavaScript. String input from untrusted sources is code injection.',
    remediation: 'Do not evaluate strings. Parse data with JSON.parse and dispatch on a fixed allow-list instead.',
  },
  {
    id: 'js-child-process', name: 'child_process exec/spawn',
    regex: /\b(child_process\.(exec|execSync|spawn|spawnSync)|require\(['"]child_process['"]\))/g,
    severity: 'medium', confidence: 'medium', exts: ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'],
    description: 'Code spawns OS processes. Arguments derived from untrusted input are command injection.',
    remediation: 'Pass arguments as an array (execFile/spawn) and never build a shell command string from input.',
  },
  {
    id: 'js-innerhtml', name: 'innerHTML assignment',
    regex: /\.innerHTML\s*=/g,
    severity: 'medium', confidence: 'low', exts: ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'],
    description: 'Code assigns to innerHTML. Untrusted data here is DOM XSS.',
    remediation: 'Use textContent, or sanitise with DOMPurify before assigning.',
  },
  {
    id: 'py-eval-exec', name: 'Python eval / exec',
    regex: /\b(eval|exec)\s*\(/g,
    severity: 'high', confidence: 'medium', exts: ['.py'],
    description: 'Code evaluates a string as Python. Untrusted input here is code injection.',
    remediation: 'Do not evaluate strings. Use ast.literal_eval for data, or dispatch on a fixed allow-list.',
  },
  {
    id: 'py-pickle', name: 'Python pickle deserialization',
    regex: /\bpickle\.(loads?|load)\s*\(/g,
    severity: 'high', confidence: 'medium', exts: ['.py'],
    description: 'Code unpickles data. Unpickling untrusted bytes is arbitrary code execution in Python.',
    remediation: 'Never unpickle untrusted data. Use JSON or another safe format.',
  },
  {
    id: 'py-subprocess-shell', name: 'Python subprocess with shell=True / os.system',
    regex: /\b(os\.system\s*\(|subprocess\.(call|Popen|run)\s*\([^)]*shell\s*=\s*True)/g,
    severity: 'high', confidence: 'medium', exts: ['.py'],
    description: 'Code runs a shell command. Untrusted input here is command injection.',
    remediation: 'Drop shell=True and pass arguments as a list; never build a shell string from input.',
  },
  {
    id: 'py-yaml-load', name: 'yaml.load without a safe Loader',
    regex: /\byaml\.load\s*\([^)]*\)/g,
    severity: 'medium', confidence: 'low', exts: ['.py'],
    description: 'yaml.load without Loader=SafeLoader can construct arbitrary Python objects.',
    remediation: 'Use yaml.safe_load().',
  },
];

/** Class-file string patterns: constant-pool references to dangerous APIs. */
const CLASS_STRING_PATTERNS: Array<DangerousApiPattern> = [
  {
    id: 'class-runtime-exec', name: 'Reference to java/lang/Runtime.exec',
    regex: /java\/lang\/Runtime/g, severity: 'high', confidence: 'low',
    description: 'The class file references java.lang.Runtime (command execution API). Constant-pool scan only — this does not prove exec is called, or with what input.',
    remediation: 'Review the decompiled class (javap -c / a decompiler) to see whether Runtime.exec is reachable with untrusted input.',
  },
  {
    id: 'class-process-builder', name: 'Reference to java/lang/ProcessBuilder',
    regex: /java\/lang\/ProcessBuilder/g, severity: 'medium', confidence: 'low',
    description: 'The class file references java.lang.ProcessBuilder (command execution API). Constant-pool scan only.',
    remediation: 'Review the decompiled class to see whether ProcessBuilder is reachable with untrusted input.',
  },
  {
    id: 'class-deserialization', name: 'Reference to ObjectInputStream / readObject',
    regex: /(java\/io\/ObjectInputStream|readObject)/g, severity: 'high', confidence: 'low',
    description: 'The class file references Java deserialization. Constant-pool scan only — this does not prove untrusted bytes are deserialized.',
    remediation: 'Review the decompiled class; do not deserialize untrusted data, or apply an allow-list filter (JEP 290).',
  },
  {
    id: 'class-reflection', name: 'Reference to reflection APIs',
    regex: /java\/lang\/(Class|reflect\/Method)/g, severity: 'medium', confidence: 'low',
    description: 'The class file references reflection APIs. Constant-pool scan only.',
    remediation: 'Review the decompiled class for reflection on attacker-influenced names.',
  },
  {
    id: 'class-script-engine', name: 'Reference to ScriptEngine',
    regex: /javax\/script\/ScriptEngine/g, severity: 'medium', confidence: 'low',
    description: 'The class file references the scripting engine API. Constant-pool scan only.',
    remediation: 'Review the decompiled class; do not evaluate untrusted scripts.',
  },
  {
    id: 'class-jndi', name: 'Reference to JNDI (InitialContext / lookup)',
    regex: /javax\/naming\/(InitialContext|Context)/g, severity: 'medium', confidence: 'low',
    description: 'The class file references JNDI. JNDI lookups with attacker-controlled names are the Log4Shell-class vector.',
    remediation: 'Review the decompiled class; never perform JNDI lookups with untrusted names.',
  },
];

function extOf(path: string): string {
  const i = path.lastIndexOf('.');
  return i === -1 ? '' : path.slice(i).toLowerCase();
}

function isPlaceholderValue(match: string): boolean {
  return /example|placeholder|test|dummy|xxx+|your[-_ ]?(key|secret|password)/i.test(match);
}

function scanText(
  text: string,
  location: string,
  out: CodeIntakeFinding[],
  opts: { dangerousApis: boolean; ext: string },
): void {
  for (const p of SECRET_PATTERNS) {
    const re = new RegExp(p.regex.source, p.regex.flags.includes('g') ? p.regex.flags : p.regex.flags + 'g');
    let m: RegExpExecArray | null;
    let reported = 0;
    while ((m = re.exec(text)) !== null && reported < MAX_FINDINGS_PER_PATTERN) {
      if (m.index === re.lastIndex) re.lastIndex++;
      if (isPlaceholderValue(m[0])) continue;
      reported++;
      out.push({
        category: 'whitebox',
        title: `${p.name} in ${location}`,
        description: `${p.description} Location: ${location}. Evidence is redacted; verify the match in your own copy of the code.`,
        severity: p.severity,
        confidence: p.severity === 'critical' ? 'high' : 'medium',
        location,
        evidence: redactText(m[0].slice(0, 120)),
        remediation: p.remediation,
        references: [],
      });
    }
  }
  if (!opts.dangerousApis) return;
  for (const p of DANGEROUS_API_PATTERNS) {
    if (!p.exts.includes(opts.ext)) continue;
    const re = new RegExp(p.regex.source, p.regex.flags.includes('g') ? p.regex.flags : p.regex.flags + 'g');
    let m: RegExpExecArray | null;
    let reported = 0;
    while ((m = re.exec(text)) !== null && reported < MAX_FINDINGS_PER_PATTERN) {
      if (m.index === re.lastIndex) re.lastIndex++;
      reported++;
      const line = text.slice(0, m.index).split('\n').length;
      out.push({
        category: 'whitebox',
        title: `${p.name} in ${location}`,
        description: `${p.description} Location: ${location} (line ${line}). Static pattern match — confirm the data flow before reporting.`,
        severity: p.severity,
        confidence: p.confidence,
        location: `${location}:${line}`,
        evidence: redactText(m[0].slice(0, 120)),
        remediation: p.remediation,
        references: [],
      });
    }
  }
}

/** Printable ASCII runs (>= 6 chars) out of raw bytes. */
function extractStrings(buf: Buffer): string {
  const out: string[] = [];
  let run = '';
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b >= 0x20 && b <= 0x7e) run += String.fromCharCode(b);
    else {
      if (run.length >= 6) out.push(run);
      run = '';
    }
  }
  if (run.length >= 6) out.push(run);
  return out.join('\n');
}

function scanClassStrings(text: string, location: string, out: CodeIntakeFinding[]): void {
  // Secrets / JDBC URLs can hide in constant pools too.
  scanText(text, location, out, { dangerousApis: false, ext: '.class' });
  for (const p of CLASS_STRING_PATTERNS) {
    const re = new RegExp(p.regex.source, 'g');
    let reported = 0;
    while (re.exec(text) !== null && reported < MAX_FINDINGS_PER_PATTERN) {
      reported++;
      out.push({
        category: 'whitebox',
        title: `${p.name} in ${location}`,
        description: `${p.description} Location: ${location}.`,
        severity: p.severity,
        confidence: p.confidence,
        location,
        evidence: redactText(p.name),
        remediation: p.remediation,
        references: [],
      });
    }
  }
}

/**
 * Analyse an uploaded archive. `kind` is 'jar' for JAR/WAR files (class
 * files get the constant-pool treatment) and 'zip' for anything else.
 * Throws on unreadable / empty archives.
 */
export async function analyzeCodeArchive(
  buf: Buffer,
  kind: 'zip' | 'jar',
  filename: string,
): Promise<CodeIntakeResult> {
  const zip = await JSZip.loadAsync(buf);
  const entries = Object.values(zip.files).filter((f) => !f.dir);
  if (entries.length === 0) {
    throw new Error('Archive contains no files');
  }
  if (entries.length > MAX_ENTRIES) {
    throw new Error(`Archive contains ${entries.length} files (limit ${MAX_ENTRIES})`);
  }

  const findings: CodeIntakeFinding[] = [];
  const warnings: string[] = [];
  let filesScanned = 0;
  let entriesSkipped = 0;
  let totalScanned = 0;

  for (const entry of entries) {
    const ext = extOf(entry.name);
    const isClass = kind === 'jar' && ext === '.class';
    const isSource = SOURCE_EXTENSIONS.has(ext);
    const isSecretOnly =
      SECRET_ONLY_EXTENSIONS.has(ext) ||
      entry.name === 'MANIFEST.MF' ||
      entry.name.endsWith('MANIFEST.MF');
    if (!isClass && !isSource && !isSecretOnly) {
      entriesSkipped++;
      continue;
    }
    if (totalScanned >= MAX_TOTAL_SCANNED_BYTES) {
      entriesSkipped++;
      continue;
    }
    let content: Buffer;
    try {
      content = await entry.async('nodebuffer');
    } catch {
      warnings.push(`Could not read ${entry.name} — skipped`);
      entriesSkipped++;
      continue;
    }
    if (content.length > MAX_FILE_BYTES) {
      warnings.push(`${entry.name} (${Math.round(content.length / 1024)} KB) exceeds the 2 MB per-file cap — skipped`);
      entriesSkipped++;
      continue;
    }
    totalScanned += content.length;
    filesScanned++;

    if (isClass) {
      scanClassStrings(extractStrings(content), entry.name, findings);
    } else {
      const text = content.toString('utf8');
      scanText(text, entry.name, findings, { dangerousApis: isSource, ext });
    }
  }

  return {
    kind,
    method: kind === 'jar' ? JAR_METHOD : ZIP_METHOD,
    filesScanned,
    entriesSkipped,
    findings,
    warnings,
  };
}

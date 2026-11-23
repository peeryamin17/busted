import * as acorn from 'acorn';

export interface TaintTraceStep {
  file: string;
  line: number;
  column: number;
  code: string;
  kind: 'source' | 'propagation' | 'call' | 'sink';
}

export interface SourceToSinkFlow {
  sourceName: string;
  sinkName: string;
  confidence: number;
  trace: TaintTraceStep[];
  /** True when the flow crosses a script/bundle boundary (see crossFileTaint.ts). */
  crossFile?: boolean;
  /** Short human-readable note, e.g. that a rule is a framework heuristic. */
  note?: string;
}

/** A function summary other files may reuse (see crossFileTaint.ts). */
export interface ExportedFunctionSummary {
  name: string;
  /** Indices of parameters that flow into the return value */
  paramToReturn: number[];
  /** Indices of parameters that flow into a sink inside this function */
  paramToSink: Record<number, Array<{ sinkName: string; line: number; column: number }>>;
}

interface FunctionSummary {
  name: string;
  // Indices of parameters that flow into the return value
  paramToReturn: Set<number>;
  // Indices of parameters that flow directly into a sink inside this function
  paramToSink: Map<number, { sinkName: string; line: number; column: number }[]>;
}

const UNTRUSTED_SOURCES = new Set([
  'location.search',
  'location.hash',
  'location.href',
  'document.URL',
  'document.referrer',
  'window.name',
  // Cookie reads: attacker-controlled on any site that reflects them, and
  // frequently attacker-settable via subdomains / related-site cookies.
  'document.cookie',
  // postMessage handler payloads: `event.data` / `e.data` / `evt.data`.
  // Only the conventional handler-parameter names are treated as sources;
  // arbitrary `.data` properties are not (too noisy).
  'event.data',
  'e.data',
  'evt.data',
  'msg.data',
  'message.data',
]);

/** Call expressions whose return value is untrusted input. */
const SOURCE_CALLS = new Set([
  'localStorage.getItem',
  'sessionStorage.getItem',
  'localStorage.key',
  'sessionStorage.key',
]);

const DANGEROUS_SINKS = new Set([
  'innerHTML',
  'outerHTML',
  'document.write',
  'eval',
  'Function',
  'insertAdjacentHTML',
  'bypassSecurityTrustHtml',
  'dangerouslySetInnerHTML',
]);

/**
 * Call-expression sinks: the callee (or its `.suffix`) is dangerous when an
 * argument is tainted. `fetch` / XHR take a tainted URL (SSRF / open-redirect
 * / request smuggling surface); string args to setTimeout/setInterval are
 * implicit eval; `document.cookie` writes and location.assign() move tainted
 * data into a new trust domain.
 */
const DANGEROUS_CALL_SINKS = new Set([
  'fetch',
  'setTimeout',
  'setInterval',
  'location.assign',
  'location.replace',
]);

/**
 * Framework-aware sinks. These are HEURISTICS, not guarantees: the engine
 * sees plain JS, not framework templates, so a match means "this pattern is
 * how the framework reaches a dangerous sink", a human still has to confirm
 * the data really is attacker-controlled in that framework's binding.
 */
const FRAMEWORK_SINKS = new Set([
  'bypassSecurityTrustHtml',
  'bypassSecurityTrustScript',
  'bypassSecurityTrustStyle',
  'bypassSecurityTrustUrl',
  'bypassSecurityTrustResourceUrl',
  'dangerouslySetInnerHTML',
]);

/** The React `__html` object key that feeds dangerouslySetInnerHTML. */
const REACT_HTML_KEY = '__html';

// Alpha-beta cutoffs: passing through these kills taint on that branch
const SANITIZERS = new Set([
  'encodeURIComponent',
  'encodeURI',
  'Number',
  'parseInt',
  'parseFloat',
  'Boolean',
  'DOMPurify.sanitize',
  'sanitizeHtml',
]);

function memberExprToString(node: any): string {
  if (!node) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression' && !node.computed) {
    const obj = memberExprToString(node.object);
    const prop = memberExprToString(node.property);
    return obj && prop ? `${obj}.${prop}` : prop;
  }
  return '';
}

function locOf(node: any): { line: number; column: number } {
  return node?.loc?.start ?? { line: 0, column: 0 };
}

/**
 * Canonical sink name for a callee / property string, or null. Matches the
 * full string or the `.suffix` after the last dot, so `el.innerHTML`,
 * `sanitizer.bypassSecurityTrustHtml` and bare `eval` all resolve. Returns
 * the canonical name plus whether it is a framework heuristic.
 */
function resolveSink(calleeOrProp: string): { name: string; frameworkHeuristic: boolean } | null {
  if (!calleeOrProp) return null;
  const suffix = calleeOrProp.includes('.')
    ? calleeOrProp.slice(calleeOrProp.lastIndexOf('.') + 1)
    : calleeOrProp;
  for (const cand of [calleeOrProp, suffix]) {
    if (DANGEROUS_SINKS.has(cand) || DANGEROUS_CALL_SINKS.has(cand)) {
      return { name: cand, frameworkHeuristic: FRAMEWORK_SINKS.has(cand) };
    }
  }
  return null;
}

/** XHR `.open(method, url)`, matched when the receiver looks like an XHR. */
function isXhrOpen(callee: string): boolean {
  if (!callee.endsWith('.open')) return false;
  const recv = callee.slice(0, -'.open'.length);
  return /^(xhr|request|req|client|http)$/i.test(recv) || recv.endsWith('Request');
}

/**
 * Which argument positions carry attacker data into a sink. `fetch(url)`,
 * `setTimeout(code)` and `location.assign(url)` take it in argument 0;
 * `xhr.open(method, url)` in argument 1; eval/Function-style sinks take any.
 */
function sinkArgIndices(sinkName: string, argCount: number): number[] {
  const all = Array.from({ length: argCount }, (_, i) => i);
  if (sinkName === 'XMLHttpRequest.open') return argCount > 1 ? [1] : [];
  if (
    sinkName === 'fetch' ||
    sinkName === 'setTimeout' ||
    sinkName === 'setInterval' ||
    sinkName === 'location.assign' ||
    sinkName === 'location.replace'
  ) {
    return argCount > 0 ? [0] : [];
  }
  return all;
}

function isSourceCall(callee: string): boolean {
  return SOURCE_CALLS.has(callee);
}

export class DeepTaintEngine {
  // Transposition table: functionName -> cached taint transfer summary
  private summaries = new Map<string, FunctionSummary>();
  // Summaries imported from other scripts (cross-file analysis).
  private externalSummaries = new Map<string, FunctionSummary>();
  private findings: SourceToSinkFlow[] = [];
  private taintedVarNames = new Set<string>();

  analyzeSource(
    code: string,
    filename: string,
    externalSummaries?: ExportedFunctionSummary[],
  ): SourceToSinkFlow[] {
    this.findings = [];
    this.taintedVarNames = new Set();
    this.externalSummaries = new Map();
    for (const s of externalSummaries ?? []) {
      this.externalSummaries.set(s.name, {
        name: s.name,
        paramToReturn: new Set(s.paramToReturn),
        paramToSink: new Map(
          Object.entries(s.paramToSink).map(([k, v]) => [Number(k), v]),
        ),
      });
    }
    const ast = acorn.parse(code, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      locations: true,
      allowHashBang: true,
    }) as any;

    // Pass 1: Build Function Summaries (Transposition Table)
    this.buildFunctionSummaries(ast);

    // Pass 2: Inter-Procedural Taint Propagation from Untrusted Sources
    const rootTaint = new Map<string, TaintTraceStep[]>();
    this.walkBlock(ast.body, rootTaint, filename);

    return this.findings;
  }

  /** Function summaries for this file, for reuse by cross-file analysis. */
  getFunctionSummaries(): ExportedFunctionSummary[] {
    return [...this.summaries.values()].map((s) => ({
      name: s.name,
      paramToReturn: [...s.paramToReturn],
      paramToSink: Object.fromEntries(s.paramToSink),
    }));
  }

  /** Variable names observed tainted in the most recent analyzeSource call. */
  getTaintedVariableNames(): string[] {
    return [...this.taintedVarNames];
  }

  private buildFunctionSummaries(ast: any): void {
    const visit = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (
        (node.type === 'FunctionDeclaration' && node.id?.name) ||
        (node.type === 'VariableDeclarator' &&
          node.id?.name &&
          (node.init?.type === 'ArrowFunctionExpression' ||
            node.init?.type === 'FunctionExpression'))
      ) {
        const fnName = node.id.name;
        const fnNode = node.type === 'FunctionDeclaration' ? node : node.init;
        const summary = this.summarizeFunction(fnName, fnNode);
        this.summaries.set(fnName, summary);
      }

      for (const key of Object.keys(node)) {
        const child = node[key];
        if (Array.isArray(child)) child.forEach(visit);
        else if (child && typeof child.type === 'string') visit(child);
      }
    };

    visit(ast);
  }

  private summarizeFunction(name: string, fnNode: any): FunctionSummary {
    const paramMap = new Map<string, number>();
    (fnNode.params ?? []).forEach((p: any, idx: number) => {
      if (p.type === 'Identifier') paramMap.set(p.name, idx);
    });

    const paramToReturn = new Set<number>();
    const paramToSink = new Map<number, { sinkName: string; line: number; column: number }[]>();
    // Local variable -> set of parameter indices it depends on
    const localDeps = new Map<string, Set<number>>();
    for (const [pName, idx] of paramMap.entries()) {
      localDeps.set(pName, new Set([idx]));
    }

    const exprDeps = (expr: any): Set<number> => {
      const deps = new Set<number>();
      if (!expr) return deps;

      if (expr.type === 'Identifier') {
        localDeps.get(expr.name)?.forEach((i) => deps.add(i));
      } else if (expr.type === 'BinaryExpression') {
        exprDeps(expr.left).forEach((i) => deps.add(i));
        exprDeps(expr.right).forEach((i) => deps.add(i));
      } else if (expr.type === 'TemplateLiteral') {
        expr.expressions?.forEach((e: any) => exprDeps(e).forEach((i) => deps.add(i)));
      } else if (expr.type === 'CallExpression') {
        const callee = memberExprToString(expr.callee);
        if (SANITIZERS.has(callee)) return deps; // Prune sanitized branch
        expr.arguments?.forEach((a: any) => exprDeps(a).forEach((i) => deps.add(i)));
      }
      return deps;
    };

    const scanBody = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier') {
        const d = exprDeps(node.init);
        if (d.size > 0) localDeps.set(node.id.name, d);
      } else if (node.type === 'ReturnStatement') {
        exprDeps(node.argument).forEach((i) => paramToReturn.add(i));
      } else if (node.type === 'AssignmentExpression') {
        const lhs = memberExprToString(node.left);
        const prop = node.left?.property?.name ?? lhs;
        const sink = resolveSink(prop) ?? resolveSink(lhs);
        // Cookie writes: `document.cookie = <tainted>` hands attacker data
        // to the browser's cookie jar (session fixation / XSS persistence).
        const cookieWrite = lhs === 'document.cookie';
        if (sink || cookieWrite) {
          const sinkName = sink ? sink.name : 'document.cookie (write)';
          const d = exprDeps(node.right);
          const loc = locOf(node);
          d.forEach((idx) => {
            const list = paramToSink.get(idx) ?? [];
            list.push({ sinkName, ...loc });
            paramToSink.set(idx, list);
          });
        }
      } else if (node.type === 'ObjectExpression') {
        // React: `{ __html: <tainted> }` feeds dangerouslySetInnerHTML.
        // Framework heuristic, the object may never reach React.
        for (const prop of node.properties ?? []) {
          if (prop?.key?.name !== REACT_HTML_KEY && prop?.key?.value !== REACT_HTML_KEY) continue;
          const d = exprDeps(prop.value);
          const loc = locOf(prop);
          d.forEach((idx) => {
            const list = paramToSink.get(idx) ?? [];
            list.push({ sinkName: 'dangerouslySetInnerHTML (__html)', ...loc });
            paramToSink.set(idx, list);
          });
        }
      } else if (node.type === 'CallExpression') {
        const callee = memberExprToString(node.callee);
        const sink = resolveSink(callee) ?? (isXhrOpen(callee) ? { name: 'XMLHttpRequest.open', frameworkHeuristic: false } : null);
        if (sink) {
          const loc = locOf(node);
          sinkArgIndices(sink.name, node.arguments?.length ?? 0).forEach((argIdx) => {
            const arg = node.arguments?.[argIdx];
            if (!arg) return;
            exprDeps(arg).forEach((idx) => {
              const list = paramToSink.get(idx) ?? [];
              list.push({ sinkName: sink.name, ...loc });
              paramToSink.set(idx, list);
            });
          });
        }
      }

      for (const key of Object.keys(node)) {
        if (key === 'params') continue;
        const child = node[key];
        if (Array.isArray(child)) child.forEach(scanBody);
        else if (child && typeof child.type === 'string') scanBody(child);
      }
    };

    scanBody(fnNode.body);
    return { name, paramToReturn, paramToSink };
  }

  private evalExprTaint(
    expr: any,
    taintEnv: Map<string, TaintTraceStep[]>,
    filename: string
  ): TaintTraceStep[] | null {
    if (!expr) return null;

    // 1. Direct untrusted source (e.g., location.hash, document.referrer)
    const memberStr = memberExprToString(expr);
    if (UNTRUSTED_SOURCES.has(memberStr)) {
      return [
        {
          file: filename,
          ...locOf(expr),
          code: memberStr,
          kind: 'source',
        },
      ];
    }

    // 2. Previously tainted variable
    if (expr.type === 'Identifier' && taintEnv.has(expr.name)) {
      return taintEnv.get(expr.name)!;
    }

    // 3. String concatenation / template literals
    if (expr.type === 'BinaryExpression') {
      return (
        this.evalExprTaint(expr.left, taintEnv, filename) ??
        this.evalExprTaint(expr.right, taintEnv, filename)
      );
    }
    if (expr.type === 'TemplateLiteral') {
      for (const sub of expr.expressions ?? []) {
        const t = this.evalExprTaint(sub, taintEnv, filename);
        if (t) return t;
      }
    }

    // 4. Function Call (Transposition Table Lookup + Sanitizer Pruning)
    if (expr.type === 'CallExpression') {
      const callee = memberExprToString(expr.callee);
      if (SANITIZERS.has(callee)) return null; // Alpha-beta cutoff

      // Storage reads are untrusted sources (another tab / earlier XSS /
      // attacker-set values can sit in storage).
      if (isSourceCall(callee)) {
        return [
          {
            file: filename,
            ...locOf(expr),
            code: callee,
            kind: 'source',
          },
        ];
      }

      // URLSearchParams.get() is a common source wrapper
      if (callee.endsWith('.get') && expr.callee?.object) {
        const objTaint = this.evalExprTaint(expr.callee.object, taintEnv, filename);
        if (objTaint) return objTaint;
      }

      const summary = this.summaries.get(callee) ?? this.externalSummaries.get(callee);
      if (summary) {
        for (let i = 0; i < (expr.arguments?.length ?? 0); i++) {
          const argTaint = this.evalExprTaint(expr.arguments[i], taintEnv, filename);
          if (!argTaint) continue;

          // If this argument reaches a sink inside the called function, record the finding
          const internalSinks = summary.paramToSink.get(i);
          if (internalSinks) {
            for (const s of internalSinks) {
              const framework = FRAMEWORK_SINKS.has(s.sinkName.replace(' (__html)', ''));
              this.findings.push({
                sourceName: argTaint[0].code,
                sinkName: s.sinkName,
                confidence: framework ? 0.8 : 0.92,
                trace: [
                  ...argTaint,
                  { file: filename, ...locOf(expr), code: `${callee}(...)`, kind: 'call' },
                  { file: filename, line: s.line, column: s.column, code: s.sinkName, kind: 'sink' },
                ],
                ...(framework
                  ? { note: 'Framework heuristic: the sink is reached through a framework API; confirm the binding is attacker-controlled.' }
                  : {}),
              });
            }
          }

          // If this argument flows to the return value, propagate taint to caller
          if (summary.paramToReturn.has(i)) {
            return [
              ...argTaint,
              { file: filename, ...locOf(expr), code: `${callee}(...)`, kind: 'call' },
            ];
          }
        }
      }
    }

    // 4b. React `{ __html: <tainted> }` object literal (framework heuristic).
    if (expr.type === 'ObjectExpression') {
      for (const prop of expr.properties ?? []) {
        if (prop?.key?.name !== REACT_HTML_KEY && prop?.key?.value !== REACT_HTML_KEY) continue;
        const t = this.evalExprTaint(prop.value, taintEnv, filename);
        if (t) {
          this.findings.push({
            sourceName: t[0].code,
            sinkName: 'dangerouslySetInnerHTML (__html)',
            confidence: 0.8,
            trace: [
              ...t,
              { file: filename, ...locOf(prop), code: '__html', kind: 'sink' },
            ],
            note: 'Framework heuristic: React dangerouslySetInnerHTML via an __html object literal; confirm the object reaches React.',
          });
          return t;
        }
      }
    }

    // 5. `new URLSearchParams(location.search)`
    if (expr.type === 'NewExpression') {
      // `new Function(<tainted>)` is a code-execution sink.
      if (memberExprToString(expr.callee) === 'Function') {
        for (const arg of expr.arguments ?? []) {
          const t = this.evalExprTaint(arg, taintEnv, filename);
          if (t) {
            this.findings.push({
              sourceName: t[0].code,
              sinkName: 'Function',
              confidence: 0.95,
              trace: [
                ...t,
                { file: filename, ...locOf(expr), code: 'new Function(...)', kind: 'sink' },
              ],
            });
            return t;
          }
        }
      }
      for (const arg of expr.arguments ?? []) {
        const t = this.evalExprTaint(arg, taintEnv, filename);
        if (t) return t;
      }
    }

    return null;
  }

  private walkBlock(
    statements: any[],
    taintEnv: Map<string, TaintTraceStep[]>,
    filename: string
  ): void {
    for (const stmt of statements ?? []) {
      if (!stmt) continue;

      if (stmt.type === 'VariableDeclaration') {
        for (const decl of stmt.declarations ?? []) {
          if (decl.id?.type === 'Identifier') {
            const t = this.evalExprTaint(decl.init, taintEnv, filename);
            if (t) {
              this.taintedVarNames.add(decl.id.name);
              taintEnv.set(decl.id.name, [
                ...t,
                { file: filename, ...locOf(decl), code: decl.id.name, kind: 'propagation' },
              ]);
            }
          }
          // Descend into function-valued initialisers so sinks inside
          // callbacks/handlers are seen (postMessage handlers live here).
          const init = decl.init;
          if (
            init?.type === 'FunctionExpression' ||
            init?.type === 'ArrowFunctionExpression'
          ) {
            this.walkFunctionBody(init, taintEnv, filename);
          }
        }
      } else if (stmt.type === 'FunctionDeclaration') {
        // Top-level function bodies: analyse with the enclosing env copied
        // (closures can capture tainted outer variables). Parameters stay
        // untainted, inter-procedural flow goes through the summaries.
        this.walkFunctionBody(stmt, taintEnv, filename);
      } else if (stmt.type === 'ExpressionStatement') {
        const expr = stmt.expression;

        if (expr?.type === 'AssignmentExpression') {
          // `x.onmessage = function (e) { ... }`, analyse the handler body.
          if (
            expr.right?.type === 'FunctionExpression' ||
            expr.right?.type === 'ArrowFunctionExpression'
          ) {
            this.walkFunctionBody(expr.right, taintEnv, filename);
          }
          const rhsTaint = this.evalExprTaint(expr.right, taintEnv, filename);
          const lhsStr = memberExprToString(expr.left);
          const prop = expr.left?.property?.name ?? lhsStr;
          const sink = resolveSink(prop) ?? resolveSink(lhsStr);
          const cookieWrite = lhsStr === 'document.cookie';

          if (rhsTaint && (sink || cookieWrite)) {
            const sinkName = sink ? sink.name : 'document.cookie (write)';
            this.findings.push({
              sourceName: rhsTaint[0].code,
              sinkName,
              confidence: sink?.frameworkHeuristic ? 0.8 : 0.95,
              trace: [
                ...rhsTaint,
                { file: filename, ...locOf(expr), code: lhsStr, kind: 'sink' },
              ],
              ...(sink?.frameworkHeuristic
                ? { note: 'Framework heuristic: the sink is reached through a framework API; confirm the binding is attacker-controlled.' }
                : {}),
            });
          } else if (rhsTaint && expr.left?.type === 'Identifier') {
            this.taintedVarNames.add(expr.left.name);
            taintEnv.set(expr.left.name, rhsTaint);
          }
        } else if (expr?.type === 'CallExpression') {
          const callee = memberExprToString(expr.callee);
          // `addEventListener('message', handler)`, analyse the handler
          // body; `event.data` / `e.data` inside it is a direct source.
          if (
            callee.endsWith('addEventListener') &&
            expr.arguments?.[0]?.value === 'message' &&
            (expr.arguments?.[1]?.type === 'FunctionExpression' ||
              expr.arguments?.[1]?.type === 'ArrowFunctionExpression')
          ) {
            this.walkFunctionBody(expr.arguments[1], taintEnv, filename);
          }
          const sink =
            resolveSink(callee) ??
            (isXhrOpen(callee) ? { name: 'XMLHttpRequest.open', frameworkHeuristic: false } : null);
          if (sink) {
            for (const argIdx of sinkArgIndices(sink.name, expr.arguments?.length ?? 0)) {
              const arg = expr.arguments?.[argIdx];
              if (!arg) continue;
              const argTaint = this.evalExprTaint(arg, taintEnv, filename);
              if (argTaint) {
                this.findings.push({
                  sourceName: argTaint[0].code,
                  sinkName: sink.name,
                  confidence: sink.frameworkHeuristic ? 0.8 : 0.95,
                  trace: [
                    ...argTaint,
                    { file: filename, ...locOf(expr), code: callee, kind: 'sink' },
                  ],
                  ...(sink.frameworkHeuristic
                    ? { note: 'Framework heuristic: the sink is reached through a framework API (e.g. Angular bypassSecurityTrust*); confirm the input is attacker-controlled.' }
                    : {}),
                });
              }
            }
          } else {
            // Still evaluate call to trigger inter-procedural sink checks via summaries
            this.evalExprTaint(expr, taintEnv, filename);
          }
        } else if (expr?.type === 'NewExpression') {
          // `new Function(<tainted>)` and `new URLSearchParams(<tainted>)`
          // are evaluated inside evalExprTaint (sink check + propagation).
          this.evalExprTaint(expr, taintEnv, filename);
        }
      } else if (stmt.type === 'IfStatement') {
        if (stmt.consequent?.body) this.walkBlock(stmt.consequent.body, new Map(taintEnv), filename);
        if (stmt.alternate?.body) this.walkBlock(stmt.alternate.body, new Map(taintEnv), filename);
      }
    }
  }

  /** Walk a function body with a copy of the enclosing taint env. */
  private walkFunctionBody(
    fnNode: any,
    taintEnv: Map<string, TaintTraceStep[]>,
    filename: string,
  ): void {
    const body = fnNode?.body;
    if (!body) return;
    if (body.type === 'BlockStatement') {
      this.walkBlock(body.body, new Map(taintEnv), filename);
    }
    // Arrow functions with an expression body hold no statements.
  }
}

/**
 * Vue `v-html` template heuristic.
 *
 * The AST engine cannot see Vue templates, so this is a separate regex pass
 * over the raw source: it flags `v-html="<expr>"` bindings whose expression
 * mentions a variable the taint engine already found tainted in this file.
 * It is a HEURISTIC, not a proof, a binding may be sanitized upstream, or
 * the variable may be tainted only on a branch the template never takes.
 * Returns at most `maxHits` flows, lowest confidence (0.65).
 */
const V_HTML_RE = /v-html\s*=\s*["']([^"']+)["']/g;

export function scanVueHtmlBindings(
  code: string,
  filename: string,
  taintedNames: string[],
  maxHits = 5,
): SourceToSinkFlow[] {
  const flows: SourceToSinkFlow[] = [];
  if (taintedNames.length === 0) return flows;
  const tainted = new Set(taintedNames);
  let m: RegExpExecArray | null;
  while ((m = V_HTML_RE.exec(code)) !== null && flows.length < maxHits) {
    const expr = m[1];
    // Identifier tokens inside the binding expression.
    const used = expr.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) ?? [];
    const hit = used.find((id) => tainted.has(id));
    if (!hit) continue;
    const before = code.slice(0, m.index);
    const line = before.split('\n').length;
    const column = m.index - (before.lastIndexOf('\n') + 1);
    flows.push({
      sourceName: hit,
      sinkName: 'v-html',
      confidence: 0.65,
      trace: [
        {
          file: filename,
          line,
          column,
          code: `v-html="${expr.slice(0, 80)}"`,
          kind: 'sink',
        },
      ],
      note: 'Framework heuristic: Vue v-html binding referencing a tainted variable; confirm the value is attacker-controlled and unsanitized.',
    });
  }
  return flows;
}

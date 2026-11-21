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

export class DeepTaintEngine {
  // Transposition table: functionName -> cached taint transfer summary
  private summaries = new Map<string, FunctionSummary>();
  private findings: SourceToSinkFlow[] = [];

  analyzeSource(code: string, filename: string): SourceToSinkFlow[] {
    this.findings = [];
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
        if (DANGEROUS_SINKS.has(prop) || DANGEROUS_SINKS.has(lhs)) {
          const d = exprDeps(node.right);
          const loc = locOf(node);
          d.forEach((idx) => {
            const list = paramToSink.get(idx) ?? [];
            list.push({ sinkName: prop, ...loc });
            paramToSink.set(idx, list);
          });
        }
      } else if (node.type === 'CallExpression') {
        const callee = memberExprToString(node.callee);
        if (DANGEROUS_SINKS.has(callee)) {
          const loc = locOf(node);
          node.arguments?.forEach((arg: any) => {
            exprDeps(arg).forEach((idx) => {
              const list = paramToSink.get(idx) ?? [];
              list.push({ sinkName: callee, ...loc });
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

      // URLSearchParams.get() is a common source wrapper
      if (callee.endsWith('.get') && expr.callee?.object) {
        const objTaint = this.evalExprTaint(expr.callee.object, taintEnv, filename);
        if (objTaint) return objTaint;
      }

      const summary = this.summaries.get(callee);
      if (summary) {
        for (let i = 0; i < (expr.arguments?.length ?? 0); i++) {
          const argTaint = this.evalExprTaint(expr.arguments[i], taintEnv, filename);
          if (!argTaint) continue;

          // If this argument reaches a sink inside the called function, record the finding
          const internalSinks = summary.paramToSink.get(i);
          if (internalSinks) {
            for (const s of internalSinks) {
              this.findings.push({
                sourceName: argTaint[0].code,
                sinkName: s.sinkName,
                confidence: 0.92,
                trace: [
                  ...argTaint,
                  { file: filename, ...locOf(expr), code: `${callee}(...)`, kind: 'call' },
                  { file: filename, line: s.line, column: s.column, code: s.sinkName, kind: 'sink' },
                ],
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

    // 5. `new URLSearchParams(location.search)`
    if (expr.type === 'NewExpression') {
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
              taintEnv.set(decl.id.name, [
                ...t,
                { file: filename, ...locOf(decl), code: decl.id.name, kind: 'propagation' },
              ]);
            }
          }
        }
      } else if (stmt.type === 'ExpressionStatement') {
        const expr = stmt.expression;

        if (expr?.type === 'AssignmentExpression') {
          const rhsTaint = this.evalExprTaint(expr.right, taintEnv, filename);
          const lhsStr = memberExprToString(expr.left);
          const prop = expr.left?.property?.name ?? lhsStr;

          if (rhsTaint && (DANGEROUS_SINKS.has(prop) || DANGEROUS_SINKS.has(lhsStr))) {
            this.findings.push({
              sourceName: rhsTaint[0].code,
              sinkName: prop,
              confidence: 0.95,
              trace: [
                ...rhsTaint,
                { file: filename, ...locOf(expr), code: lhsStr, kind: 'sink' },
              ],
            });
          } else if (rhsTaint && expr.left?.type === 'Identifier') {
            taintEnv.set(expr.left.name, rhsTaint);
          }
        } else if (expr?.type === 'CallExpression') {
          const callee = memberExprToString(expr.callee);
          if (DANGEROUS_SINKS.has(callee)) {
            for (const arg of expr.arguments ?? []) {
              const argTaint = this.evalExprTaint(arg, taintEnv, filename);
              if (argTaint) {
                this.findings.push({
                  sourceName: argTaint[0].code,
                  sinkName: callee,
                  confidence: 0.95,
                  trace: [
                    ...argTaint,
                    { file: filename, ...locOf(expr), code: callee, kind: 'sink' },
                  ],
                });
              }
            }
          } else {
            // Still evaluate call to trigger inter-procedural sink checks via summaries
            this.evalExprTaint(expr, taintEnv, filename);
          }
        }
      } else if (stmt.type === 'IfStatement') {
        if (stmt.consequent?.body) this.walkBlock(stmt.consequent.body, new Map(taintEnv), filename);
        if (stmt.alternate?.body) this.walkBlock(stmt.alternate.body, new Map(taintEnv), filename);
      }
    }
  }
}

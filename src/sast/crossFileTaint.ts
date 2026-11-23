/**
 * Cross-file taint propagation (white-box, client-side).
 *
 * A page's JS is usually split across bundles, and the single-file
 * taint engine cannot see a tainted value leave one bundle and reach
 * a sink in another. This links them, and only that far: each script
 * is parsed once for its top-level functions and per-function summaries
 * (which params flow to a sink / to the return), then re-analysed with
 * the merged summary table, so a call into another bundle's function
 * resolves like a local call. A flow counts as cross-file only when
 * its trace calls a function defined in a different script.
 *
 * Not full cross-file data flow: globals, object properties,
 * event-driven hand-offs and dynamic dispatch (`window[x]()`) are not
 * tracked across files. Cross-file flows are capped at 0.75 confidence
 * and labelled definition-to-use linking.
 */
import * as acorn from 'acorn';
import {
  DeepTaintEngine,
  scanVueHtmlBindings,
  type ExportedFunctionSummary,
  type SourceToSinkFlow,
} from './taintEngine';

export interface ScriptInput {
  /** Display label, e.g. the bundle URL or `inline <script> #1`. */
  url: string;
  code: string;
}

export interface CrossFileLink {
  /** Name of the shared function (or global) that carries the value. */
  name: string;
  definedIn: string;
  usedIn: string;
  kind: 'function-call' | 'global-use';
  /** True when a tainted argument through this link reaches a sink. */
  reachesSink: boolean;
  confidence: number;
}

export interface CrossFileResult {
  /** Source→sink flows, including cross-file ones (flagged + de-rated). */
  flows: SourceToSinkFlow[];
  /** Definition→use links between scripts, sink-reaching or not. */
  links: CrossFileLink[];
  /** Per-script parse failures (minified bundles the parser rejected). */
  warnings: string[];
}

const MAX_SCRIPTS = 20;
const MAX_BYTES_PER_SCRIPT = 2 * 1024 * 1024;

function collectTopLevelFunctions(code: string): Set<string> {
  const names = new Set<string>();
  let ast: any;
  try {
    ast = acorn.parse(code, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      locations: false,
      allowHashBang: true,
    });
  } catch {
    return names;
  }
  const visit = (node: any): void => {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'FunctionDeclaration' && node.id?.name) {
      names.add(node.id.name);
    } else if (
      node.type === 'VariableDeclarator' &&
      node.id?.name &&
      (node.init?.type === 'ArrowFunctionExpression' ||
        node.init?.type === 'FunctionExpression')
    ) {
      names.add(node.id.name);
    }
    for (const key of Object.keys(node)) {
      const child = node[key];
      if (Array.isArray(child)) child.forEach(visit);
      else if (child && typeof child.type === 'string') visit(child);
    }
  };
  visit(ast);
  return names;
}

/** Names of functions called in `code` (bare identifier call sites). */
function collectCallNames(code: string): Set<string> {
  const names = new Set<string>();
  let ast: any;
  try {
    ast = acorn.parse(code, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      locations: false,
      allowHashBang: true,
    });
  } catch {
    return names;
  }
  const visit = (node: any): void => {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'CallExpression' && node.callee?.type === 'Identifier') {
      names.add(node.callee.name);
    }
    for (const key of Object.keys(node)) {
      const child = node[key];
      if (Array.isArray(child)) child.forEach(visit);
      else if (child && typeof child.type === 'string') visit(child);
    }
  };
  visit(ast);
  return names;
}

/**
 * Run the taint engine over a set of scripts with a shared summary table.
 * Parse failures are skipped (the warning list says which).
 */
export function analyzeScriptsCrossFile(scripts: ScriptInput[]): CrossFileResult {
  const usable = scripts
    .filter((s) => s.code && s.code.length <= MAX_BYTES_PER_SCRIPT)
    .slice(0, MAX_SCRIPTS);
  const warnings: string[] = [];

  // Pass 1: per-file summaries + definition map.
  const allSummaries: ExportedFunctionSummary[] = [];
  const definedIn = new Map<string, string>(); // function name -> script url
  const perFileSummaries = new Map<string, ExportedFunctionSummary[]>();
  const vueFlows: SourceToSinkFlow[] = [];
  for (const script of usable) {
    const engine = new DeepTaintEngine();
    try {
      engine.analyzeSource(script.code, script.url);
      // Vue template heuristic runs on the same per-file pass (cheap:
      // only regex-scans files that actually contain a v-html binding).
      if (script.code.includes('v-html')) {
        vueFlows.push(
          ...scanVueHtmlBindings(script.code, script.url, engine.getTaintedVariableNames()),
        );
      }
    } catch {
      warnings.push(`Could not parse ${script.url} — skipped from cross-file analysis`);
      continue;
    }
    const summaries = engine.getFunctionSummaries();
    perFileSummaries.set(script.url, summaries);
    allSummaries.push(...summaries);
    for (const name of collectTopLevelFunctions(script.code)) {
      if (!definedIn.has(name)) definedIn.set(name, script.url);
    }
  }

  // Pass 2: re-analyse each file with the merged table.
  const flows: SourceToSinkFlow[] = [...vueFlows];
  const seenFlow = new Set<string>(
    vueFlows.map(
      (f) => `${f.sourceName}|${f.sinkName}|${f.trace.map((t) => `${t.file}:${t.line}`).join(',')}`,
    ),
  );
  const sinkLinks = new Set<string>(); // "definedIn|usedIn|name" that reached a sink
  for (const script of usable) {
    if (!perFileSummaries.has(script.url)) continue;
    const engine = new DeepTaintEngine();
    let fileFlows: SourceToSinkFlow[];
    try {
      fileFlows = engine.analyzeSource(script.code, script.url, allSummaries);
    } catch {
      continue;
    }
    for (const flow of fileFlows) {
      const key = `${flow.sourceName}|${flow.sinkName}|${flow.trace.map((t) => `${t.file}:${t.line}`).join(',')}`;
      if (seenFlow.has(key)) continue;
      seenFlow.add(key);
      // A flow is cross-file when a `call` step invokes a function defined
      // in a different script than the file being analysed.
      const crossCall = flow.trace.find(
        (t) =>
          t.kind === 'call' &&
          definedIn.has(t.code.replace(/\(\.\.\.\)$/, '')) &&
          definedIn.get(t.code.replace(/\(\.\.\.\)$/, '')) !== script.url,
      );
      if (crossCall) {
        const calleeName = crossCall.code.replace(/\(\.\.\.\)$/, '');
        sinkLinks.add(`${definedIn.get(calleeName)}|${script.url}|${calleeName}`);
        flows.push({
          ...flow,
          crossFile: true,
          confidence: Math.min(flow.confidence, 0.75),
          note:
            'Cross-file flow (definition→use linking): the tainted value reaches a sink through a function defined in another bundle. ' +
            'This is name-based linking, not full cross-file data-flow — confirm the call site really passes attacker-controlled data.',
        });
      } else {
        flows.push(flow);
      }
    }
  }

  // Definition→use links: every call from one script into a function
  // defined in another, whether or not a sink was reached.
  const links: CrossFileLink[] = [];
  const seenLink = new Set<string>();
  for (const script of usable) {
    if (!perFileSummaries.has(script.url)) continue;
    for (const callee of collectCallNames(script.code)) {
      const home = definedIn.get(callee);
      if (!home || home === script.url) continue;
      const key = `${home}|${script.url}|${callee}`;
      if (seenLink.has(key)) continue;
      seenLink.add(key);
      links.push({
        name: callee,
        definedIn: home,
        usedIn: script.url,
        kind: 'function-call',
        reachesSink: sinkLinks.has(key),
        // A link that reaches a sink is corroborated by the flow itself;
        // a bare reuse link is only "this helper is shared across bundles".
        confidence: sinkLinks.has(key) ? 0.75 : 0.5,
      });
    }
  }

  return { flows, links, warnings };
}

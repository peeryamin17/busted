/**
 * Convert white-box analysis output (taint flows, cross-file links) into
 * the extension's shared Finding shape for the scan results list.
 */
import type { Finding } from '../lib/types';
import type { CrossFileLink } from './crossFileTaint';
import type { SourceToSinkFlow } from './taintEngine';

let findingSeq = 0;

function severityFor(confidence: number): Finding['severity'] {
  if (confidence >= 0.9) return 'high';
  if (confidence >= 0.75) return 'medium';
  return 'low';
}

function traceText(flow: SourceToSinkFlow): string {
  return flow.trace
    .map((t) => `${t.kind} @ ${t.file.split('/').slice(-1)[0]}:${t.line} — ${t.code}`)
    .join('\n');
}

/** One finding per source→sink taint flow. */
export function taintFlowsToFindings(flows: SourceToSinkFlow[]): Finding[] {
  return flows.map((flow) => {
    const last = flow.trace[flow.trace.length - 1];
    return {
      id: `taint-${findingSeq++}`,
      category: 'sinks',
      title: flow.crossFile
        ? `Cross-file taint flow: ${flow.sourceName} → ${flow.sinkName}`
        : `Tainted data reaches ${flow.sinkName}`,
      description:
        `Untrusted data from \`${flow.sourceName}\` reaches the dangerous sink \`${flow.sinkName}\` ` +
        `without passing a recognised sanitizer.${flow.crossFile ? ' The flow crosses a bundle boundary (definition→use linking between scripts).' : ''}` +
        (flow.note ? ` ${flow.note}` : '') +
        ` Confirm the source is attacker-controlled on this page before reporting.`,
      severity: severityFor(flow.confidence),
      confidence: flow.confidence >= 0.9 ? 'high' : flow.confidence >= 0.7 ? 'medium' : 'low',
      location: last ? `${last.file}:${last.line}` : undefined,
      evidence: traceText(flow).slice(0, 500),
      remediation:
        'Validate and encode untrusted input before it reaches the sink: use textContent instead of innerHTML, ' +
        'encodeURIComponent for URLs, and never pass user input to eval/Function or string setTimeout. ' +
        'If the value must reach the sink, sanitise it with a vetted library (e.g. DOMPurify) first.',
    };
  });
}

/**
 * Info-level findings for shared helpers reused across bundles where no
 * sink was reached, useful context, explicitly not vulnerabilities.
 * Capped so a bundle-heavy page does not flood the results.
 */
export function crossFileLinksToFindings(links: CrossFileLink[], max = 5): Finding[] {
  return links
    .filter((l) => !l.reachesSink)
    .slice(0, max)
    .map((l) => ({
      id: `xfile-link-${findingSeq++}`,
      category: 'whitebox' as const,
      title: `Shared helper \`${l.name}\` used across bundles`,
      description:
        `The function \`${l.name}\` is defined in ${shortLabel(l.definedIn)} and called from ${shortLabel(l.usedIn)}. ` +
        `No tainted argument through this link reached a sink in this scan — this is inventory, not a vulnerability. ` +
        `Cross-file tracking here is name-based definition→use linking, not full cross-file data-flow.`,
      severity: 'info' as const,
      confidence: 'low' as const,
      location: l.usedIn,
      evidence: `${l.name}: ${shortLabel(l.definedIn)} → ${shortLabel(l.usedIn)}`,
      remediation: 'No action required. Re-check if the helper gains a dangerous sink or starts receiving untrusted input.',
    }));
}

function shortLabel(url: string): string {
  if (url.startsWith('inline ')) return url;
  try {
    const u = new URL(url);
    return u.pathname.split('/').slice(-2).join('/');
  } catch {
    return url.slice(-60);
  }
}

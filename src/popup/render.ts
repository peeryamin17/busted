/**
 * Shared finding-card renderer for the popup (passive + active panes).
 *
 * Passive cards render exactly as in Phase 1. Active cards additionally show
 * CVSS badges, trap-probability flags, confirmation state, reproduction
 * steps, and attack-chain membership.
 */
import type { Finding, Severity } from '../lib/types';
import { SEVERITY_LABEL } from '../lib/types';
import type { SwarmOutcome } from '../lib/apiClient';
import { formatWorkerTelemetry } from '../lib/popupHelpers';

/** One specialist card in the swarm run record, with provider/model/token telemetry when the run record carries it. */
export function swarmWorkerCard(
  w: SwarmOutcome['workerReports'][number],
  enter: boolean,
): HTMLElement {
  const card = document.createElement('div');
  card.className = enter ? 'swarm-card swarm-enter' : 'swarm-card';

  const name = document.createElement('div');
  name.className = 'swarm-card-name';
  name.textContent = w.specialistName;
  card.appendChild(name);

  const stats = document.createElement('div');
  stats.className = 'swarm-card-stats';
  stats.textContent =
    `${w.testsRun} tests · ${w.findings} finding${w.findings === 1 ? '' : 's'}` +
    ` · ${(w.durationMs / 1000).toFixed(1)}s`;
  card.appendChild(stats);

  const telemetry = formatWorkerTelemetry(w);
  if (telemetry) {
    const tele = document.createElement('div');
    tele.className = 'swarm-card-stats';
    tele.textContent = telemetry;
    card.appendChild(tele);
  }

  if (w.summary) {
    const sum = document.createElement('p');
    sum.className = 'swarm-card-summary';
    sum.textContent = w.summary;
    card.appendChild(sum);
  }
  return card;
}

export function addMeta(dl: HTMLElement, term: string, value: string): void {
  const dt = document.createElement('dt');
  dt.textContent = term;
  const dd = document.createElement('dd');
  dd.textContent = value;
  dl.appendChild(dt);
  dl.appendChild(dd);
}

export interface DisplaySecurityScore {
  value: number;
  grade: string;
  effectiveGrade?: string;
  coverageLabel?: string;
  coverageRatio?: number;
  warnings?: string[];
}

export function renderScoreSummary(score: DisplaySecurityScore): HTMLElement {
  const container = document.createElement('div');
  container.className = 'score-summary-pill';
  const grade = score.effectiveGrade || score.grade;
  const gradeSpan = document.createElement('span');
  gradeSpan.className = `score-grade grade-${grade.toLowerCase()}`;
  gradeSpan.textContent = grade;
  container.appendChild(gradeSpan);

  const labelSpan = document.createElement('span');
  labelSpan.className = 'score-coverage-label';
  labelSpan.textContent = score.coverageLabel || `${score.value}/100`;
  container.appendChild(labelSpan);

  return container;
}

/** One expandable finding card. */
export function findingCard(f: Finding, index: number): HTMLElement {
  const sev: Severity = f.severity;
  const card = document.createElement('details');
  card.className = `card card-${sev}`;
  if (sev === 'critical' || sev === 'high') card.open = true;

  const summary = document.createElement('summary');
  summary.className = 'card-title';

  const badge = document.createElement('span');
  badge.className = `sev-badge sev-${sev}`;
  badge.textContent = SEVERITY_LABEL[sev];
  summary.appendChild(badge);
  summary.appendChild(document.createTextNode(` ${index + 1}. ${f.title}`));

  // Extra badges (active findings).
  if (f.mode === 'active') {
    const mode = document.createElement('span');
    mode.className = 'tag tag-active';
    mode.textContent = 'ACTIVE';
    mode.title = 'Produced by active testing';
    summary.appendChild(document.createTextNode(' '));
    summary.appendChild(mode);
  }
  if (f.honeypotSuspect) {
    const trap = document.createElement('span');
    trap.className = 'tag tag-trap';
    trap.textContent = `POSSIBLE TRAP ${Math.round((f.trapProbability ?? 0) * 100)}%`;
    trap.title = (f.trapSignals ?? []).join(' • ') || 'High trap probability';
    summary.appendChild(document.createTextNode(' '));
    summary.appendChild(trap);
  } else if (f.confirmed === true && f.mode === 'active') {
    const conf = document.createElement('span');
    conf.className = 'tag tag-confirmed';
    conf.textContent = 'CONFIRMED';
    conf.title = 'Confirmed by observation, not just presence';
    summary.appendChild(document.createTextNode(' '));
    summary.appendChild(conf);
  } else if (f.confirmed === false && f.mode === 'active') {
    const hint = document.createElement('span');
    hint.className = 'tag tag-hint';
    hint.textContent = 'REVIEW HINT';
    hint.title = 'Not confirmed — manual review needed';
    summary.appendChild(document.createTextNode(' '));
    summary.appendChild(hint);
  }
  card.appendChild(summary);

  const body = document.createElement('div');
  body.className = 'card-body';

  const desc = document.createElement('p');
  desc.textContent = f.description;
  body.appendChild(desc);

  const meta = document.createElement('dl');
  meta.className = 'card-meta';
  addMeta(meta, 'Confidence', f.confidence);
  addMeta(meta, 'Category', f.category);
  if (f.location) addMeta(meta, 'Location', f.location);
  if (f.cvssScore !== undefined) {
    addMeta(
      meta,
      'CVSS v3.1',
      `${f.cvssScore.toFixed(1)}${f.cvssVector ? ` (${f.cvssVector})` : ''}`,
    );
  }
  if (f.trapProbability !== undefined && f.trapProbability > 0) {
    addMeta(meta, 'Trap probability', `${Math.round(f.trapProbability * 100)}%`);
  }
  if (f.requestCount !== undefined && f.requestCount > 0) {
    addMeta(meta, 'Requests spent', String(f.requestCount));
  }
  if (f.attackChainIds && f.attackChainIds.length > 0) {
    addMeta(meta, 'Attack chains', f.attackChainIds.join(', '));
  }
  body.appendChild(meta);

  if (f.cvssJustification) {
    const j = document.createElement('p');
    j.className = 'cvss-just';
    j.textContent = `Why this score: ${f.cvssJustification}`;
    body.appendChild(j);
  }

  if (f.trapSignals && f.trapSignals.length > 0 && (f.trapProbability ?? 0) > 0) {
    const t = document.createElement('p');
    t.className = 'trap-signals';
    t.textContent = `Trap signals: ${f.trapSignals.join(' • ')}`;
    body.appendChild(t);
  }

  if (f.evidence) {
    const pre = document.createElement('pre');
    pre.className = 'evidence';
    pre.textContent = f.evidence;
    body.appendChild(pre);
  }

  if (f.reproSteps && f.reproSteps.length > 0) {
    const rl = document.createElement('p');
    rl.className = 'rem-label';
    rl.textContent = 'Reproduction';
    body.appendChild(rl);
    const ol = document.createElement('ol');
    ol.className = 'repro-steps';
    for (const s of f.reproSteps) {
      const li = document.createElement('li');
      li.textContent = s;
      ol.appendChild(li);
    }
    body.appendChild(ol);
  }

  const remLabel = document.createElement('p');
  remLabel.className = 'rem-label';
  remLabel.textContent = 'Remediation';
  body.appendChild(remLabel);
  const rem = document.createElement('p');
  rem.className = 'remediation';
  rem.textContent = f.remediation;
  body.appendChild(rem);

  card.appendChild(body);
  return card;
}

/** Render grouped finding cards into a container. */
export function renderFindings(
  container: HTMLElement,
  findings: Finding[],
  severities: Severity[],
  emptyText: string,
): void {
  container.innerHTML = '';
  if (findings.length === 0) {
    const p = document.createElement('p');
    p.className = 'no-findings';
    p.textContent = emptyText;
    container.appendChild(p);
    return;
  }
  for (const sev of severities) {
    const group = findings.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    const heading = document.createElement('h2');
    heading.className = `group-heading group-${sev}`;
    heading.textContent = `${SEVERITY_LABEL[sev]} (${group.length})`;
    container.appendChild(heading);
    group.forEach((f, i) => container.appendChild(findingCard(f, i)));
  }
}

/** Severity summary chips. */
export function renderSummary(container: HTMLElement, findings: Finding[]): void {
  container.innerHTML = '';
  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severities) {
    const count = findings.filter((f) => f.severity === sev).length;
    const chip = document.createElement('span');
    chip.className = `chip chip-${sev}`;
    chip.innerHTML = `<strong>${count}</strong> ${SEVERITY_LABEL[sev]}`;
    container.appendChild(chip);
  }
}

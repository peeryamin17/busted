/**
 * Active testing pane: authorization confirmation flow, scope definition,
 * throttle status, scan controls, and results (findings + attack chains).
 *
 * Active testing is LOCKED until the user completes the authorization form.
 * No active request is ever sent before that point.
 */
import type {
  AuthorizationRecord,
  ScanMessage,
  ScanResult,
  Severity,
} from '../lib/types';
import {
  basisLabel,
  getAuthorization,
  newAuthorizationId,
  normalizeHost,
  revokeAuthorization,
  saveAuthorization,
  summarizeScope,
} from '../lib/authorization';
import {
  DEFAULT_ACTIVE_REQUEST_GAP_MS,
  MIN_ACTIVE_REQUEST_GAP_MS,
  STORAGE_KEYS,
} from '../lib/config';
import { checkBackendStatus, getBackendApiKey, runSwarmScan, setBackendApiKey } from '../lib/apiClient';
import type { SwarmAuthorizationInput, SwarmOutcome } from '../lib/apiClient';
import { findingCard, renderFindings, renderSummary } from './render';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const el = {
  pane: document.getElementById('pane-active') as HTMLElement,
  hostLine: document.getElementById('active-host') as HTMLElement,
  backendBadge: document.getElementById('backend-status') as HTMLElement,
  // Authorization form
  authzForm: document.getElementById('authz-form') as HTMLElement,
  authzAuthorized: document.getElementById('authz-authorized') as HTMLElement,
  authzSummary: document.getElementById('authz-summary') as HTMLElement,
  authzRevoke: document.getElementById('authz-revoke') as HTMLButtonElement,
  authzSave: document.getElementById('authz-save') as HTMLButtonElement,
  authzError: document.getElementById('authz-error') as HTMLElement,
  // Controls
  runBtn: document.getElementById('active-run-btn') as HTMLButtonElement,
  swarmBtn: document.getElementById('swarm-run-btn') as HTMLButtonElement,
  throttle: document.getElementById('throttle-status') as HTMLElement,
  // Results
  status: document.getElementById('active-status') as HTMLElement,
  error: document.getElementById('active-error') as HTMLElement,
  results: document.getElementById('active-results') as HTMLElement,
  stats: document.getElementById('active-stats') as HTMLElement,
  chains: document.getElementById('active-chains') as HTMLElement,
  summary: document.getElementById('active-summary') as HTMLElement,
  findings: document.getElementById('active-findings') as HTMLElement,
  swarmPanel: document.getElementById('swarm-panel') as HTMLElement,
  downloadBtn: document.getElementById('active-download-btn') as HTMLButtonElement,
};

let currentTabId: number | null = null;
let currentHost: string | null = null;
let currentTabUrl: string | null = null;
let currentResult: ScanResult | null = null;
let running = false;
let swarmRunning = false;
let swarmTimers: number[] = [];
let swarmFrame = 0;

export async function initActivePane(tabId: number, tabUrl: string): Promise<void> {
  currentTabId = tabId;
  currentTabUrl = tabUrl;
  try {
    currentHost = normalizeHost(new URL(tabUrl).hostname);
  } catch {
    currentHost = null;
  }
  el.hostLine.textContent = currentHost ?? '(not a web page)';
  el.hostLine.title = tabUrl;

  el.authzSave.addEventListener('click', saveAuthorizationFromForm);
  el.authzRevoke.addEventListener('click', revokeCurrent);
  el.runBtn.addEventListener('click', startActiveScan);
  el.swarmBtn.addEventListener('click', startSwarmScan);
  el.downloadBtn.addEventListener('click', () => {
    // Delegated to popup.ts via a custom event to reuse the download helper.
    document.dispatchEvent(new CustomEvent('bugseek:download-active'));
  });

  wireScopeModeRadios();
  void refreshBackendBadge();
  void initBackendKeyRow();
  await refreshAuthzState();
  await restoreLastResult();
}

export function handleActiveMessage(msg: ScanMessage): boolean {
  if (msg.type === 'ACTIVE_PROGRESS') {
    setStatus(msg.step);
    renderThrottle(msg.requestsMade, msg.rateLimitMs, msg.nextRequestInMs);
    hideError();
    return true;
  }
  if (msg.type === 'ACTIVE_DONE') {
    currentResult = msg.result;
    renderActiveResult(msg.result);
    setStatus(
      `Active scan complete in ${(msg.result.durationMs / 1000).toFixed(1)}s — ` +
        `${msg.result.findings.length} finding(s), ` +
        `${msg.result.chains?.length ?? 0} attack chain(s).`,
    );
    setRunning(false);
    return true;
  }
  if (msg.type === 'ACTIVE_ERROR') {
    showError(msg.error);
    setRunning(false);
    setStatus('');
    return true;
  }
  return false;
}

export function getActiveResult(): ScanResult | null {
  return currentResult;
}

// ---------------------------------------------------------------------------
// Authorization flow
// ---------------------------------------------------------------------------

async function refreshAuthzState(): Promise<void> {
  if (!currentHost) {
    el.authzForm.hidden = true;
    el.authzAuthorized.hidden = true;
    showAuthzError('Active testing needs a regular web page (http/https).');
    el.runBtn.disabled = true;
    return;
  }
  const rec = await getAuthorization(currentHost);
  const authorized = !!rec;
  el.authzForm.hidden = authorized;
  el.authzAuthorized.hidden = !authorized;
  el.runBtn.disabled = !authorized || running;
  hideAuthzError();
  if (rec) renderAuthzSummary(rec);
}

function checkedRadio(name: string): string | null {
  const r = el.authzForm.querySelector<HTMLInputElement>(
    `input[name="${name}"]:checked`,
  );
  return r?.value ?? null;
}

function inputValue(id: string): string {
  return (document.getElementById(id) as HTMLInputElement).value.trim();
}

function inputChecked(id: string): boolean {
  return (document.getElementById(id) as HTMLInputElement).checked;
}

function wireScopeModeRadios(): void {
  const subdomains = document.getElementById(
    'authz-subdomains',
  ) as HTMLInputElement;
  el.authzForm
    .querySelectorAll<HTMLInputElement>('input[name="authz-scope"]')
    .forEach((r) =>
      r.addEventListener('change', () => {
        subdomains.disabled = r.value !== 'full-domain' || !r.checked;
      }),
    );
}

async function saveAuthorizationFromForm(): Promise<void> {
  hideAuthzError();
  if (!currentHost) return;

  const basis = checkedRadio('authz-type') as AuthorizationRecord['type'] | null;
  const scopeMode = checkedRadio('authz-scope') as
    | AuthorizationRecord['scope']['mode']
    | null;
  const confirmed = inputChecked('authz-confirm');
  if (!basis || !scopeMode) {
    showAuthzError('Choose an authorization basis and a scope.');
    return;
  }
  if (!confirmed) {
    showAuthzError(
      'You must tick the confirmation checkbox to authorize active testing.',
    );
    return;
  }

  let rateLimitMs = parseInt(inputValue('authz-ratelimit'), 10);
  if (Number.isNaN(rateLimitMs)) rateLimitMs = DEFAULT_ACTIVE_REQUEST_GAP_MS;
  rateLimitMs = Math.max(MIN_ACTIVE_REQUEST_GAP_MS, rateLimitMs);

  const programName = inputValue('authz-program') || undefined;
  const excludedHosts = inputValue('authz-excluded-hosts')
    .split(/[\s,]+/)
    .map((h) => h.trim())
    .filter(Boolean);
  const excludedPaths = inputValue('authz-excluded-paths')
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  const allowAuthProbes = inputChecked('authz-probes');
  const includeSubdomains =
    scopeMode === 'full-domain' ? inputChecked('authz-subdomains') : false;

  const statement =
    `I confirm that I am authorized to actively test ${currentHost} ` +
    `(${basisLabel(basis)}${programName ? ` — ${programName}` : ''}). ` +
    `I accept responsibility for this testing activity.`;

  const rec: AuthorizationRecord = {
    id: newAuthorizationId(),
    targetHost: currentHost,
    type: basis,
    programName,
    statement,
    scope: {
      mode: scopeMode,
      includeSubdomains,
      excludedHosts,
      excludedPaths,
      maxRequestsPerSecond: Math.min(4, 1000 / rateLimitMs),
    },
    allowAuthProbes,
    rateLimitMs,
    confirmedAt: new Date().toISOString(),
  };

  await saveAuthorization(rec);
  await refreshAuthzState();
  setStatus('Authorization saved. You can now run active tests.');
}

function renderAuthzSummary(rec: AuthorizationRecord): void {
  el.authzSummary.innerHTML = '';
  const rows: Array<[string, string]> = [
    ['Basis', basisLabel(rec.type) + (rec.programName ? ` — ${rec.programName}` : '')],
    ['Scope', summarizeScope(rec)],
    ['Login-form testing', rec.allowAuthProbes ? 'Allowed (separate grant)' : 'Not allowed'],
    ['Request throttle', `≥ ${rec.rateLimitMs}ms between requests`],
    ['Confirmed', new Date(rec.confirmedAt).toLocaleString()],
  ];
  const dl = document.createElement('dl');
  dl.className = 'authz-dl';
  for (const [k, v] of rows) {
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    dd.textContent = v;
    dl.appendChild(dt);
    dl.appendChild(dd);
  }
  el.authzSummary.appendChild(dl);
}

async function revokeCurrent(): Promise<void> {
  if (!currentHost) return;
  await revokeAuthorization(currentHost);
  currentResult = null;
  el.results.hidden = true;
  await refreshAuthzState();
  setStatus('Authorization revoked. Active testing is locked again.');
}

function showAuthzError(text: string): void {
  el.authzError.textContent = text;
  el.authzError.hidden = false;
}

function hideAuthzError(): void {
  el.authzError.hidden = true;
  el.authzError.textContent = '';
}

// ---------------------------------------------------------------------------
// Scan controls + throttle status
// ---------------------------------------------------------------------------

async function startActiveScan(): Promise<void> {
  if (currentTabId === null || running) return;
  hideError();
  const wantDeep = inputChecked('active-deep-inspect');
  if (wantDeep) {
    // chrome.permissions.request must run inside the click gesture.
    const granted = await chrome.permissions.request({
      permissions: ['debugger'],
    });
    if (!granted) {
      showError(
        'Deep inspect needs the debugger permission. Untick it to run a standard scan, or grant the permission and try again.',
      );
      return;
    }
  }
  setRunning(true);
  setStatus(
    wantDeep
      ? 'Starting active scan with Deep inspect…'
      : 'Starting active scan…',
  );
  renderThrottle(0, 0, 0);
  chrome.runtime.sendMessage({
    type: 'RUN_ACTIVE_SCAN',
    tabId: currentTabId,
    deepInspect: wantDeep,
  } satisfies ScanMessage);
}

function setRunning(v: boolean): void {
  running = v;
  el.runBtn.disabled = v;
  el.runBtn.textContent = v ? 'Testing… (rate-limited)' : 'Run active tests';
  if (!v) void refreshAuthzState();
}

/**
 * Deploy the backend AI swarm: a head agent plus specialist worker agents
 * run inline on the server against the authorized target (Hunter plan,
 * 25 credits). Requires the same authorization record as local active
 * testing — the backend re-validates it.
 */
async function startSwarmScan(): Promise<void> {
  if (swarmRunning || running) return;
  hideError();

  const authz = currentHost ? await getAuthorization(currentHost) : null;
  if (!authz || !currentTabUrl) {
    showError(
      !authz
        ? 'Save an authorization record first — the swarm needs the same explicit confirmation as active testing.'
        : 'No target page detected.',
    );
    return;
  }
  const apiKey = await getBackendApiKey();
  if (!apiKey) {
    showError('Save a backend API key first — the swarm runs on the backend (Hunter plan required).');
    return;
  }

  const authorization: SwarmAuthorizationInput = {
    type: authz.type,
    programName: authz.programName,
    statement: authz.statement,
    confirmed: true,
  };

  swarmRunning = true;
  el.swarmBtn.disabled = true;
  el.swarmBtn.textContent = 'Swarm running…';
  setStatus('AI swarm deployed — head agent coordinating specialist workers…');
  showSwarmDeploying();

  try {
    const outcome = await runSwarmScan(currentTabUrl, authorization, {
      mode: authz.scope.mode,
      includeSubdomains: authz.scope.includeSubdomains,
      excludedHosts: authz.scope.excludedHosts,
      excludedPaths: authz.scope.excludedPaths,
    });
    if (!outcome) {
      hideSwarmPanel();
      showError('Backend unreachable — is the BugSeek backend running?');
      return;
    }
    // Map swarm findings onto the extension Finding shape for rendering.
    const findings = outcome.findings.map((f, i) => ({
      id: f.id || `swarm-${i}`,
      category: f.category as import('../lib/types').FindingCategory,
      title: f.title,
      description: f.description,
      severity: f.severity,
      confidence: f.confidence,
      location: f.location,
      evidence: f.evidence,
      remediation: f.remediation,
      mode: 'active' as const,
      cvssScore: f.cvssScore,
      cvssVector: f.cvssVector,
      trapProbability: f.trapProbability,
      honeypotSuspect: f.honeypotSuspect,
    }));
    renderSwarmPlayback(outcome);
    el.results.hidden = false;
    el.chains.innerHTML = '';
    const h = document.createElement('h2');
    h.className = 'chains-heading';
    h.textContent = 'AI swarm — head agent summary';
    el.chains.appendChild(h);
    const sum = document.createElement('p');
    sum.className = 'card-body';
    sum.textContent = outcome.headSummary;
    el.chains.appendChild(sum);

    renderSummary(el.summary, findings as import('../lib/types').Finding[]);
    renderFindings(
      el.findings,
      findings as import('../lib/types').Finding[],
      SEVERITIES,
      'No findings — the swarm came back clean.',
    );
    setStatus(
      `Swarm complete — ${outcome.findings.length} finding(s) from ` +
        `${outcome.workerReports.length} specialist worker(s).`,
    );
  } catch (err) {
    hideSwarmPanel();
    showError(
      `Swarm failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    swarmRunning = false;
    el.swarmBtn.disabled = false;
    el.swarmBtn.textContent = 'Run AI swarm';
  }
}

// ---------------------------------------------------------------------------
// Swarm run-record panel
//
// The swarm runs inline on the backend, so worker reports only exist once
// the run is DONE. While waiting we show a deploying state; when the
// response lands we play the real run record back — worker cards stagger
// in, then the security score counts up. The caption says "run record" so
// the playback never pretends to be a live feed. All strings render via
// textContent (worker names/summaries are server-generated, never raw HTML).
// ---------------------------------------------------------------------------

const SWARM_CARD_STAGGER_MS = 320;
const SWARM_SCORE_COUNT_MS = 900;
const SCORE_RING_R = 34;
const SCORE_RING_C = 2 * Math.PI * SCORE_RING_R;

function prefersReducedMotion(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function clearSwarmTimers(): void {
  swarmTimers.forEach((t) => window.clearTimeout(t));
  swarmTimers = [];
  if (swarmFrame) {
    cancelAnimationFrame(swarmFrame);
    swarmFrame = 0;
  }
}

function swarmLater(fn: () => void, ms: number): void {
  swarmTimers.push(window.setTimeout(fn, ms));
}

function hideSwarmPanel(): void {
  clearSwarmTimers();
  el.swarmPanel.hidden = true;
  el.swarmPanel.innerHTML = '';
}

function showSwarmDeploying(): void {
  clearSwarmTimers();
  const panel = el.swarmPanel;
  panel.innerHTML = '';
  panel.hidden = false;

  const h = document.createElement('h2');
  h.className = 'chains-heading';
  h.textContent = 'AI swarm';
  panel.appendChild(h);

  const box = document.createElement('div');
  box.className = 'swarm-deploying';
  const label = document.createElement('span');
  label.textContent = 'Head agent deploying specialists';
  box.appendChild(label);
  const dots = document.createElement('span');
  dots.className = 'swarm-dots';
  dots.setAttribute('aria-hidden', 'true');
  for (let i = 0; i < 3; i++) dots.appendChild(document.createElement('span'));
  box.appendChild(dots);
  panel.appendChild(box);

  const caption = document.createElement('p');
  caption.className = 'swarm-caption';
  caption.textContent = 'Specialists report back when the run completes.';
  panel.appendChild(caption);
}

function buildSwarmCard(
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

  if (w.summary) {
    const sum = document.createElement('p');
    sum.className = 'swarm-card-summary';
    sum.textContent = w.summary;
    card.appendChild(sum);
  }
  return card;
}

function gradeColor(grade: string): string {
  switch (grade.toUpperCase()) {
    case 'A':
    case 'B':
      return 'var(--low)';
    case 'C':
      return 'var(--medium)';
    case 'D':
    case 'E':
      return 'var(--high)';
    case 'F':
      return 'var(--critical)';
    default:
      return 'var(--accent)';
  }
}

/** Big count-up number + letter grade inside an SVG progress ring. */
function renderSwarmScore(
  box: HTMLElement,
  score: { value: number; grade: string },
  instant: boolean,
): void {
  const color = gradeColor(score.grade);
  const ns = 'http://www.w3.org/2000/svg';

  const wrap = document.createElement('div');
  wrap.className = 'score-ring-wrap';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 84 84');
  svg.setAttribute('class', 'score-ring');
  const track = document.createElementNS(ns, 'circle');
  track.setAttribute('cx', '42');
  track.setAttribute('cy', '42');
  track.setAttribute('r', String(SCORE_RING_R));
  track.setAttribute('class', 'score-ring-track');
  const prog = document.createElementNS(ns, 'circle');
  prog.setAttribute('cx', '42');
  prog.setAttribute('cy', '42');
  prog.setAttribute('r', String(SCORE_RING_R));
  prog.setAttribute('class', 'score-ring-prog');
  prog.style.stroke = color;
  prog.style.strokeDasharray = String(SCORE_RING_C);
  prog.style.strokeDashoffset = String(SCORE_RING_C);
  svg.appendChild(track);
  svg.appendChild(prog);
  const gradeEl = document.createElement('div');
  gradeEl.className = 'score-grade';
  gradeEl.style.color = color;
  gradeEl.textContent = score.grade;
  wrap.appendChild(svg);
  wrap.appendChild(gradeEl);
  box.appendChild(wrap);

  const side = document.createElement('div');
  const num = document.createElement('div');
  num.className = 'score-number';
  num.textContent = '0';
  const label = document.createElement('div');
  label.className = 'score-label';
  label.textContent = 'Security score';
  const sub = document.createElement('div');
  sub.className = 'score-sub';
  sub.textContent = 'out of 100 · higher is safer';
  side.appendChild(num);
  side.appendChild(label);
  side.appendChild(sub);
  box.appendChild(side);

  const target = Math.max(0, Math.min(100, score.value));
  const setProgress = (v: number): void => {
    num.textContent = String(Math.round(v));
    prog.style.strokeDashoffset = String(SCORE_RING_C * (1 - v / 100));
  };
  if (instant) {
    setProgress(target);
    return;
  }
  const start = performance.now();
  const tick = (now: number): void => {
    const t = Math.min(1, (now - start) / SWARM_SCORE_COUNT_MS);
    const eased = 1 - Math.pow(1 - t, 3);
    setProgress(target * eased);
    swarmFrame = t < 1 ? requestAnimationFrame(tick) : 0;
  };
  swarmFrame = requestAnimationFrame(tick);
}

function renderSwarmPlayback(outcome: SwarmOutcome): void {
  clearSwarmTimers();
  const reduce = prefersReducedMotion();
  const panel = el.swarmPanel;
  panel.innerHTML = '';
  panel.hidden = false;

  const h = document.createElement('h2');
  h.className = 'chains-heading';
  h.textContent = 'AI swarm — run record';
  panel.appendChild(h);

  const caption = document.createElement('p');
  caption.className = 'swarm-caption';
  caption.textContent = 'Run record — playback of the completed run, not a live feed.';
  panel.appendChild(caption);

  const grid = document.createElement('div');
  grid.className = 'swarm-grid';
  panel.appendChild(grid);
  const cards = outcome.workerReports.map((w) => buildSwarmCard(w, !reduce));
  cards.forEach((c) => grid.appendChild(c));

  // Run totals (the same accounting line the popup has always shown).
  const totals = document.createElement('div');
  totals.className = reduce ? 'stat-line' : 'stat-line swarm-enter';
  totals.textContent =
    `${outcome.testsRun} tests · ${(outcome.tokensUsed / 1000).toFixed(1)}k tokens` +
    ` · ${(outcome.durationMs / 1000).toFixed(1)}s · scan ${outcome.scanId}`;
  panel.appendChild(totals);

  const score = outcome.score ?? null;
  const scoreBox = document.createElement('div');
  if (score) {
    scoreBox.className = reduce ? 'swarm-score' : 'swarm-score swarm-enter';
    panel.appendChild(scoreBox);
  }

  if (reduce) {
    // Final states immediately — no stagger, no count-up.
    if (score) renderSwarmScore(scoreBox, score, true);
    return;
  }

  cards.forEach((card, i) => {
    swarmLater(
      () => card.classList.add('swarm-enter-in'),
      150 + i * SWARM_CARD_STAGGER_MS,
    );
  });
  swarmLater(
    () => {
      totals.classList.add('swarm-enter-in');
      if (score) {
        scoreBox.classList.add('swarm-enter-in');
        renderSwarmScore(scoreBox, score, false);
      }
    },
    150 + cards.length * SWARM_CARD_STAGGER_MS + 150,
  );
}

function renderThrottle(
  requestsMade: number,
  rateLimitMs: number,
  nextRequestInMs: number,
): void {
  if (rateLimitMs <= 0) {
    el.throttle.hidden = true;
    return;
  }
  el.throttle.hidden = false;
  const next =
    nextRequestInMs > 50
      ? ` · next request in ${(nextRequestInMs / 1000).toFixed(1)}s`
      : ' · ready';
  el.throttle.textContent =
    `⏱ Throttle: ${requestsMade} request(s) sent · ≥${rateLimitMs}ms gap${next}`;
}

async function refreshBackendBadge(): Promise<void> {
  el.backendBadge.textContent = 'Backend: checking…';
  el.backendBadge.className = 'backend-badge backend-unknown';
  try {
    const s = await checkBackendStatus();
    if (s.reachable) {
      el.backendBadge.textContent = `Backend: connected (${s.baseUrl}) — AI deepening available`;
      el.backendBadge.className = 'backend-badge backend-on';
    } else {
      el.backendBadge.textContent =
        'Backend: offline — running standalone (local checks only)';
      el.backendBadge.className = 'backend-badge backend-off';
    }
  } catch {
    el.backendBadge.textContent = 'Backend: offline — running standalone';
    el.backendBadge.className = 'backend-badge backend-off';
  }
}

/** Backend API-key row: stored locally, sent as x-api-key on backend calls. */
async function initBackendKeyRow(): Promise<void> {
  const input = document.getElementById('backend-api-key') as HTMLInputElement | null;
  const save = document.getElementById('backend-api-key-save') as HTMLButtonElement | null;
  if (!input || !save) return;
  input.value = (await getBackendApiKey()) ? '••••••••' : '';
  input.placeholder = 'bs_… (optional — enables AI deepening & history)';
  const doSave = async () => {
    const v = input.value.trim();
    if (v === '••••••••') return; // unchanged placeholder
    if (v && !v.startsWith('bs_')) {
      input.setCustomValidity('Key should start with bs_');
      input.reportValidity();
      return;
    }
    input.setCustomValidity('');
    await setBackendApiKey(v || null);
    input.value = v ? '••••••••' : '';
    void refreshBackendBadge();
  };
  save.addEventListener('click', () => void doSave());
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      void doSave();
    }
  });
}

async function restoreLastResult(): Promise<void> {
  if (currentTabId === null) return;
  const stored = await chrome.storage.local.get(
    `${STORAGE_KEYS.activeScanPrefix}${currentTabId}`,
  );
  const prev = stored[
    `${STORAGE_KEYS.activeScanPrefix}${currentTabId}`
  ] as ScanResult | undefined;
  if (prev) {
    currentResult = prev;
    renderActiveResult(prev);
    setStatus(`Last active scan: ${new Date(prev.scannedAt).toLocaleString()}`);
  }
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

function renderActiveResult(result: ScanResult): void {
  el.results.hidden = false;
  el.downloadBtn.disabled = false;

  // Stats line: authorization + throttle accounting + backend.
  el.stats.innerHTML = '';
  const stats = result.activeStats;
  const bits: string[] = [];
  if (result.authorization) {
    bits.push(
      `Authorized: ${basisLabel(result.authorization.type)} (${new Date(result.authorization.confirmedAt).toLocaleDateString()})`,
    );
  }
  if (stats) {
    bits.push(
      `${stats.requestsMade}/${stats.maxRequests} requests · throttled ${(stats.throttledMs / 1000).toFixed(1)}s total · ${stats.rateLimitMs}ms gap`,
    );
    bits.push(
      stats.backendReachable
        ? stats.backendDeepened
          ? 'Backend AI deepened the attack chains'
          : 'Backend reachable (no chains to deepen)'
        : 'Backend offline — standalone local results',
    );
  }
  const flagged = result.findings.filter((f) => f.honeypotSuspect).length;
  if (flagged > 0) {
    bits.push(`${flagged} finding(s) flagged as possible traps — not reported as vulnerabilities`);
  }
  for (const b of bits) {
    const div = document.createElement('div');
    div.className = 'stat-line';
    div.textContent = b;
    el.stats.appendChild(div);
  }

  // Attack chains.
  el.chains.innerHTML = '';
  const chains = result.chains ?? [];
  if (chains.length > 0) {
    const h = document.createElement('h2');
    h.className = 'chains-heading';
    h.textContent = `Attack chains (${chains.length})`;
    el.chains.appendChild(h);
    for (const c of chains) {
      const card = document.createElement('details');
      card.className = `card card-${c.severity} chain-card`;
      const summary = document.createElement('summary');
      summary.className = 'card-title';
      const badge = document.createElement('span');
      badge.className = `sev-badge sev-${c.severity}`;
      badge.textContent = c.severity.toUpperCase();
      summary.appendChild(badge);
      summary.appendChild(document.createTextNode(` 🔗 ${c.title}`));
      if (c.aiDeepened) {
        const ai = document.createElement('span');
        ai.className = 'tag tag-ai';
        ai.textContent = 'AI-DEEPENED';
        ai.title = 'Verified/deepened by the backend AI agent';
        summary.appendChild(document.createTextNode(' '));
        summary.appendChild(ai);
      }
      card.appendChild(summary);
      const body = document.createElement('div');
      body.className = 'card-body';
      const desc = document.createElement('p');
      desc.textContent = c.description;
      body.appendChild(desc);
      const impact = document.createElement('p');
      impact.innerHTML = `<strong>Impact:</strong> `;
      impact.appendChild(document.createTextNode(c.impact));
      body.appendChild(impact);
      const members = document.createElement('p');
      members.className = 'chain-members';
      members.textContent = `Links ${c.findingIds.length} finding(s): ${c.findingIds.join(', ')}`;
      body.appendChild(members);
      card.appendChild(body);
      el.chains.appendChild(card);
    }
  }

  renderSummary(el.summary, result.findings);
  // Trap-flagged findings render last, visually separated.
  const vulns = result.findings.filter((f) => !f.honeypotSuspect);
  const traps = result.findings.filter((f) => f.honeypotSuspect);
  renderFindings(
    el.findings,
    vulns,
    SEVERITIES,
    'No findings — the active checks came back clean.',
  );
  if (traps.length > 0) {
    const h = document.createElement('h2');
    h.className = 'group-heading group-info trap-heading';
    h.textContent = `Flagged as possible traps (${traps.length}) — not vulnerabilities`;
    el.findings.appendChild(h);
    traps.forEach((f, i) => el.findings.appendChild(findingCard(f, i)));
  }
}

function setStatus(text: string): void {
  el.status.textContent = text;
}

function showError(text: string): void {
  el.error.textContent = text;
  el.error.hidden = false;
}

function hideError(): void {
  el.error.hidden = true;
  el.error.textContent = '';
}

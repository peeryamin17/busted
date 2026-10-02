/**
 * Active testing pane: authorization confirmation flow, scope definition,
 * throttle status, scan controls, and results (findings + attack chains).
 *
 * Active testing is LOCKED until the user completes the authorization form.
 * No active request is ever sent before that point.
 */
import type {
  AuthorizationRecord,
  Finding,
  FindingCategory,
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
import {
  checkBackendStatus,
  checkProgrammeScope,
  getBackendApiKey,
  getEnginesStatus,
  getStoredProgramme,
  importFindingsReport,
  runEngineScan,
  runSwarmScan,
  searchProgrammes,
  setBackendApiKey,
  setStoredProgramme,
} from '../lib/apiClient';
import type {
  BackendFinding,
  EngineId,
  EngineStatusEntry,
  ImportFormat,
  ProgrammeRef,
  ProgrammeScopeCheck,
  ProgrammeSummary,
  ScopePlatform,
  SwarmAuthorizationInput,
  SwarmOutcome,
} from '../lib/apiClient';
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
  // Open-source engines + report import
  enginesList: document.getElementById('engines-list') as HTMLElement,
  enginesRunBtn: document.getElementById('engines-run-btn') as HTMLButtonElement,
  importFormat: document.getElementById('import-format') as HTMLSelectElement,
  importFile: document.getElementById('import-file') as HTMLInputElement,
  // Programme scope picker + verdict chip
  scopePlatform: document.getElementById('scope-platform') as HTMLSelectElement,
  scopeHandle: document.getElementById('scope-handle') as HTMLInputElement,
  scopeList: document.getElementById('scope-programme-list') as HTMLDataListElement,
  scopeChip: document.getElementById('scope-chip') as HTMLElement,
  scopeNote: document.getElementById('scope-blocked-note') as HTMLElement,
};

let currentTabId: number | null = null;
let currentHost: string | null = null;
let currentTabUrl: string | null = null;
let currentResult: ScanResult | null = null;
let running = false;
let swarmRunning = false;
let enginesRunning = false;
let importBusy = false;
let engineStatusCache: EngineStatusEntry[] | null = null;
let swarmTimers: number[] = [];
let swarmFrame = 0;
// Programme scope state
let authorisedNow = false;
let scopeRef: ProgrammeRef | null = null;
let scopeCheck: ProgrammeScopeCheck | null = null;
let scopeSuggestions: ProgrammeSummary[] = [];
let scopeSeq = 0;
let scopeSearchTimer = 0;
let scopeCommitTimer = 0;

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
  el.enginesRunBtn.addEventListener('click', startEnginesRun);
  el.importFile.addEventListener('change', () => {
    const file = el.importFile.files?.[0];
    if (file) void handleImportFile(file);
  });
  el.downloadBtn.addEventListener('click', () => {
    // Delegated to popup.ts via a custom event to reuse the download helper.
    document.dispatchEvent(new CustomEvent('bugseek:download-active'));
  });

  wireScopeModeRadios();
  void refreshBackendBadge();
  void initBackendKeyRow();
  void initScopePicker();
  renderEnginesStatus(null);
  void refreshEnginesStatus();
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
  authorisedNow = authorized;
  el.authzForm.hidden = authorized;
  el.authzAuthorized.hidden = !authorized;
  el.runBtn.disabled = !authorized || running;
  applyScopeGate();
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
// Programme scope picker (HackerOne / Bugcrowd)
//
// Optional: the hunter names the public programme they're working under and
// BugSeek checks the current host against that programme's published scope.
// The verdict is evidence next to the authorisation record — picking a
// programme never authorises anything by itself. Only an explicit
// "out of scope" verdict pauses the active checks; "unknown" (backend
// offline, unlisted asset types) never blocks. No programme = the classic
// flow, unchanged. The backend re-checks and records the verdict on any
// swarm/engine scan that names a programme.
// ---------------------------------------------------------------------------

function scopePlatformLabel(platform: ScopePlatform): string {
  return platform === 'hackerone' ? 'HackerOne' : 'Bugcrowd';
}

function scopeBlocked(): boolean {
  return scopeCheck?.verdict === 'out_of_scope';
}

/** Why the active checks are paused — used by the blocked note and error line. */
function scopeBlockReason(): string {
  const name =
    scopeCheck?.programmeName ??
    (scopeRef ? scopePlatformLabel(scopeRef.platform) : 'the programme');
  return (
    `This host sits outside ${name}'s published scope, so active checks are paused. ` +
    'Pick the programme this target belongs to, or switch back to "No programme" ' +
    'if your authorisation comes from a contract or from owning the target.'
  );
}

/** Disable/enable the active-check buttons around the scope verdict. */
function applyScopeGate(): void {
  const blocked = scopeBlocked();
  el.scopeNote.hidden = !blocked;
  if (blocked) {
    el.runBtn.disabled = true;
    el.swarmBtn.disabled = true;
    el.enginesRunBtn.disabled = true;
    return;
  }
  el.runBtn.disabled = !authorisedNow || running;
  el.swarmBtn.disabled = swarmRunning;
  el.enginesRunBtn.disabled = enginesRunning;
}

type ScopeChipState = 'idle' | 'checking' | 'done';

function renderScopeChip(state: ScopeChipState): void {
  const chip = el.scopeChip;
  chip.className = 'scope-chip';
  if (!scopeRef) {
    chip.classList.add('scope-chip-neutral');
    chip.textContent = el.scopePlatform.value
      ? `Start typing a ${scopePlatformLabel(el.scopePlatform.value as ScopePlatform)} programme name or handle — we'll check this host against its published scope.`
      : 'No programme selected — your authorisation record below governs testing.';
    return;
  }
  const name = scopeCheck?.programmeName ?? scopeRef.handle;
  if (state === 'checking' || !scopeCheck) {
    chip.classList.add('scope-chip-neutral', 'scope-chip-checking');
    chip.textContent = `Checking ${currentHost ?? 'this host'} against ${name}'s published scope…`;
    return;
  }
  switch (scopeCheck.verdict) {
    case 'in_scope':
      chip.classList.add('scope-chip-in');
      chip.textContent = `In scope — ${scopeCheck.reason}`;
      break;
    case 'out_of_scope':
      chip.classList.add('scope-chip-out');
      chip.textContent = `Out of scope — ${scopeCheck.reason}`;
      break;
    case 'programme_not_found':
      chip.classList.add('scope-chip-neutral');
      chip.textContent = `No programme found — ${scopeCheck.reason}`;
      break;
    default:
      chip.classList.add('scope-chip-neutral');
      chip.textContent = `Scope unknown — ${scopeCheck.reason}`;
      break;
  }
}

async function runScopeCheck(): Promise<void> {
  const ref = scopeRef;
  if (!ref || !currentHost) {
    scopeCheck = null;
    renderScopeChip('idle');
    applyScopeGate();
    return;
  }
  // Supersede any in-flight check: rapid programme changes stay responsive
  // and a stale answer can never overwrite the current one.
  const seq = ++scopeSeq;
  scopeCheck = null;
  renderScopeChip('checking');
  const result = await checkProgrammeScope(
    ref,
    currentTabUrl ?? `https://${currentHost}/`,
  );
  if (seq !== scopeSeq) return;
  scopeCheck = result ?? {
    ...ref,
    verdict: 'unknown',
    reason:
      "the backend didn't answer, so this host couldn't be checked against the published scope just now",
  };
  renderScopeChip('done');
  applyScopeGate();
}

async function refreshScopeSuggestions(): Promise<void> {
  const platform = el.scopePlatform.value as ScopePlatform | '';
  const query = el.scopeHandle.value.trim();
  if (!platform || query.length < 2) {
    scopeSuggestions = [];
    el.scopeList.innerHTML = '';
    return;
  }
  const results = await searchProgrammes(platform, query);
  scopeSuggestions = (results ?? []).filter((p) => p.platform === platform);
  el.scopeList.innerHTML = '';
  for (const p of scopeSuggestions) {
    const opt = document.createElement('option');
    opt.value = p.handle;
    opt.label = p.name;
    opt.textContent = p.name;
    el.scopeList.appendChild(opt);
  }
}

/** Resolve whatever the hunter typed (handle or picked programme name) into a stored ref. */
async function commitScopeSelection(): Promise<void> {
  const platform = el.scopePlatform.value as ScopePlatform | '';
  const raw = el.scopeHandle.value.trim();
  if (!platform || !raw) {
    const had = scopeRef !== null || scopeCheck !== null;
    scopeRef = null;
    scopeCheck = null;
    if (had) await setStoredProgramme(null);
    renderScopeChip('idle');
    applyScopeGate();
    return;
  }
  const lowered = raw.toLowerCase();
  const match = scopeSuggestions.find(
    (p) =>
      p.platform === platform &&
      (p.handle === lowered || p.name.toLowerCase() === lowered),
  );
  const ref: ProgrammeRef = { platform, handle: match?.handle ?? lowered };
  const changed =
    ref.platform !== scopeRef?.platform || ref.handle !== scopeRef?.handle;
  scopeRef = ref;
  if (changed) {
    scopeCheck = null;
    await setStoredProgramme(ref);
  }
  await runScopeCheck();
}

async function initScopePicker(): Promise<void> {
  el.scopePlatform.addEventListener('change', () => {
    el.scopeHandle.disabled = !el.scopePlatform.value;
    scopeSuggestions = [];
    el.scopeList.innerHTML = '';
    if (el.scopePlatform.value) void refreshScopeSuggestions();
    void commitScopeSelection();
  });
  el.scopeHandle.addEventListener('input', () => {
    window.clearTimeout(scopeSearchTimer);
    window.clearTimeout(scopeCommitTimer);
    scopeSearchTimer = window.setTimeout(() => {
      void refreshScopeSuggestions();
    }, 300);
    // Commit on a longer pause so a half-typed handle doesn't fire checks.
    scopeCommitTimer = window.setTimeout(() => {
      void commitScopeSelection();
    }, 700);
  });
  el.scopeHandle.addEventListener('change', () => {
    window.clearTimeout(scopeCommitTimer);
    void commitScopeSelection();
  });

  const stored = await getStoredProgramme();
  if (stored) {
    el.scopePlatform.value = stored.platform;
    el.scopeHandle.disabled = false;
    el.scopeHandle.value = stored.handle;
    scopeRef = stored;
    void refreshScopeSuggestions();
    await runScopeCheck();
  } else {
    renderScopeChip('idle');
  }
}

// ---------------------------------------------------------------------------
// Scan controls + throttle status
// ---------------------------------------------------------------------------

async function startActiveScan(): Promise<void> {
  if (currentTabId === null || running) return;
  hideError();
  if (scopeBlocked()) {
    showError(scopeBlockReason());
    return;
  }
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
  if (scopeBlocked()) {
    showError(scopeBlockReason());
    return;
  }

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
    const outcome = await runSwarmScan(
      currentTabUrl,
      authorization,
      {
        mode: authz.scope.mode,
        includeSubdomains: authz.scope.includeSubdomains,
        excludedHosts: authz.scope.excludedHosts,
        excludedPaths: authz.scope.excludedPaths,
      },
      scopeRef ?? undefined,
    );
    if (!outcome) {
      hideSwarmPanel();
      showError('Backend unreachable — is the BugSeek backend running?');
      return;
    }
    // Map swarm findings onto the extension Finding shape for rendering.
    const findings = toExtensionFindings(outcome.findings, 'swarm');
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

    renderSummary(el.summary, findings);
    renderFindings(
      el.findings,
      findings,
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
// Open-source engines + report import
//
// The backend orchestrates three open-source scanners (WhatWeb, Nikto,
// Nuclei) and can import reports from external scanners (ZAP / Nuclei /
// Nikto / SQLMap). Both flows render through the same results area and the
// same finding cards as the swarm. All strings render via textContent.
// ---------------------------------------------------------------------------

/** Map backend findings (swarm / engines / import) onto the extension Finding shape. */
function toExtensionFindings(raw: BackendFinding[], prefix: string): Finding[] {
  return raw.map((f, i) => ({
    id: f.id || `${prefix}-${i}`,
    category: f.category as FindingCategory,
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
  })) as Finding[];
}

const ENGINE_META: Array<{ id: EngineId; name: string; blurb: string }> = [
  { id: 'whatweb', name: 'WhatWeb', blurb: 'fingerprinting' },
  { id: 'nikto', name: 'Nikto', blurb: 'server checks' },
  { id: 'nuclei', name: 'Nuclei', blurb: 'template scans' },
];

let enginesStatusLoaded = false;

function renderEnginesStatus(entries: EngineStatusEntry[] | null): void {
  el.enginesList.innerHTML = '';
  for (const meta of ENGINE_META) {
    const entry = entries?.find((e) => e.engine === meta.id);
    const row = document.createElement('div');
    row.className = 'engine-row';

    const main = document.createElement('div');
    main.className = 'engine-main';
    const name = document.createElement('span');
    name.className = 'engine-name';
    name.textContent = meta.name;
    main.appendChild(name);
    const blurb = document.createElement('span');
    blurb.className = 'engine-blurb';
    blurb.textContent = `— ${meta.blurb}`;
    main.appendChild(blurb);
    row.appendChild(main);

    const right = document.createElement('div');
    right.className = 'engine-right';
    const state = document.createElement('span');
    let detail: string | undefined;
    if (!enginesStatusLoaded) {
      state.className = 'engine-state engine-state-unknown';
      state.textContent = 'checking…';
    } else if (!entries) {
      state.className = 'engine-state engine-state-off';
      state.textContent = 'Unavailable';
      detail = 'Backend unreachable';
    } else if (entry?.available) {
      state.className = 'engine-state engine-state-on';
      state.textContent = 'Available';
      detail = entry.detail;
    } else {
      state.className = 'engine-state engine-state-off';
      state.textContent = 'Unavailable';
      detail = entry?.detail ?? 'Not reported by the backend';
    }
    right.appendChild(state);
    if (detail) {
      const d = document.createElement('span');
      d.className = 'engine-detail';
      d.textContent = detail;
      right.appendChild(d);
    }
    row.appendChild(right);
    el.enginesList.appendChild(row);
  }
}

async function refreshEnginesStatus(): Promise<EngineStatusEntry[] | null> {
  const entries = await getEnginesStatus();
  engineStatusCache = entries;
  enginesStatusLoaded = true;
  renderEnginesStatus(entries);
  return entries;
}

/** Render a heading + stat lines + findings into the shared active results area. */
function renderBackendResults(
  heading: string,
  statLines: string[],
  findings: Finding[],
  emptyText: string,
): void {
  hideSwarmPanel();
  el.results.hidden = false;
  el.chains.innerHTML = '';
  const h = document.createElement('h2');
  h.className = 'chains-heading';
  h.textContent = heading;
  el.chains.appendChild(h);
  for (const line of statLines) {
    const div = document.createElement('div');
    div.className = 'stat-line';
    div.textContent = line;
    el.chains.appendChild(div);
  }
  renderSummary(el.summary, findings);
  renderFindings(el.findings, findings, SEVERITIES, emptyText);
}

/**
 * Run every AVAILABLE open-source engine, in sequence, against the current
 * target on the backend. Same gating as the swarm: a saved authorization
 * record plus a backend API key are required (the backend re-validates).
 */
async function startEnginesRun(): Promise<void> {
  if (enginesRunning || swarmRunning || running) return;
  hideError();
  if (scopeBlocked()) {
    showError(scopeBlockReason());
    return;
  }

  const authz = currentHost ? await getAuthorization(currentHost) : null;
  if (!authz || !currentTabUrl) {
    showError(
      !authz
        ? 'Save an authorization record first — the engines need the same explicit confirmation as active testing.'
        : 'No target page detected.',
    );
    return;
  }
  const apiKey = await getBackendApiKey();
  if (!apiKey) {
    showError('Save a backend API key first — the engines run on the backend (Hunter plan required).');
    return;
  }

  const status = engineStatusCache ?? (await refreshEnginesStatus());
  const available = ENGINE_META.filter((m) =>
    status?.some((e) => e.engine === m.id && e.available),
  );
  if (available.length === 0) {
    showError(
      status
        ? 'No open-source engines are available on the backend.'
        : 'Backend unreachable — is the BugSeek backend running?',
    );
    return;
  }

  const authorization: SwarmAuthorizationInput = {
    type: authz.type,
    programName: authz.programName,
    statement: authz.statement,
    confirmed: true,
  };

  enginesRunning = true;
  el.enginesRunBtn.disabled = true;
  el.enginesRunBtn.textContent = 'Engines running…';

  const merged: Finding[] = [];
  const lines: string[] = [];
  let failures = 0;
  let firstError = '';
  try {
    for (const meta of available) {
      setStatus(`Running ${meta.name} on the backend…`);
      try {
        const outcome = await runEngineScan(
          meta.id,
          currentTabUrl,
          authorization,
          scopeRef ?? undefined,
        );
        merged.push(...toExtensionFindings(outcome.findings, meta.id));
        lines.push(
          `${meta.name} — ${outcome.findings.length} finding(s)` +
            (outcome.score
              ? ` · score ${outcome.score.value}/100 (grade ${outcome.score.grade})`
              : ''),
        );
      } catch (err) {
        failures += 1;
        const msg = err instanceof Error ? err.message : String(err);
        if (!firstError) firstError = msg;
        lines.push(`${meta.name} — failed: ${msg}`);
      }
    }
    if (failures === available.length) {
      showError(firstError || 'All engines failed.');
      setStatus('');
      return;
    }
    renderBackendResults(
      'Open-source engines',
      lines,
      merged,
      'No findings — the engines came back clean.',
    );
    setStatus(
      `Engines complete — ${merged.length} finding(s) from ` +
        `${available.length - failures} of ${available.length} engine(s).`,
    );
  } finally {
    enginesRunning = false;
    el.enginesRunBtn.disabled = false;
    el.enginesRunBtn.textContent = 'Run engines';
  }
}

const MAX_IMPORT_BYTES = 25 * 1024 * 1024;

/** Import an external scanner report file (ZAP / Nuclei / Nikto / SQLMap). */
async function handleImportFile(file: File): Promise<void> {
  if (importBusy) return;
  hideError();
  if (!currentTabUrl) {
    showError('No target page detected.');
    return;
  }
  if (file.size > MAX_IMPORT_BYTES) {
    showError('That report is larger than 25 MB — trim it and try again.');
    return;
  }
  importBusy = true;
  el.importFile.disabled = true;
  try {
    const content = await file.text();
    const format = (el.importFormat.value || 'auto') as ImportFormat;
    setStatus(`Importing ${file.name}…`);
    const outcome = await importFindingsReport(format, content, currentTabUrl);
    const findings = toExtensionFindings(outcome.findings, 'import');
    renderBackendResults(
      'Imported findings',
      [
        `Imported ${outcome.imported} finding(s) from ${file.name}` +
          (outcome.score
            ? ` · score ${outcome.score.value}/100 (grade ${outcome.score.grade})`
            : ''),
      ],
      findings,
      'No findings were imported from that report.',
    );
    setStatus(`Import complete — ${outcome.imported} finding(s) from ${file.name}.`);
  } catch (err) {
    showError(
      `Import failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    setStatus('');
  } finally {
    importBusy = false;
    el.importFile.disabled = false;
    el.importFile.value = '';
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
    void refreshEnginesStatus();
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

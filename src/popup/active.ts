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
  cleanupLegacyProviderKeys,
  deleteAiKey,
  getAiKeys,
  getBackendAccount,
  getBackendApiKey,
  getCapabilities,
  getEnginesStatus,
  importFindingsReport,
  pairWithCode,
  refreshAiKey,
  runEngineScan,
  runSwarmScan,
  saveAiKey,
  saveLlmRouting,
  setBackendApiKey,
} from '../lib/apiClient';
import { hasBackendConsent, saveBackendConsent } from '../lib/consent';
import type {
  AccountState,
  BackendFinding,
  CapabilitiesResponse,
  EngineId,
  EngineStatusEntry,
  ImportFormat,
  LlmRouting,
  ProviderId,
  SavedAiKey,
  SwarmAuthorizationInput,
  SwarmOutcome,
} from '../lib/apiClient';
import { findingCard, renderFindings, renderSummary, swarmWorkerCard } from './render';
import {
  formatRoutingBadge,
  formatSaveKeyError,
  formatTokenCount,
  formatWorkerTelemetry,
  getLocalOllamaEnabled,
  onProviderKeySaved,
  resolveOmniRouteBaseUrl,
  restoreTabScanIfMatching,
  setLocalOllamaEnabled,
  shortProviderLabel,
} from '../lib/popupHelpers';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const el = {
  pane: document.getElementById('pane-active') as HTMLElement,
  hostLine: document.getElementById('active-host') as HTMLElement,
  backendBadge: document.getElementById('backend-status') as HTMLElement,
  backendAccount: document.getElementById('backend-account') as HTMLElement,
  // Authorization form
  authzForm: document.getElementById('authz-form') as HTMLElement,
  authzAuthorized: document.getElementById('authz-authorized') as HTMLElement,
  devUnlock: document.getElementById('dev-unlock') as HTMLElement,
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
  // Backend-runs consent (just-in-time)
  backendConsent: document.getElementById('backend-consent') as HTMLElement,
  backendConsentCheck: document.getElementById('backend-consent-check') as HTMLInputElement,
  backendConsentYes: document.getElementById('backend-consent-yes') as HTMLButtonElement,
  backendConsentNo: document.getElementById('backend-consent-no') as HTMLButtonElement,
};

let currentTabId: number | null = null;
let currentHost: string | null = null;
let currentTabUrl: string | null = null;
let currentResult: ScanResult | null = null;
/** Set when the stored API key belongs to the operator account (developer unlock). */
let operatorAccount: AccountState | null = null;
/** Whose account the stored key belongs to, when the backend answered. */
let linkedAccount: AccountState | null = null;
let running = false;
let swarmRunning = false;
let enginesRunning = false;
let importBusy = false;
let engineStatusCache: EngineStatusEntry[] | null = null;
let swarmTimers: number[] = [];
let swarmFrame = 0;
let pendingBackendRun: (() => void) | null = null;

export async function initActivePane(tabId: number, tabUrl: string): Promise<void> {
  currentTabId = tabId;
  currentTabUrl = tabUrl;
  try {
    currentHost = normalizeHost(new URL(tabUrl).hostname);
  } catch {
    currentHost = null;
  }
  el.hostLine.textContent = currentHost ?? '(no web page in this tab)';
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
  el.backendConsentCheck.addEventListener('change', () => {
    el.backendConsentYes.disabled = !el.backendConsentCheck.checked;
  });
  el.backendConsentYes.addEventListener('click', () => {
    void (async () => {
      await saveBackendConsent();
      hideBackendConsent();
      const run = pendingBackendRun;
      pendingBackendRun = null;
      run?.();
    })();
  });
  el.backendConsentNo.addEventListener('click', () => {
    hideBackendConsent();
    pendingBackendRun = null;
    setStatus('Backend run cancelled — nothing was sent.');
  });

  wireScopeModeRadios();
  void refreshBackendBadge();
  void cleanupLegacyProviderKeys();
  void initBackendKeyRow();
  void initAiKeysSection();
  void initLocalOllamaSection();
  renderEnginesStatus(null);
  void refreshEnginesStatus();
  void (async () => {
    await initOperatorUnlock();
    await refreshAuthzState();
  })();
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
    el.devUnlock.hidden = true;
    showAuthzError(
      'Open the website you want to test in this tab, then reopen BugSeek — the target host is read from the page you are standing on.',
    );
    el.runBtn.disabled = true;
    return;
  }
  const rec = await getAuthorization(currentHost);
  const authorized = !!rec;
  const unlocked = !authorized && operatorAccount !== null;
  el.authzForm.hidden = authorized || unlocked;
  el.authzAuthorized.hidden = !authorized;
  el.devUnlock.hidden = !unlocked;
  if (unlocked && operatorAccount) {
    el.devUnlock.textContent =
      `Developer unlock active — ${operatorAccount.email}. ` +
      'Authorisation for each host is recorded automatically on this machine; every request still passes the scope checks.';
  }
  el.runBtn.disabled = !(authorized || unlocked) || running;
  hideAuthzError();
  if (rec) renderAuthzSummary(rec);
}

/**
 * Developer unlock: when the stored API key belongs to the operator
 * account, the popup stops interrupting its owner with the per-host
 * authorization form. Fails closed, no key, an unreachable backend, or
 * a non-operator account all leave the form exactly as it was.
 */
let accountError: string | null = null;

async function initOperatorUnlock(): Promise<void> {
  const acct = await getBackendAccount();
  linkedAccount = acct.authenticated ? acct : null;
  operatorAccount = acct.operator ? acct : null;
  accountError = null;
  renderLinkedAccount();
}

/** Say whose account the extension acts for, right under the key row. */
function renderLinkedAccount(): void {
  if (!el.backendAccount) return;
  if (accountError) {
    el.backendAccount.textContent = accountError;
    el.backendAccount.className = 'backend-account backend-account-error';
    el.backendAccount.hidden = false;
    return;
  }
  el.backendAccount.className = 'backend-account';
  if (!linkedAccount) {
    el.backendAccount.hidden = true;
    el.backendAccount.textContent = '';
    return;
  }
  el.backendAccount.textContent =
    `Linked to ${linkedAccount.email} · ${linkedAccount.plan} plan` +
    (linkedAccount.operator ? ' · operator' : '');
  el.backendAccount.hidden = false;
}

/**
 * The record a run is about to rely on. With the developer unlock, a
 * missing record is saved on the spot, same fields, same statement,
 * same scope checks on every request; only the form is skipped.
 * Without the unlock this never writes anything.
 */
async function ensureAuthorization(): Promise<AuthorizationRecord | null> {
  if (!currentHost) return null;
  const existing = await getAuthorization(currentHost);
  if (existing) return existing;
  if (!operatorAccount) return null;
  const rec: AuthorizationRecord = {
    id: newAuthorizationId(),
    targetHost: currentHost,
    type: 'ownership',
    statement:
      `I confirm that I am authorized to actively test ${currentHost} ` +
      `(ownership — operator account ${operatorAccount.email}, developer unlock). ` +
      `I accept responsibility for this testing activity.`,
    scope: {
      mode: 'full-domain',
      includeSubdomains: true,
      excludedHosts: [],
      excludedPaths: [],
      maxRequestsPerSecond: Math.min(4, 1000 / DEFAULT_ACTIVE_REQUEST_GAP_MS),
    },
    allowAuthProbes: false,
    rateLimitMs: DEFAULT_ACTIVE_REQUEST_GAP_MS,
    confirmedAt: new Date().toISOString(),
  };
  await saveAuthorization(rec);
  await refreshAuthzState();
  setStatus(`Authorization recorded for ${currentHost} (developer unlock).`);
  return rec;
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
  const authz = await ensureAuthorization();
  if (!authz) {
    showError(
      'Save an authorization record first — active testing needs the same explicit confirmation.',
    );
    return;
  }
  const wantDeep = inputChecked('active-deep-inspect');
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

function hideBackendConsent(): void {
  el.backendConsent.hidden = true;
  el.backendConsentCheck.checked = false;
  el.backendConsentYes.disabled = true;
}

/**
 * Just-in-time consent for runs that leave the device: the first swarm or
 * engine run shows what is sent to the backend and waits for its own yes.
 * The agreed version is stored; later runs skip the panel until the
 * disclosure text's version bumps.
 */
async function ensureBackendConsent(run: () => void): Promise<void> {
  if (await hasBackendConsent()) {
    run();
    return;
  }
  pendingBackendRun = run;
  el.backendConsent.hidden = false;
  el.backendConsent.scrollIntoView({ block: 'nearest' });
}

/**
 * Deploy the backend AI swarm: a head agent plus specialist worker agents
 * run inline on the server against the authorized target (Hunter plan,
 * 25 credits). Requires the same authorization record as local active
 * testing, the backend re-validates it.
 */
async function startSwarmScan(): Promise<void> {
  if (swarmRunning || running) return;
  hideError();

  const authz = await ensureAuthorization();
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
    showError(
      'Link your account first — the swarm runs on the backend and needs your BugSeek key. ' +
        'Paste a link code or bs_ key in the field above.',
    );
    document.getElementById('backend-api-key')?.focus();
    return;
  }

  const authorization: SwarmAuthorizationInput = {
    type: authz.type,
    programName: authz.programName,
    statement: authz.statement,
    confirmed: true,
  };

  await ensureBackendConsent(() => {
    void proceedSwarmScan(authz, authorization);
  });
}

async function collectTabSurface(tabId: number, tabUrl: string): Promise<Record<string, unknown>> {
  let bundleEndpoints: Array<{ path: string; scriptUrl: string }> = [];
  let forms: Array<{ action?: string; method?: string; hasCsrfInput?: boolean }> = [];
  let globals: string[] = [];
  let cookies: Array<{ name: string; secure: boolean; httpOnly: boolean; sameSite: string }> = [];

  try {
    const rawCookies = await chrome.cookies.getAll({ url: tabUrl });
    cookies = rawCookies.map((c) => ({
      name: c.name,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite ?? 'lax',
    }));
  } catch {}

  try {
    const domRes = await chrome.tabs.sendMessage(tabId, { type: 'COLLECT_DOM' });
    if (domRes?.ok && domRes.data) {
      forms = domRes.data.forms ?? [];
      globals = domRes.data.globals ?? [];
    }
  } catch {}

  try {
    const bundleRes = await chrome.tabs.sendMessage(tabId, { type: 'SCAN_BUNDLES' });
    if (bundleRes?.ok && bundleRes.data) {
      bundleEndpoints = bundleRes.data.endpoints ?? [];
    }
  } catch {}

  let urlOrigin = '';
  let urlPathname = '/';
  try {
    const parsed = new URL(tabUrl);
    urlOrigin = parsed.origin;
    urlPathname = parsed.pathname || '/';
  } catch {}

  const observedApis: Array<{
    method: string;
    path: string;
    source: 'live_traffic' | 'js_bundle' | 'dom_form';
    scriptUrl?: string;
    hasAuthHeader: boolean;
    hasCsrfHeader?: boolean;
  }> = [
    {
      method: 'GET',
      path: urlPathname,
      source: 'live_traffic',
      hasAuthHeader: false,
    },
  ];

  for (const ep of bundleEndpoints) {
    const p = ep.path;
    const method = p.toLowerCase().includes('delete')
      ? 'DELETE'
      : p.toLowerCase().includes('login') ||
        p.toLowerCase().includes('create') ||
        p.toLowerCase().includes('basket') ||
        p.toLowerCase().includes('update')
      ? 'POST'
      : 'GET';
    observedApis.push({
      method,
      path: p,
      source: 'js_bundle',
      scriptUrl: ep.scriptUrl,
      hasAuthHeader: false,
    });
  }

  for (const f of forms) {
    if (f.action) {
      observedApis.push({
        method: (f.method || 'POST').toUpperCase(),
        path: f.action,
        source: 'dom_form',
        hasAuthHeader: false,
        hasCsrfHeader: Boolean(f.hasCsrfInput),
      });
    }
  }

  return {
    origin: urlOrigin,
    headers: {},
    cookies,
    observedApis,
    htmlForms: forms.map((f) => ({
      action: f.action || '',
      method: (f.method || 'POST').toUpperCase(),
      hasCsrfInput: Boolean(f.hasCsrfInput),
    })),
    detectedLibraries: globals.map((g) => ({
      name: g.split(' ')[0] || g,
      version: g.split(' ')[1] || '',
      scriptUrl: '',
    })),
  };
}

async function proceedSwarmScan(
  authz: AuthorizationRecord,
  authorization: SwarmAuthorizationInput,
): Promise<void> {
  if (swarmRunning || !currentTabUrl) return;
  swarmRunning = true;
  el.swarmBtn.disabled = true;
  el.swarmBtn.textContent = 'Swarm running…';
  setStatus('Collecting surface & scanning JavaScript bundles…');
  showSwarmDeploying();

  try {
    let surfaceSnapshot: Record<string, unknown> | undefined = undefined;
    if (currentTabId !== null) {
      surfaceSnapshot = await collectTabSurface(currentTabId, currentTabUrl).catch(() => undefined);
    }
    const observedCount = Array.isArray(surfaceSnapshot?.observedApis)
      ? (surfaceSnapshot!.observedApis as unknown[]).length
      : 1;
    setStatus(`Surface mapped: ${observedCount} endpoint(s). Deploying AI swarm…`);

    const outcome = await runSwarmScan(
      {
        targetUrl: currentTabUrl,
        authorization,
        scope: {
          mode: authz.scope.mode,
          includeSubdomains: authz.scope.includeSubdomains,
          excludedHosts: authz.scope.excludedHosts,
          excludedPaths: authz.scope.excludedPaths,
        },
        surfaceSnapshot,
        async: true,
      },
      (status) => {
        if (status === 'running') {
          setStatus('AI swarm running — specialist workers testing endpoints…');
        } else if (status === 'queued') {
          setStatus('AI swarm queued — initializing head agent…');
        } else {
          setStatus(`AI swarm ${status}…`);
        }
      },
    );
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
      detail = 'Backend unreachable — Render free tier is waking up, please wait ~30s or check your connection.';
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

  const authz = await ensureAuthorization();
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
    showError(
      'Link your account first — the engines run on the backend and need your BugSeek key. ' +
        'Paste a link code or bs_ key in the field above.',
    );
    document.getElementById('backend-api-key')?.focus();
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
        : 'Backend unreachable — Render free tier is waking up, please wait ~30s or check your connection.',
    );
    return;
  }

  const authorization: SwarmAuthorizationInput = {
    type: authz.type,
    programName: authz.programName,
    statement: authz.statement,
    confirmed: true,
  };

  await ensureBackendConsent(() => {
    void proceedEnginesRun(available, authorization);
  });
}

async function proceedEnginesRun(
  available: typeof ENGINE_META,
  authorization: SwarmAuthorizationInput,
): Promise<void> {
  if (enginesRunning || !currentTabUrl) return;
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
        const outcome = await runEngineScan(meta.id, currentTabUrl, authorization);
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
// response lands we play the real run record back, worker cards stagger
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
    case 'INCOMPLETE':
      return 'var(--medium)';
    default:
      return 'var(--accent)';
  }
}

/** Big count-up number + letter grade inside an SVG progress ring. */
function renderSwarmScore(
  box: HTMLElement,
  score: { value: number; grade: string; effectiveGrade?: string; coverageLabel?: string; warnings?: string[] },
  instant: boolean,
): void {
  const displayGrade = score.effectiveGrade || score.grade;
  const color = gradeColor(displayGrade);
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
  gradeEl.textContent = displayGrade;
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
  sub.textContent = score.coverageLabel || 'out of 100 · higher is safer';
  side.appendChild(num);
  side.appendChild(label);
  side.appendChild(sub);
  if (score.warnings && score.warnings.length > 0) {
    const warnEl = document.createElement('div');
    warnEl.className = 'score-coverage-warn';
    warnEl.style.fontSize = '10px';
    warnEl.style.color = 'var(--muted)';
    warnEl.textContent = score.warnings[0];
    side.appendChild(warnEl);
  }
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
  const cards = outcome.workerReports.map((w) => swarmWorkerCard(w, !reduce));
  cards.forEach((c) => grid.appendChild(c));

  const retesterLine = outcome.retester ? formatWorkerTelemetry(outcome.retester) : '';
  if (retesterLine) {
    const retest = document.createElement('div');
    retest.className = 'stat-line';
    retest.textContent = `Retester — ${retesterLine}`;
    panel.appendChild(retest);
  }

  // Run totals (the same accounting line the popup has always shown).
  const totals = document.createElement('div');
  totals.className = reduce ? 'stat-line' : 'stat-line swarm-enter';
  const tokenDisplay = formatTokenCount(outcome.tokensUsed);
  totals.textContent =
    `${outcome.testsRun} tests · ${tokenDisplay}` +
    ` · ${(outcome.durationMs / 1000).toFixed(1)}s · scan ${outcome.scanId}`;
  panel.appendChild(totals);

  const score = outcome.score ?? null;
  const scoreBox = document.createElement('div');
  if (score) {
    scoreBox.className = reduce ? 'swarm-score' : 'swarm-score swarm-enter';
    panel.appendChild(scoreBox);
  }

  if (reduce) {
    // Final states immediately, no stagger, no count-up.
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
    if (s.state === 'online') {
      el.backendBadge.textContent = 'Backend: connected — AI deepening available';
      el.backendBadge.className = 'backend-badge backend-on';
      // The engines panel probed while the backend was still asleep;
      // ask again now that it is awake.
      void refreshEnginesStatus();
    } else if (s.state === 'auth_error') {
      el.backendBadge.textContent =
        'Backend: connected, but your key was rejected — link your account again';
      el.backendBadge.className = 'backend-badge backend-off';
    } else if (s.state === 'server_error') {
      el.backendBadge.textContent =
        'Backend: error — running standalone (local checks only)';
      el.backendBadge.className = 'backend-badge backend-off';
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

/**
 * Account link row: the stored bs_ key, or a one-time link code from the
 * website. Hosted provider keys are no longer handled here, they live in
 * the AI provider keys section below and are synced to the account.
 */
type QwenRegionChoice = 'intl' | 'cn' | 'custom';

/** DashScope OpenAI-compatible base URLs, by region. Mirrors the backend. */
const QWEN_BASE_URLS: Record<'intl' | 'cn', string> = {
  intl: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
  cn: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
};

/**
 * Resolve the DashScope base URL for a Qwen key. Mirrors the server-side
 * allowlist in backend/src/routes/aiKey.ts, the popup never fetches a
 * custom URL that fails this check.
 */
function resolveQwenBaseUrl(
  region: string,
  customUrl: string | undefined,
): { baseUrl: string; region: QwenRegionChoice } | { error: string } {
  if (region === 'intl' || region === 'cn') {
    return { baseUrl: QWEN_BASE_URLS[region], region };
  }
  if (region !== 'custom') {
    return { error: `Unknown Qwen region "${region}".` };
  }
  const raw = (customUrl ?? '').trim().replace(/\/+$/, '');
  if (!raw) return { error: 'Enter your custom DashScope workspace URL for Qwen.' };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { error: 'That Qwen workspace URL does not look like a valid URL.' };
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    (url.port !== '' && url.port !== '443') ||
    !url.hostname.endsWith('.aliyuncs.com') ||
    url.pathname !== '/compatible-mode/v1'
  ) {
    return {
      error: 'Custom Qwen URL must be an https://*.aliyuncs.com/compatible-mode/v1 endpoint.',
    };
  }
  return { baseUrl: url.toString().replace(/\/+$/, ''), region: 'custom' };
}

/** Client-side Ollama reachability check (popup only, the server must never fetch localhost). */
async function checkOllamaReachable(): Promise<boolean> {
  try {
    const res = await fetch('http://127.0.0.1:11434/api/tags', {
      method: 'GET',
      signal: AbortSignal.timeout(5000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

async function initBackendKeyRow(): Promise<void> {
  const input = document.getElementById('backend-api-key') as HTMLInputElement | null;
  const save = document.getElementById('backend-api-key-save') as HTMLButtonElement | null;
  if (!input || !save) return;

  const hasKey = await getBackendApiKey();
  input.value = hasKey ? '••••••••' : '';

  const doSave = async () => {
    const v = input.value.trim();
    input.setCustomValidity('');

    if (v === '••••••••') return; // unchanged placeholder
    if (!v) {
      // Cleared: unlink this browser.
      await setBackendApiKey(null);
      linkedAccount = null;
      operatorAccount = null;
      accountError = null;
      renderLinkedAccount();
      await refreshAuthzState();
      await refreshAiKeysSection();
      setStatus('Key removed.');
      return;
    }
    if (v.startsWith('bs_')) {
      await setBackendApiKey(v);
      input.value = '••••••••';
      void refreshBackendBadge();
      void refreshEnginesStatus();
      void (async () => {
        await initOperatorUnlock();
        await refreshAuthzState();
        await refreshAiKeysSection();
      })();
      return;
    }
    if (v.startsWith('AIza') || v.startsWith('sk-') || v.length > 32) {
      const msg =
        'That looks like an AI provider key. Save it in the AI provider keys section below, not here.';
      input.setCustomValidity(msg);
      input.reportValidity();
      showError(msg);
      return;
    }
    // Anything else is a one-time link code from the website.
    save.disabled = true;
    input.value = 'Linking…';
    try {
      const account = await pairWithCode(v);
      linkedAccount = account;
      operatorAccount = account.operator ? account : null;
      accountError = null;
      renderLinkedAccount();
      input.value = '••••••••';
      void refreshBackendBadge();
      void refreshEnginesStatus();
      await refreshAuthzState();
      await refreshAiKeysSection();
      setStatus(`Linked to ${account.email}.`);
    } catch (err) {
      input.value = '';
      const msg = err instanceof Error ? err.message : 'That link code did not work.';
      input.setCustomValidity(msg);
      input.reportValidity();
      accountError = msg;
      renderLinkedAccount();
      showError(msg);
    } finally {
      save.disabled = false;
    }
  };
  save.addEventListener('click', () => void doSave());
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      void doSave();
    }
  });
}

// ---------------------------------------------------------------------------
// AI provider keys, synced to the account
//
// The provider dropdown, saved-key badges, and tier pickers render from
// GET /api/v1/capabilities and GET /api/v1/ai-keys. Unpaired browsers see
// the Connect/Pairing prompt instead of the form, hosted keys are never
// written to browser storage.
// ---------------------------------------------------------------------------

let aiKeysWired = false;
let aiKeysCapabilities: CapabilitiesResponse | null = null;
let aiKeysSaved: SavedAiKey[] = [];
let aiKeysRouting: LlmRouting | null = null;

/** Dropdown value that reveals the free-text input for a model outside the discovered list. */
const CUSTOM_MODEL_OPTION = '__custom__';
/** How many discovered model ids the badge line shows before "+N more". */
const MAX_MODELS_SHOWN = 6;

function showAiKeyError(text: string): void {
  const errEl = document.getElementById('ai-key-error') as HTMLElement | null;
  if (!errEl) return;
  errEl.textContent = text;
  errEl.hidden = false;
}

function hideAiKeyError(): void {
  const errEl = document.getElementById('ai-key-error') as HTMLElement | null;
  if (errEl) errEl.hidden = true;
}

function showRoutingError(text: string): void {
  const errEl = document.getElementById('routing-error') as HTMLElement | null;
  if (!errEl) return;
  errEl.textContent = text;
  errEl.hidden = false;
}

function hideRoutingError(): void {
  const errEl = document.getElementById('routing-error') as HTMLElement | null;
  if (errEl) errEl.hidden = true;
}

/** Status badge for the active routing: provider + effective models as values. */
function renderRoutingBadge(routing: LlmRouting): void {
  const badge = document.getElementById('ai-keys-badge') as HTMLElement | null;
  if (!badge) return;
  badge.textContent = formatRoutingBadge(routing, (id) => {
    const cap = aiKeysCapabilities?.llmProviders.find((p) => p.id === id);
    return cap ? shortProviderLabel(cap.label) : id;
  });
  badge.hidden = false;
}

function hideRoutingBadge(): void {
  const badge = document.getElementById('ai-keys-badge') as HTMLElement | null;
  if (badge) {
    badge.hidden = true;
    badge.textContent = '';
  }
  hideDiscoveredModels();
}

function hideDiscoveredModels(): void {
  const box = document.getElementById('ai-keys-models') as HTMLElement | null;
  if (box) {
    box.hidden = true;
    box.innerHTML = '';
  }
}

/**
 * Discovered-model line under the badge, for the worker tier's saved key
 * (first saved key when the worker provider has none). A null list means
 * the key predates discovery: show the re-save/refresh hint, never a
 * guessed list.
 */
function renderDiscoveredModels(keys: SavedAiKey[], routing: LlmRouting): void {
  const box = document.getElementById('ai-keys-models') as HTMLElement | null;
  if (!box) return;
  box.innerHTML = '';
  if (keys.length === 0) {
    box.hidden = true;
    return;
  }
  const key = keys.find((k) => k.providerId === routing.workerProvider) ?? keys[0];
  const cap = aiKeysCapabilities?.llmProviders.find((p) => p.id === key.providerId);
  const label = cap ? shortProviderLabel(cap.label) : key.providerId;
  box.hidden = false;
  const text = document.createElement('span');
  const models = key.discoveredModels;
  if (models && models.length > 0) {
    const shown = models.slice(0, MAX_MODELS_SHOWN);
    const rest = models.length - shown.length;
    text.textContent =
      `${label} can use: ${shown.join(', ')}` + (rest > 0 ? ` +${rest} more` : '');
    box.appendChild(text);
    return;
  }
  text.textContent = 'Re-save the key, or refresh, to see its models';
  box.appendChild(text);
  const refreshBtn = document.createElement('button');
  refreshBtn.type = 'button';
  refreshBtn.textContent = 'Refresh';
  refreshBtn.addEventListener('click', () => {
    void (async () => {
      refreshBtn.disabled = true;
      hideAiKeyError();
      try {
        const res = await refreshAiKey(key.providerId);
        if (!res.ok) {
          showAiKeyError(
            res.status > 0
              ? `Refresh failed (HTTP ${res.status}): ${res.error}`
              : `Refresh failed: ${res.error}`,
          );
          return;
        }
        await refreshAiKeysSection();
        setStatus('Model list refreshed.');
      } catch (err) {
        showAiKeyError(
          err instanceof Error ? `Refresh failed: ${err.message}` : 'Refresh failed.',
        );
      } finally {
        refreshBtn.disabled = false;
      }
    })();
  });
  box.appendChild(refreshBtn);
}

/** Show the Qwen region block or the OmniRoute URL field for the picked provider. */
function refreshAiKeyProviderUi(): void {
  const providerSelect = document.getElementById('ai-key-provider') as HTMLSelectElement | null;
  const qwenBlock = document.getElementById('ai-key-qwen') as HTMLElement | null;
  const qwenRegion = document.getElementById('ai-qwen-region') as HTMLSelectElement | null;
  const qwenCustomUrl = document.getElementById('ai-qwen-custom-url') as HTMLInputElement | null;
  const omniBlock = document.getElementById('ai-key-omniroute') as HTMLElement | null;
  const keyInput = document.getElementById('ai-key-input') as HTMLInputElement | null;
  if (!providerSelect) return;
  const provider = providerSelect.value;
  if (qwenBlock) qwenBlock.hidden = provider !== 'qwen';
  if (qwenCustomUrl) {
    qwenCustomUrl.hidden = provider !== 'qwen' || qwenRegion?.value !== 'custom';
  }
  if (omniBlock) omniBlock.hidden = provider !== 'omniroute';
  if (keyInput) {
    const cap = aiKeysCapabilities?.llmProviders.find((p) => p.id === provider);
    keyInput.placeholder = cap ? `Paste ${cap.label} API key` : 'Paste provider API key';
  }
}

function fillProviderSelect(
  id: string,
  providers: CapabilitiesResponse['llmProviders'],
): void {
  const sel = document.getElementById(id) as HTMLSelectElement | null;
  if (!sel) return;
  const current = sel.value;
  sel.innerHTML = '';
  for (const p of providers) {
    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = p.available ? p.label : `${p.label} (unavailable)`;
    opt.disabled = !p.available;
    sel.appendChild(opt);
  }
  if (current && providers.some((p) => p.id === current && p.available)) {
    sel.value = current;
  }
}

function defaultModelFor(
  providers: CapabilitiesResponse['llmProviders'],
  providerId: string,
  tier: 'worker' | 'reasoning',
): string {
  return providers.find((p) => p.id === providerId)?.defaultModels[tier] ?? '';
}

/** Discovered models for a provider, null when the key predates discovery or found none. */
function discoveredModelsFor(providerId: string): string[] | null {
  const found = aiKeysSaved.find((k) => k.providerId === providerId)?.discoveredModels;
  return found && found.length > 0 ? found : null;
}

/**
 * Worker/reasoning model field for one tier. With a discovered list it is
 * a dropdown of the list plus a custom option; without one it stays the
 * plain text input with the registry-default placeholder. A typed custom
 * id is never wiped by a re-render: when the list loads under a typed
 * value, the field lands on the custom option with the typed value kept.
 */
function renderModelField(
  tier: 'worker' | 'reasoning',
  providerId: string,
  routingModel: string | null | undefined,
  preserveTyped: boolean,
): void {
  const select = document.getElementById(
    `routing-${tier}-model-select`,
  ) as HTMLSelectElement | null;
  const input = document.getElementById(`routing-${tier}-model`) as HTMLInputElement | null;
  if (!select || !input) return;
  const placeholder = aiKeysCapabilities
    ? defaultModelFor(aiKeysCapabilities.llmProviders, providerId, tier)
    : '';
  const models = discoveredModelsFor(providerId);
  if (!models) {
    select.hidden = true;
    input.hidden = false;
    if (!preserveTyped) input.value = routingModel ?? '';
    input.placeholder = placeholder;
    return;
  }
  select.innerHTML = '';
  const def = document.createElement('option');
  def.value = '';
  def.textContent = placeholder ? `Default (${placeholder})` : 'Default';
  select.appendChild(def);
  for (const m of models) {
    const opt = document.createElement('option');
    opt.value = m;
    opt.textContent = m;
    select.appendChild(opt);
  }
  const custom = document.createElement('option');
  custom.value = CUSTOM_MODEL_OPTION;
  custom.textContent = 'Custom model ID…';
  select.appendChild(custom);
  select.hidden = false;
  input.placeholder = placeholder || 'Custom model ID';
  const typed = input.value.trim();
  if (routingModel && models.includes(routingModel)) {
    select.value = routingModel;
    input.hidden = true;
  } else if (typed !== '' && models.includes(typed)) {
    select.value = typed;
    input.hidden = true;
  } else if (typed !== '') {
    select.value = CUSTOM_MODEL_OPTION;
    input.hidden = false;
  } else if (routingModel) {
    select.value = CUSTOM_MODEL_OPTION;
    input.hidden = false;
    input.value = routingModel;
  } else {
    select.value = '';
    input.hidden = true;
  }
}

/** Effective model for one tier: dropdown pick, custom typed id, or the text input. */
function readModelField(tier: 'worker' | 'reasoning'): string | null {
  const select = document.getElementById(
    `routing-${tier}-model-select`,
  ) as HTMLSelectElement | null;
  const input = document.getElementById(`routing-${tier}-model`) as HTMLInputElement | null;
  if (select && !select.hidden) {
    if (select.value === CUSTOM_MODEL_OPTION) return input?.value.trim() || null;
    return select.value || null;
  }
  return input?.value.trim() || null;
}

/** Tier provider change re-renders that tier's model field; dropdown change reveals the custom input. */
function wireModelField(tier: 'worker' | 'reasoning'): void {
  const providerSel = document.getElementById(
    `routing-${tier}-provider`,
  ) as HTMLSelectElement | null;
  const modelSelect = document.getElementById(
    `routing-${tier}-model-select`,
  ) as HTMLSelectElement | null;
  const modelInput = document.getElementById(
    `routing-${tier}-model`,
  ) as HTMLInputElement | null;
  providerSel?.addEventListener('change', () => {
    const routing = aiKeysRouting;
    const routingModel =
      routing &&
      providerSel.value ===
        (tier === 'worker' ? routing.workerProvider : routing.reasoningProvider)
        ? tier === 'worker'
          ? routing.workerModel
          : routing.reasoningModel
        : null;
    renderModelField(tier, providerSel.value, routingModel, true);
  });
  modelSelect?.addEventListener('change', () => {
    if (!modelInput) return;
    modelInput.hidden = modelSelect.value !== CUSTOM_MODEL_OPTION;
    if (modelSelect.value === CUSTOM_MODEL_OPTION) modelInput.focus();
  });
}

function renderSavedKeys(
  keys: SavedAiKey[],
  providers: CapabilitiesResponse['llmProviders'],
): void {
  const list = document.getElementById('ai-keys-saved') as HTMLElement | null;
  if (!list) return;
  list.innerHTML = '';
  if (keys.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'backend-key-note';
    empty.textContent = 'No provider keys saved yet.';
    list.appendChild(empty);
    return;
  }
  for (const k of keys) {
    const label = providers.find((p) => p.id === k.providerId)?.label ?? k.providerId;
    const row = document.createElement('div');
    row.className = 'ai-key-row';
    const name = document.createElement('span');
    name.textContent = label;
    row.appendChild(name);
    const hint = document.createElement('span');
    hint.className = 'ai-key-hint';
    hint.textContent = k.keyHint;
    row.appendChild(hint);
    const when = document.createElement('span');
    when.className = 'ai-key-hint';
    when.textContent = `verified ${new Date(k.verifiedAt).toLocaleDateString()}`;
    row.appendChild(when);
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.textContent = 'Remove';
    remove.addEventListener('click', () => {
      void (async () => {
        remove.disabled = true;
        const res = await deleteAiKey(k.providerId);
        if (!res.ok) {
          showAiKeyError(res.error);
          remove.disabled = false;
          return;
        }
        await refreshAiKeysSection();
        setStatus(`${label} key removed.`);
      })();
    });
    row.appendChild(remove);
    list.appendChild(row);
  }
}

async function initAiKeysSection(): Promise<void> {
  const providerSelect = document.getElementById('ai-key-provider') as HTMLSelectElement | null;
  const keyInput = document.getElementById('ai-key-input') as HTMLInputElement | null;
  const saveBtn = document.getElementById('ai-key-save') as HTMLButtonElement | null;
  const qwenRegion = document.getElementById('ai-qwen-region') as HTMLSelectElement | null;
  const qwenCustomUrl = document.getElementById('ai-qwen-custom-url') as HTMLInputElement | null;
  const omniUrl = document.getElementById('ai-omniroute-url') as HTMLInputElement | null;
  const routingSave = document.getElementById('routing-save') as HTMLButtonElement | null;
  if (!providerSelect || !keyInput || !saveBtn || !routingSave) return;

  if (aiKeysWired) {
    await refreshAiKeysSection();
    return;
  }
  aiKeysWired = true;

  providerSelect.addEventListener('change', refreshAiKeyProviderUi);
  qwenRegion?.addEventListener('change', refreshAiKeyProviderUi);
  wireModelField('worker');
  wireModelField('reasoning');

  saveBtn.addEventListener('click', () => {
    void (async () => {
      const provider = providerSelect.value as ProviderId;
      const v = keyInput.value.trim();
      hideAiKeyError();
      if (!v) {
        showAiKeyError('Paste a provider API key first.');
        return;
      }
      let baseUrl: string | undefined;
      if (provider === 'qwen') {
        const resolved = resolveQwenBaseUrl(qwenRegion?.value ?? 'intl', qwenCustomUrl?.value);
        if ('error' in resolved) {
          showAiKeyError(resolved.error);
          return;
        }
        baseUrl = resolved.baseUrl;
      }
      if (provider === 'omniroute') {
        const resolved = resolveOmniRouteBaseUrl(omniUrl?.value);
        if ('error' in resolved) {
          showAiKeyError(resolved.error);
          return;
        }
        baseUrl = resolved.baseUrl;
      }
      saveBtn.disabled = true;
      keyInput.value = 'Verifying…';
      let savedRouting: LlmRouting | null = null;
      try {
        await onProviderKeySaved(
          async () => {
            const res = await saveAiKey(provider, v, baseUrl);
            if (!res.ok) throw new Error(formatSaveKeyError(res.status, res.error));
            // The POST response carries the routing the save picked; use
            // it straight away instead of waiting on the GET refresh.
            savedRouting = res.data.routing;
          },
          refreshAiKeysSection,
          setStatus,
        );
        if (savedRouting) renderRoutingBadge(savedRouting);
        keyInput.value = '';
        hideAiKeyError();
        hideError();
      } catch (err) {
        keyInput.value = v;
        showAiKeyError(err instanceof Error ? err.message : 'Could not save this key.');
      } finally {
        saveBtn.disabled = false;
      }
    })();
  });

  routingSave.addEventListener('click', () => {
    void (async () => {
      const workerProvider = (
        document.getElementById('routing-worker-provider') as HTMLSelectElement
      ).value;
      const workerModel = readModelField('worker');
      const reasoningProvider = (
        document.getElementById('routing-reasoning-provider') as HTMLSelectElement
      ).value;
      const reasoningModel = readModelField('reasoning');
      const routing: LlmRouting = {
        workerProvider,
        workerModel,
        reasoningProvider,
        reasoningModel,
      };
      routingSave.disabled = true;
      try {
        const res = await saveLlmRouting(routing);
        if (!res.ok) {
          showRoutingError(res.error);
          return;
        }
        hideRoutingError();
        renderRoutingBadge(res.data.routing);
        setStatus('Model routing saved.');
      } catch (err) {
        showRoutingError(err instanceof Error ? err.message : 'Could not save routing.');
      } finally {
        routingSave.disabled = false;
      }
    })();
  });

  await refreshAiKeysSection();
}

async function refreshAiKeysSection(): Promise<void> {
  const unpaired = document.getElementById('ai-keys-unpaired') as HTMLElement | null;
  const form = document.getElementById('ai-keys-form') as HTMLElement | null;
  if (!unpaired || !form) return;

  const paired = (await getBackendApiKey()) !== null;
  unpaired.hidden = paired;
  form.hidden = !paired;
  if (!paired) return;

  const [caps, keys] = await Promise.all([getCapabilities(), getAiKeys()]);
  if (!caps.ok) {
    showAiKeyError(`Could not load providers: ${caps.error}`);
    return;
  }
  if (!keys.ok) {
    showAiKeyError(`Could not load saved keys: ${keys.error}`);
    return;
  }
  aiKeysCapabilities = caps.data;
  aiKeysSaved = keys.data.keys;
  aiKeysRouting = keys.data.routing;
  const hosted = caps.data.llmProviders.filter((p) => p.mode === 'hosted');
  fillProviderSelect('ai-key-provider', hosted);
  fillProviderSelect('routing-worker-provider', hosted);
  fillProviderSelect('routing-reasoning-provider', hosted);
  renderSavedKeys(keys.data.keys, hosted);

  const routing = keys.data.routing;
  const workerProviderSel = document.getElementById(
    'routing-worker-provider',
  ) as HTMLSelectElement | null;
  const reasoningProviderSel = document.getElementById(
    'routing-reasoning-provider',
  ) as HTMLSelectElement | null;
  const workerModelInput = document.getElementById(
    'routing-worker-model',
  ) as HTMLInputElement | null;
  const reasoningModelInput = document.getElementById(
    'routing-reasoning-model',
  ) as HTMLInputElement | null;
  if (keys.data.keys.length === 0) {
    // No saved key: the empty state ("No provider keys saved yet") is
    // the whole story. Show no badge and no model names — the backend
    // default routing (Gemini) is not a configuration the user has.
    hideRoutingBadge();
    for (const id of ['routing-worker-model-select', 'routing-reasoning-model-select']) {
      const sel = document.getElementById(id) as HTMLSelectElement | null;
      if (sel) sel.hidden = true;
    }
    if (workerModelInput) {
      workerModelInput.value = '';
      workerModelInput.placeholder = '';
      workerModelInput.hidden = false;
    }
    if (reasoningModelInput) {
      reasoningModelInput.value = '';
      reasoningModelInput.placeholder = '';
      reasoningModelInput.hidden = false;
    }
    refreshAiKeyProviderUi();
    return;
  }
  renderRoutingBadge(routing);
  renderDiscoveredModels(keys.data.keys, routing);
  if (workerProviderSel && hosted.some((p) => p.id === routing.workerProvider)) {
    workerProviderSel.value = routing.workerProvider;
  }
  if (reasoningProviderSel && hosted.some((p) => p.id === routing.reasoningProvider)) {
    reasoningProviderSel.value = routing.reasoningProvider;
  }
  renderModelField(
    'worker',
    workerProviderSel?.value ?? routing.workerProvider,
    routing.workerModel,
    false,
  );
  renderModelField(
    'reasoning',
    reasoningProviderSel?.value ?? routing.reasoningProvider,
    routing.reasoningModel,
    false,
  );
  refreshAiKeyProviderUi();
}

// ---------------------------------------------------------------------------
// Local Triage (Ollama, extension only)
//
// A plain on/off preference plus a click-to-probe reachability check. It
// never calls initOperatorUnlock and never grants operator status.
// ---------------------------------------------------------------------------

async function initLocalOllamaSection(): Promise<void> {
  const toggle = document.getElementById('ollama-triage-toggle') as HTMLInputElement | null;
  const checkBtn = document.getElementById('ollama-triage-check') as HTMLButtonElement | null;
  const status = document.getElementById('ollama-triage-status') as HTMLElement | null;
  if (!toggle || !checkBtn) return;
  toggle.checked = await getLocalOllamaEnabled();
  toggle.addEventListener('change', () => {
    void setLocalOllamaEnabled(toggle.checked);
  });
  checkBtn.addEventListener('click', () => {
    void (async () => {
      if (!status) return;
      checkBtn.disabled = true;
      status.textContent = 'Checking…';
      const reachable = await checkOllamaReachable();
      status.textContent = reachable
        ? 'Ollama is reachable on this machine.'
        : 'Ollama is not reachable — start it, then check again.';
      checkBtn.disabled = false;
    })();
  });
}

async function restoreLastResult(): Promise<void> {
  if (currentTabId === null || !currentTabUrl) return;
  await restoreTabScanIfMatching<ScanResult>(
    currentTabId,
    currentTabUrl,
    (prev) => {
      currentResult = prev;
      renderActiveResult(prev);
      setStatus(`Last active scan: ${new Date(prev.scannedAt).toLocaleString()}`);
    },
    `${STORAGE_KEYS.activeScanPrefix}${currentTabId}`,
  );
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

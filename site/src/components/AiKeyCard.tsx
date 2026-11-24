import { useEffect, useState } from 'react';
import {
  deleteAiKey,
  fetchCapabilities,
  formatRoutingBadge,
  formatSaveKeyError,
  hostedProviders,
  listAiKeys,
  modelOptionsFor,
  ollamaCapability,
  resolveQwenBaseUrl,
  saveAiKey,
  shortProviderLabel,
  updateRouting,
} from '../lib/aiKeys';
import type {
  AiKeysListResponse,
  CapabilitiesResponse,
  LlmProviderCapability,
  LlmRouting,
  ProviderId,
  QwenRegion,
} from '../lib/aiKeys';

type LegacyProvider = 'gemini' | 'qwen' | 'ollama';

interface KeyStatus {
  connected: boolean;
  provider: string;
  baseUrl: string | null;
  region: QwenRegion | null;
  verified: boolean;
  hint: string | null;
  updatedAt: string | null;
}

const QWEN_PRICING_URL = 'https://www.alibabacloud.com/help/en/model-studio/model-pricing';

export function AiKeyCard() {
  const [capsState, setCapsState] = useState<'loading' | 'synced' | 'legacy'>('loading');
  const [caps, setCaps] = useState<CapabilitiesResponse | null>(null);
  const [keysList, setKeysList] = useState<AiKeysListResponse | null>(null);
  const [status, setStatus] = useState<KeyStatus | null>(null);
  const [provider, setProvider] = useState<ProviderId>('qwen');
  const [apiKey, setApiKey] = useState('');
  const [qwenRegion, setQwenRegion] = useState<QwenRegion>('intl');
  const [qwenCustomUrl, setQwenCustomUrl] = useState('');
  const [ollamaReachable, setOllamaReachable] = useState<boolean | null>(null);
  const [ollamaChecking, setOllamaChecking] = useState(false);
  const [workerProvider, setWorkerProvider] = useState('gemini');
  const [workerModel, setWorkerModel] = useState('');
  const [reasoningProvider, setReasoningProvider] = useState('gemini');
  const [reasoningModel, setReasoningModel] = useState('');
  const [loading, setLoading] = useState(false);
  const [routingLoading, setRoutingLoading] = useState(false);
  const [removing, setRemoving] = useState<ProviderId | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const [routingError, setRoutingError] = useState<string | null>(null);
  const [routingSuccess, setRoutingSuccess] = useState<string | null>(null);

  function applyRouting(routing: LlmRouting, capabilities: CapabilitiesResponse) {
    const pick = (id: string) => {
      const found = capabilities.llmProviders.find((p) => p.id === id);
      return found ?? capabilities.llmProviders[0];
    };
    const worker = pick(routing.workerProvider);
    const reasoning = pick(routing.reasoningProvider);
    if (worker) {
      setWorkerProvider(worker.id);
      setWorkerModel(routing.workerModel ?? worker.defaultModels.worker);
    }
    if (reasoning) {
      setReasoningProvider(reasoning.id);
      setReasoningModel(routing.reasoningModel ?? reasoning.defaultModels.reasoning);
    }
  }

  async function loadLegacyStatus() {
    try {
      const res = await fetch('/api/me/ai-key', { credentials: 'include' });
      if (res.ok) {
        const data = (await res.json()) as KeyStatus;
        setStatus(data);
        if (
          data.connected &&
          (data.provider === 'gemini' || data.provider === 'qwen' || data.provider === 'ollama')
        ) {
          setProvider(data.provider);
          if (data.provider === 'qwen' && data.region) setQwenRegion(data.region);
        }
      }
    } catch {
      // Ignore initial load error
    }
  }

  async function reloadKeys() {
    const res = await listAiKeys();
    if (res.ok) {
      setKeysList(res.data);
      if (caps) applyRouting(res.data.routing, caps);
    }
    return res;
  }

  useEffect(() => {
    let cancelled = false;
    async function init() {
      const [capsRes, keysRes] = await Promise.all([fetchCapabilities(), listAiKeys()]);
      if (cancelled) return;
      if (capsRes.ok) {
        setCaps(capsRes.data);
        if (keysRes.ok) {
          setKeysList(keysRes.data);
          applyRouting(keysRes.data.routing, capsRes.data);
          const saved = keysRes.data.keys.find((k) =>
            capsRes.data.llmProviders.some((p) => p.id === k.providerId && p.available),
          );
          if (saved) setProvider(saved.providerId);
        } else {
          const firstHosted = hostedProviders(capsRes.data)[0];
          if (firstHosted) setProvider(firstHosted.id);
        }
        setCapsState('synced');
      } else {
        await loadLegacyStatus();
        if (!cancelled) setCapsState('legacy');
      }
    }
    void init();
    return () => {
      cancelled = true;
    };
    // Runs once on mount; the new endpoints either exist or the card falls back.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function checkOllama() {
    setOllamaChecking(true);
    setOllamaReachable(null);
    try {
      const res = await fetch('http://127.0.0.1:11434/api/tags', {
        signal: AbortSignal.timeout(5000),
      });
      setOllamaReachable(res.ok);
    } catch {
      setOllamaReachable(false);
    } finally {
      setOllamaChecking(false);
    }
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setWarning(null);
    setSuccess(null);

    if (capsState === 'synced') {
      if (provider === 'ollama' && ollamaReachable === false) {
        setWarning(
          'Saving anyway, but Ollama is not reachable on this machine right now. Start Ollama before running local AI scans.',
        );
      }
      let baseUrl: string | undefined;
      if (provider === 'qwen') {
        const resolved = resolveQwenBaseUrl(qwenRegion, qwenCustomUrl);
        if (resolved === null) {
          setError('Enter your custom DashScope workspace URL for Qwen.');
          return;
        }
        baseUrl = resolved;
      }
      setLoading(true);
      try {
        const res = await saveAiKey({
          providerId: provider,
          apiKey: provider === 'ollama' ? '' : apiKey,
          ...(baseUrl ? { baseUrl } : {}),
        });
        if (!res.ok) {
          setError(formatSaveKeyError(res.status, res.error));
        } else {
          setApiKey('');
          setSuccess('Key verified and saved.');
          // The POST response carries the routing the save picked; apply
          // it straight away instead of waiting on the reload below.
          if (res.data.routing && caps) applyRouting(res.data.routing, caps);
          await reloadKeys();
        }
      } catch {
        setError('Network error while verifying key.');
      } finally {
        setLoading(false);
      }
      return;
    }

    // Legacy path: the pre-0.4.0 single-key endpoint.
    if (provider === 'ollama' && ollamaReachable === false) {
      setWarning(
        'Saving anyway, but Ollama is not reachable on this machine right now. Start Ollama before running local AI scans.',
      );
    }
    setLoading(true);
    try {
      const res = await fetch('/api/me/ai-key', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          apiKey: provider === 'ollama' ? '' : apiKey,
          provider,
          ...(provider === 'qwen'
            ? {
                region: qwenRegion,
                ...(qwenRegion === 'custom' ? { baseUrl: qwenCustomUrl } : {}),
              }
            : {}),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Could not verify API key.');
      } else {
        setApiKey('');
        setSuccess(data.message || 'Key verified and saved.');
        await loadLegacyStatus();
      }
    } catch {
      setError('Network error while verifying key.');
    } finally {
      setLoading(false);
    }
  }

  async function handleRemoveKey(providerId: ProviderId) {
    setRemoveError(null);
    setSuccess(null);
    setRemoving(providerId);
    const res = await deleteAiKey(providerId);
    if (!res.ok) {
      setRemoveError(res.error);
      setRemoving(null);
      return;
    }
    setSuccess('Key removed.');
    await reloadKeys();
    setRemoving(null);
  }

  async function handleLegacyRemove() {
    setError(null);
    setWarning(null);
    setSuccess(null);
    setLoading(true);
    try {
      const res = await fetch('/api/me/ai-key', { method: 'DELETE', credentials: 'include' });
      if (!res.ok) {
        const data = (await res.json().catch(() => null)) as { error?: string } | null;
        setError(data?.error ?? `Could not remove the key (${res.status}). It is still saved.`);
        return;
      }
      setOllamaReachable(null);
      setSuccess('Key removed.');
      await loadLegacyStatus();
    } catch {
      setError('Network error while removing the key. It is still saved.');
    } finally {
      setLoading(false);
    }
  }

  async function handleSaveRouting() {
    if (!caps) return;
    setRoutingError(null);
    setRoutingSuccess(null);
    setRoutingLoading(true);
    const res = await updateRouting({
      workerProvider,
      workerModel,
      reasoningProvider,
      reasoningModel,
    });
    if (!res.ok) {
      setRoutingError(res.error);
    } else {
      setRoutingSuccess('Routing saved.');
      applyRouting(res.data.routing, caps);
    }
    setRoutingLoading(false);
  }

  function pickProvider(p: ProviderId, cap: LlmProviderCapability | undefined) {
    if (cap && !cap.available) return;
    setProvider(p);
    setError(null);
    setWarning(null);
    setSuccess(null);
  }

  function changeRoutingProvider(tier: 'worker' | 'reasoning', id: string) {
    const cap = caps?.llmProviders.find((p) => p.id === id);
    if (!cap) return;
    if (tier === 'worker') {
      setWorkerProvider(id);
      setWorkerModel(cap.defaultModels.worker);
    } else {
      setReasoningProvider(id);
      setReasoningModel(cap.defaultModels.reasoning);
    }
    setRoutingError(null);
    setRoutingSuccess(null);
  }

  const selectedCap = caps?.llmProviders.find((p) => p.id === provider);
  const ollamaCap = caps ? ollamaCapability(caps) : undefined;
  const ollamaDisabled = capsState === 'synced' && ollamaCap !== undefined && !ollamaCap.available;
  const legacyLabels: Record<LegacyProvider, string> = {
    gemini: 'Gemini',
    qwen: 'Qwen',
    ollama: 'Ollama (local)',
  };

  const keyPlaceholder =
    provider === 'gemini'
      ? 'Paste Gemini API key (AIza...)'
      : provider === 'qwen'
        ? 'Paste DashScope API key (sk-...)'
        : provider === 'ollama'
          ? 'No key needed - Ollama runs on your machine'
          : 'Paste API key';

  const canSave =
    !loading &&
    (capsState !== 'synced' || (selectedCap?.available ?? true)) &&
    (provider === 'ollama' ||
      (apiKey.trim().length > 0 &&
        (provider !== 'qwen' || qwenRegion !== 'custom' || qwenCustomUrl.trim().length > 0)));

  const hosted = caps ? hostedProviders(caps) : [];
  const workerCap = caps?.llmProviders.find((p) => p.id === workerProvider);
  const reasoningCap = caps?.llmProviders.find((p) => p.id === reasoningProvider);

  // Status badge for the active routing, shown only once a key is saved —
  // with no key there is no configuration to report, only the empty state.
  const routingBadge =
    capsState === 'synced' && caps && keysList && keysList.keys.length > 0
      ? formatRoutingBadge(
          { workerProvider, workerModel, reasoningProvider, reasoningModel },
          (id) => {
            const cap = caps.llmProviders.find((p) => p.id === id);
            return cap ? shortProviderLabel(cap.label) : id;
          },
        )
      : null;

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-6 backdrop-blur-md">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h3 className="text-lg font-semibold text-white">AI Engine Key (BYOK)</h3>
          <p className="mt-1 text-sm text-zinc-400">
            Bring your own AI provider to unlock AI Swarm scans. Hosted keys are encrypted in
            Postgres and shared across both the web app and your paired extension, without
            storing raw keys in browser storage.
          </p>
        </div>
        {capsState === 'legacy' && status?.connected && (
          <span className="rounded-full bg-emerald-500/15 px-3 py-1 text-xs font-medium text-emerald-300">
            Connected · {legacyLabels[(status.provider as LegacyProvider) ?? 'gemini']} ·{' '}
            {status.verified ? status.hint : 'unverified'}
          </span>
        )}
        {capsState === 'synced' && keysList && keysList.hasByok && (
          <span className="rounded-full bg-emerald-500/15 px-3 py-1 text-xs font-medium text-emerald-300">
            Connected · {keysList.keys.length} provider{keysList.keys.length === 1 ? '' : 's'}
          </span>
        )}
      </div>

      {capsState === 'loading' && (
        <p className="mt-4 text-sm text-zinc-400">Loading AI providers...</p>
      )}

      {capsState === 'synced' && caps && (
        <>
          {keysList && keysList.keys.length > 0 && (
            <ul className="mt-4 flex flex-col gap-2">
              {keysList.keys.map((k) => {
                const cap = caps.llmProviders.find((p) => p.id === k.providerId);
                return (
                  <li
                    key={k.providerId}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/10 bg-black/30 px-4 py-3"
                  >
                    <span className="text-sm text-zinc-200">
                      <span className="font-medium text-white">{cap?.label ?? k.providerId}</span>{' '}
                      <span className="font-mono text-xs text-zinc-400">
                        {k.keyHint} · verified {new Date(k.verifiedAt).toLocaleDateString()}
                      </span>
                    </span>
                    <button
                      type="button"
                      onClick={() => void handleRemoveKey(k.providerId)}
                      disabled={removing !== null}
                      className="rounded-full border border-red-500/30 px-3 py-1.5 text-xs font-medium text-red-300 transition hover:bg-red-500/10 disabled:opacity-50"
                    >
                      {removing === k.providerId ? 'Removing...' : 'Remove'}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
          {keysList && keysList.keys.length === 0 && (
            <p className="mt-4 text-sm text-zinc-400">
              No provider keys saved yet. Add one below to unlock AI Swarm scans.
            </p>
          )}
          {routingBadge && (
            <p className="mt-3 inline-flex rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300">
              {routingBadge}
            </p>
          )}
          {removeError && (
            <p className="mt-3 text-sm text-red-400" role="alert">
              {removeError}
            </p>
          )}

          <form onSubmit={handleSave} className="mt-4 flex flex-col gap-3">
            <div className="flex flex-wrap gap-2" role="group" aria-label="AI provider">
              {caps.llmProviders.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => pickProvider(p.id, p)}
                  aria-pressed={provider === p.id}
                  disabled={!p.available}
                  title={p.available ? undefined : p.reason}
                  className={`rounded-full px-4 py-2 text-sm font-medium transition ${
                    provider === p.id
                      ? 'bg-white text-black'
                      : 'border border-white/15 text-zinc-300 hover:border-white/30'
                  } disabled:cursor-not-allowed disabled:opacity-40`}
                >
                  {p.label}
                  {p.id === 'qwen' && (
                    <span
                      className={`ml-1.5 rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${
                        provider === p.id
                          ? 'bg-emerald-500/20 text-emerald-700'
                          : 'bg-emerald-500/20 text-emerald-300'
                      }`}
                    >
                      Recommended
                    </span>
                  )}
                </button>
              ))}
            </div>
            {caps.llmProviders.some((p) => !p.available) && (
              <p className="text-xs text-zinc-500">
                {caps.llmProviders
                  .filter((p) => !p.available)
                  .map((p) => `${p.label} disabled: ${p.reason ?? 'unavailable'}`)
                  .join(' · ')}
              </p>
            )}

            {provider === 'qwen' && (
              <div className="flex flex-col gap-2 rounded-xl border border-white/10 bg-black/30 p-3">
                <p className="text-sm text-zinc-400">
                  Your key is a DashScope API key from Alibaba Cloud Model Studio. Usage is
                  billed to your own Alibaba Cloud account - BugSeek charges nothing for the
                  model itself.{' '}
                  <a
                    href={QWEN_PRICING_URL}
                    target="_blank"
                    rel="noreferrer"
                    className="text-indigo-300 underline hover:text-indigo-200"
                  >
                    See DashScope pricing
                  </a>
                </p>
                <label className="flex flex-col gap-1 text-sm text-zinc-300">
                  <span>Region - pick the one your key was created in</span>
                  <select
                    value={qwenRegion}
                    onChange={(e) => setQwenRegion(e.target.value as QwenRegion)}
                    className="rounded-xl border border-white/15 bg-black/40 px-4 py-2.5 text-sm text-white focus:border-indigo-400 focus:outline-none"
                  >
                    <option value="intl">International (default)</option>
                    <option value="cn">Beijing (China mainland)</option>
                    <option value="custom">Custom workspace URL</option>
                  </select>
                </label>
                {qwenRegion === 'custom' && (
                  <input
                    type="url"
                    value={qwenCustomUrl}
                    onChange={(e) => setQwenCustomUrl(e.target.value)}
                    placeholder="https://your-workspace.dashscope.aliyuncs.com/compatible-mode/v1"
                    className="rounded-xl border border-white/15 bg-black/40 px-4 py-2.5 text-sm text-white placeholder-zinc-500 focus:border-indigo-400 focus:outline-none"
                  />
                )}
                <p className="text-xs text-zinc-500">
                  A key from one region returns an error in another - if saving fails,
                  double-check the region first.
                </p>
              </div>
            )}

            {provider === 'ollama' && (
              <div className="flex flex-col gap-2 rounded-xl border border-white/10 bg-black/30 p-3">
                <p className="text-sm text-zinc-400">
                  Ollama runs models on your own machine - no key, no cloud bill. It only works
                  with a locally-run backend: the hosted BugSeek backend cannot reach your
                  localhost, so Ollama unlocks the extension&apos;s local paths, not hosted
                  swarm runs.
                </p>
                {ollamaDisabled ? (
                  <p className="text-sm text-amber-400">
                    Ollama is disabled on this backend: {ollamaCap?.reason ?? 'unavailable'}.
                  </p>
                ) : (
                  <div className="flex items-center gap-3">
                    <button
                      type="button"
                      onClick={checkOllama}
                      disabled={ollamaChecking}
                      className="rounded-xl border border-white/15 px-4 py-2 text-sm font-medium text-white transition hover:border-white/30 disabled:opacity-50"
                    >
                      {ollamaChecking ? 'Checking...' : 'Check local Ollama'}
                    </button>
                    {ollamaReachable === true && (
                      <span className="text-sm text-emerald-400">
                        Ollama is reachable on this machine.
                      </span>
                    )}
                    {ollamaReachable === false && (
                      <span className="text-sm text-amber-400">
                        Ollama is not reachable - start it, then check again. This page is
                        served over HTTPS, so stricter browsers may block the check to
                        http://127.0.0.1:11434 even while Ollama is running; saving still works,
                        the check is only a hint.
                      </span>
                    )}
                  </div>
                )}
              </div>
            )}

            <div className="flex flex-col gap-3 sm:flex-row">
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={keyPlaceholder}
                disabled={provider === 'ollama'}
                className="flex-1 rounded-xl border border-white/15 bg-black/40 px-4 py-2.5 text-sm text-white placeholder-zinc-500 focus:border-indigo-400 focus:outline-none disabled:opacity-50"
                required={provider !== 'ollama'}
              />
              <button
                type="submit"
                disabled={!canSave}
                className="rounded-xl bg-indigo-500 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-indigo-400 disabled:opacity-50"
              >
                {loading ? 'Verifying...' : 'Verify & Save'}
              </button>
            </div>
          </form>

          <details className="mt-6 rounded-xl border border-white/10 bg-black/30 p-4">
            <summary className="cursor-pointer text-sm font-semibold text-white">
              Advanced: override models
            </summary>
            <p className="mt-1 text-xs text-zinc-500">
              Pick which provider and model runs each tier of the swarm. Worker runs the
              specialists; Reasoning runs the head planner and the retester proof gate.
            </p>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <label className="flex flex-col gap-1 text-sm text-zinc-300">
                <span>Worker Tier provider</span>
                <select
                  value={workerProvider}
                  onChange={(e) => changeRoutingProvider('worker', e.target.value)}
                  className="rounded-xl border border-white/15 bg-black/40 px-4 py-2.5 text-sm text-white focus:border-indigo-400 focus:outline-none"
                >
                  {hosted.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-sm text-zinc-300">
                <span>Worker Tier model</span>
                <select
                  value={workerModel}
                  onChange={(e) => setWorkerModel(e.target.value)}
                  className="rounded-xl border border-white/15 bg-black/40 px-4 py-2.5 text-sm text-white focus:border-indigo-400 focus:outline-none"
                >
                  {workerCap &&
                    modelOptionsFor(workerCap, workerModel).map((m) => (
                      <option key={m} value={m}>
                        {m}
                      </option>
                    ))}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-sm text-zinc-300">
                <span>Reasoning Tier provider</span>
                <select
                  value={reasoningProvider}
                  onChange={(e) => changeRoutingProvider('reasoning', e.target.value)}
                  className="rounded-xl border border-white/15 bg-black/40 px-4 py-2.5 text-sm text-white focus:border-indigo-400 focus:outline-none"
                >
                  {hosted.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-sm text-zinc-300">
                <span>Reasoning Tier model</span>
                <select
                  value={reasoningModel}
                  onChange={(e) => setReasoningModel(e.target.value)}
                  className="rounded-xl border border-white/15 bg-black/40 px-4 py-2.5 text-sm text-white focus:border-indigo-400 focus:outline-none"
                >
                  {reasoningCap &&
                    modelOptionsFor(reasoningCap, reasoningModel).map((m) => (
                      <option key={m} value={m}>
                        {m}
                      </option>
                    ))}
                </select>
              </label>
            </div>
            <button
              type="button"
              onClick={() => void handleSaveRouting()}
              disabled={routingLoading || hosted.length === 0}
              className="mt-3 rounded-xl bg-indigo-500 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-indigo-400 disabled:opacity-50"
            >
              {routingLoading ? 'Saving...' : 'Save Routing'}
            </button>
            {routingError && (
              <p className="mt-3 text-sm text-red-400" role="alert">
                {routingError}
              </p>
            )}
            {routingSuccess && (
              <p className="mt-3 text-sm text-emerald-400">{routingSuccess}</p>
            )}
          </details>
        </>
      )}

      {capsState === 'legacy' && (
        <form onSubmit={handleSave} className="mt-4 flex flex-col gap-3">
          <div className="flex flex-wrap gap-2" role="group" aria-label="AI provider">
            {(['gemini', 'qwen', 'ollama'] as LegacyProvider[]).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => {
                  setProvider(p);
                  setError(null);
                  setWarning(null);
                  setSuccess(null);
                }}
                aria-pressed={provider === p}
                className={`rounded-full px-4 py-2 text-sm font-medium transition ${
                  provider === p
                    ? 'bg-white text-black'
                    : 'border border-white/15 text-zinc-300 hover:border-white/30'
                }`}
              >
                {legacyLabels[p]}
                {p === 'qwen' && (
                  <span
                    className={`ml-1.5 rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${
                      provider === p
                        ? 'bg-emerald-500/20 text-emerald-700'
                        : 'bg-emerald-500/20 text-emerald-300'
                    }`}
                  >
                    Recommended
                  </span>
                )}
              </button>
            ))}
          </div>

          {provider === 'qwen' && (
            <div className="flex flex-col gap-2 rounded-xl border border-white/10 bg-black/30 p-3">
              <p className="text-sm text-zinc-400">
                Your key is a DashScope API key from Alibaba Cloud Model Studio. Usage is
                billed to your own Alibaba Cloud account - BugSeek charges nothing for the
                model itself.{' '}
                <a
                  href={QWEN_PRICING_URL}
                  target="_blank"
                  rel="noreferrer"
                  className="text-indigo-300 underline hover:text-indigo-200"
                >
                  See DashScope pricing
                </a>
              </p>
              <label className="flex flex-col gap-1 text-sm text-zinc-300">
                <span>Region - pick the one your key was created in</span>
                <select
                  value={qwenRegion}
                  onChange={(e) => setQwenRegion(e.target.value as QwenRegion)}
                  className="rounded-xl border border-white/15 bg-black/40 px-4 py-2.5 text-sm text-white focus:border-indigo-400 focus:outline-none"
                >
                  <option value="intl">International (default)</option>
                  <option value="cn">Beijing (China mainland)</option>
                  <option value="custom">Custom workspace URL</option>
                </select>
              </label>
              {qwenRegion === 'custom' && (
                <input
                  type="url"
                  value={qwenCustomUrl}
                  onChange={(e) => setQwenCustomUrl(e.target.value)}
                  placeholder="https://your-workspace.dashscope.aliyuncs.com/compatible-mode/v1"
                  className="rounded-xl border border-white/15 bg-black/40 px-4 py-2.5 text-sm text-white placeholder-zinc-500 focus:border-indigo-400 focus:outline-none"
                />
              )}
              <p className="text-xs text-zinc-500">
                A key from one region returns an error in another - if saving fails,
                double-check the region first.
              </p>
            </div>
          )}

          {provider === 'ollama' && (
            <div className="flex flex-col gap-2 rounded-xl border border-white/10 bg-black/30 p-3">
              <p className="text-sm text-zinc-400">
                Ollama runs models on your own machine - no key, no cloud bill. It only works
                with a locally-run backend: the hosted BugSeek backend cannot reach your
                localhost, so Ollama unlocks the extension&apos;s local paths, not hosted
                swarm runs.
              </p>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={checkOllama}
                  disabled={ollamaChecking}
                  className="rounded-xl border border-white/15 px-4 py-2 text-sm font-medium text-white transition hover:border-white/30 disabled:opacity-50"
                >
                  {ollamaChecking ? 'Checking...' : 'Check local Ollama'}
                </button>
                {ollamaReachable === true && (
                  <span className="text-sm text-emerald-400">
                    Ollama is reachable on this machine.
                  </span>
                )}
                {ollamaReachable === false && (
                  <span className="text-sm text-amber-400">
                    Ollama is not reachable - start it, then check again. This page is served
                    over HTTPS, so stricter browsers may block the check to
                    http://127.0.0.1:11434 even while Ollama is running; saving still works,
                    the check is only a hint.
                  </span>
                )}
              </div>
            </div>
          )}

          <div className="flex flex-col gap-3 sm:flex-row">
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={keyPlaceholder}
              disabled={provider === 'ollama'}
              className="flex-1 rounded-xl border border-white/15 bg-black/40 px-4 py-2.5 text-sm text-white placeholder-zinc-500 focus:border-indigo-400 focus:outline-none disabled:opacity-50"
              required={provider !== 'ollama'}
            />
            <button
              type="submit"
              disabled={!canSave}
              className="rounded-xl bg-indigo-500 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-indigo-400 disabled:opacity-50"
            >
              {loading ? 'Verifying...' : status?.connected ? 'Update Key' : 'Verify & Unlock'}
            </button>
            {status?.connected && (
              <button
                type="button"
                onClick={handleLegacyRemove}
                disabled={loading}
                className="rounded-xl border border-red-500/30 px-4 py-2.5 text-sm font-medium text-red-300 transition hover:bg-red-500/10 disabled:opacity-50"
              >
                Remove
              </button>
            )}
          </div>
        </form>
      )}

      {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
      {warning && <p className="mt-3 text-sm text-amber-400">{warning}</p>}
      {success && <p className="mt-3 text-sm text-emerald-400">{success}</p>}
    </div>
  );
}

import { useEffect, useState } from 'react';

type Provider = 'gemini' | 'qwen' | 'ollama';
type QwenRegion = 'intl' | 'cn' | 'custom';

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

const PROVIDER_LABELS: Record<Provider, string> = {
  gemini: 'Gemini',
  qwen: 'Qwen',
  ollama: 'Ollama (local)',
};

export function AiKeyCard() {
  const [status, setStatus] = useState<KeyStatus | null>(null);
  const [provider, setProvider] = useState<Provider>('qwen');
  const [apiKey, setApiKey] = useState('');
  const [qwenRegion, setQwenRegion] = useState<QwenRegion>('intl');
  const [qwenCustomUrl, setQwenCustomUrl] = useState('');
  const [ollamaReachable, setOllamaReachable] = useState<boolean | null>(null);
  const [ollamaChecking, setOllamaChecking] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function loadStatus() {
    try {
      const res = await fetch('/api/me/ai-key', { credentials: 'include' });
      if (res.ok) {
        const data = (await res.json()) as KeyStatus;
        setStatus(data);
        if (data.connected && (data.provider === 'gemini' || data.provider === 'qwen' || data.provider === 'ollama')) {
          setProvider(data.provider);
          if (data.provider === 'qwen' && data.region) setQwenRegion(data.region);
        }
      }
    } catch {
      // Ignore initial load error
    }
  }

  useEffect(() => {
    loadStatus();
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

    // Ollama may be saved while unreachable (e.g. it is not running right
    // now), warn, but do not block: the user runs it locally.
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
        await loadStatus();
      }
    } catch {
      setError('Network error while verifying key.');
    } finally {
      setLoading(false);
    }
  }

  async function handleRemove() {
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
      await loadStatus();
    } catch {
      setError('Network error while removing the key. It is still saved.');
    } finally {
      setLoading(false);
    }
  }

  const keyPlaceholder =
    provider === 'gemini'
      ? 'Paste Gemini API key (AIza...)'
      : provider === 'qwen'
        ? 'Paste DashScope API key (sk-...)'
        : 'No key needed — Ollama runs on your machine';

  const canSave =
    !loading &&
    (provider === 'ollama' ||
      (apiKey.trim().length > 0 &&
        (provider !== 'qwen' || qwenRegion !== 'custom' || qwenCustomUrl.trim().length > 0)));

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-6 backdrop-blur-md">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h3 className="text-lg font-semibold text-white">
            AI Engine Key (BYOK)
          </h3>
          <p className="mt-1 text-sm text-zinc-400">
            Bring your own AI provider to unlock AI Swarm scans. Keys are
            encrypted at rest (AES-256-GCM) and saved to your account,
            paired with the extension&apos;s bs_ key: the extension keeps
            its own copy of the same key for local runs, and the backend
            copy is what powers hosted swarm runs.
          </p>
        </div>
        {status?.connected && (
          <span className="rounded-full bg-emerald-500/15 px-3 py-1 text-xs font-medium text-emerald-300">
            Connected · {PROVIDER_LABELS[(status.provider as Provider) ?? 'gemini']} ·{' '}
            {status.verified ? status.hint : 'unverified'}
          </span>
        )}
      </div>

      <form onSubmit={handleSave} className="mt-4 flex flex-col gap-3">
        <div className="flex flex-wrap gap-2" role="group" aria-label="AI provider">
          {(['gemini', 'qwen', 'ollama'] as Provider[]).map((p) => (
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
              {PROVIDER_LABELS[p]}
              {p === 'qwen' && (
                <span
                  className={`ml-1.5 rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${
                    provider === p ? 'bg-emerald-500/20 text-emerald-700' : 'bg-emerald-500/20 text-emerald-300'
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
              Your key is a DashScope API key from Alibaba Cloud Model Studio.
              Usage is billed to your own Alibaba Cloud account — BugSeek
              charges nothing for the model itself.{' '}
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
              <span>Region — pick the one your key was created in</span>
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
              A key from one region returns an error in another — if saving
              fails, double-check the region first.
            </p>
          </div>
        )}

        {provider === 'ollama' && (
          <div className="flex flex-col gap-2 rounded-xl border border-white/10 bg-black/30 p-3">
            <p className="text-sm text-zinc-400">
              Ollama runs models on your own machine — no key, no cloud
              bill. It only works with a locally-run backend: the hosted
              BugSeek backend cannot reach your localhost, so Ollama unlocks
              the extension&rsquo;s local paths, not hosted swarm runs.
            </p>
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={checkOllama}
                disabled={ollamaChecking}
                className="rounded-xl border border-white/15 px-4 py-2 text-sm font-medium text-white transition hover:border-white/30 disabled:opacity-50"
              >
                {ollamaChecking ? 'Checking…' : 'Check local Ollama'}
              </button>
              {ollamaReachable === true && (
                <span className="text-sm text-emerald-400">Ollama is reachable on this machine.</span>
              )}
              {ollamaReachable === false && (
                <span className="text-sm text-amber-400">
                  Ollama is not reachable — start it, then check again. This
                  page is served over HTTPS, so stricter browsers may block
                  the check to http://127.0.0.1:11434 even while Ollama is
                  running; saving still works, the check is only a hint.
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
              onClick={handleRemove}
              disabled={loading}
              className="rounded-xl border border-red-500/30 px-4 py-2.5 text-sm font-medium text-red-300 transition hover:bg-red-500/10 disabled:opacity-50"
            >
              Remove
            </button>
          )}
        </div>
      </form>

      {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
      {warning && <p className="mt-3 text-sm text-amber-400">{warning}</p>}
      {success && <p className="mt-3 text-sm text-emerald-400">{success}</p>}
    </div>
  );
}

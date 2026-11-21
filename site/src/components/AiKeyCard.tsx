import { useEffect, useState } from 'react';

interface KeyStatus {
  connected: boolean;
  provider: string;
  hint: string | null;
  updatedAt: string | null;
}

export function AiKeyCard({ onUnlocked }: { onUnlocked?: () => void }) {
  const [status, setStatus] = useState<KeyStatus | null>(null);
  const [apiKey, setApiKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function loadStatus() {
    try {
      const res = await fetch('/api/me/ai-key', { credentials: 'include' });
      if (res.ok) setStatus(await res.json());
    } catch {
      // Ignore initial load error
    }
  }

  useEffect(() => {
    loadStatus();
  }, []);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      const res = await fetch('/api/me/ai-key', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey, provider: 'gemini' }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Could not verify API key.');
      } else {
        setApiKey('');
        setSuccess(data.message || 'Key verified and saved.');
        await loadStatus();
        onUnlocked?.();
      }
    } catch {
      setError('Network error while verifying key.');
    } finally {
      setLoading(false);
    }
  }

  async function handleRemove() {
    setError(null);
    setSuccess(null);
    setLoading(true);
    try {
      await fetch('/api/me/ai-key', { method: 'DELETE', credentials: 'include' });
      await loadStatus();
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-6 backdrop-blur-md">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h3 className="text-lg font-semibold text-white">
            AI Engine Key (BYOK)
          </h3>
          <p className="mt-1 text-sm text-zinc-400">
            Add your Gemini API key to unlock AI Swarm scans. Encrypted at rest
            (AES-256-GCM) and never exposed to the browser extension.
          </p>
        </div>
        {status?.connected && (
          <span className="rounded-full bg-emerald-500/15 px-3 py-1 text-xs font-medium text-emerald-300">
            Connected · {status.hint}
          </span>
        )}
      </div>

      <form onSubmit={handleSave} className="mt-4 flex flex-col gap-3 sm:flex-row">
        <input
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="Paste Gemini API key (AIza...)"
          className="flex-1 rounded-xl border border-white/15 bg-black/40 px-4 py-2.5 text-sm text-white placeholder-zinc-500 focus:border-indigo-400 focus:outline-none"
          required
        />
        <button
          type="submit"
          disabled={loading || !apiKey.trim()}
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
      </form>

      {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
      {success && <p className="mt-3 text-sm text-emerald-400">{success}</p>}
    </div>
  );
}

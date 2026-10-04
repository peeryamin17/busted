import { useCallback, useEffect, useRef, useState } from 'react';
import { Check, Copy, KeyRound, Link2, Puzzle, Trash2 } from 'lucide-react';
import { Reveal } from './Reveal';

/**
 * "Connect the extension" — the members'-site half of extension sign-in
 * sync. The extension carries a tiny relay that runs only on this origin:
 * it announces itself to the page, and on the user's click this card
 * mints a fresh API key (shown once, hashed server-side) and hands it
 * over. No relay? The same key is shown once for a manual paste.
 */

interface ApiKeyRow {
  id: string;
  name: string;
  keyPrefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

type ExtState = 'checking' | 'present' | 'absent';
type ConnectState = 'idle' | 'working' | 'connected' | 'manual' | 'error';

const SITE_SOURCE = 'bugseek-site';
const EXT_SOURCE = 'bugseek-extension';

function postToExtension(payload: Record<string, unknown>): void {
  window.postMessage({ source: SITE_SOURCE, ...payload }, window.location.origin);
}

export function ConnectExtensionCard() {
  const [ext, setExt] = useState<ExtState>('checking');
  const [keys, setKeys] = useState<ApiKeyRow[]>([]);
  const [connect, setConnect] = useState<ConnectState>('idle');
  const [freshKey, setFreshKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [link, setLink] = useState<{ code: string; expiresAt: string } | null>(null);
  const [linkState, setLinkState] = useState<'idle' | 'working' | 'error'>('idle');
  const [codeCopied, setCodeCopied] = useState(false);
  const ackWaiter = useRef<((ok: boolean) => void) | null>(null);

  const loadKeys = useCallback(async () => {
    try {
      const res = await fetch('/api/auth/api-keys', { credentials: 'include' });
      if (!res.ok) return;
      const data = (await res.json()) as { keys: ApiKeyRow[] };
      setKeys(data.keys ?? []);
    } catch {
      /* leave the list as-is; the connect flow surfaces errors itself */
    }
  }, []);

  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;
      const data = event.data as { source?: string; type?: string; ok?: boolean } | null;
      if (!data || data.source !== EXT_SOURCE) return;
      if (data.type === 'BUGSEEK_EXTENSION_PRESENT') setExt('present');
      if (data.type === 'BUGSEEK_CONNECTED' && ackWaiter.current) {
        ackWaiter.current(data.ok === true);
        ackWaiter.current = null;
      }
    };
    window.addEventListener('message', onMessage);
    postToExtension({ type: 'BUGSEEK_PING' });
    const t = window.setTimeout(() => {
      setExt((s) => (s === 'checking' ? 'absent' : s));
    }, 1800);
    void loadKeys();
    return () => {
      window.removeEventListener('message', onMessage);
      window.clearTimeout(t);
    };
  }, [loadKeys]);

  const waitForAck = useCallback(
    () =>
      new Promise<boolean>((resolve) => {
        ackWaiter.current = resolve;
        window.setTimeout(() => {
          if (ackWaiter.current === resolve) {
            ackWaiter.current = null;
            resolve(false);
          }
        }, 4000);
      }),
    [],
  );

  const doConnect = async () => {
    setError(null);
    setConnect('working');
    setFreshKey(null);
    try {
      const res = await fetch('/api/auth/api-keys', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Extension' }),
      });
      if (!res.ok) throw new Error(`Key request failed (${res.status})`);
      const data = (await res.json()) as { key: string; keyPrefix: string };
      await loadKeys();
      if (ext === 'present') {
        const ackPromise = waitForAck();
        postToExtension({ type: 'BUGSEEK_CONNECT', apiKey: data.key });
        if (await ackPromise) {
          setConnect('connected');
          return;
        }
      }
      // No relay (or no answer): the one-time key becomes a manual paste.
      setFreshKey(data.key);
      setConnect('manual');
    } catch (err) {
      setConnect('error');
      setError(err instanceof Error ? err.message : 'Something went wrong.');
    }
  };

  const doGenerateCode = async () => {
    setLinkState('working');
    try {
      const res = await fetch('/api/auth/pairing-codes', {
        method: 'POST',
        credentials: 'include',
      });
      if (!res.ok) throw new Error(`Link code request failed (${res.status})`);
      const data = (await res.json()) as { code: string; expiresAt: string };
      setLink(data);
      setLinkState('idle');
    } catch {
      setLinkState('error');
    }
  };

  const doCopyCode = async () => {
    if (!link) return;
    try {
      await navigator.clipboard.writeText(link.code);
      setCodeCopied(true);
      window.setTimeout(() => setCodeCopied(false), 2000);
    } catch {
      /* clipboard unavailable; the code stays visible to copy by hand */
    }
  };

  const doRevoke = async (id: string) => {
    try {
      await fetch(`/api/auth/api-keys/${id}`, {
        method: 'DELETE',
        credentials: 'include',
      });
      await loadKeys();
    } catch {
      /* list refresh will show the truth */
    }
  };

  const doCopy = async () => {
    if (!freshKey) return;
    try {
      await navigator.clipboard.writeText(freshKey);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable; the key stays visible to copy by hand */
    }
  };

  const liveKeys = keys.filter((k) => !k.revokedAt);

  return (
    <section className="relative mx-auto max-w-6xl px-4 py-12 sm:px-6" aria-label="Connect the extension">
      <Reveal>
        <div className="glass overflow-hidden rounded-[2rem] p-7 sm:p-9">
          <div className="grid gap-8 lg:grid-cols-[1.15fr_0.85fr]">
            <div>
              <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">
                THE EXTENSION, SIGNED IN
              </p>
              <h2 className="mt-3 font-display text-3xl font-bold tracking-tight text-bone sm:text-4xl">
                Connect the extension to your account.
              </h2>
              <p className="mt-3 max-w-xl leading-relaxed text-body/85">
                Two ways in: generate a one-time link code here and paste it into the extension,
                or let this page hand a key over directly. Either way the extension ends up signed
                in as you — keys are stored hashed on our side and only ever unlock your own
                backend runs.
              </p>
              <p className="mt-3 font-mono text-[11px] leading-relaxed text-slate2">
                {ext === 'checking' && 'LOOKING FOR THE EXTENSION ON THIS PAGE…'}
                {ext === 'present' && 'EXTENSION DETECTED IN THIS BROWSER. IT CAN TAKE THE KEY DIRECTLY.'}
                {ext === 'absent' &&
                  'NO EXTENSION ANSWERED HERE. INSTALL IT, OR TAKE THE KEY AND PASTE IT IN MANUALLY.'}
              </p>
            </div>

            <div>
              <div className="rounded-2xl border border-white/10 bg-black/30 p-4">
                <p className="flex items-center gap-2 font-mono text-[11px] tracking-[0.18em] text-slate2">
                  <Link2 className="h-3.5 w-3.5" aria-hidden /> LINK WITH A CODE
                </p>
                <p className="mt-2 text-sm leading-relaxed text-body/85">
                  Generate a one-time code, then paste it into the extension under “Link your
                  account”. It works once and dies in ten minutes.
                </p>
                <button
                  type="button"
                  onClick={() => void doGenerateCode()}
                  disabled={linkState === 'working'}
                  className="mt-3 inline-flex items-center gap-2 rounded-full bg-bone px-5 py-2.5 font-display text-sm font-bold tracking-tight text-ink transition-transform duration-300 hover:scale-[1.03] disabled:opacity-50"
                >
                  {linkState === 'working' ? 'Generating…' : link ? 'Generate a fresh code' : 'Generate link code'}
                </button>
                {linkState === 'error' && (
                  <p className="mt-3 text-sm text-red-300" role="alert">
                    Couldn't generate a code just now — the backend may be waking up. Try again in
                    a moment.
                  </p>
                )}
                {link && (
                  <div className="mt-4">
                    <p className="break-all font-mono text-base tracking-[0.14em] text-bone">
                      {link.code.match(/.{4}/g)?.join('-')}
                    </p>
                    <button
                      type="button"
                      onClick={() => void doCopyCode()}
                      className="mt-3 inline-flex items-center gap-2 rounded-full border border-white/15 px-4 py-2 text-xs font-semibold text-bone transition-colors hover:bg-white/5"
                    >
                      {codeCopied ? (
                        <>
                          <Check className="h-3.5 w-3.5" aria-hidden /> Copied
                        </>
                      ) : (
                        <>
                          <Copy className="h-3.5 w-3.5" aria-hidden /> Copy the code
                        </>
                      )}
                    </button>
                    <p className="mt-3 text-xs leading-relaxed text-body/75">
                      Valid until {new Date(link.expiresAt).toLocaleTimeString()} · single use ·
                      generating a fresh one kills this one.
                    </p>
                  </div>
                )}
              </div>

              <p className="my-4 text-center font-mono text-[11px] tracking-[0.24em] text-slate2">
                — OR CONNECT AUTOMATICALLY —
              </p>

              <button
                type="button"
                onClick={() => void doConnect()}
                disabled={connect === 'working'}
                className="inline-flex items-center gap-2 rounded-full bg-bone px-6 py-3 font-display text-sm font-bold tracking-tight text-ink transition-transform duration-300 hover:scale-[1.03] disabled:opacity-50"
              >
                {connect === 'working' ? (
                  'Connecting…'
                ) : (
                  <>
                    <Puzzle className="h-4 w-4" aria-hidden /> Connect the extension
                  </>
                )}
              </button>

              {connect === 'connected' && (
                <p className="mt-3 flex items-center gap-2 text-sm text-body/90" role="status">
                  <Check className="h-4 w-4" aria-hidden /> Connected — the extension has its
                  key. Open it and check the Active tab.
                </p>
              )}

              {connect === 'manual' && freshKey && (
                <div className="mt-4 rounded-2xl border border-white/10 bg-black/30 p-4">
                  <p className="flex items-center gap-2 font-mono text-[11px] tracking-[0.18em] text-slate2">
                    <KeyRound className="h-3.5 w-3.5" aria-hidden /> YOUR KEY — SHOWN ONCE
                  </p>
                  <p className="mt-2 break-all font-mono text-sm text-bone">{freshKey}</p>
                  <button
                    type="button"
                    onClick={() => void doCopy()}
                    className="mt-3 inline-flex items-center gap-2 rounded-full border border-white/15 px-4 py-2 text-xs font-semibold text-bone transition-colors hover:bg-white/5"
                  >
                    {copied ? (
                      <>
                        <Check className="h-3.5 w-3.5" aria-hidden /> Copied
                      </>
                    ) : (
                      <>
                        <Copy className="h-3.5 w-3.5" aria-hidden /> Copy the key
                      </>
                    )}
                  </button>
                  <p className="mt-3 text-xs leading-relaxed text-body/75">
                    In the extension: Active testing → Link your account → paste → Save. We keep
                    only a hash; lose it and you mint another here.
                  </p>
                </div>
              )}

              {connect === 'error' && (
                <p className="mt-3 text-sm text-red-300" role="alert">
                  {error ?? 'Something went wrong.'} Try again in a moment.
                </p>
              )}

              {liveKeys.length > 0 && (
                <div className="mt-6">
                  <p className="font-mono text-[11px] tracking-[0.18em] text-slate2">
                    YOUR KEYS
                  </p>
                  <ul className="mt-2 space-y-2">
                    {liveKeys.map((k) => (
                      <li
                        key={k.id}
                        className="flex items-center justify-between gap-3 rounded-xl border border-white/10 px-3.5 py-2.5 text-sm"
                      >
                        <span className="min-w-0">
                          <span className="block truncate text-bone">{k.name}</span>
                          <span className="block font-mono text-[11px] text-slate2">
                            {k.keyPrefix}… · made {new Date(k.createdAt).toLocaleDateString()}
                            {k.lastUsedAt
                              ? ` · last used ${new Date(k.lastUsedAt).toLocaleDateString()}`
                              : ' · never used'}
                          </span>
                        </span>
                        <button
                          type="button"
                          onClick={() => void doRevoke(k.id)}
                          className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-white/10 px-3 py-1.5 text-xs text-body/80 transition-colors hover:bg-white/5 hover:text-bone"
                        >
                          <Trash2 className="h-3.5 w-3.5" aria-hidden /> Revoke
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>
      </Reveal>
    </section>
  );
}

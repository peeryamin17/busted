import { useEffect, useState } from 'react';

interface Detection {
  id: string;
  pattern: string;
  severity: string;
  title: string;
  detail: string;
  evidence?: string;
  createdAt: string;
}

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-300',
  high: 'bg-orange-500/15 text-orange-300',
  medium: 'bg-amber-500/15 text-amber-300',
  low: 'bg-sky-500/15 text-sky-300',
  info: 'bg-zinc-500/15 text-zinc-300',
};

const PATTERN_LABEL: Record<string, string> = {
  'failed-login-velocity': 'Failed-login velocity',
  'password-spray': 'Password spray',
  'many-accounts-few-ips': 'Many accounts, few IPs',
  'user-agent-diversity': 'User-agent diversity',
  'api-key-anomaly': 'API-key anomaly',
  'probe-pattern': 'Probe pattern',
};

/**
 * Runtime detections panel (Thread 5, DEFENSIVE).
 *
 * Lists what BugSeek's own backend detection layer has spotted hitting
 * your account — failed-login velocity, spray patterns, API-key
 * anomalies, probing — newest first. Read-only: detections are produced
 * by the rule engine, never by clients.
 */
export function DetectionsPanel() {
  const [detections, setDetections] = useState<Detection[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch('/api/detections?limit=20', { credentials: 'include' });
        if (!res.ok) {
          if (res.status === 404) {
            // Route not registered yet (coordinator wires server.ts) —
            // the panel stays quiet instead of erroring.
            setDetections([]);
            return;
          }
          setError('Could not load detections.');
          return;
        }
        const data = await res.json();
        setDetections(Array.isArray(data.detections) ? data.detections : []);
      } catch {
        setError('Network error while loading detections.');
      }
    }
    load();
  }, []);

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-6 backdrop-blur-md">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h3 className="text-lg font-semibold text-white">Runtime detections</h3>
          <p className="mt-1 text-sm text-zinc-400">
            What BugSeek&apos;s detection layer has spotted hitting your
            account — failed-login velocity, spray patterns, API-key
            anomalies, probing. The layer watches from inside; the
            extension probes verify your defenses from outside.
          </p>
        </div>
      </div>

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      {detections === null && !error && (
        <p className="mt-4 text-sm text-zinc-400">Loading detections…</p>
      )}

      {detections !== null && detections.length === 0 && (
        <p className="mt-4 text-sm text-zinc-400">
          No detections yet. That means nothing has tripped the rules — or
          the layer has not seen any login, API-key, or request events yet.
          Events only arrive once the backend intake is wired in.
        </p>
      )}

      {detections !== null && detections.length > 0 && (
        <ul className="mt-4 space-y-3">
          {detections.map((d) => (
            <li
              key={d.id}
              className="rounded-xl border border-white/10 bg-black/30 px-4 py-3"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${SEVERITY_STYLE[d.severity] ?? SEVERITY_STYLE.info}`}
                >
                  {d.severity.toUpperCase()}
                </span>
                <span className="text-xs font-medium text-zinc-300">
                  {PATTERN_LABEL[d.pattern] ?? d.pattern}
                </span>
                <span className="ml-auto text-xs text-zinc-500">
                  {new Date(d.createdAt).toLocaleString()}
                </span>
              </div>
              <p className="mt-2 text-sm font-medium text-white">{d.title}</p>
              <p className="mt-1 text-sm text-zinc-400">{d.detail}</p>
              {d.evidence && (
                <p className="mt-1 font-mono text-xs text-zinc-500">{d.evidence}</p>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

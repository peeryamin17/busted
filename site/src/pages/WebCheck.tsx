import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import { ArrowRight, Check, Loader2, Lock, Radar } from 'lucide-react';
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Footer } from '../components/Footer';
import { Nav } from '../components/Nav';
import { Reveal } from '../components/Reveal';
import { ScoreRing } from '../components/fx/ScoreRing';
import { LiquidGlassButton } from '../components/fx/LiquidGlassButton';
import { SonarGrid } from '../components/fx/SonarGrid';
import { useAuth } from '../lib/auth';
import { springPop, springQuiet } from '../lib/motion';
import { navigate } from '../lib/router';

/* ── API shapes (gated view of /api/webcheck) ─────────────────── */

type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface FindingView {
  severity: Sev;
  category: string;
  title?: string;
  detail?: string;
  evidence?: string;
  confidence?: string;
}

interface LockedRow {
  label: string;
  count: number | null;
  note: string;
}

interface CheckView {
  id: string;
  url: string;
  host: string;
  createdAt: string;
  score: number | null;
  grade: string | null;
  counts: Record<Sev, number>;
  gated: boolean;
  findings: FindingView[];
  info: {
    perf: {
      ttfbMs: number | null;
      totalMs: number | null;
      bytes: number | null;
      redirectCount: number | null;
      compression: string | null;
      scripts: number | null;
      styles: number | null;
      images: number | null;
      htmlBytes: number | null;
    };
    server: {
      ip: string | null;
      country: string | null;
      city: string | null;
      region: string | null;
      org: string | null;
    };
    domain: {
      registrar: string | null;
      created: string | null;
      expires: string | null;
      daysLeft: number | null;
      status: string[];
      nameservers: string[];
    };
    dns: {
      a: string[];
      aaaa: string[];
      mx: string[];
      ns: string[];
      spf: boolean | null;
      dmarc: boolean | null;
      caa: boolean | null;
    };
    tls: {
      issuer: string | null;
      subject: string | null;
      validTo: string | null;
      daysLeft: number | null;
      authorized: boolean;
      protocol: string | null;
    } | null;
    api: { endpoints: string[]; openApiDoc: boolean; graphql: boolean };
    robotsTxt: boolean;
    securityTxt: boolean;
  };
  locked: LockedRow[];
}

interface RunSummary {
  id: string;
  url: string;
  host: string;
  score: number | null;
  grade: string | null;
  findingCount: number;
  requesterIp: string | null;
  requesterGeo: { country: string | null; city: string | null; region: string | null } | null;
  createdAt: string;
}

const SEV_STYLE: Record<Sev, { label: string; chip: string; bar: string }> = {
  critical: { label: 'CRITICAL', chip: 'bg-crit/15 text-crit border-crit/30', bar: 'bg-crit' },
  high: { label: 'HIGH', chip: 'bg-hot/15 text-hot border-hot/30', bar: 'bg-hot' },
  medium: { label: 'MEDIUM', chip: 'bg-amber2/15 text-amber2 border-amber2/30', bar: 'bg-amber2' },
  low: { label: 'LOW', chip: 'bg-sky2/15 text-sky2 border-sky2/35', bar: 'bg-sky2' },
  info: { label: 'INFO', chip: 'bg-white/10 text-body border-white/20', bar: 'bg-white/40' },
};

const PHASES = [
  'Resolving',
  'Fetching the page',
  'Headers & cookies',
  'Files that should not answer',
  'APIs & shipped code',
  'Domain & DNS',
  'Scoring',
];

const fmtMs = (ms: number | null): string | null =>
  ms === null ? null : ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.round(ms)} ms`;

const fmtBytes = (b: number | null): string | null =>
  b === null
    ? null
    : b >= 1_000_000
      ? `${(b / 1_000_000).toFixed(2)} MB`
      : b >= 1000
        ? `${(b / 1000).toFixed(1)} KB`
        : `${b} B`;

const fmtDate = (iso: string | null): string | null => {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? null
    : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
};

const scoreColor = (v: number): string =>
  v >= 90 ? '#2EEA8C' : v >= 75 ? '#A3E635' : v >= 55 ? '#FFD60A' : v >= 35 ? '#FF9F0A' : '#FF453A';

/* ── small building blocks ────────────────────────────────────── */

function InfoCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="glass rounded-3xl p-6">
      <h3 className="font-mono text-[11px] tracking-[0.24em] text-slate2">{title}</h3>
      <dl className="mt-4 space-y-2.5">{children}</dl>
    </div>
  );
}

function Row({ label, value, mono = false }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4">
      <dt className="shrink-0 text-sm text-body/70">{label}</dt>
      <dd
        className={`text-right text-sm text-bone ${mono ? 'break-all font-mono text-[13px]' : ''}`}
      >
        {value ?? <span className="text-slate2">couldn’t read</span>}
      </dd>
    </div>
  );
}

function PresenceChip({ label, value }: { label: string; value: boolean | null }) {
  const text = value === null ? 'unknown' : value ? 'present' : 'missing';
  const cls =
    value === true
      ? 'border-signal/40 text-signal'
      : value === null
        ? 'border-white/15 text-slate2'
        : 'border-white/15 text-body/60';
  return (
    <span className={`rounded-md border px-2 py-1 font-mono text-[11px] ${cls}`}>
      {label} · {text}
    </span>
  );
}

function ListRow({ label, items }: { label: string; items: string[] }) {
  return (
    <div>
      <dt className="text-sm text-body/70">{label}</dt>
      <dd className="mt-1.5 flex flex-wrap gap-1.5">
        {items.length === 0 ? (
          <span className="text-sm text-slate2">couldn’t read</span>
        ) : (
          items.map((item) => (
            <span
              key={item}
              className="rounded-md border border-white/10 bg-ink px-2 py-1 font-mono text-[11px] text-body"
            >
              {item}
            </span>
          ))
        )}
      </dd>
    </div>
  );
}

/* ── the page ─────────────────────────────────────────────────── */

function replaceTo(to: string) {
  window.history.replaceState({}, '', to);
  window.dispatchEvent(new PopStateEvent('popstate'));
  window.scrollTo({ top: 0, behavior: 'auto' });
}

function WebCheckLoading() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-ink px-4">
      <img src="/bug.svg" alt="" className="h-12 w-12 animate-pulse" />
      <p className="mt-5 font-mono text-[10px] tracking-[0.3em] text-slate2">CHECKING YOUR KEY</p>
    </div>
  );
}

export function WebCheck() {
  const { user, loading } = useAuth();
  const reduce = useReducedMotion();

  const [url, setUrl] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [running, setRunning] = useState(false);
  const [phase, setPhase] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CheckView | null>(null);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [loadingRunId, setLoadingRunId] = useState<string | null>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!loading && !user) replaceTo('/signin');
  }, [loading, user]);

  const refreshRuns = useCallback(async () => {
    try {
      const res = await fetch('/api/webcheck', { credentials: 'include' });
      if (!res.ok) return;
      const data = (await res.json()) as { runs: RunSummary[] };
      setRuns(data.runs ?? []);
    } catch {
      /* the list is a courtesy — the form still works without it */
    }
  }, []);

  useEffect(() => {
    if (!user) return;
    let alive = true;
    fetch('/api/webcheck', { credentials: 'include' })
      .then((res) => (res.ok ? res.json() : null))
      .then((data: { runs: RunSummary[] } | null) => {
        if (alive && data) setRuns(data.runs ?? []);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [user]);

  // Progress theatre, tied to the real wait: phases light in sequence
  // and the last one holds until the patrol actually answers.
  useEffect(() => {
    if (!running) return;
    const t = window.setInterval(() => {
      setPhase((p) => Math.min(p + 1, PHASES.length - 1));
    }, 2100);
    return () => window.clearInterval(t);
  }, [running]);

  const runPatrol = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    let target = url.trim();
    if (!target) {
      setError('Paste the site to patrol first.');
      return;
    }
    if (!/^https?:\/\//i.test(target)) target = `https://${target}`;
    if (!authorized) {
      setError('Tick the box first — the patrol only visits sites you own or may test.');
      return;
    }
    setRunning(true);
    setPhase(0);
    try {
      const res = await fetch('/api/webcheck', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target, authorized }),
      });
      const data = (await res.json().catch(() => null)) as CheckView | { error?: string } | null;
      if (!res.ok) {
        setError(
          (data as { error?: string } | null)?.error ?? `The patrol failed (${res.status}).`,
        );
        return;
      }
      setResult(data as CheckView);
      void refreshRuns();
      requestAnimationFrame(() => {
        resultsRef.current?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
      });
    } catch {
      setError('Could not reach the BugSeek backend — give it a second and try again.');
    } finally {
      setRunning(false);
    }
  };

  const openRun = async (id: string) => {
    setError(null);
    setLoadingRunId(id);
    try {
      const res = await fetch(`/api/webcheck/${id}`, { credentials: 'include' });
      const data = (await res.json().catch(() => null)) as CheckView | { error?: string } | null;
      if (!res.ok) {
        setError((data as { error?: string } | null)?.error ?? 'That run would not open.');
        return;
      }
      setResult(data as CheckView);
      requestAnimationFrame(() => {
        resultsRef.current?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
      });
    } catch {
      setError('Could not reach the BugSeek backend — give it a second and try again.');
    } finally {
      setLoadingRunId(null);
    }
  };

  if (loading || !user) return <WebCheckLoading />;

  const withheldCount = result ? result.findings.filter((f) => f.title === undefined).length : 0;
  const countsOrder: Sev[] = ['critical', 'high', 'medium', 'low', 'info'];

  return (
    <div className="min-h-screen bg-ink text-body">
      <SonarGrid />
      <Nav />
      <main className="relative z-10 mx-auto max-w-6xl px-4 pb-24 pt-28 sm:px-6 sm:pt-32">
        <Reveal>
          <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">THE WEB DEMO</p>
          <h1 className="mt-3 font-display text-4xl font-bold tracking-tight text-bone sm:text-5xl">
            Case your own site.
          </h1>
          <p className="mt-4 max-w-2xl leading-relaxed text-body/85">
            One URL, one honest tick, and the patrol walks your site the way a hunter
            would on first contact — headers, cookies, files that should never answer,
            secrets hiding in your own JavaScript. Thirty seconds, no extension.
          </p>
        </Reveal>

        {/* ── the form ── */}
        <Reveal delay={0.08}>
          <form onSubmit={runPatrol} className="glass mt-10 rounded-[2rem] p-6 sm:p-8">
            <label htmlFor="patrol-url" className="font-mono text-[11px] tracking-[0.2em] text-slate2">
              YOUR WEBSITE
            </label>
            <div className="mt-3 flex flex-col gap-3 sm:flex-row">
              <input
                id="patrol-url"
                type="text"
                inputMode="url"
                autoComplete="url"
                spellCheck={false}
                placeholder="your-site.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={running}
                className="min-w-0 flex-1 rounded-2xl border border-white/10 bg-ink px-4 py-3.5 font-mono text-sm text-bone placeholder:text-slate2 focus:border-white/40 focus:outline-none disabled:opacity-60"
              />
              <LiquidGlassButton type="submit" size="lg" disabled={running}>
                <Radar className="h-4 w-4" aria-hidden />
                {running ? 'Patrolling…' : 'Run the patrol'}
              </LiquidGlassButton>
            </div>
            <label className="mt-5 flex cursor-pointer items-start gap-3 text-sm leading-relaxed text-body/85">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                disabled={running}
                className="mt-0.5 h-4 w-4 shrink-0 accent-white"
              />
              <span>
                This is my site, or I have permission to test it.{' '}
                <span className="text-slate2">
                  The tick is recorded with the run — it is the licence to probe.
                </span>
              </span>
            </label>
            <p className="mt-3 font-mono text-[11px] leading-relaxed text-slate2">
              RUNNING A PATROL ALSO STORES YOUR IP ADDRESS AND APPROXIMATE LOCATION (CITY, COUNTRY) WITH THE
              RUN — IT SHOWS BACK TO YOU IN YOUR PATROL HISTORY BELOW.
            </p>

            {error && (
              <p role="alert" className="mt-4 rounded-xl border border-crit/30 bg-crit/10 px-4 py-3 text-sm text-crit">
                {error}
              </p>
            )}

            <AnimatePresence>
              {running && (
                <motion.ul
                  initial={reduce ? false : { opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={springQuiet}
                  className="mt-6 space-y-2 overflow-hidden border-t border-white/10 pt-5"
                  aria-live="polite"
                >
                  {PHASES.map((label, i) => (
                    <li key={label} className="flex items-center gap-2.5 font-mono text-xs">
                      {i < phase ? (
                        <Check className="h-3.5 w-3.5 text-signal" aria-hidden />
                      ) : i === phase ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin text-bone" aria-hidden />
                      ) : (
                        <span className="h-3.5 w-3.5 rounded-full border border-white/15" aria-hidden />
                      )}
                      <span className={i <= phase ? 'text-bone' : 'text-slate2'}>{label}</span>
                    </li>
                  ))}
                </motion.ul>
              )}
            </AnimatePresence>
          </form>
        </Reveal>

        {/* ── my patrols ── */}
        {runs.length > 0 && (
          <Reveal delay={0.05}>
            <section aria-label="My patrols" className="mt-10">
              <h2 className="font-mono text-[11px] tracking-[0.24em] text-slate2">MY PATROLS</h2>
              <ul className="mt-4 space-y-2">
                {runs.map((run) => (
                  <li key={run.id}>
                    <button
                      type="button"
                      onClick={() => void openRun(run.id)}
                      disabled={loadingRunId !== null}
                      className="flex w-full items-center gap-4 rounded-2xl border border-white/10 bg-panel px-4 py-3 text-left transition-colors hover:border-white/25 disabled:opacity-60"
                    >
                      <span className="min-w-0 flex-1 truncate font-mono text-sm text-bone">
                        {run.host}
                      </span>
                      <span className="hidden font-mono text-[11px] text-slate2 sm:inline">
                        {run.findingCount} finding{run.findingCount === 1 ? '' : 's'}
                      </span>
                      <span className="hidden font-mono text-[11px] text-slate2 md:inline">
                        {fmtDate(run.createdAt)}
                      </span>
                      {run.requesterGeo && (run.requesterGeo.city || run.requesterGeo.country) && (
                        <span className="hidden font-mono text-[11px] text-slate2 lg:inline">
                          from{' '}
                          {[run.requesterGeo.city, run.requesterGeo.country]
                            .filter(Boolean)
                            .join(', ')}
                        </span>
                      )}
                      {run.score !== null && (
                        <span
                          className="rounded-md px-2 py-0.5 font-mono text-[11px] font-semibold"
                          style={{
                            color: scoreColor(run.score),
                            border: `1px solid ${scoreColor(run.score)}66`,
                            background: `${scoreColor(run.score)}1f`,
                          }}
                        >
                          {run.score} · {run.grade}
                        </span>
                      )}
                      {loadingRunId === run.id && (
                        <Loader2 className="h-4 w-4 animate-spin text-slate2" aria-hidden />
                      )}
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          </Reveal>
        )}

        {/* ── results ── */}
        {result && (
          <div ref={resultsRef} className="scroll-mt-28">
            <section aria-label="What BugSeek found" className="mt-16">
              <Reveal>
                <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">
                  PART 1 — WHAT BUGSEEK FOUND
                </p>
                <div className="mt-6 flex flex-col gap-8 lg:flex-row lg:items-center">
                  {result.score !== null && result.grade !== null && (
                    <ScoreRing
                      value={result.score}
                      grade={result.grade}
                      size={170}
                      caption="Scored from everything the patrol found."
                    />
                  )}
                  <div className="min-w-0">
                    <h2 className="break-all font-mono text-lg text-bone">{result.url}</h2>
                    <p className="mt-1 font-mono text-xs text-slate2">
                      patrolled {fmtDate(result.createdAt)} · {result.host}
                    </p>
                    <div className="mt-4 flex flex-wrap gap-2">
                      {countsOrder.map((sev) =>
                        result.counts[sev] > 0 ? (
                          <span
                            key={sev}
                            className={`rounded-md border px-2 py-1 font-mono text-[11px] font-semibold ${SEV_STYLE[sev].chip}`}
                          >
                            {result.counts[sev]} {SEV_STYLE[sev].label}
                          </span>
                        ) : null,
                      )}
                    </div>
                    <p className="mt-4 max-w-xl text-sm leading-relaxed text-body/85">
                      {result.gated
                        ? 'Two findings are yours to read. The rest are already run, already stored on your account — just locked on the free plan.'
                        : 'The full picture, unlocked. Every finding the patrol brought home is below.'}
                    </p>
                  </div>
                </div>
              </Reveal>

              {/* findings */}
              <div className="mt-8 space-y-2.5">
                <AnimatePresence initial={false}>
                  {result.findings.map((f, i) => {
                    const s = SEV_STYLE[f.severity];
                    if (f.title === undefined) {
                      return (
                        <div
                          key={`withheld-${i}`}
                          className="relative overflow-hidden rounded-xl border border-white/10 bg-panel p-3.5"
                        >
                          <div className="flex items-center gap-2">
                            <span className={`h-6 w-1 rounded-full ${s.bar}`} aria-hidden />
                            <span
                              className={`rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-wide ${s.chip}`}
                            >
                              {s.label}
                            </span>
                            <span className="font-mono text-[11px] uppercase tracking-wider text-slate2">
                              {f.category}
                            </span>
                            <Lock className="ml-auto h-3.5 w-3.5 text-slate2" aria-hidden />
                          </div>
                          <div className="pointer-events-none mt-3 select-none blur-[4px]" aria-hidden>
                            <div className="h-3.5 w-1/2 rounded bg-white/15" />
                            <div className="mt-2 h-3 w-11/12 rounded bg-white/10" />
                            <div className="mt-1.5 h-3 w-3/4 rounded bg-white/10" />
                          </div>
                          <span className="sr-only">
                            A {s.label.toLowerCase()} finding in {f.category}, locked on the free plan.
                          </span>
                        </div>
                      );
                    }
                    return (
                      <motion.article
                        key={`${f.title}-${i}`}
                        initial={reduce ? false : { opacity: 0, scale: 0.97, y: 8 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        transition={{ ...springPop, delay: i * 0.05 }}
                        className="rounded-xl border border-white/10 bg-panel p-3.5"
                      >
                        <div className="flex items-center gap-2">
                          <span className={`h-6 w-1 rounded-full ${s.bar}`} aria-hidden />
                          <span
                            className={`rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-wide ${s.chip}`}
                          >
                            {s.label}
                          </span>
                          <span className="font-mono text-[11px] uppercase tracking-wider text-slate2">
                            {f.category}
                          </span>
                        </div>
                        <h3 className="mt-1.5 text-[15px] font-semibold leading-snug text-bone">
                          {f.title}
                        </h3>
                        <p className="mt-1 font-mono text-[13px] leading-relaxed text-body/90">
                          {f.detail}
                        </p>
                        {f.evidence && (
                          <p className="mt-2 break-all font-mono text-[11px] text-slate2">
                            {f.evidence}
                          </p>
                        )}
                      </motion.article>
                    );
                  })}
                </AnimatePresence>
              </div>

              {withheldCount > 0 && (
                <p className="mt-4 font-mono text-xs text-slate2">
                  {withheldCount} more finding{withheldCount === 1 ? '' : 's'} under the blur —
                  already run, already yours, locked for now.
                </p>
              )}

              {/* locked rows */}
              {result.gated && (
                <div className="mt-6 grid gap-3 sm:grid-cols-2">
                  {result.locked.map((row) => (
                    <div
                      key={row.label}
                      className="rounded-2xl border border-dashed border-white/20 bg-white/[0.02] p-5"
                    >
                      <div className="flex items-center gap-2">
                        <Lock className="h-4 w-4 text-slate2" aria-hidden />
                        <h3 className="font-display text-base font-semibold text-bone">{row.label}</h3>
                        {row.count !== null && (
                          <span className="ml-auto rounded-md border border-white/15 px-2 py-0.5 font-mono text-[11px] text-body">
                            {row.count} checks
                          </span>
                        )}
                      </div>
                      <p className="mt-2 text-sm leading-relaxed text-body/80">{row.note}</p>
                    </div>
                  ))}
                </div>
              )}

              {/* plan card */}
              {result.gated && (
                <Reveal className="mt-8">
                  <div className="glass rounded-[2rem] p-7 sm:p-9">
                    <div className="grid items-center gap-6 lg:grid-cols-[1.2fr_0.8fr]">
                      <div>
                        <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">
                          THE FULL PICTURE
                        </p>
                        <h2 className="mt-3 font-display text-3xl font-bold tracking-tight text-bone">
                          You’re seeing the trailer.
                        </h2>
                        <p className="mt-3 max-w-xl leading-relaxed text-body/85">
                          Unlock it and the blur lifts off everything above — every finding
                          with its fix, the stored run already on your account, plus the
                          active battery that runs in the extension. No re-scan, no waiting.
                        </p>
                      </div>
                      <div className="lg:text-right">
                        <LiquidGlassButton
                          size="lg"
                          onClick={() => navigate('/app#pricing')}
                        >
                          See the plans <ArrowRight className="h-4 w-4" aria-hidden />
                        </LiquidGlassButton>
                        <p className="mt-3 font-mono text-[11px] text-slate2">
                          The run stays saved either way. It is yours.
                        </p>
                      </div>
                    </div>
                  </div>
                </Reveal>
              )}
            </section>

            {/* ── PART 2: the matrix ── */}
            <section aria-label="Website info" className="mt-16">
              <Reveal>
                <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">
                  PART 2 — WEBSITE INFO
                </p>
                <h2 className="mt-3 font-display text-3xl font-bold tracking-tight text-bone">
                  The full matrix, on the house.
                </h2>
                <p className="mt-3 max-w-2xl leading-relaxed text-body/85">
                  Measured from our server and the public record — yours to read whether
                  or not you ever pay us a rupee.
                </p>
              </Reveal>

              <div className="mt-8 grid gap-4 md:grid-cols-2">
                <Reveal>
                  <InfoCard title="PERFORMANCE — FROM OUR SERVER">
                    <Row label="Time to first byte" value={fmtMs(result.info.perf.ttfbMs)} />
                    <Row label="Full page load" value={fmtMs(result.info.perf.totalMs)} />
                    <Row label="Page weight" value={fmtBytes(result.info.perf.bytes)} />
                    <Row label="HTML size" value={fmtBytes(result.info.perf.htmlBytes)} />
                    <Row
                      label="Redirects"
                      value={
                        result.info.perf.redirectCount === null
                          ? null
                          : String(result.info.perf.redirectCount)
                      }
                    />
                    <Row label="Compression" value={result.info.perf.compression} mono />
                    <Row
                      label="Scripts · styles · images"
                      value={
                        result.info.perf.scripts === null
                          ? null
                          : `${result.info.perf.scripts} · ${result.info.perf.styles ?? '–'} · ${result.info.perf.images ?? '–'}`
                      }
                    />
                  </InfoCard>
                </Reveal>

                <Reveal delay={0.05}>
                  <InfoCard title="SERVER">
                    <Row label="IP address" value={result.info.server.ip} mono />
                    <Row
                      label="Location"
                      value={
                        [result.info.server.city, result.info.server.region, result.info.server.country]
                          .filter(Boolean)
                          .join(', ') || null
                      }
                    />
                    <Row label="Provider" value={result.info.server.org} />
                    <Row label="TLS issuer" value={result.info.tls?.issuer ?? null} />
                    <Row
                      label="TLS expires"
                      value={
                        result.info.tls?.validTo
                          ? `${fmtDate(result.info.tls.validTo)}${
                              result.info.tls.daysLeft !== null
                                ? ` (${result.info.tls.daysLeft} days left)`
                                : ''
                            }`
                          : null
                      }
                    />
                    <Row label="TLS protocol" value={result.info.tls?.protocol ?? null} mono />
                  </InfoCard>
                </Reveal>

                <Reveal>
                  <InfoCard title="DOMAIN">
                    <Row label="Registrar" value={result.info.domain.registrar} />
                    <Row label="Registered" value={fmtDate(result.info.domain.created)} />
                    <div className="flex items-baseline justify-between gap-4">
                      <dt className="shrink-0 text-sm text-body/70">Expires</dt>
                      <dd className="text-right text-sm text-bone">
                        {result.info.domain.expires ? (
                          <>
                            {fmtDate(result.info.domain.expires)}
                            {result.info.domain.daysLeft !== null &&
                              result.info.domain.daysLeft < 90 && (
                                <span className="ml-2 rounded-md border border-amber2/40 bg-amber2/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-amber2">
                                  {result.info.domain.daysLeft} DAYS LEFT
                                </span>
                              )}
                          </>
                        ) : (
                          <span className="text-slate2">couldn’t read</span>
                        )}
                      </dd>
                    </div>
                    <ListRow label="Status" items={result.info.domain.status} />
                    <ListRow label="Nameservers" items={result.info.domain.nameservers} />
                  </InfoCard>
                </Reveal>

                <Reveal delay={0.05}>
                  <InfoCard title="DNS & MAIL">
                    <ListRow label="A records" items={result.info.dns.a} />
                    <ListRow label="Mail (MX)" items={result.info.dns.mx} />
                    <ListRow label="Nameservers" items={result.info.dns.ns} />
                    <div>
                      <dt className="text-sm text-body/70">Mail & certificate posture</dt>
                      <dd className="mt-1.5 flex flex-wrap gap-1.5">
                        <PresenceChip label="SPF" value={result.info.dns.spf} />
                        <PresenceChip label="DMARC" value={result.info.dns.dmarc} />
                        <PresenceChip label="CAA" value={result.info.dns.caa} />
                      </dd>
                    </div>
                    <div>
                      <dt className="text-sm text-body/70">Public good practice</dt>
                      <dd className="mt-1.5 flex flex-wrap gap-1.5">
                        <PresenceChip label="robots.txt" value={result.info.robotsTxt} />
                        <PresenceChip label="security.txt" value={result.info.securityTxt} />
                      </dd>
                    </div>
                  </InfoCard>
                </Reveal>

                <Reveal className="md:col-span-2">
                  <InfoCard title="API SURFACE — FROM YOUR OWN CODE">
                    <ListRow label="Endpoints spotted" items={result.info.api.endpoints} />
                    <div>
                      <dt className="text-sm text-body/70">Notable doors</dt>
                      <dd className="mt-1.5 flex flex-wrap gap-1.5">
                        <PresenceChip label="OpenAPI doc" value={result.info.api.openApiDoc} />
                        <PresenceChip label="GraphQL" value={result.info.api.graphql} />
                      </dd>
                    </div>
                  </InfoCard>
                </Reveal>
              </div>
            </section>
          </div>
        )}
      </main>
      <Footer home />
    </div>
  );
}

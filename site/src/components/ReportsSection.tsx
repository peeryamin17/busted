import { useCallback, useEffect, useState } from 'react';
import { ChevronDown, Download, FileText, RefreshCw } from 'lucide-react';
import { Reveal } from './Reveal';

/**
 * "My reports" — every scan tied to this account (extension runs, swarm
 * runs, engine runs), read back from the backend. The list comes from
 * GET /api/scans; opening a row pulls its findings and offers the same
 * markdown report the backend generates.
 */

type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info';

const SEV_STYLE: Record<Sev, { label: string; chip: string }> = {
  critical: { label: 'CRITICAL', chip: 'bg-crit/15 text-crit border-crit/30' },
  high: { label: 'HIGH', chip: 'bg-hot/15 text-hot border-hot/30' },
  medium: { label: 'MEDIUM', chip: 'bg-amber2/15 text-amber2 border-amber2/30' },
  low: { label: 'LOW', chip: 'bg-sky2/15 text-sky2 border-sky2/35' },
  info: { label: 'INFO', chip: 'bg-white/10 text-body border-white/20' },
};

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

interface ScanRow {
  id: string;
  targetUrl: string;
  mode: string;
  status: string;
  createdAt: string;
  finishedAt?: string;
}

interface FindingRow {
  id: string;
  severity: string;
  title: string;
  description: string;
  location?: string;
  evidence?: string;
  remediation: string;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

export function ReportsSection() {
  const [scans, setScans] = useState<ScanRow[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const [findings, setFindings] = useState<Record<string, FindingRow[]>>({});
  const [loadingFindings, setLoadingFindings] = useState<string | null>(null);

  const load = useCallback(async () => {
    setFailed(false);
    try {
      const res = await fetch('/api/scans?limit=25', { credentials: 'include' });
      if (!res.ok) throw new Error(String(res.status));
      const data = (await res.json()) as { scans: ScanRow[] };
      setScans(data.scans ?? []);
    } catch {
      setFailed(true);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const toggle = async (scan: ScanRow) => {
    if (openId === scan.id) {
      setOpenId(null);
      return;
    }
    setOpenId(scan.id);
    if (findings[scan.id] || scan.status !== 'completed') return;
    setLoadingFindings(scan.id);
    try {
      const res = await fetch(`/api/scans/${scan.id}/findings`, { credentials: 'include' });
      if (res.ok) {
        const data = (await res.json()) as { findings: FindingRow[] };
        const sorted = [...(data.findings ?? [])].sort(
          (a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9),
        );
        setFindings((prev) => ({ ...prev, [scan.id]: sorted }));
      }
    } catch {
      /* the row stays expandable; a re-open retries */
    } finally {
      setLoadingFindings(null);
    }
  };

  return (
    <section className="relative mx-auto max-w-6xl px-4 py-12 sm:px-6" aria-label="My reports">
      <Reveal>
        <div className="glass overflow-hidden rounded-[2rem] p-7 sm:p-9">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">MY REPORTS</p>
              <h2 className="mt-3 font-display text-3xl font-bold tracking-tight text-bone sm:text-4xl">
                Every run, on the record.
              </h2>
              <p className="mt-3 max-w-xl leading-relaxed text-body/85">
                Scans from the extension land here automatically — target, findings and the full
                report, tied to your account.
              </p>
            </div>
            <button
              type="button"
              onClick={() => void load()}
              className="inline-flex items-center gap-2 rounded-full border border-white/15 px-4 py-2 text-xs font-semibold text-bone transition-colors hover:bg-white/5"
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden /> Refresh
            </button>
          </div>

          <div className="mt-7">
            {scans === null && !failed && (
              <p className="font-mono text-[11px] tracking-[0.18em] text-slate2">LOADING…</p>
            )}
            {failed && (
              <p className="text-sm text-body/85" role="alert">
                Couldn't load your reports just now — the backend may be waking up. Hit Refresh in
                a moment.
              </p>
            )}
            {scans !== null && scans.length === 0 && (
              <p className="text-sm leading-relaxed text-body/85">
                No reports yet. Run a scan in the extension and it will show up here on its own.
              </p>
            )}
            {scans !== null && scans.length > 0 && (
              <ul className="divide-y divide-white/8 overflow-hidden rounded-2xl border border-white/10">
                {scans.map((scan) => {
                  const rows = findings[scan.id];
                  const open = openId === scan.id;
                  return (
                    <li key={scan.id} className="bg-black/20">
                      <button
                        type="button"
                        onClick={() => void toggle(scan)}
                        aria-expanded={open}
                        className="flex w-full items-center justify-between gap-3 px-4 py-3.5 text-left transition-colors hover:bg-white/5"
                      >
                        <span className="min-w-0">
                          <span className="block truncate font-display text-sm font-bold text-bone">
                            {hostOf(scan.targetUrl)}
                          </span>
                          <span className="block font-mono text-[11px] text-slate2">
                            {scan.mode.toUpperCase()} · {scan.status.toUpperCase()} ·{' '}
                            {new Date(scan.createdAt).toLocaleString()}
                            {rows ? ` · ${rows.length} FINDING${rows.length === 1 ? '' : 'S'}` : ''}
                          </span>
                        </span>
                        <ChevronDown
                          className={`h-4 w-4 shrink-0 text-slate2 transition-transform duration-300 ${open ? 'rotate-180' : ''}`}
                          aria-hidden
                        />
                      </button>

                      {open && (
                        <div className="border-t border-white/8 px-4 py-4">
                          {scan.status !== 'completed' && (
                            <p className="text-sm text-body/85">
                              This scan is {scan.status} — findings appear here when it finishes.
                            </p>
                          )}
                          {scan.status === 'completed' && loadingFindings === scan.id && (
                            <p className="font-mono text-[11px] tracking-[0.18em] text-slate2">
                              LOADING FINDINGS…
                            </p>
                          )}
                          {scan.status === 'completed' && rows && rows.length === 0 && (
                            <p className="text-sm text-body/85">
                              Nothing found on this run. A quiet report is a good report.
                            </p>
                          )}
                          {scan.status === 'completed' && rows && rows.length > 0 && (
                            <ul className="space-y-3">
                              {rows.map((f) => {
                                const style = SEV_STYLE[f.severity as Sev] ?? SEV_STYLE.info;
                                return (
                                  <li
                                    key={f.id}
                                    className="rounded-xl border border-white/10 bg-black/30 p-4"
                                  >
                                    <p className="flex flex-wrap items-center gap-2">
                                      <span
                                        className={`rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold ${style.chip}`}
                                      >
                                        {style.label}
                                      </span>
                                      <span className="font-display text-sm font-bold text-bone">
                                        {f.title}
                                      </span>
                                    </p>
                                    <p className="mt-2 text-sm leading-relaxed text-body/85">
                                      {f.description}
                                    </p>
                                    {f.location && (
                                      <p className="mt-2 break-all font-mono text-[11px] text-slate2">
                                        {f.location}
                                      </p>
                                    )}
                                    {f.evidence && (
                                      <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded-lg bg-black/40 p-3 font-mono text-[11px] leading-relaxed text-body/80">
                                        {f.evidence}
                                      </pre>
                                    )}
                                    {f.remediation && (
                                      <p className="mt-2 text-xs leading-relaxed text-body/70">
                                        <span className="font-semibold text-bone">Fix: </span>
                                        {f.remediation}
                                      </p>
                                    )}
                                  </li>
                                );
                              })}
                            </ul>
                          )}
                          {scan.status === 'completed' && (
                            <a
                              href={`/api/scans/${scan.id}/report?format=md`}
                              className="mt-4 inline-flex items-center gap-2 rounded-full border border-white/15 px-4 py-2 text-xs font-semibold text-bone transition-colors hover:bg-white/5"
                            >
                              <Download className="h-3.5 w-3.5" aria-hidden /> Download the full
                              report (.md)
                            </a>
                          )}
                          <p className="mt-3 flex items-center gap-2 font-mono text-[11px] text-slate2">
                            <FileText className="h-3.5 w-3.5" aria-hidden /> {scan.targetUrl}
                          </p>
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
      </Reveal>
    </section>
  );
}

import { useCallback, useEffect, useMemo, useState } from 'react';
import { ArrowLeft, RefreshCw } from 'lucide-react';
import { Footer } from '../components/Footer';
import { Nav } from '../components/Nav';
import { Reveal } from '../components/Reveal';
import { CoveragePanel, type CoverageEntryView, type CoverageSummary } from '../components/CoveragePanel';
import { ApprovalsPanel } from '../components/ApprovalsPanel';
import { useAuth } from '../lib/auth';
import { navigate } from '../lib/router';

/**
 * Tasks, the task list + detail view.
 *
 * A task is the first-class object a swarm run hangs off: the goal it
 * was given, the target, and its exploration graph. The detail view
 * shows the graph as a plain chronological timeline of nodes grouped
 * by kind, with edges as "A --rel--> B" lines, no force-directed
 * graph.
 *
 * Reads GET /api/tasks and GET /api/tasks/:id; pause/resume post to
 * /api/tasks/:id/pause and /api/tasks/:id/resume. Everything is
 * session-authenticated (cookies included); signed-out visitors get
 * the sign-in door, never a task list.
 */

type TaskStatus = 'running' | 'paused' | 'done' | 'timeout' | 'failed';
type NodeKind = 'goal' | 'intent' | 'fact' | 'finding' | 'hint' | 'digest';
type EdgeRel = 'spawns' | 'derived_from' | 'yields' | 'proves' | 'covers';

interface TaskRow {
  id: string;
  goalText: string;
  targetUrl: string;
  status: TaskStatus;
  createdAt: string;
  finishedAt?: string | null;
}

interface GraphNodeRow {
  id: string;
  kind: NodeKind;
  label: string;
  detail?: string | null;
  status?: string | null;
  createdAt: string;
}

interface GraphEdgeRow {
  id: string;
  fromNodeId: string;
  toNodeId: string;
  rel: EdgeRel;
  createdAt: string;
}

interface AssetRow {
  id: string;
  kind: string;
  value: string;
  host?: string | null;
}

interface AnchorRow {
  id: string;
  nodeId: string;
  assetId: string;
}

interface WorkerReportRow {
  specialistId?: string;
  specialistName?: string;
  summary?: string | null;
  providerId?: string | null;
  model?: string | null;
  tokensUsed?: number | { input?: number; output?: number; total?: number } | null;
  testsRun?: number;
  findings?: number;
  durationMs?: number;
}

interface RetesterRow {
  providerId?: string | null;
  model?: string | null;
  tokensUsed?: number | { input?: number; output?: number; total?: number } | null;
}

interface TaskDetail {
  task: TaskRow;
  nodes: GraphNodeRow[];
  edges: GraphEdgeRow[];
  anchors: AnchorRow[];
  assets: AssetRow[];
  workerReports?: WorkerReportRow[];
  retester?: RetesterRow | null;
}

function finiteTokens(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.max(0, Math.floor(value));
  if (value && typeof value === 'object') {
    const v = value as { total?: unknown; input?: unknown; output?: unknown };
    const t = Number(v.total);
    if (Number.isFinite(t) && t > 0) return Math.max(0, Math.floor(t));
    const i = Number(v.input);
    const o = Number(v.output);
    return Math.max(0, Math.floor((Number.isFinite(i) ? i : 0) + (Number.isFinite(o) ? o : 0)));
  }
  return 0;
}

function formatRunTelemetry(r: {
  providerId?: string | null;
  model?: string | null;
  tokensUsed?: number | { input?: number; output?: number; total?: number } | null;
}): string {
  const parts: string[] = [];
  if (r.providerId) parts.push(r.providerId);
  if (r.model) parts.push(r.model);
  if (r.tokensUsed !== undefined && r.tokensUsed !== null) {
    const total = finiteTokens(r.tokensUsed);
    parts.push(total > 0 ? `${(total / 1000).toFixed(1)}k tokens` : '0k tokens');
  }
  return parts.join(' · ');
}

const KIND_ORDER: NodeKind[] = ['goal', 'intent', 'fact', 'finding', 'hint', 'digest'];

const STATUS_STYLE: Record<TaskStatus, string> = {
  running: 'bg-sky2/15 text-sky2 border-sky2/35',
  paused: 'bg-amber2/15 text-amber2 border-amber2/30',
  done: 'bg-white/10 text-bone border-white/20',
  timeout: 'bg-hot/15 text-hot border-hot/30',
  failed: 'bg-crit/15 text-crit border-crit/30',
};

const KIND_STYLE: Record<NodeKind, string> = {
  goal: 'bg-white/10 text-bone border-white/20',
  intent: 'bg-sky2/15 text-sky2 border-sky2/35',
  fact: 'bg-amber2/15 text-amber2 border-amber2/30',
  finding: 'bg-crit/15 text-crit border-crit/30',
  hint: 'bg-hot/15 text-hot border-hot/30',
  digest: 'bg-white/5 text-slate2 border-white/15',
};

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

interface CoverageData {
  summary: CoverageSummary;
  entries: CoverageEntryView[];
}

export function TasksPage() {
  const { user, loading: authLoading } = useAuth();
  const [tasks, setTasks] = useState<TaskRow[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const [details, setDetails] = useState<Record<string, TaskDetail>>({});
  const [coverage, setCoverage] = useState<Record<string, CoverageData>>({});
  const [detailErrors, setDetailErrors] = useState<Record<string, string>>({});
  const [loadingDetail, setLoadingDetail] = useState<string | null>(null);
  const [acting, setActing] = useState<string | null>(null);
  const [actError, setActError] = useState<string | null>(null);
  const [extracting, setExtracting] = useState<string | null>(null);
  const [extractNote, setExtractNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    setFailed(false);
    try {
      const res = await fetch('/api/tasks', { credentials: 'include' });
      if (!res.ok) throw new Error(String(res.status));
      const data = (await res.json()) as { tasks: TaskRow[] };
      setTasks(data.tasks ?? []);
    } catch {
      setFailed(true);
    }
  }, []);

  useEffect(() => {
    if (!authLoading && user) void load();
  }, [authLoading, user, load]);

  const anyActive = (tasks ?? []).some((t) => t.status === 'running');
  useEffect(() => {
    if (!anyActive) return;
    const timer = setInterval(() => void load(), 5000);
    return () => clearInterval(timer);
  }, [anyActive, load]);

  const fetchDetail = async (task: TaskRow) => {
    setDetailErrors((prev) => {
      const next = { ...prev };
      delete next[task.id];
      return next;
    });
    setLoadingDetail(task.id);
    try {
      const res = await fetch(`/api/tasks/${task.id}`, { credentials: 'include' });
      if (!res.ok) throw new Error(`Task detail failed (${res.status})`);
      const data = (await res.json()) as TaskDetail;
      setDetails((prev) => ({ ...prev, [task.id]: data }));
      const cov = await fetch(`/api/tasks/${task.id}/coverage`, { credentials: 'include' });
      if (cov.ok) {
        const covData = (await cov.json()) as CoverageData;
        setCoverage((prev) => ({ ...prev, [task.id]: covData }));
      }
    } catch (err) {
      setDetailErrors((prev) => ({
        ...prev,
        [task.id]: err instanceof Error ? err.message : 'Could not load this task.',
      }));
    } finally {
      setLoadingDetail(null);
    }
  };

  const open = async (task: TaskRow) => {
    if (openId === task.id) {
      setOpenId(null);
      return;
    }
    setOpenId(task.id);
    if (details[task.id]) return;
    await fetchDetail(task);
  };

  const act = async (task: TaskRow, action: 'pause' | 'resume') => {
    setActing(task.id);
    setActError(null);
    try {
      const res = await fetch(`/api/tasks/${task.id}/${action}`, {
        method: 'POST',
        credentials: 'include',
      });
      if (!res.ok) throw new Error(`${action} failed (${res.status})`);
      const data = (await res.json()) as { task: TaskRow };
      setTasks((prev) => prev?.map((t) => (t.id === task.id ? data.task : t)) ?? null);
      setDetails((prev) => {
        const d = prev[task.id];
        return d ? { ...prev, [task.id]: { ...d, task: data.task } } : prev;
      });
    } catch (err) {
      setActError(err instanceof Error ? err.message : `${action} failed.`);
    } finally {
      setActing(null);
    }
  };

  const extractLessons = async (task: TaskRow) => {
    setExtracting(task.id);
    setExtractNote(null);
    setActError(null);
    try {
      const res = await fetch(`/api/tasks/${task.id}/lessons/extract`, {
        method: 'POST',
        credentials: 'include',
      });
      if (!res.ok) throw new Error(`Lesson extract failed (${res.status})`);
      const data = (await res.json()) as { lessons: unknown[] };
      setExtractNote(
        `Extracted ${data.lessons.length} lesson${data.lessons.length === 1 ? '' : 's'} from this task.`,
      );
    } catch (err) {
      setActError(err instanceof Error ? err.message : 'Lesson extract failed.');
    } finally {
      setExtracting(null);
    }
  };

  const detail = openId ? details[openId] : undefined;
  const grouped = useMemo(() => {
    if (!detail) return [];
    return KIND_ORDER.map((kind) => ({
      kind,
      nodes: detail.nodes.filter((n) => n.kind === kind),
    })).filter((g) => g.nodes.length > 0);
  }, [detail]);
  const nodeLabel = useMemo(() => {
    const map = new Map<string, string>();
    detail?.nodes.forEach((n) => map.set(n.id, n.label));
    return map;
  }, [detail]);

  return (
    <div className="min-h-screen bg-ink text-body">
      <Nav />
      <main className="mx-auto max-w-6xl px-4 pb-16 pt-28 sm:px-6">
        <Reveal>
          <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">TASKS</p>
          <h1 className="mt-3 font-display text-3xl font-bold tracking-tight text-bone sm:text-4xl">
            Every run, with its receipts.
          </h1>
          <p className="mt-3 max-w-xl leading-relaxed text-body/85">
            A task is the goal, the target, and the exploration graph of what was tried — nodes
            for goals, intents, facts, findings and hints, edges for how one led to the next.
          </p>
          <button
            type="button"
            onClick={(e) => {
              e.preventDefault();
              navigate('/app');
            }}
            className="mt-5 inline-flex items-center gap-2 text-xs font-semibold text-slate2 transition-colors hover:text-bone"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Back to the members&apos; home
          </button>
        </Reveal>

        <Reveal>
          <div className="glass mt-8 overflow-hidden rounded-[2rem] p-7 sm:p-9">
            <div className="flex flex-wrap items-end justify-between gap-4">
              <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">MY TASKS</p>
              <button
                type="button"
                onClick={() => void load()}
                className="inline-flex items-center gap-2 rounded-full border border-white/15 px-4 py-2 text-xs font-semibold text-bone transition-colors hover:bg-white/5"
              >
                <RefreshCw className="h-3.5 w-3.5" aria-hidden /> Refresh
              </button>
            </div>

            <div className="mt-7">
              {authLoading && (
                <p className="font-mono text-[11px] tracking-[0.18em] text-slate2">CHECKING YOUR KEY…</p>
              )}
              {!authLoading && !user && (
                <p className="text-sm leading-relaxed text-body/85">
                  Sign in to see your tasks.{' '}
                  <a href="/signin" className="font-semibold text-bone underline">
                    Go to sign-in
                  </a>
                </p>
              )}
              {!authLoading && user && tasks === null && !failed && (
                <p className="font-mono text-[11px] tracking-[0.18em] text-slate2">LOADING…</p>
              )}
              {failed && (
                <p className="text-sm text-body/85" role="alert">
                  Couldn&apos;t load your tasks just now — the backend may be waking up. Hit
                  Refresh in a moment.
                </p>
              )}
              {tasks !== null && tasks.length === 0 && (
                <p className="text-sm leading-relaxed text-body/85">
                  No tasks yet. Tasks are created when a swarm run starts with a goal — this list
                  fills up as you run them.
                </p>
              )}
              {tasks !== null && tasks.length > 0 && (
                <ul className="divide-y divide-white/8 overflow-hidden rounded-2xl border border-white/10">
                  {tasks.map((task) => {
                    const isOpen = openId === task.id;
                    const d = details[task.id];
                    return (
                      <li key={task.id} className="bg-black/20">
                        <button
                          type="button"
                          onClick={() => void open(task)}
                          aria-expanded={isOpen}
                          className="flex w-full items-center justify-between gap-3 px-4 py-3.5 text-left transition-colors hover:bg-white/5"
                        >
                          <span className="min-w-0">
                            <span className="block truncate font-display text-sm font-bold text-bone">
                              {task.goalText}
                            </span>
                            <span className="block font-mono text-[11px] text-slate2">
                              {hostOf(task.targetUrl)} · {new Date(task.createdAt).toLocaleString()}
                            </span>
                          </span>
                          <span
                            className={`shrink-0 rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold ${STATUS_STYLE[task.status]}`}
                          >
                            {task.status.toUpperCase()}
                          </span>
                        </button>

                        {isOpen && (
                          <div className="border-t border-white/8 px-4 py-4">
                            {loadingDetail === task.id && !d && !detailErrors[task.id] && (
                              <p className="font-mono text-[11px] tracking-[0.18em] text-slate2">
                                LOADING GRAPH…
                              </p>
                            )}
                            {detailErrors[task.id] && !d && (
                              <div>
                                <p className="text-sm text-body/85" role="alert">
                                  Couldn&apos;t load this task ({detailErrors[task.id]}).
                                </p>
                                <button
                                  type="button"
                                  onClick={() => void fetchDetail(task)}
                                  disabled={loadingDetail === task.id}
                                  className="mt-3 rounded-full border border-white/15 px-4 py-2 text-xs font-semibold text-bone transition-colors hover:bg-white/5 disabled:opacity-50"
                                >
                                  Retry
                                </button>
                              </div>
                            )}
                            {d && (
                              <>
                                <div className="flex flex-wrap items-center gap-3">
                                  <p className="break-all font-mono text-[11px] text-slate2">
                                    {d.task.targetUrl}
                                  </p>
                                  {(d.task.status === 'running' || d.task.status === 'paused') && (
                                    <button
                                      type="button"
                                      disabled={acting === task.id}
                                      onClick={() =>
                                        void act(d.task, d.task.status === 'running' ? 'pause' : 'resume')
                                      }
                                      className="rounded-full border border-white/15 px-3 py-1.5 text-xs font-semibold text-bone transition-colors hover:bg-white/5 disabled:opacity-50"
                                    >
                                      {d.task.status === 'running' ? 'Pause' : 'Resume'}
                                    </button>
                                  )}
                                  {(d.task.status === 'done' ||
                                    d.task.status === 'timeout' ||
                                    d.task.status === 'failed') && (
                                    <button
                                      type="button"
                                      disabled={extracting === task.id}
                                      onClick={() => void extractLessons(d.task)}
                                      className="rounded-full border border-white/15 px-3 py-1.5 text-xs font-semibold text-bone transition-colors hover:bg-white/5 disabled:opacity-50"
                                    >
                                      {extracting === task.id ? 'Extracting…' : 'Extract lessons'}
                                    </button>
                                  )}
                                  <span className="font-mono text-[11px] text-slate2">
                                    {d.nodes.length} NODE{d.nodes.length === 1 ? '' : 'S'} ·{' '}
                                    {d.edges.length} EDGE{d.edges.length === 1 ? '' : 'S'} ·{' '}
                                    {d.assets.length} ASSET{d.assets.length === 1 ? '' : 'S'}
                                  </span>
                                </div>
                                {actError && (
                                  <p className="mt-3 text-sm text-red-300" role="alert">
                                    {actError}
                                  </p>
                                )}
                                {extractNote && (
                                  <p className="mt-3 text-sm text-emerald-300" role="status">
                                    {extractNote}
                                  </p>
                                )}
                                <p className="mt-3 text-xs leading-relaxed text-slate2">
                                  Findings below are verified at POE 3 or higher. Hints are POE
                                  2 at best — reproduced in one context only — and are never
                                  labelled verified.
                                </p>

                                {grouped.length === 0 && (
                                  <p className="mt-4 text-sm text-body/85">
                                    No graph nodes yet beyond the goal.
                                  </p>
                                )}
                                {grouped.map((group) => (
                                  <div key={group.kind} className="mt-5">
                                    <p className="font-mono text-[11px] tracking-[0.18em] text-slate2">
                                      {group.kind.toUpperCase()}
                                      {group.kind === 'hint' ? ' — NOT VERIFIED (POE 2 AT BEST)' : ''}
                                    </p>
                                    <ul className="mt-2 space-y-2">
                                      {group.nodes.map((n) => (
                                        <li
                                          key={n.id}
                                          className="rounded-xl border border-white/10 bg-black/30 p-3"
                                        >
                                          <p className="flex flex-wrap items-center gap-2">
                                            <span
                                              className={`rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold ${KIND_STYLE[n.kind]}`}
                                            >
                                              {n.kind.toUpperCase()}
                                            </span>
                                            <span className="font-display text-sm font-bold text-bone">
                                              {n.label}
                                            </span>
                                            {n.status && (
                                              <span className="font-mono text-[11px] text-slate2">
                                                {n.status}
                                              </span>
                                            )}
                                          </p>
                                          {n.detail && (
                                            <p className="mt-1.5 break-all font-mono text-[11px] leading-relaxed text-body/80">
                                              {n.detail}
                                            </p>
                                          )}
                                          <p className="mt-1.5 font-mono text-[11px] text-slate2">
                                            {new Date(n.createdAt).toLocaleString()}
                                          </p>
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                ))}

                                {d.edges.length > 0 && (
                                  <div className="mt-5">
                                    <p className="font-mono text-[11px] tracking-[0.18em] text-slate2">
                                      EDGES
                                    </p>
                                    <ul className="mt-2 space-y-1.5">
                                      {d.edges.map((e) => (
                                        <li
                                          key={e.id}
                                          className="break-words font-mono text-[11px] leading-relaxed text-body/80"
                                        >
                                          {nodeLabel.get(e.fromNodeId) ?? e.fromNodeId} --{e.rel}
                                          --&gt; {nodeLabel.get(e.toNodeId) ?? e.toNodeId}
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                )}

                                {d.assets.length > 0 && (
                                  <div className="mt-5">
                                    <p className="font-mono text-[11px] tracking-[0.18em] text-slate2">
                                      ASSETS
                                    </p>
                                    <ul className="mt-2 space-y-1.5">
                                      {d.assets.map((a) => {
                                        const anchoredBy = d.anchors
                                          .filter((an) => an.assetId === a.id)
                                          .map((an) => nodeLabel.get(an.nodeId) ?? an.nodeId);
                                        return (
                                          <li
                                            key={a.id}
                                            className="break-all font-mono text-[11px] leading-relaxed text-body/80"
                                          >
                                            <span className="font-semibold text-bone">
                                              {a.kind.toUpperCase()}
                                            </span>{' '}
                                            {a.value}
                                            {a.host && a.host !== a.value ? ` (${a.host})` : ''}
                                            {anchoredBy.length > 0 &&
                                              ` — anchored by: ${anchoredBy.join(', ')}`}
                                          </li>
                                        );
                                      })}
                                    </ul>
                                  </div>
                                )}

                                {((d.workerReports && d.workerReports.length > 0) ||
                                  (d.retester && formatRunTelemetry(d.retester))) && (
                                  <div className="mt-5">
                                    <p className="font-mono text-[11px] tracking-[0.18em] text-slate2">
                                      SWARM RUN RECORD
                                    </p>
                                    <ul className="mt-2 space-y-1.5">
                                      {(d.workerReports ?? []).map((w, i) => {
                                        const telemetry = formatRunTelemetry(w);
                                        if (!telemetry) return null;
                                        return (
                                          <li
                                            key={w.specialistId ?? `worker-${i}`}
                                            className="break-words font-mono text-[11px] leading-relaxed text-body/80"
                                          >
                                            <span className="font-semibold text-bone">
                                              {(w.specialistName ?? w.specialistId ?? `Specialist ${i + 1}`).toUpperCase()}
                                            </span>{' '}
                                            {telemetry}
                                          </li>
                                        );
                                      })}
                                      {d.retester && formatRunTelemetry(d.retester) && (
                                        <li className="break-words font-mono text-[11px] leading-relaxed text-body/80">
                                          <span className="font-semibold text-bone">RETESTER</span>{' '}
                                          {formatRunTelemetry(d.retester)}
                                        </li>
                                      )}
                                    </ul>
                                  </div>
                                )}

                                {coverage[task.id] && (
                                  <div className="mt-5">
                                    <CoveragePanel
                                      summary={coverage[task.id].summary}
                                      entries={coverage[task.id].entries}
                                    />
                                  </div>
                                )}

                                <div className="mt-5">
                                  <ApprovalsPanel taskId={task.id} />
                                </div>
                              </>
                            )}
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
      </main>
      <Footer />
    </div>
  );
}

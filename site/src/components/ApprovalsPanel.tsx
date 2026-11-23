/**
 * Approvals panel: steps the swarm paused on, waiting for the operator
 * to allow or deny. Pending first, each row shows the proposed action,
 * the kind, the risk score if one was computed, who asked and when.
 * Ticking "always allow this kind" posts a standing rule for that
 * pattern before deciding, so the swarm stops asking about it.
 *
 * Self-fetching: polls GET /api/tasks/:id/approvals every 5s while
 * anything is pending, or while the last load failed.
 */

import { useCallback, useEffect, useState } from 'react';
import { decideApproval, shouldKeepPolling } from '../lib/approvals';

export type ApprovalKind = 'tool-call' | 'new-target' | 'judge' | 'rule';
export type ApprovalStatus = 'pending' | 'allowed' | 'denied' | 'skipped' | 'expired';

export interface ApprovalView {
  id: string;
  taskId: string;
  kind: ApprovalKind;
  status: ApprovalStatus;
  action: string;
  detail?: Record<string, unknown>;
  ruleId?: string | null;
  riskScore?: number | null;
  requestedBy: string;
  decidedBy?: string | null;
  decidedAt?: string | null;
  createdAt: string;
  expiresAt?: string | null;
}

const STATUS_STYLE: Record<ApprovalStatus, string> = {
  pending: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  allowed: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  denied: 'bg-red-500/15 text-red-300 border-red-500/30',
  skipped: 'bg-white/10 text-zinc-300 border-white/20',
  expired: 'bg-white/10 text-zinc-400 border-white/20',
};

const KIND_LABEL: Record<ApprovalKind, string> = {
  'tool-call': 'Tool call',
  'new-target': 'New target',
  judge: 'Judge',
  rule: 'Rule',
};

/** Turn an approval row into the rule pattern "always allow this kind" posts. */
function patternFor(approval: ApprovalView): { kind: 'tool' | 'target-host' | 'category'; value: string } {
  const detail = approval.detail ?? {};
  const tool = typeof detail['tool'] === 'string' ? detail['tool'] : null;
  const host = typeof detail['host'] === 'string' ? detail['host'] : null;
  const category = typeof detail['category'] === 'string' ? detail['category'] : null;
  if (approval.kind === 'tool-call' && tool) return { kind: 'tool', value: tool };
  if (approval.kind === 'new-target' && host) return { kind: 'target-host', value: host };
  if (category) return { kind: 'category', value: category };
  if (tool) return { kind: 'tool', value: tool };
  if (host) return { kind: 'target-host', value: host };
  return { kind: 'category', value: approval.kind };
}

function detailSummary(approval: ApprovalView): string | null {
  const detail = approval.detail ?? {};
  const parts: string[] = [];
  if (typeof detail['tool'] === 'string') parts.push(`tool: ${detail['tool']}`);
  if (typeof detail['host'] === 'string') parts.push(`host: ${detail['host']}`);
  if (typeof detail['target'] === 'string') parts.push(`target: ${detail['target']}`);
  if (typeof detail['category'] === 'string') parts.push(`category: ${detail['category']}`);
  if (Array.isArray(detail['questions'])) parts.push(`${detail['questions'].length} question${detail['questions'].length === 1 ? '' : 's'}`);
  return parts.length > 0 ? parts.join(' · ') : null;
}

export function ApprovalsPanel({ taskId }: { taskId: string }) {
  const [approvals, setApprovals] = useState<ApprovalView[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [acting, setActing] = useState<string | null>(null);
  const [batchActing, setBatchActing] = useState(false);
  const [alwaysAllow, setAlwaysAllow] = useState<Record<string, boolean>>({});

  const load = useCallback(async () => {
    try {
      const res = await fetch(`/api/tasks/${taskId}/approvals`, { credentials: 'include' });
      if (!res.ok) throw new Error(String(res.status));
      const data = (await res.json()) as { approvals: ApprovalView[] };
      setApprovals(data.approvals ?? []);
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }, [taskId]);

  useEffect(() => {
    void load();
  }, [load]);

  const hasPending = approvals?.some((a) => a.status === 'pending') ?? false;
  useEffect(() => {
    if (!shouldKeepPolling(hasPending, failed)) return;
    const timer = setInterval(() => void load(), 5000);
    return () => clearInterval(timer);
  }, [hasPending, failed, load]);

  const decideOne = async (approval: ApprovalView, decision: 'allow' | 'deny') => {
    setActing(approval.id);
    setActionError(null);
    try {
      await decideApproval({
        taskId,
        approvalId: approval.id,
        decision,
        alwaysAllow: alwaysAllow[approval.id] ?? false,
        pattern: patternFor(approval),
      });
      await load();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Decision was not saved.');
    } finally {
      setActing(null);
    }
  };

  const decideAll = async (decision: 'allow' | 'deny') => {
    const pendingIds = (approvals ?? []).filter((a) => a.status === 'pending').map((a) => a.id);
    if (pendingIds.length === 0) return;
    setBatchActing(true);
    setActionError(null);
    try {
      const res = await fetch(`/api/tasks/${taskId}/approvals/batch-decide`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: pendingIds, decision }),
      });
      if (!res.ok) throw new Error(`Batch decision was not saved (${res.status})`);
      await load();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Batch decision was not saved.');
    } finally {
      setBatchActing(false);
    }
  };

  const pending = (approvals ?? []).filter((a) => a.status === 'pending');
  const decided = (approvals ?? []).filter((a) => a.status !== 'pending');

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-6 backdrop-blur-md">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <h3 className="text-lg font-semibold text-white">Approvals</h3>
          <p className="mt-1 text-sm text-zinc-400">
            Steps the swarm paused on and is waiting for you to allow or
            deny. A step you never answer times out to denied — it never
            runs on silence.
          </p>
        </div>
        <p className="font-mono text-[11px] tracking-[0.18em] text-zinc-500">
          {pending.length} PENDING
        </p>
      </div>

      {failed && (
        <p className="mt-4 text-sm text-zinc-400" role="alert">
          Couldn&apos;t load approvals just now — retrying every few seconds.
        </p>
      )}
      {actionError && (
        <p className="mt-4 text-sm text-red-400" role="alert">
          {actionError}
        </p>
      )}
      {approvals !== null && approvals.length === 0 && !failed && (
        <p className="mt-4 text-sm text-zinc-400">
          No approval requests for this task yet. When the swarm reaches a
          step it should not take on its own, it pauses here and asks.
        </p>
      )}

      {pending.length > 0 && (
        <div className="mt-5 flex flex-wrap items-center gap-2">
          <span className="font-mono text-[11px] tracking-[0.18em] text-zinc-500">
            DECIDE ALL:
          </span>
          <button
            type="button"
            disabled={batchActing}
            onClick={() => void decideAll('allow')}
            className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-200 transition-colors hover:bg-emerald-500/20 disabled:opacity-50"
          >
            Allow all ({pending.length})
          </button>
          <button
            type="button"
            disabled={batchActing}
            onClick={() => void decideAll('deny')}
            className="rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-semibold text-red-200 transition-colors hover:bg-red-500/20 disabled:opacity-50"
          >
            Deny all ({pending.length})
          </button>
        </div>
      )}

      <ul className="mt-5 space-y-3">
        {[...pending, ...decided].map((approval) => {
          const summary = detailSummary(approval);
          const isPending = approval.status === 'pending';
          return (
            <li
              key={approval.id}
              className="rounded-xl border border-white/10 bg-black/30 p-4"
            >
              <p className="flex flex-wrap items-center gap-2">
                <span
                  className={`rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold ${STATUS_STYLE[approval.status]}`}
                >
                  {approval.status.toUpperCase()}
                </span>
                <span className="rounded-md border border-white/10 bg-white/5 px-2 py-0.5 font-mono text-[11px] font-semibold text-zinc-300">
                  {KIND_LABEL[approval.kind]}
                </span>
                {approval.riskScore !== null && approval.riskScore !== undefined && (
                  <span className="rounded-md border border-white/10 bg-white/5 px-2 py-0.5 font-mono text-[11px] text-zinc-300">
                    RISK {approval.riskScore}/100
                  </span>
                )}
                <span className="font-mono text-[11px] text-zinc-500">
                  {approval.requestedBy} · {new Date(approval.createdAt).toLocaleString()}
                </span>
              </p>
              <p className="mt-2 text-sm leading-relaxed text-white">{approval.action}</p>
              {summary && (
                <p className="mt-1.5 break-all font-mono text-[11px] leading-relaxed text-zinc-400">
                  {summary}
                </p>
              )}
              {!isPending && approval.decidedBy && (
                <p className="mt-1.5 font-mono text-[11px] text-zinc-500">
                  Decided by {approval.decidedBy}
                  {approval.decidedAt ? ` · ${new Date(approval.decidedAt).toLocaleString()}` : ''}
                  {approval.ruleId ? ` · via rule ${approval.ruleId.slice(0, 8)}` : ''}
                </p>
              )}
              {isPending && (
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    disabled={acting === approval.id}
                    onClick={() => void decideOne(approval, 'allow')}
                    className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-4 py-1.5 text-xs font-semibold text-emerald-200 transition-colors hover:bg-emerald-500/20 disabled:opacity-50"
                  >
                    Allow
                  </button>
                  <button
                    type="button"
                    disabled={acting === approval.id}
                    onClick={() => void decideOne(approval, 'deny')}
                    className="rounded-full border border-red-500/30 bg-red-500/10 px-4 py-1.5 text-xs font-semibold text-red-200 transition-colors hover:bg-red-500/20 disabled:opacity-50"
                  >
                    Deny
                  </button>
                  <label className="inline-flex cursor-pointer items-center gap-1.5 text-xs text-zinc-400">
                    <input
                      type="checkbox"
                      checked={alwaysAllow[approval.id] ?? false}
                      onChange={(e) =>
                        setAlwaysAllow((prev) => ({ ...prev, [approval.id]: e.target.checked }))
                      }
                      className="h-3.5 w-3.5 accent-emerald-400"
                    />
                    Always allow this kind
                  </label>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

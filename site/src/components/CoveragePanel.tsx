/**
 * Coverage panel: one row per risk class with tested / untested /
 * finding / n/a counts. Classes with nothing tested and no findings
 * are highlighted, unexamined is not the same as clean. A per-asset
 * list follows for entries that carry an assetValue.
 *
 * Presentational only, it renders the exact shape
 * GET /api/tasks/:id/coverage returns.
 */

import { mergeCoverageClasses } from '../lib/coverage';
import type { CoverageClassCounts } from '../lib/coverage';

export type { CoverageClassCounts } from '../lib/coverage';

export interface CoverageSummary {
  byClass: Record<string, CoverageClassCounts>;
  untestedClasses: string[];
  testedAssets: number;
  totalEntries: number;
}

export interface CoverageEntryView {
  id?: string;
  taskId: string;
  assetId?: string;
  assetValue?: string;
  riskClass: string;
  outcome: 'tested' | 'untested' | 'finding' | 'not_applicable';
  evidence?: string;
  reason?: string;
  createdAt?: string;
}

export interface CoveragePanelProps {
  summary: CoverageSummary;
  entries: CoverageEntryView[];
}

function hostOf(value: string): string {
  try {
    return new URL(value).hostname;
  } catch {
    return value;
  }
}

export function CoveragePanel({ summary, entries }: CoveragePanelProps) {
  const untested = new Set(summary.untestedClasses);
  const assetEntries = entries.filter((e) => e.assetValue);
  const assets = [...new Set(assetEntries.map((e) => e.assetValue as string))];
  const rows = mergeCoverageClasses(summary.byClass);
  const labelOf = (id: string) => rows.find((r) => r.id === id)?.label ?? id;

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-6 backdrop-blur-md">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <h3 className="text-lg font-semibold text-white">Coverage</h3>
          <p className="mt-1 text-sm text-zinc-400">
            Which risk areas this task actually examined — and which it did
            not. A quiet area is not a clean area.
          </p>
        </div>
        <p className="font-mono text-[11px] tracking-[0.18em] text-zinc-500">
          {summary.testedAssets} ASSET{summary.testedAssets === 1 ? '' : 'S'} COVERED ·{' '}
          {summary.totalEntries} ENTR{summary.totalEntries === 1 ? 'Y' : 'IES'}
        </p>
      </div>

      {summary.untestedClasses.length > 0 && (
        <p className="mt-4 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm leading-relaxed text-amber-200">
          Unexamined is not clean — these areas were not tested:{' '}
          {summary.untestedClasses.map((c) => labelOf(c)).join(', ')}
          .
        </p>
      )}

      {summary.untestedClasses.length === 0 && summary.totalEntries > 0 && (
        <p className="mt-4 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm leading-relaxed text-emerald-200">
          Every risk class has at least one tested or finding entry — nothing
          in this task went unexamined.
        </p>
      )}

      <div className="mt-5 overflow-x-auto">
        <table className="w-full min-w-[480px] text-left text-sm">
          <thead>
            <tr className="border-b border-white/10 font-mono text-[11px] tracking-[0.14em] text-zinc-500">
              <th scope="col" className="py-2 pr-3 font-medium">RISK AREA</th>
              <th scope="col" className="px-3 py-2 text-right font-medium">TESTED</th>
              <th scope="col" className="px-3 py-2 text-right font-medium">UNTESTED</th>
              <th scope="col" className="px-3 py-2 text-right font-medium">FINDING</th>
              <th scope="col" className="py-2 pl-3 text-right font-medium">N/A</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const counts = row.counts;
              const isUntested = untested.has(row.id);
              return (
                <tr
                  key={row.id}
                  className={`border-b border-white/5 ${isUntested ? 'bg-amber-500/5' : ''}`}
                >
                  <th scope="row" className="py-2.5 pr-3 font-medium text-white">
                    {row.label}
                    {isUntested && (
                      <span className="ml-2 rounded-full bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-300">
                        Not tested
                      </span>
                    )}
                  </th>
                  <td className="px-3 py-2.5 text-right text-zinc-300">{counts.tested}</td>
                  <td className={`px-3 py-2.5 text-right ${isUntested ? 'font-semibold text-amber-300' : 'text-zinc-300'}`}>
                    {counts.untested}
                  </td>
                  <td className="px-3 py-2.5 text-right text-zinc-300">{counts.finding}</td>
                  <td className="py-2.5 pl-3 text-right text-zinc-300">{counts.notApplicable}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {assets.length > 0 && (
        <div className="mt-6">
          <h4 className="font-mono text-[11px] tracking-[0.18em] text-zinc-500">
            PER-ASSET COVERAGE
          </h4>
          <ul className="mt-3 space-y-3">
            {assets.map((asset) => {
              const rows = assetEntries.filter((e) => e.assetValue === asset);
              return (
                <li
                  key={asset}
                  className="rounded-xl border border-white/10 bg-black/30 px-4 py-3"
                >
                  <p className="break-all font-mono text-xs text-zinc-300">{hostOf(asset)}</p>
                  <p className="mt-1 break-all font-mono text-[11px] text-zinc-500">{asset}</p>
                  <ul className="mt-2 flex flex-wrap gap-1.5">
                    {rows.map((e, i) => (
                      <li
                        key={`${e.riskClass}-${i}`}
                        className="rounded-full border border-white/10 bg-white/5 px-2.5 py-0.5 text-xs text-zinc-300"
                      >
                        {labelOf(e.riskClass)}
                        {' · '}
                        {e.outcome === 'not_applicable' ? 'n/a' : e.outcome}
                      </li>
                    ))}
                  </ul>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {assets.length === 0 && summary.totalEntries === 0 && (
        <p className="mt-4 text-sm text-zinc-400">
          No coverage recorded for this task yet. Every risk area above is
          unexamined — run the swarm and the ledger fills in as each
          specialist finishes.
        </p>
      )}
    </div>
  );
}

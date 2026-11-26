import {
  RISK_CLASSES,
  RISK_CLASS_LABELS,
  coverageSummary,
  type CoverageSummary,
} from '../coverage/ledger.js';

/** How much of the intended surface was actually examined. */
export type CoverageTier = 'high' | 'partial' | 'low' | 'none';

export interface CoverageVerdict {
  tier: CoverageTier;
  testedClasses: number;
  applicableClasses: number;
  /** Applicable classes with no tested/finding entry. */
  untestedClasses: string[];
  testedAssets: number;
  totalEntries: number;
  /**
   * True only when the report has zero findings and the surface was not
   * fully examined. Findings present means there is something to report,
   * whatever the coverage. No ledger data at all means tier none.
   */
  inconclusive: boolean;
}

/**
 * Verdict over a coverage summary. A class ruled not applicable (only
 * not_applicable entries) is out of scope and does not count against the
 * tier; a class with no entry at all is untested, never clean.
 */
export function coverageVerdict(
  summary: CoverageSummary,
  findingCount: number,
): CoverageVerdict {
  let testedClasses = 0;
  let applicableClasses = 0;
  const untestedClasses: string[] = [];
  for (const rc of RISK_CLASSES) {
    const c = summary.byClass[rc];
    const examined = (c?.tested ?? 0) + (c?.finding ?? 0);
    const ruledOut =
      (c?.notApplicable ?? 0) > 0 && examined === 0 && (c?.untested ?? 0) === 0;
    if (ruledOut) continue;
    applicableClasses += 1;
    if (examined > 0) testedClasses += 1;
    else untestedClasses.push(rc);
  }
  const fraction =
    applicableClasses === 0 ? 0 : testedClasses / applicableClasses;
  const tier: CoverageTier =
    fraction === 1
      ? 'high'
      : fraction >= 0.5
        ? 'partial'
        : fraction > 0
          ? 'low'
          : 'none';
  return {
    tier,
    testedClasses,
    applicableClasses,
    untestedClasses,
    testedAssets: summary.testedAssets,
    totalEntries: summary.totalEntries,
    inconclusive: findingCount === 0 && tier !== 'high',
  };
}

/** Verdict for a report with no coverage data: nothing was examined. */
export function emptyCoverageVerdict(findingCount: number): CoverageVerdict {
  return coverageVerdict(coverageSummary([]), findingCount);
}

/**
 * Lines for the Findings section when it is empty. An inconclusive
 * report says so plainly and never reads as clean; a fully covered
 * report keeps the existing wording and adds the tier.
 */
export function zeroFindingsLines(verdict: CoverageVerdict): string[] {
  if (!verdict.inconclusive) {
    return [
      'No findings were identified during this scan.',
      `Coverage: ${verdict.tier}. All ${verdict.applicableClasses} applicable risk classes were examined.`,
    ];
  }
  const examined =
    verdict.applicableClasses === 0
      ? 'no risk class applied to this target'
      : `${verdict.testedClasses} of ${verdict.applicableClasses} applicable risk classes examined`;
  const untested =
    verdict.untestedClasses.length > 0
      ? ` Untested: ${verdict.untestedClasses
          .map((c) => RISK_CLASS_LABELS[c] ?? c)
          .join(', ')}.`
      : '';
  return [
    `INCONCLUSIVE: no findings were identified, but the scan did not examine the full intended surface ` +
      `(coverage: ${verdict.tier}, ${examined}).${untested} ` +
      `Unexamined is not clean. This report does not show the target is free of vulnerabilities.`,
  ];
}

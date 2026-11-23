export interface CoverageClassCounts {
  tested: number;
  untested: number;
  finding: number;
  notApplicable: number;
}

export interface CoverageClassRow {
  id: string;
  label: string;
  counts: CoverageClassCounts;
}

export const KNOWN_COVERAGE_CLASSES: { id: string; label: string }[] = [
  { id: 'recon', label: 'Recon' },
  { id: 'secrets', label: 'Secrets' },
  { id: 'headers', label: 'Headers & cookies' },
  { id: 'cors', label: 'CORS' },
  { id: 'xss', label: 'XSS' },
  { id: 'idor', label: 'IDOR' },
  { id: 'auth', label: 'Auth' },
  { id: 'graphql', label: 'GraphQL' },
  { id: 'sourcemap', label: 'Source maps' },
  { id: 'general', label: 'General' },
];

const ZERO: CoverageClassCounts = { tested: 0, untested: 0, finding: 0, notApplicable: 0 };

/**
 * Build the coverage table rows: the known classes first, then any
 * extra class the backend returns, in id order, so new risk classes
 * show up instead of being dropped.
 */
export function mergeCoverageClasses(
  byClass: Record<string, CoverageClassCounts>,
): CoverageClassRow[] {
  const knownIds = new Set(KNOWN_COVERAGE_CLASSES.map((c) => c.id));
  const extra = Object.keys(byClass)
    .filter((id) => !knownIds.has(id))
    .sort();
  return [
    ...KNOWN_COVERAGE_CLASSES.map((c) => ({
      id: c.id,
      label: c.label,
      counts: byClass[c.id] ?? ZERO,
    })),
    ...extra.map((id) => ({ id, label: id, counts: byClass[id] ?? ZERO })),
  ];
}

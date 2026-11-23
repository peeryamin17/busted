import type { Finding } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { verificationLabel } from './verification.js';
import type { ReportInput } from './markdown.js';

/**
 * CSV findings export, one row per finding, same fields the Markdown
 * report shows for each finding (id/title/severity/CVSS/endpoint/
 * evidence/status), sorted by severity like the Markdown report.
 *
 * Spreadsheet safety: cells that could be interpreted as a formula by
 * Excel/Sheets are neutralised (see escapeCsvCell), and the output
 * starts with a UTF-8 BOM so Excel opens it with the right encoding.
 */

export const CSV_HEADERS = [
  'id',
  'title',
  'category',
  'severity',
  'cvss_score',
  'cvss_vector',
  'confidence',
  'verification',
  'location',
  'description',
  'evidence',
  'remediation',
  'suggested_fix',
  'honeypot_suspect',
  'trap_probability',
  'references',
  'repro_steps',
] as const;

/** Characters that turn a spreadsheet cell into a formula / command. */
const FORMULA_LEADERS = new Set(['=', '+', '-', '@']);

/**
 * Neutralise formula injection (OWASP CSV Injection): a cell whose first
 * character after trimming is one of = + - @, or whose raw first
 * character is a tab or carriage return, is prefixed with a single quote
 * so the spreadsheet treats it as text. The quote is part of the stored
 * cell value, so the guard survives a save/re-open round trip.
 */
export function escapeCsvCell(value: string | number | boolean | null | undefined): string {
  if (value === null || value === undefined) return '';
  const raw = String(value);
  if (raw.length === 0) return '';
  const trimmed = raw.trim();
  if (trimmed.length > 0 && FORMULA_LEADERS.has(trimmed[0])) return `'${trimmed}`;
  if (raw[0] === '\t' || raw[0] === '\r') return `'${raw}`;
  return raw;
}

/** Standard RFC 4180 quoting: quote fields containing a comma, quote or newline. */
export function quoteCsvCell(value: string): string {
  if (/[",\n\r]/.test(value)) return `"${value.replace(/"/g, '""')}"`;
  return value;
}

/** Escape + quote one cell. */
export function csvCell(value: string | number | boolean | null | undefined): string {
  return quoteCsvCell(escapeCsvCell(value));
}

function findingRow(f: Finding): string {
  const cells: Array<string | number | boolean | null | undefined> = [
    f.id,
    f.title,
    f.category,
    f.severity,
    f.cvssScore ?? '',
    f.cvssVector ?? '',
    f.confidence,
    verificationLabel(f),
    f.location ?? '',
    f.description,
    f.evidence ?? '',
    f.remediation,
    f.suggestedFix ?? '',
    f.honeypotSuspect,
    f.trapProbability,
    f.references.join('; '),
    f.reproSteps.join('; '),
  ];
  return cells.map(csvCell).join(',');
}

/** CSV export of a scan's findings, with a UTF-8 BOM for Excel. */
export function generateCsvReport(input: ReportInput): string {
  const sorted = [...input.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );
  const lines = [CSV_HEADERS.join(','), ...sorted.map(findingRow)];
  return '\uFEFF' + lines.join('\r\n') + '\r\n';
}

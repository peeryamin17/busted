/**
 * Programme scope types.
 *
 * A "programme scope check" answers one question: does the public bug bounty
 * programme the hunter picked (HackerOne / Bugcrowd) place this target inside
 * its published scope? The verdict is advisory evidence — it never grants
 * authorisation on its own (see docs/scope-validation.md).
 */

export type ScopePlatform = 'hackerone' | 'bugcrowd';

export type ScopeVerdict =
  | 'in_scope'
  | 'out_of_scope'
  | 'programme_not_found'
  | 'unknown';

/** One published scope line, normalised for matching. */
export interface ScopeEntry {
  /** The identifier exactly as published — shown back as evidence. */
  raw: string;
  /** Lowercase host the entry covers, without any `*.` prefix. */
  host: string;
  /**
   * Published as `*.host`: subdomains only, never the bare host itself
   * (that is the convention both platforms use).
   */
  wildcard: boolean;
  /**
   * Non-root path the asset is limited to (lowercase, leading slash, no
   * trailing slash). Absent when the whole host is covered.
   */
  pathPrefix?: string;
}

export interface ScopeProgramme {
  platform: ScopePlatform;
  handle: string;
  name: string;
  url?: string;
  inScope: ScopeEntry[];
  outOfScope: ScopeEntry[];
  /** At least one web asset (either side) could be parsed from the listing. */
  hasWebAssets: boolean;
}

export interface ScopeProgrammeSummary {
  platform: ScopePlatform;
  handle: string;
  name: string;
  url?: string;
}

export interface ScopeCheckResult {
  verdict: ScopeVerdict;
  platform: ScopePlatform;
  handle: string;
  programmeName?: string;
  /** The published identifier that decided the verdict, when one matched. */
  matchedEntry?: string;
  /** Human-readable explanation, safe to show the user. */
  reason: string;
  /** ISO timestamp of the check. */
  checkedAt: string;
}

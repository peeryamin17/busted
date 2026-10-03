import type { Confidence, Severity } from '../types.js';

/**
 * Shapes for the web demo patrol (`src/webcheck/`).
 *
 * `WebFinding` mirrors the canonical Finding (types.ts) in the fields
 * the demo needs — severity/title/detail/category/evidence — plus the
 * scorer's `confidence`. Findings are constructed so evidence can
 * never carry a secret value (names and URLs only); see checks.ts.
 */
export interface WebFinding {
  severity: Severity;
  category: string;
  title: string;
  detail: string;
  evidence?: string;
  confidence: Confidence;
}

export interface ApiInfo {
  /** API paths discovered in the site's own code (paths only, no values). */
  endpoints: string[];
  /** A Swagger/OpenAPI document answered publicly. */
  openApiDoc: boolean;
  /** A GraphQL endpoint reference was found in the site's code. */
  graphql: boolean;
}

export interface TlsInfo {
  issuer: string | null;
  subject: string | null;
  validTo: string | null;
  daysLeft: number | null;
  authorized: boolean;
  authorizationError?: string;
  protocol: string | null;
}

export interface PerfInfo {
  ttfbMs: number | null;
  totalMs: number | null;
  bytes: number | null;
  redirectCount: number | null;
  /** content-encoding of the main response (gzip/br/…), null when identity. */
  compression: string | null;
  scripts: number | null;
  styles: number | null;
  images: number | null;
  htmlBytes: number | null;
}

export interface ServerInfo {
  ip: string | null;
  country: string | null;
  city: string | null;
  region: string | null;
  org: string | null;
}

export interface DomainInfo {
  registrar: string | null;
  created: string | null;
  expires: string | null;
  daysLeft: number | null;
  status: string[];
  nameservers: string[];
}

export interface DnsInfo {
  a: string[];
  aaaa: string[];
  mx: string[];
  ns: string[];
  spf: boolean | null;
  dmarc: boolean | null;
  caa: boolean | null;
}

/**
 * The trust layer's verdict on a patrolled page: is this a trap?
 *
 * Deliberately separate from the security score — the score grades how
 * a site is BUILT (headers, cookies, exposed files); trust asks whether
 * it is HONEST. A well-built scam aces the first and fails this one.
 */
export interface TrustAssessment {
  verdict: 'clear' | 'suspicious' | 'known-bad';
  /** Human-readable one-liners, shown to the user. */
  reasons: string[];
  /** Where the verdict came from, e.g. ['urlhaus', 'page-warning', 'heuristics']. */
  sources: string[];
}

/** The "website info" matrix — every field nullable, never fabricated. */
export interface WebInfo {
  perf: PerfInfo;
  server: ServerInfo;
  domain: DomainInfo;
  dns: DnsInfo;
  tls: TlsInfo | null;
  api: ApiInfo;
  robotsTxt: boolean;
  securityTxt: boolean;
  /**
   * The trust verdict, written fresh by every patrol. Runs stored
   * before the trust layer existed lack it at runtime (the Postgres
   * jsonb has no `trust` key) — every reader must tolerate undefined.
   */
  trust: TrustAssessment;
}

/** Coarse place (city/country granularity, never finer). */
export interface GeoStamp {
  country: string | null;
  city: string | null;
  region: string | null;
}

/** Both origin halves of a patrol request, stored side by side. */
export interface RequesterOrigin {
  /** Where the requester's address resolves to (always attempted). */
  ip: GeoStamp | null;
  /** The device's own position, when the visitor chose to share it. */
  gps: (GeoStamp & { lat: number; lon: number; accuracyM?: number }) | null;
}

/** One stored patrol run (row of web_checks). */
export interface WebCheckRecord {
  id: string;
  userId: string;
  url: string;
  host: string;
  authorized: boolean;
  score: number | null;
  grade: string | null;
  findings: WebFinding[];
  info: WebInfo;
  /** The owner's address + both location stamps when they asked (disclosed on the form). */
  requesterIp: string | null;
  requesterGeo: RequesterOrigin | null;
  createdAt: string; // ISO
}

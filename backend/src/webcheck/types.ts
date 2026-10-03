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
}

/** Coarse origin of a patrol request (city/country granularity, never finer). */
export interface GeoStamp {
  country: string | null;
  city: string | null;
  region: string | null;
  /** Device coordinates when the visitor allowed the browser prompt. */
  lat?: number;
  lon?: number;
  /** Reported GPS accuracy radius in metres, when known. */
  accuracyM?: number;
  /** How the stamp was derived: the device's GPS, or the address's IP. */
  source?: 'gps' | 'ip';
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
  /** The owner's address + coarse location when they asked (disclosed on the form). */
  requesterIp: string | null;
  requesterGeo: GeoStamp | null;
  createdAt: string; // ISO
}

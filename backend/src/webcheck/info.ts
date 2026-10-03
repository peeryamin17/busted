import type { FetchedResponse } from './fetch.js';
import { isPrivateAddress } from './guard.js';
import type { DnsInfo, DomainInfo, GeoStamp, PerfInfo, ServerInfo } from './types.js';

/**
 * The "website info" matrix sources — all free, key-less public APIs,
 * all best-effort: every reader degrades to nulls/empty lists rather
 * than failing the patrol. Nothing here is invented; a field is null
 * because it could not be read, and the UI says exactly that.
 */

export interface JsonFetchOptions {
  timeoutMs?: number;
  headers?: Record<string, string>;
}

export type JsonFetcher = (url: string, opts?: JsonFetchOptions) => Promise<unknown>;

export const defaultJsonFetcher: JsonFetcher = async (url, opts = {}) => {
  const res = await fetch(url, {
    headers: { 'User-Agent': 'BugSeek-Demo/1.0 (+https://bugseek-ai.vercel.app)', ...(opts.headers ?? {}) },
    signal: AbortSignal.timeout(opts.timeoutMs ?? 5_000),
    redirect: 'follow',
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
};

/** Multi-part public suffixes handled for registrable-host purposes. */
const MULTI_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
  'co.in', 'net.in', 'org.in', 'co.nz', 'com.br', 'com.cn', 'com.tw',
]);

export function registrableHost(host: string): string {
  const clean = host.toLowerCase().replace(/^\[|\]$/g, '').replace(/^www\./, '');
  const labels = clean.split('.').filter(Boolean);
  if (labels.length <= 2) return clean;
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_SUFFIXES.has(lastTwo)) return labels.slice(-3).join('.');
  return lastTwo;
}

/* ── DNS over HTTPS (Cloudflare) ──────────────────────────────── */

interface DohAnswer {
  type: number;
  data: string;
}

async function doh(
  name: string,
  type: string,
  fetchJson: JsonFetcher,
): Promise<DohAnswer[] | null> {
  try {
    const data = (await fetchJson(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { Accept: 'application/dns-json' }, timeoutMs: 4_000 },
    )) as { Answer?: DohAnswer[] };
    return Array.isArray(data?.Answer) ? data.Answer : [];
  } catch {
    return null;
  }
}

const ofType = (answers: DohAnswer[] | null, type: number): string[] =>
  (answers ?? []).filter((a) => a.type === type).map((a) => a.data.replace(/\.$/, ''));

const txtRecords = (answers: DohAnswer[] | null): string[] =>
  ofType(answers, 16).map((raw) =>
    raw
      .split('" "')
      .map((s) => s.replace(/^"|"$/g, ''))
      .join(''),
  );

export async function fetchDnsInfo(
  host: string,
  registrable: string,
  fetchJson: JsonFetcher = defaultJsonFetcher,
): Promise<DnsInfo> {
  const [aRes, aaaaRes, mxRes, nsRes, txtRes, dmarcRes, caaRes] = await Promise.all([
    doh(host, 'A', fetchJson),
    doh(host, 'AAAA', fetchJson),
    doh(registrable, 'MX', fetchJson),
    doh(registrable, 'NS', fetchJson),
    doh(registrable, 'TXT', fetchJson),
    doh(`_dmarc.${registrable}`, 'TXT', fetchJson),
    doh(registrable, 'CAA', fetchJson),
  ]);

  const txt = txtRecords(txtRes);
  const dmarcTxt = txtRecords(dmarcRes);
  return {
    a: ofType(aRes, 1),
    aaaa: ofType(aaaaRes, 28),
    mx: ofType(mxRes, 15)
      .map((r) => r.replace(/^\d+\s+/, ''))
      .sort(),
    ns: ofType(nsRes, 2).sort(),
    spf: txtRes === null ? null : txt.some((t) => t.startsWith('v=spf1')),
    dmarc: dmarcRes === null ? null : dmarcTxt.some((t) => t.startsWith('v=DMARC1')),
    caa: caaRes === null ? null : caaRes.some((a) => a.type === 257),
  };
}

/* ── Domain registration (RDAP) ───────────────────────────────── */

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}
interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, Array<[string, unknown, string, unknown]>];
}
interface RdapResponse {
  entities?: RdapEntity[];
  events?: RdapEvent[];
  status?: string[];
  nameservers?: Array<{ ldhName?: string }>;
}

export async function fetchDomainInfo(
  registrable: string,
  fetchJson: JsonFetcher = defaultJsonFetcher,
): Promise<DomainInfo> {
  const empty: DomainInfo = {
    registrar: null,
    created: null,
    expires: null,
    daysLeft: null,
    status: [],
    nameservers: [],
  };
  try {
    const data = (await fetchJson(`https://rdap.org/domain/${encodeURIComponent(registrable)}`, {
      timeoutMs: 5_000,
    })) as RdapResponse;

    let registrar: string | null = null;
    for (const entity of data.entities ?? []) {
      if (!entity.roles?.includes('registrar')) continue;
      const fnProp = entity.vcardArray?.[1]?.find((p) => p[0] === 'fn');
      if (typeof fnProp?.[3] === 'string') registrar = fnProp[3];
    }
    const eventDate = (action: string) =>
      data.events?.find((e) => e.eventAction === action)?.eventDate ?? null;
    const expires = eventDate('expiration');
    return {
      registrar,
      created: eventDate('registration'),
      expires,
      daysLeft: expires
        ? Math.floor((new Date(expires).getTime() - Date.now()) / 86_400_000)
        : null,
      status: Array.isArray(data.status) ? data.status : [],
      nameservers: (data.nameservers ?? [])
        .map((n) => n.ldhName)
        .filter((n): n is string => typeof n === 'string'),
    };
  } catch {
    return empty;
  }
}

/* ── Server location (ipwho.is) ───────────────────────────────── */

interface IpWhoResponse {
  success?: boolean;
  country?: string;
  city?: string;
  region?: string;
  connection?: { org?: string; isp?: string };
}

export async function fetchServerInfo(
  ip: string | null,
  fetchJson: JsonFetcher = defaultJsonFetcher,
): Promise<ServerInfo> {
  const empty: ServerInfo = { ip, country: null, city: null, region: null, org: null };
  if (!ip) return empty;
  try {
    const data = (await fetchJson(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      timeoutMs: 5_000,
    })) as IpWhoResponse;
    if (data.success === false) return empty;
    return {
      ip,
      country: data.country ?? null,
      city: data.city ?? null,
      region: data.region ?? null,
      org: data.connection?.org ?? data.connection?.isp ?? null,
    };
  } catch {
    return empty;
  }
}

/* ── Requester origin (who asked for a patrol, roughly where) ───── */

/**
 * Coarse geo for the person requesting a patrol, stamped on their run
 * and disclosed on the form before they run it. City/country
 * granularity only; private or unresolvable addresses stamp nothing.
 */
export async function fetchRequesterGeo(
  ip: string | null,
  fetchJson: JsonFetcher = defaultJsonFetcher,
): Promise<GeoStamp | null> {
  if (!ip || isPrivateAddress(ip)) return null;
  const s = await fetchServerInfo(ip, fetchJson);
  if (!s.country && !s.city && !s.region) return null;
  return { country: s.country, city: s.city, region: s.region };
}

interface BigDataCloudResponse {
  city?: string;
  locality?: string;
  principalSubdivision?: string;
  countryName?: string;
}

/**
 * Place names for device coordinates (BigDataCloud's free, key-less
 * reverse geocoder). Garnish only — the coordinates are the record;
 * failure leaves the names blank rather than inventing them.
 */
export async function fetchReverseGeo(
  lat: number,
  lon: number,
  fetchJson: JsonFetcher = defaultJsonFetcher,
): Promise<{ city: string | null; region: string | null; country: string | null } | null> {
  try {
    const data = (await fetchJson(
      `https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${lat}&longitude=${lon}&localityLanguage=en`,
      { timeoutMs: 5_000 },
    )) as BigDataCloudResponse;
    const out = {
      city: data.city ?? data.locality ?? null,
      region: data.principalSubdivision ?? null,
      country: data.countryName ?? null,
    };
    return out.city || out.region || out.country ? out : null;
  } catch {
    return null;
  }
}

/* ── Performance census (from the main fetch, measured here) ──── */

export function buildPerfInfo(page: FetchedResponse): PerfInfo {
  const html = page.body;
  const count = (re: RegExp) => (html ? (html.match(re) ?? []).length : null);
  return {
    ttfbMs: page.ttfbMs,
    totalMs: page.totalMs,
    bytes: page.bytes,
    redirectCount: page.redirectCount,
    compression: page.compression,
    scripts: count(/<script[\s>]/gi),
    styles: count(/<link[^>]*rel=["']?stylesheet/gi),
    images: count(/<img[\s>]/gi),
    htmlBytes: html ? Buffer.byteLength(html, 'utf8') : null,
  };
}

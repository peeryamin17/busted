import type { Confidence, Severity } from '../types.js';

/**
 * Report importers (Phase 5) — convert open-source scanner output into
 * BugSeek findings so external results get the same treatment as native
 * ones: dedupe, CVSS, trap review and remediation enrichment downstream.
 *
 * Supported inputs:
 *   - OWASP ZAP JSON report          (zap -J / GUI JSON export)
 *   - Nuclei JSONL                   (nuclei -jsonl)
 *   - Nikto JSON                     (nikto -Format json)
 *   - SQLMap JSON report             (sqlmap --report-json)
 *   - WhatWeb JSON log               (whatweb --log-json) — used by the
 *                                      bundled-engine runner, same shape.
 *
 * Parsers are pure and defensive: unknown shapes yield zero findings or a
 * thrown Error('unrecognised …') — never a crash. Evidence is truncated
 * here and re-redacted by the route before persistence.
 */

export type ImportFormat = 'zap' | 'nuclei' | 'nikto' | 'sqlmap' | 'whatweb';

export interface ImportedFinding {
  category: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  location?: string;
  evidence?: string;
  remediation: string;
  references: string[];
  source: string;
}

const MAX_FINDINGS = 500;
const s = (v: unknown, max = 5000): string =>
  typeof v === 'string' ? v.slice(0, max) : v == null ? '' : String(v).slice(0, max);
const stripHtml = (v: string): string =>
  v.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
const strList = (v: unknown): string[] =>
  Array.isArray(v) ? v.map((x) => s(x, 500)).filter(Boolean) : typeof v === 'string' ? [v] : [];

function dedupe(findings: ImportedFinding[]): ImportedFinding[] {
  const seen = new Set<string>();
  const out: ImportedFinding[] = [];
  for (const f of findings) {
    const key = `${f.title.toLowerCase()}|${(f.location ?? '').toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
    if (out.length >= MAX_FINDINGS) break;
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* OWASP ZAP                                                           */
/* ------------------------------------------------------------------ */

const ZAP_RISK: Record<string, Severity> = { '3': 'high', '2': 'medium', '1': 'low', '0': 'info' };
const ZAP_CONF: Record<string, Confidence> = { '3': 'high', '2': 'medium', '1': 'low', '0': 'low' };

export function parseZap(raw: string): ImportedFinding[] {
  const root = JSON.parse(raw) as { site?: Array<{ alerts?: unknown[] }> };
  const out: ImportedFinding[] = [];
  for (const site of root.site ?? []) {
    for (const a of (site.alerts ?? []) as Array<Record<string, unknown>>) {
      const instances = (a['instances'] as Array<Record<string, unknown>>) ?? [];
      const first = instances[0] ?? {};
      out.push({
        category: 'network',
        title: s(a['alert'] ?? a['name'] ?? 'ZAP alert', 300),
        description: stripHtml(s(a['desc'])) || 'Reported by OWASP ZAP.',
        severity: ZAP_RISK[s(a['riskcode'], 1)] ?? 'info',
        confidence: ZAP_CONF[s(a['confidence'], 1)] ?? 'low',
        location: s(first['uri'], 1000) || undefined,
        evidence: s(first['evidence'], 300) || undefined,
        remediation: stripHtml(s(a['solution'])) || 'Review and remediate per the linked references.',
        references: s(a['reference']).split(/\s+/).filter(Boolean).slice(0, 6),
        source: `OWASP ZAP (plugin ${s(a['pluginid'], 20) || '?'})`,
      });
    }
  }
  return dedupe(out);
}

/* ------------------------------------------------------------------ */
/* Nuclei                                                              */
/* ------------------------------------------------------------------ */

const NUC_SEV = new Set<Severity>(['critical', 'high', 'medium', 'low', 'info']);

export function parseNuclei(raw: string): ImportedFinding[] {
  const out: ImportedFinding[] = [];
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t.startsWith('{')) continue;
    let e: Record<string, unknown>;
    try {
      e = JSON.parse(t) as Record<string, unknown>;
    } catch {
      continue;
    }
    const info = (e['info'] ?? {}) as Record<string, unknown>;
    const sevRaw = s(info['severity'], 20).toLowerCase() as Severity;
    const tags = strList(info['tags']).join(' ').toLowerCase();
    out.push({
      category: tags.includes('cve') ? 'tech' : 'network',
      title: s(info['name'] ?? e['template-id'] ?? 'Nuclei match', 300),
      description: s(info['description']) || `Template ${s(e['template-id'], 100)} matched.`,
      severity: NUC_SEV.has(sevRaw) ? sevRaw : 'info',
      confidence: 'high',
      location: s(e['matched-at'] ?? e['host'], 1000) || undefined,
      evidence: strList(e['extracted-results']).join(', ').slice(0, 300) || undefined,
      remediation: s(info['remediation']) || 'Review the template guidance and remediate.',
      references: strList(info['reference']).slice(0, 6),
      source: `Nuclei (${s(e['template-id'], 100)})`,
    });
  }
  return dedupe(out);
}

/* ------------------------------------------------------------------ */
/* Nikto                                                               */
/* ------------------------------------------------------------------ */

export function parseNikto(raw: string): ImportedFinding[] {
  // Nikto ≥ 2.5 writes JSON; 2.1.x writes XML (no JSON format). Support both.
  if (raw.includes('<niktoscan')) return parseNiktoXml(raw);
  const start = raw.indexOf('{');
  if (start < 0) return [];
  const root = JSON.parse(raw.slice(start)) as {
    host?: string;
    vulnerabilities?: Array<Record<string, unknown>>;
  };
  const out: ImportedFinding[] = [];
  for (const v of root.vulnerabilities ?? []) {
    const msg = s(v['msg'], 1000);
    const sev: Severity = /(outdated|vulnerab|remote code|shell|backup|\.git|phpinfo|default (account|password))/i.test(msg)
      ? 'medium'
      : /(directory indexing|listing)/i.test(msg)
        ? 'low'
        : 'low';
    const urlPath = s(v['url'], 500);
    out.push({
      category: 'network',
      title: msg.slice(0, 160) || 'Nikto finding',
      description: msg,
      severity: sev,
      confidence: 'medium',
      location: urlPath ? `${s(root.host, 300)}${urlPath.startsWith('/') ? '' : '/'}${urlPath}` : s(root.host, 300),
      remediation: 'Review the Nikto reference for this check and remediate the server configuration.',
      references: s(v['OSVDB'], 50) ? [`OSVDB ${s(v['OSVDB'], 50)}`] : [],
      source: `Nikto (id ${s(v['id'], 20) || '?'})`,
    });
  }
  return dedupe(out);
}

/** Nikto 2.1.x XML: <item id osvdbid method><description/><uri/></item>. */
function parseNiktoXml(raw: string): ImportedFinding[] {
  const decode = (v: string): string =>
    v.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&').trim();
  const cdata = (block: string, tag: string): string => {
    const m = block.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`));
    if (!m) return '';
    return decode(m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1'));
  };
  const hostMatch = raw.match(/<scandetails[^>]*targetip="([^"]*)"[^>]*targetport="([^"]*)"/);
  const hostBase = hostMatch ? `${hostMatch[1]}:${hostMatch[2]}` : '';
  const out: ImportedFinding[] = [];
  for (const m of raw.matchAll(/<item\s+([^>]*)>([\s\S]*?)<\/item>/g)) {
    const attrs = m[1];
    const block = m[2];
    const id = /id="(\d+)"/.exec(attrs)?.[1] ?? '?';
    const osvdb = /osvdbid="(\d+)"/.exec(attrs)?.[1] ?? '';
    const msg = cdata(block, 'description');
    const uri = cdata(block, 'uri');
    if (!msg) continue;
    out.push({
      category: 'network',
      title: msg.slice(0, 160),
      description: msg,
      severity: /(outdated|vulnerab|remote code|shell|backup|\.git|phpinfo|default (account|password))/i.test(msg)
        ? 'medium'
        : 'low',
      confidence: 'medium',
      location: uri ? `${hostBase}${uri.startsWith('/') ? '' : '/'}${uri}` : hostBase || undefined,
      remediation: 'Review the Nikto reference for this check and remediate the server configuration.',
      references: osvdb && osvdb !== '0' ? [`OSVDB ${osvdb}`] : [],
      source: `Nikto (id ${id})`,
    });
  }
  return dedupe(out);
}

/* ------------------------------------------------------------------ */
/* SQLMap (--report-json) — walked defensively; shapes vary by version */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */

export function parseSqlmap(raw: string): ImportedFinding[] {
  const root = JSON.parse(raw) as Record<string, unknown>;
  const out: ImportedFinding[] = [];

  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (!node || typeof node !== 'object') return;
    const o = node as Record<string, unknown>;
    // Injection point: { parameter, place, dbms, data: [{title, payload, ...}] }
    if (typeof o['parameter'] === 'string' && Array.isArray(o['data'])) {
      const param = s(o['parameter'], 100);
      const place = s(o['place'], 50);
      const dbms = s(o['dbms'], 100);
      for (const d of o['data'] as Array<Record<string, unknown>>) {
        out.push({
          category: 'api',
          title: `SQL injection (SQLMap): ${s(d['title'], 200) || param}`,
          description:
            `SQLMap confirmed an injection point in parameter "${param}" (${place || 'request'})` +
            (dbms ? ` against ${dbms}` : '') +
            '. This is a tool-confirmed exploitable injection — treat as critical until disproven.',
          severity: 'critical',
          confidence: 'high',
          evidence: s(d['payload'], 300) || undefined,
          remediation:
            'Use parameterised queries / prepared statements for this parameter; never concatenate input into SQL. Audit all queries built the same way.',
          references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
          source: 'SQLMap',
        });
      }
    }
    // DBMS fingerprint entries
    if (typeof o['type_name'] === 'string' && /fingerprint/i.test(o['type_name'])) {
      out.push({
        category: 'tech',
        title: 'Database fingerprint (SQLMap)',
        description: s(o['value'], 500),
        severity: 'info',
        confidence: 'high',
        remediation: 'Informational — fingerprint data gathered during SQLMap testing.',
        references: [],
        source: 'SQLMap',
      });
    }
    Object.values(o).forEach(walk);
  };
  walk(root);
  return dedupe(out);
}

/* ------------------------------------------------------------------ */
/* WhatWeb (--log-json)                                                */
/* ------------------------------------------------------------------ */

export function parseWhatweb(raw: string): ImportedFinding[] {
  const parsed = JSON.parse(raw) as Array<Record<string, unknown>> | Record<string, unknown>;
  const entries = Array.isArray(parsed) ? parsed : [parsed];
  const out: ImportedFinding[] = [];
  for (const e of entries) {
    const target = s(e['target'], 1000);
    const plugins = (e['plugins'] ?? {}) as Record<string, { version?: unknown; string?: unknown }>;
    const techs: string[] = [];
    for (const [name, info] of Object.entries(plugins)) {
      const ver = Array.isArray(info.version) ? s(info.version[0], 50) : '';
      techs.push(ver ? `${name} ${ver}` : name);
    }
    if (techs.length > 0) {
      out.push({
        category: 'tech',
        title: `Fingerprint (WhatWeb): ${techs.slice(0, 10).join(', ')}`,
        description:
          `WhatWeb identified on ${target}: ${techs.join(', ')}. ` +
          'Version disclosure helps attackers shop for known CVEs — keep components current and suppress version banners where configurable.',
        severity: 'info',
        confidence: 'high',
        location: target || undefined,
        remediation: 'Keep fingerprinted components patched; hide version banners where the stack allows.',
        references: [],
        source: 'WhatWeb',
      });
    }
  }
  return dedupe(out);
}

/* ------------------------------------------------------------------ */

export function detectFormat(raw: string): ImportFormat {
  const t = raw.trim();
  if (t.includes('"template-id"') || t.includes('"templateID"')) return 'nuclei';
  if (t.includes('<niktoscan')) return 'nikto';
  try {
    const j = JSON.parse(t) as Record<string, unknown>;
    if (Array.isArray(j['site'])) return 'zap';
    if (Array.isArray(j['vulnerabilities']) && ('host' in j || 'banner' in j)) return 'nikto';
    if (Array.isArray(j) && j.length > 0 && typeof j[0] === 'object' && j[0] !== null && 'plugins' in (j[0] as object)) return 'whatweb';
    if ('data' in j || 'success' in j) return 'sqlmap';
  } catch {
    /* not single JSON — nuclei JSONL handled above; fall through */
  }
  if (t.startsWith('{') && t.includes('"vulnerabilities"')) return 'nikto';
  throw new Error('Could not detect the report format — specify zap, nuclei, nikto or sqlmap');
}

export function parseImport(format: ImportFormat | 'auto', raw: string): ImportedFinding[] {
  const fmt = format === 'auto' ? detectFormat(raw) : format;
  switch (fmt) {
    case 'zap':
      return parseZap(raw);
    case 'nuclei':
      return parseNuclei(raw);
    case 'nikto':
      return parseNikto(raw);
    case 'sqlmap':
      return parseSqlmap(raw);
    case 'whatweb':
      return parseWhatweb(raw);
  }
}

/**
 * Sensitive-file prober (Phase 4, AUTHORISED active tier only).
 *
 * The classic recon checklist: is the target accidentally publishing its
 * own source, configuration, or backups? A tight list of well-known paths,
 * GET-only, through the scope-checked rate-limited client. A path counts
 * as exposed only when the response is 200 AND carries a content signature
 * — a 200 alone is usually a SPA fallback or a custom error page.
 *
 * Evidence discipline: for files like .env we report matched KEY NAMES
 * only. Secret values are never copied into findings.
 */
import type { ActiveHttpClient } from './httpClient';
import type { Finding } from '../lib/types';

let seq = 0;
const nid = (p: string) => `sensfile-${p}-${seq++}`;

interface Probe {
  path: string;
  title: string;
  severity: Finding['severity'];
  /** Returns true when the body proves exposure; may also set evidence. */
  match: (body: string, contentType: string) => string | null;
  remediation: string;
}

const envMatch = (body: string): string | null => {
  const keys = new Set<string>();
  for (const m of body.matchAll(/^([A-Z][A-Z0-9_]{2,})\s*=/gm)) {
    if (/(KEY|SECRET|TOKEN|PASSWORD|DATABASE|DB_|AWS_|STRIPE|SMTP|MAIL_)/.test(m[1])) keys.add(m[1]);
  }
  return keys.size > 0 ? `exposed variable names: ${[...keys].slice(0, 12).join(', ')} (values never captured)` : null;
};

const PROBES: Probe[] = [
  {
    path: '/.git/HEAD',
    title: 'Exposed .git repository (HEAD readable)',
    severity: 'critical',
    match: (b) => (/^ref: refs\//m.test(b) || /^[0-9a-f]{40}$/m.test(b.trim()) ? 'body is a git HEAD ref' : null),
    remediation:
      'Block access to /.git at the web server (or deploy from a build artifact, not a working tree). Anyone can reconstruct the full source from an exposed .git.',
  },
  {
    path: '/.git/config',
    title: 'Exposed .git/config',
    severity: 'high',
    match: (b) => (/\[core\]|\[remote /.test(b) ? 'body is a git config (may include remote URLs with credentials)' : null),
    remediation: 'Deny all /.git paths at the server edge and rotate any credentials present in remote URLs.',
  },
  {
    path: '/.env',
    title: 'Exposed .env file',
    severity: 'critical',
    match: envMatch,
    remediation:
      'Remove .env from the web root immediately and ROTATE every secret it contained — assume they are public now. Serve configuration from the process environment, not a reachable file.',
  },
  {
    path: '/.env.local',
    title: 'Exposed .env.local file',
    severity: 'critical',
    match: envMatch,
    remediation: 'Same as .env: remove from web root and rotate every contained secret.',
  },
  {
    path: '/.aws/credentials',
    title: 'Exposed AWS credentials file',
    severity: 'critical',
    match: (b) => (/aws_access_key_id|\[default\]|\[profile/.test(b) ? 'body matches an AWS credentials file' : null),
    remediation: 'Remove the file from the web root and rotate the AWS keys NOW; check CloudTrail for misuse.',
  },
  {
    path: '/.svn/entries',
    title: 'Exposed .svn metadata',
    severity: 'medium',
    match: (b) => (/^dir$|svn:/m.test(b) ? 'body is subversion metadata' : null),
    remediation: 'Block /.svn at the web server; it leaks source paths and history.',
  },
  {
    path: '/.DS_Store',
    title: 'Exposed .DS_Store file',
    severity: 'low',
    match: (b) => (b.includes('Bud1') ? 'body carries the .DS_Store signature' : null),
    remediation: 'Remove .DS_Store files from deployments; they enumerate directory contents for attackers.',
  },
  {
    path: '/backup.zip',
    title: 'Publicly downloadable backup archive',
    severity: 'high',
    match: (b, ct) =>
      ct.includes('zip') || b.startsWith('PK') ? 'response is a ZIP archive' : null,
    remediation: 'Never store backups under the web root. Move archives to private storage and audit what this one contained.',
  },
  {
    path: '/server-status',
    title: 'Apache server-status exposed',
    severity: 'medium',
    match: (b) => (/Apache Server Status|Total accesses/i.test(b) ? 'body is a mod_status page' : null),
    remediation: 'Restrict /server-status to localhost/monitoring IPs; it leaks URLs, IPs and vhost layout.',
  },
  {
    path: '/ftp/',
    title: 'Directory listing enabled on /ftp/',
    severity: 'medium',
    match: (b) => (/Index of \/ftp/i.test(b) ? 'body is a directory index' : null),
    remediation: 'Disable directory indexes (Options -Indexes) and review everything the listing exposes.',
  },
  {
    path: '/assets/',
    title: 'Directory listing enabled on /assets/',
    severity: 'low',
    match: (b) => (/Index of \/assets/i.test(b) ? 'body is a directory index' : null),
    remediation: 'Disable directory indexes; listings hand attackers a file inventory for free.',
  },
];

export async function probeSensitiveFiles(
  http: ActiveHttpClient,
  targetUrl: string,
): Promise<{ findings: Finding[] }> {
  const findings: Finding[] = [];
  const origin = new URL(targetUrl).origin;

  for (const probe of PROBES) {
    try {
      const res = await http.get(origin + probe.path);
      if (res.status !== 200) continue;
      const evidence = probe.match(res.bodyText ?? '', res.contentType ?? '');
      if (!evidence) continue;
      findings.push({
        id: nid('hit'),
        category: 'api',
        title: probe.title,
        description:
          `GET ${probe.path} returned 200 with matching content (${evidence}). ` +
          'This file was never meant to be public — treat anything it contains as disclosed.',
        severity: probe.severity,
        confidence: 'high',
        location: origin + probe.path,
        evidence,
        remediation: probe.remediation,
      });
    } catch {
      /* unreachable path — absence is the expected, safe outcome */
    }
  }

  return { findings };
}

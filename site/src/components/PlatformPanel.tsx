/**
 * Platform panel: tabbed member-page section for skills, MCP, search,
 * alerts, workspace, companies and lessons. Every tab fetches its own
 * relative /api URL and shows the backend's error text when a call
 * fails. Secrets are write-only, inputs never show a stored value.
 *
 * Two limits the panel states outright: workspace files live on the
 * backend host's disk, which is ephemeral on hosted deploys, and stdio
 * MCP is not supported (HTTP/SSE only).
 */
import { useCallback, useEffect, useState } from 'react';
import { safeExternalUrl } from '../lib/urls';
import { safeStorageGet, safeStorageRemove, safeStorageSet } from '../lib/storage';

type Tab = 'skills' | 'mcp' | 'search' | 'alerts' | 'workspace' | 'companies' | 'lessons';

const TABS: Array<{ id: Tab; label: string }> = [
  { id: 'skills', label: 'Skills' },
  { id: 'mcp', label: 'MCP servers' },
  { id: 'search', label: 'Web search' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'workspace', label: 'Workspace' },
  { id: 'companies', label: 'Companies' },
  { id: 'lessons', label: 'Lessons' },
];

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
  const data: unknown = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg =
      data && typeof data === 'object' && 'error' in data && typeof (data as { error: unknown }).error === 'string'
        ? (data as { error: string }).error
        : `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return data as T;
}

function useError(): [string | null, (msg: string | null) => void] {
  const [error, setError] = useState<string | null>(null);
  return [error, setError];
}

const inputCls =
  'w-full rounded-lg border border-white/15 bg-white/5 px-3 py-2 text-sm text-bone placeholder:text-slate2/70 focus:border-mint/60 focus:outline-none';
const btnCls =
  'rounded-lg border border-white/20 bg-white/10 px-3 py-2 text-sm text-bone transition hover:bg-white/15 disabled:opacity-50';
const btnDangerCls =
  'rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs text-red-300 transition hover:bg-red-500/20';
const rowCls = 'flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3';

function Section({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="font-display text-lg font-bold text-bone">{title}</h3>
      {hint ? <p className="mt-1 text-sm leading-relaxed text-slate2">{hint}</p> : null}
      <div className="mt-4 space-y-3">{children}</div>
    </div>
  );
}

/* ── Skills ─────────────────────────────────────────────────────────────── */

interface SkillMeta {
  name: string;
  description: string;
  whenToUse: string;
  roles: string[];
  tools: string[];
}

interface SkillGap {
  id: string;
  taskId: string | null;
  capability: string;
  context: string | null;
  createdAt: string;
}

function SkillsTab() {
  const [skills, setSkills] = useState<SkillMeta[]>([]);
  const [gaps, setGaps] = useState<SkillGap[]>([]);
  const [error, setError] = useError();
  const load = useCallback(async () => {
    try {
      const [s, g] = await Promise.all([
        api<{ skills: SkillMeta[] }>('/api/skills'),
        api<{ gaps: SkillGap[] }>('/api/skill-gaps'),
      ]);
      setSkills(s.skills);
      setGaps(g.gaps);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [setError]);
  useEffect(() => {
    void load();
  }, [load]);
  return (
    <Section
      title="Skills"
      hint="Playbook packs the swarm can load. A skill is prompt text only — it advises the agent, it never runs code, and it never bypasses scope, approvals, pins, or the noise governor."
    >
      {error ? <p className="text-sm text-red-300">{error}</p> : null}
      {skills.length === 0 ? (
        <p className="text-sm text-slate2">No skill packs loaded.</p>
      ) : (
        skills.map((s) => (
          <div key={s.name} className={rowCls}>
            <div>
              <p className="font-mono text-sm font-bold text-bone">{s.name}</p>
              <p className="mt-1 text-sm text-slate2">{s.description}</p>
              <p className="mt-1 font-mono text-[11px] text-slate2">
                roles: {s.roles.join(', ') || '—'} · gates tools: {s.tools.join(', ') || '—'}
              </p>
            </div>
          </div>
        ))
      )}
      <h4 className="pt-2 font-mono text-[11px] tracking-[0.2em] text-slate2">SKILL GAPS — CAPABILITIES THE AGENT LACKED</h4>
      {gaps.length === 0 ? (
        <p className="text-sm text-slate2">No gaps recorded.</p>
      ) : (
        gaps.map((g) => (
          <div key={g.id} className={rowCls}>
            <div>
              <p className="text-sm text-bone">{g.capability}</p>
              {g.context ? <p className="mt-1 text-sm text-slate2">{g.context}</p> : null}
              <p className="mt-1 font-mono text-[11px] text-slate2">{new Date(g.createdAt).toLocaleString()}</p>
            </div>
          </div>
        ))
      )}
    </Section>
  );
}

/* ── MCP ────────────────────────────────────────────────────────────────── */

interface McpServer {
  id: string;
  label: string;
  url: string;
  transport: string;
  enabled: boolean;
  credentialHint: string | null;
  createdAt: string;
}

function McpTab() {
  const [servers, setServers] = useState<McpServer[]>([]);
  const [label, setLabel] = useState('');
  const [url, setUrl] = useState('');
  const [transport, setTransport] = useState('http');
  const [credential, setCredential] = useState('');
  const [error, setError] = useError();
  const [note, setNote] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      const data = await api<{ servers: McpServer[] }>('/api/mcp/servers');
      setServers(data.servers);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [setError]);
  useEffect(() => {
    void load();
  }, [load]);
  async function add(e: React.FormEvent) {
    e.preventDefault();
    setNote(null);
    try {
      await api('/api/mcp/servers', {
        method: 'POST',
        body: JSON.stringify({ label, url, transport, credential: credential || undefined }),
      });
      setLabel('');
      setUrl('');
      setCredential('');
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  async function test(id: string) {
    setNote(null);
    try {
      const data = await api<{ ok: boolean; tools?: Array<{ name: string }>; error?: string }>(`/api/mcp/servers/${id}/test`, {
        method: 'POST',
      });
      setNote(data.ok ? `Reachable — ${data.tools?.length ?? 0} tools listed.` : `Unreachable: ${data.error ?? 'unknown error'}`);
    } catch (err) {
      setError((err as Error).message);
    }
  }
  async function remove(id: string) {
    try {
      await api(`/api/mcp/servers/${id}`, { method: 'DELETE' });
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  return (
    <Section
      title="MCP servers"
      hint="Remote MCP servers over Streamable HTTP or legacy SSE. Tools stay deferred until a skill that gates them loads. stdio MCP is not supported here, it needs the worker host."
    >
      {error ? <p className="text-sm text-red-300">{error}</p> : null}
      {note ? <p className="text-sm text-emerald-300">{note}</p> : null}
      {servers.map((s) => (
        <div key={s.id} className={rowCls}>
          <div>
            <p className="font-mono text-sm font-bold text-bone">{s.label}</p>
            <p className="mt-1 break-all text-sm text-slate2">{s.url} · {s.transport}</p>
            {s.credentialHint ? <p className="mt-1 font-mono text-[11px] text-slate2">credential: {s.credentialHint}</p> : null}
          </div>
          <div className="flex gap-2">
            <button type="button" className={btnCls} onClick={() => void test(s.id)}>Test</button>
            <button type="button" className={btnDangerCls} onClick={() => void remove(s.id)}>Remove</button>
          </div>
        </div>
      ))}
      <form onSubmit={(e) => void add(e)} className="space-y-2 rounded-xl border border-white/10 bg-white/[0.03] p-4">
        <p className="font-mono text-[11px] tracking-[0.2em] text-slate2">ADD A SERVER</p>
        <input className={inputCls} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Label (e.g. playright-mcp)" required />
        <input className={inputCls} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Server URL (https://…)" required />
        <div className="flex gap-2">
          <select className={inputCls} value={transport} onChange={(e) => setTransport(e.target.value)}>
            <option value="http">Streamable HTTP</option>
            <option value="sse">Legacy SSE</option>
          </select>
          <input
            className={inputCls}
            type="password"
            value={credential}
            onChange={(e) => setCredential(e.target.value)}
            placeholder="Credential (optional, stored encrypted)"
          />
        </div>
        <button type="submit" className={btnCls}>Add server</button>
      </form>
    </Section>
  );
}

/* ── Web search ─────────────────────────────────────────────────────────── */

interface SearchProviderInfo {
  name: string;
  isSearchProvider: boolean;
  needsKey: boolean;
  description: string;
  hasKey: boolean;
}

interface SearchResult {
  title: string;
  url: string;
  snippet: string;
}

function SearchTab() {
  const [providers, setProviders] = useState<SearchProviderInfo[]>([]);
  const [current, setCurrent] = useState('duckduckgo');
  const [key, setKey] = useState('');
  const [keyProvider, setKeyProvider] = useState('brave');
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [error, setError] = useError();
  const [note, setNote] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      const [p, s] = await Promise.all([
        api<{ providers: SearchProviderInfo[] }>('/api/search/providers'),
        api<{ provider: string }>('/api/search/settings'),
      ]);
      setProviders(p.providers);
      setCurrent(s.provider);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [setError]);
  useEffect(() => {
    void load();
  }, [load]);
  async function saveKey(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api('/api/search/key', { method: 'POST', body: JSON.stringify({ provider: keyProvider, key }) });
      setKey('');
      setNote(`Key saved for ${keyProvider} (encrypted at rest).`);
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  async function run(e: React.FormEvent) {
    e.preventDefault();
    setNote(null);
    try {
      const data = await api<{ results: SearchResult[] }>('/api/search', {
        method: 'POST',
        body: JSON.stringify({ query }),
      });
      setResults(data.results);
    } catch (err) {
      setError((err as Error).message);
    }
  }
  return (
    <Section
      title="Web search"
      hint="The agent's search tool. DuckDuckGo needs no key; Brave and Tavily need one (stored encrypted). Results are untrusted web content — framed as data, never instructions."
    >
      {error ? <p className="text-sm text-red-300">{error}</p> : null}
      {note ? <p className="text-sm text-emerald-300">{note}</p> : null}
      <div className="flex flex-wrap gap-2">
        {providers.map((p) => (
          <button
            key={p.name}
            type="button"
            className={`${btnCls} ${current === p.name ? 'border-mint/60 text-mint' : ''}`}
            onClick={() => {
              void api('/api/search/provider', { method: 'POST', body: JSON.stringify({ provider: p.name }) })
                .then(() => setCurrent(p.name))
                .catch((err: Error) => setError(err.message));
            }}
            disabled={!p.isSearchProvider}
          >
            {p.name}
            {p.needsKey ? (p.hasKey ? ' · key saved' : ' · needs key') : ' · keyless'}
            {!p.isSearchProvider ? ' · not a search provider' : ''}
          </button>
        ))}
      </div>
      <form onSubmit={(e) => void saveKey(e)} className="flex flex-wrap gap-2">
        <select className={`${inputCls} w-auto`} value={keyProvider} onChange={(e) => setKeyProvider(e.target.value)}>
          {providers.filter((p) => p.needsKey).map((p) => (
            <option key={p.name} value={p.name}>{p.name}</option>
          ))}
        </select>
        <input className={`${inputCls} flex-1`} type="password" value={key} onChange={(e) => setKey(e.target.value)} placeholder="Provider API key" required />
        <button type="submit" className={btnCls}>Save key</button>
      </form>
      <form onSubmit={(e) => void run(e)} className="flex gap-2">
        <input className={`${inputCls} flex-1`} value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search the web…" required />
        <button type="submit" className={btnCls}>Search</button>
      </form>
      {results.map((r) => {
        const href = safeExternalUrl(r.url);
        return (
          <div key={r.url} className={rowCls}>
            <div>
              {href ? (
                <a href={href} target="_blank" rel="noreferrer" className="text-sm font-bold text-bone underline decoration-white/30 underline-offset-2">
                  {r.title}
                </a>
              ) : (
                <span className="text-sm font-bold text-bone">{r.title}</span>
              )}
              <p className="mt-1 text-sm text-slate2">{r.snippet}</p>
            </div>
          </div>
        );
      })}
    </Section>
  );
}

/* ── Notifications ──────────────────────────────────────────────────────── */

interface NotifyChannel {
  id: string;
  type: 'webhook' | 'telegram' | 'smtp';
  label: string;
  target: Record<string, unknown>;
  filters: { minSeverity: string; events: string[] };
  enabled: boolean;
  secretHint: string | null;
  createdAt: string;
}

function targetSummary(c: NotifyChannel): string {
  if (c.type === 'webhook') return String(c.target['url'] ?? '');
  if (c.type === 'telegram') return `chat ${String(c.target['chatId'] ?? '')}`;
  return `${String(c.target['host'] ?? '')}:${String(c.target['port'] ?? '')} → ${String(c.target['to'] ?? '')}`;
}

function AlertsTab() {
  const [channels, setChannels] = useState<NotifyChannel[]>([]);
  const [type, setType] = useState<'webhook' | 'telegram' | 'smtp'>('webhook');
  const [label, setLabel] = useState('');
  const [url, setUrl] = useState('');
  const [chatId, setChatId] = useState('');
  const [smtpHost, setSmtpHost] = useState('');
  const [smtpPort, setSmtpPort] = useState('25');
  const [smtpUser, setSmtpUser] = useState('');
  const [smtpFrom, setSmtpFrom] = useState('');
  const [smtpTo, setSmtpTo] = useState('');
  const [secret, setSecret] = useState('');
  const [minSeverity, setMinSeverity] = useState('high');
  const [error, setError] = useError();
  const [note, setNote] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      const data = await api<{ channels: NotifyChannel[] }>('/api/notify/channels');
      setChannels(data.channels);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [setError]);
  useEffect(() => {
    void load();
  }, [load]);
  async function add(e: React.FormEvent) {
    e.preventDefault();
    setNote(null);
    const target =
      type === 'webhook'
        ? { url }
        : type === 'telegram'
          ? { chatId }
          : { host: smtpHost, port: Number(smtpPort), user: smtpUser, from: smtpFrom, to: smtpTo };
    try {
      await api('/api/notify/channels', {
        method: 'POST',
        body: JSON.stringify({ type, label, target, filters: { minSeverity }, secret: secret || undefined }),
      });
      setLabel('');
      setUrl('');
      setChatId('');
      setSecret('');
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  async function test(id: string) {
    try {
      const data = await api<{ ok: boolean; error?: string }>(`/api/notify/channels/${id}/test`, { method: 'POST' });
      setNote(data.ok ? 'Test notification sent.' : `Test failed: ${data.error ?? 'unknown error'}`);
    } catch (err) {
      setError((err as Error).message);
    }
  }
  async function remove(id: string) {
    try {
      await api(`/api/notify/channels/${id}`, { method: 'DELETE' });
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  return (
    <Section
      title="Alerts"
      hint="Where BugSeek tells you something happened: task finished, or a critical/high finding landed. Per-channel filters and a 10-sends-per-minute cap apply. SMTP here is plain (no TLS) — for production alerts prefer webhook or Telegram."
    >
      {error ? <p className="text-sm text-red-300">{error}</p> : null}
      {note ? <p className="text-sm text-emerald-300">{note}</p> : null}
      {channels.map((c) => (
        <div key={c.id} className={rowCls}>
          <div>
            <p className="font-mono text-sm font-bold text-bone">{c.label} <span className="text-slate2">· {c.type}</span></p>
            <p className="mt-1 break-all text-sm text-slate2">{targetSummary(c)}</p>
            <p className="mt-1 font-mono text-[11px] text-slate2">
              from {c.filters.minSeverity} · {c.filters.events.join(', ')}
              {c.secretHint ? ` · secret ${c.secretHint}` : ''}
            </p>
          </div>
          <div className="flex gap-2">
            <button type="button" className={btnCls} onClick={() => void test(c.id)}>Test</button>
            <button type="button" className={btnDangerCls} onClick={() => void remove(c.id)}>Remove</button>
          </div>
        </div>
      ))}
      <form onSubmit={(e) => void add(e)} className="space-y-2 rounded-xl border border-white/10 bg-white/[0.03] p-4">
        <p className="font-mono text-[11px] tracking-[0.2em] text-slate2">ADD A CHANNEL</p>
        <div className="flex gap-2">
          <select className={inputCls} value={type} onChange={(e) => setType(e.target.value as typeof type)}>
            <option value="webhook">Webhook</option>
            <option value="telegram">Telegram</option>
            <option value="smtp">Email (SMTP)</option>
          </select>
          <input className={inputCls} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Label" required />
        </div>
        {type === 'webhook' ? (
          <input className={inputCls} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Webhook URL (https://…)" required />
        ) : null}
        {type === 'telegram' ? (
          <>
            <input className={inputCls} value={chatId} onChange={(e) => setChatId(e.target.value)} placeholder="Telegram chat id" required />
            <input className={inputCls} type="password" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="Bot token (stored encrypted)" required />
          </>
        ) : null}
        {type === 'smtp' ? (
          <>
            <div className="flex gap-2">
              <input className={inputCls} value={smtpHost} onChange={(e) => setSmtpHost(e.target.value)} placeholder="SMTP host" required />
              <input className={inputCls} value={smtpPort} onChange={(e) => setSmtpPort(e.target.value)} placeholder="Port" required />
            </div>
            <input className={inputCls} value={smtpUser} onChange={(e) => setSmtpUser(e.target.value)} placeholder="SMTP username" required />
            <div className="flex gap-2">
              <input className={inputCls} value={smtpFrom} onChange={(e) => setSmtpFrom(e.target.value)} placeholder="From address" required />
              <input className={inputCls} value={smtpTo} onChange={(e) => setSmtpTo(e.target.value)} placeholder="To address" required />
            </div>
            <input className={inputCls} type="password" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="SMTP password (stored encrypted)" required />
          </>
        ) : null}
        <select className={inputCls} value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
          <option value="info">Notify from info</option>
          <option value="low">Notify from low</option>
          <option value="medium">Notify from medium</option>
          <option value="high">Notify from high</option>
          <option value="critical">Critical only</option>
        </select>
        <button type="submit" className={btnCls}>Add channel</button>
      </form>
    </Section>
  );
}

/* ── Workspace ──────────────────────────────────────────────────────────── */

interface WorkspaceFile {
  name: string;
  path: string;
  size: number;
  mtime: string;
  isDir: boolean;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

function WorkspaceTab() {
  const [files, setFiles] = useState<WorkspaceFile[]>([]);
  const [usage, setUsage] = useState(0);
  const [quota, setQuota] = useState(0);
  const [fileName, setFileName] = useState('');
  const [fileText, setFileText] = useState('');
  const [error, setError] = useError();
  const [note, setNote] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      const data = await api<{ files: WorkspaceFile[]; usageBytes: number; quotaBytes: number }>('/api/workspace');
      setFiles(data.files);
      setUsage(data.usageBytes);
      setQuota(data.quotaBytes);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [setError]);
  useEffect(() => {
    void load();
  }, [load]);
  async function upload(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setNote(null);
    const bytes = new TextEncoder().encode(fileText).length;
    if (bytes > 10 * 1024 * 1024) {
      setError(`That file is ${(bytes / (1024 * 1024)).toFixed(1)} MiB — the per-file cap is 10 MiB.`);
      return;
    }
    try {
      const contentBase64 = btoa(unescape(encodeURIComponent(fileText)));
      await api('/api/workspace/upload', {
        method: 'POST',
        body: JSON.stringify({ name: fileName, contentBase64 }),
      });
      setFileName('');
      setFileText('');
      setNote('Uploaded. Remember: workspace files live on the backend host and a redeploy can wipe them.');
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  async function download(path: string) {
    setError(null);
    try {
      const res = await fetch(`/api/workspace/file?path=${encodeURIComponent(path)}`, {
        credentials: 'include',
      });
      if (!res.ok) {
        throw new Error(
          res.status === 401
            ? 'Sign in again to download this file.'
            : res.status === 404
              ? 'That file is no longer on the backend.'
              : `Download failed (${res.status}).`,
        );
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = path.split('/').pop() ?? 'file';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError((err as Error).message);
    }
  }
  async function remove(path: string) {
    try {
      await api(`/api/workspace/file?path=${encodeURIComponent(path)}`, { method: 'DELETE' });
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  return (
    <Section
      title="Workspace"
      hint="Your files: task working files, code-intake uploads, exported reports. Per-file cap 10 MiB, 100 MiB per user. Files live on the backend host's disk, which is ephemeral on the hosted backend — a redeploy can wipe them, so keep originals elsewhere."
    >
      {error ? <p className="text-sm text-red-300">{error}</p> : null}
      {note ? <p className="text-sm text-emerald-300">{note}</p> : null}
      <p className="font-mono text-[11px] text-slate2">USING {fmtBytes(usage)} OF {fmtBytes(quota)}</p>
      {files.length === 0 ? (
        <p className="text-sm text-slate2">Workspace is empty.</p>
      ) : (
        files.map((f) => (
          <div key={f.path} className={rowCls}>
            <div>
              <p className="font-mono text-sm text-bone">{f.path}</p>
              <p className="mt-1 font-mono text-[11px] text-slate2">{fmtBytes(f.size)} · {new Date(f.mtime).toLocaleString()}</p>
            </div>
            {!f.isDir ? (
              <div className="flex gap-2">
                <button type="button" className={btnCls} onClick={() => void download(f.path)}>Download</button>
                <button type="button" className={btnDangerCls} onClick={() => void remove(f.path)}>Delete</button>
              </div>
            ) : null}
          </div>
        ))
      )}
      <form onSubmit={(e) => void upload(e)} className="space-y-2 rounded-xl border border-white/10 bg-white/[0.03] p-4">
        <p className="font-mono text-[11px] tracking-[0.2em] text-slate2">UPLOAD A TEXT FILE</p>
        <input className={inputCls} value={fileName} onChange={(e) => setFileName(e.target.value)} placeholder="File name (e.g. notes.md)" required />
        <textarea className={`${inputCls} min-h-24 font-mono`} value={fileText} onChange={(e) => setFileText(e.target.value)} placeholder="Paste file contents…" required />
        <button type="submit" className={btnCls}>Upload</button>
      </form>
    </Section>
  );
}

/* ── Companies ──────────────────────────────────────────────────────────── */

interface Company {
  id: string;
  name: string;
  scope: { domains: string[]; notes?: string };
  createdAt: string;
}

const COMPANY_KEY = 'bugseek-company';

function CompaniesTab() {
  const [companies, setCompanies] = useState<Company[]>([]);
  const [selected, setSelected] = useState<string>(() => safeStorageGet(COMPANY_KEY) ?? '');
  const [name, setName] = useState('');
  const [domains, setDomains] = useState('');
  const [error, setError] = useError();
  const load = useCallback(async () => {
    try {
      const data = await api<{ companies: Company[] }>('/api/companies');
      setCompanies(data.companies);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [setError]);
  useEffect(() => {
    void load();
  }, [load]);
  async function add(e: React.FormEvent) {
    e.preventDefault();
    try {
      const scope = domains.trim()
        ? { domains: domains.split(/[,\s]+/).map((d) => d.trim()).filter(Boolean) }
        : undefined;
      await api('/api/companies', { method: 'POST', body: JSON.stringify({ name, scope }) });
      setName('');
      setDomains('');
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  async function remove(id: string) {
    try {
      await api(`/api/companies/${id}`, { method: 'DELETE' });
      if (selected === id) {
        setSelected('');
        safeStorageRemove(COMPANY_KEY);
      }
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  return (
    <Section
      title="Companies"
      hint="Group tasks and assets by company. Picking a company here sets the active company for this browser — tasks you create while it is active are linked to it."
    >
      {error ? <p className="text-sm text-red-300">{error}</p> : null}
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-[11px] tracking-[0.2em] text-slate2">ACTIVE COMPANY</span>
        <select
          className={`${inputCls} w-auto`}
          value={selected}
          onChange={(e) => {
            setSelected(e.target.value);
            if (e.target.value) safeStorageSet(COMPANY_KEY, e.target.value);
            else safeStorageRemove(COMPANY_KEY);
          }}
        >
          <option value="">No company selected</option>
          {companies.map((c) => (
            <option key={c.id} value={c.id}>{c.name}</option>
          ))}
        </select>
      </div>
      {companies.map((c) => (
        <div key={c.id} className={rowCls}>
          <div>
            <p className="font-mono text-sm font-bold text-bone">{c.name}</p>
            <p className="mt-1 text-sm text-slate2">{c.scope.domains.join(', ') || 'No domains in scope'}</p>
            {c.scope.notes ? <p className="mt-1 text-sm text-slate2">{c.scope.notes}</p> : null}
          </div>
          <button type="button" className={btnDangerCls} onClick={() => void remove(c.id)}>Remove</button>
        </div>
      ))}
      <form onSubmit={(e) => void add(e)} className="space-y-2 rounded-xl border border-white/10 bg-white/[0.03] p-4">
        <p className="font-mono text-[11px] tracking-[0.2em] text-slate2">ADD A COMPANY</p>
        <input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="Company name" required />
        <input className={inputCls} value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="Domains in scope, comma-separated" />
        <button type="submit" className={btnCls}>Add company</button>
      </form>
    </Section>
  );
}

/* ── Lessons ────────────────────────────────────────────────────────────── */

interface Lesson {
  id: string;
  taskId: string | null;
  kind: 'worked' | 'failed' | 'pattern';
  title: string;
  detail: string;
  evidence: string[];
  createdAt: string;
}

function LessonsTab() {
  const [lessons, setLessons] = useState<Lesson[]>([]);
  const [mode, setMode] = useState('shadow');
  const [error, setError] = useError();
  const load = useCallback(async () => {
    try {
      const data = await api<{ lessons: Lesson[]; mode: string }>('/api/lessons');
      setLessons(data.lessons);
      setMode(data.mode);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [setError]);
  useEffect(() => {
    void load();
  }, [load]);
  return (
    <Section
      title="Lessons"
      hint="What past tasks taught BugSeek — what worked, what failed, reusable patterns. Shadow mode: lessons are recorded and shown here, but never fed back into agent prompts. Promoting them to active use is a deliberate later decision, not a toggle here."
    >
      {error ? <p className="text-sm text-red-300">{error}</p> : null}
      <p className="font-mono text-[11px] text-slate2">
        MODE: {mode.toUpperCase()} {mode === 'shadow' ? '— recorded, never injected into prompts' : '— recording paused'}
      </p>
      {lessons.length === 0 ? (
        <p className="text-sm text-slate2">No lessons yet. Extract them from a finished task on the Tasks page.</p>
      ) : (
        lessons.map((l) => (
          <div key={l.id} className={rowCls}>
            <div>
              <p className="text-sm text-bone">
                <span className="font-mono text-[11px] uppercase tracking-wider text-mint">{l.kind}</span> — {l.title}
              </p>
              <p className="mt-1 text-sm text-slate2">{l.detail}</p>
              <p className="mt-1 font-mono text-[11px] text-slate2">{new Date(l.createdAt).toLocaleString()}</p>
            </div>
          </div>
        ))
      )}
    </Section>
  );
}

/* ── Panel ──────────────────────────────────────────────────────────────── */

export function PlatformPanel() {
  const [tab, setTab] = useState<Tab>('skills');
  return (
    <div className="glass overflow-hidden rounded-[2rem] p-7 sm:p-9">
      <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">PLATFORM</p>
      <h2 className="mt-3 font-display text-3xl font-bold tracking-tight text-bone sm:text-4xl">
        Skills, servers, search &amp; alerts.
      </h2>
      <p className="mt-3 max-w-xl leading-relaxed text-body/85">
        The platform layer: playbook skills, remote MCP servers, web
        search providers, alert channels, your workspace, companies and
        the lessons BugSeek is learning — in shadow mode for now.
      </p>
      <div className="mt-6 flex flex-wrap gap-2" role="tablist" aria-label="Platform sections">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            className={`${btnCls} ${tab === t.id ? 'border-mint/60 text-mint' : ''}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div className="mt-6">
        {tab === 'skills' ? <SkillsTab /> : null}
        {tab === 'mcp' ? <McpTab /> : null}
        {tab === 'search' ? <SearchTab /> : null}
        {tab === 'alerts' ? <AlertsTab /> : null}
        {tab === 'workspace' ? <WorkspaceTab /> : null}
        {tab === 'companies' ? <CompaniesTab /> : null}
        {tab === 'lessons' ? <LessonsTab /> : null}
      </div>
    </div>
  );
}

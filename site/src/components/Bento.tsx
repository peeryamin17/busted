import {
  Cookie,
  Crosshair,
  FileKey2,
  Radar,
  ShieldAlert,
  ShoppingCart,
  Sparkles,
  type LucideIcon,
} from 'lucide-react';
import type { ReactNode } from 'react';
import { Reveal } from './Reveal';
import { Spotlight } from './fx/Spotlight';

interface Cell {
  icon: LucideIcon;
  tag: string;
  title: string;
  body: string;
  span: string;
  children?: ReactNode;
}

function Chip({ children, tone = 'mint' }: { children: ReactNode; tone?: 'mint' | 'amber' | 'plain' }) {
  const tones = {
    mint: 'border-mint/25 bg-mint/10 text-mintlight',
    amber: 'border-amber2/30 bg-amber2/10 text-amber2',
    plain: 'border-white/10 bg-white/5 text-body/80',
  } as const;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[11px] ${tones[tone]}`}>
      {children}
    </span>
  );
}

const CELLS: Cell[] = [
  {
    icon: Radar,
    tag: 'PASSIVE · 1 CREDIT',
    title: 'Passive recon',
    body: 'Reads the room before touching anything. DOM analysis, secrets hiding in JavaScript, security headers graded against OWASP, tech fingerprinting — then a one-click Markdown report.',
    span: 'md:col-span-2',
    children: (
      <>
        <Chip>bundle.js → AKIA…(redacted)</Chip>
        <Chip tone="plain">CSP: missing</Chip>
        <Chip tone="plain">X-Frame-Options: missing</Chip>
        <Chip>HSTS: present ✓</Chip>
      </>
    ),
  },
  {
    icon: Cookie,
    tag: 'DEEP SURFACE',
    title: 'The DevTools stuff, automated',
    body: 'Every cookie inventoried with its session carriers flagged. Storage inventoried — JWTs decoded for alg and expiry, never the raw value. Payment gateways fingerprinted, third-party integrations mapped.',
    span: '',
    children: (
      <>
        <Chip>jwt · alg HS256 · no exp ⚠</Chip>
        <Chip tone="plain">gateway: Stripe</Chip>
      </>
    ),
  },
  {
    icon: Crosshair,
    tag: 'ACTIVE · AUTHORIZATION-GATED',
    title: 'Active testing',
    body: 'Only after you confirm authorization and set the scope. Every request is scope-checked and rate-limited: CORS, GraphQL, reflected XSS confirmed in the DOM, IDOR, auth posture, API discovery.',
    span: '',
  },
  {
    icon: FileKey2,
    tag: 'SENSITIVE FILES',
    title: '.git, .env & other confessions',
    body: 'Signature-verified probes for exposed repos, env files, AWS credentials and backup archives. A .env finding shows key names only — the values never enter the report.',
    span: '',
    children: (
      <>
        <Chip tone="amber">/.git/HEAD → 200</Chip>
        <Chip tone="amber">/.env → KEY NAMES ONLY</Chip>
      </>
    ),
  },
  {
    icon: ShoppingCart,
    tag: 'COMMERCE CHECKS',
    title: 'The book-it-free playbook',
    body: 'Client-controlled price fields, cart/checkout/coupon mapping, and the payment-replay surface — identifiers in URLs, bearer order-pay links, long-lived payment cookies. It maps the loaded gun and writes the exact manual checks. It never places an order.',
    span: 'md:col-span-2',
    children: (
      <>
        <Chip>hidden input: price</Chip>
        <Chip tone="plain">order-pay link = bearer credential</Chip>
        <Chip tone="plain">coupon: reuse? stacking?</Chip>
      </>
    ),
  },
  {
    icon: ShieldAlert,
    tag: 'TRAPS & CHAINS',
    title: 'It saves you from yourself',
    body: 'Honeypots get flagged as possible traps instead of reported as wins, and lone findings get linked into attack-chain narratives with CVSS v3.1 on everything.',
    span: '',
    children: (
      <>
        <Chip tone="amber">⚑ possible trap — verify manually</Chip>
      </>
    ),
  },
];

/**
 * Bento grid (Magic UI bento-grid treatment): asymmetric cells, icons,
 * live-feeling evidence chips and a cursor spotlight — no two cells the
 * same shape, one coherent system.
 */
export function Bento() {
  return (
    <section id="what" className="relative mx-auto max-w-6xl scroll-mt-24 px-4 py-24 sm:px-6 sm:py-32">
      <Reveal>
        <p className="font-mono text-xs tracking-[0.2em] text-mint">THE TOOLKIT</p>
        <h2 className="mt-3 font-display text-4xl font-bold tracking-tight text-bone sm:text-5xl">
          Everything a hunter checks.
          <span className="text-slate2"> In one popup.</span>
        </h2>
        <p className="mt-4 max-w-2xl text-lg text-body/85">
          Start quiet, go loud only when you're allowed to, and let the agents
          handle the boring parts in between.
        </p>
      </Reveal>

      <div className="mt-12 grid gap-5 md:grid-cols-3">
        {CELLS.map((c, i) => (
          <Reveal key={c.title} delay={(i % 3) * 0.08} className={c.span}>
            <Spotlight className="h-full overflow-hidden rounded-3xl border border-white/10 bg-panel">
              <article className="relative flex h-full flex-col p-6 sm:p-7">
                <div className="flex items-center justify-between gap-3">
                  <span className="flex h-11 w-11 items-center justify-center rounded-2xl border border-mint/25 bg-mint/10 text-mint">
                    <c.icon className="h-5 w-5" aria-hidden />
                  </span>
                  <span className="font-mono text-[10px] tracking-[0.18em] text-slate2">{c.tag}</span>
                </div>
                <h3 className="mt-5 font-display text-[1.35rem] font-semibold leading-snug text-bone">{c.title}</h3>
                <p className="mt-2 flex-1 text-sm leading-relaxed text-body/85">{c.body}</p>
                {c.children && <div className="mt-5 flex flex-wrap gap-2">{c.children}</div>}
              </article>
            </Spotlight>
          </Reveal>
        ))}

        {/* swarm teaser cell — spans the full row, points at #swarm */}
        <Reveal delay={0.05} className="md:col-span-3">
          <Spotlight className="overflow-hidden rounded-3xl border border-mint/25 bg-panel">
            <article className="relative flex flex-col items-start gap-5 p-6 sm:p-7 md:flex-row md:items-center">
              <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-mint/25 bg-mint/10 text-mint">
                <Sparkles className="h-5 w-5" aria-hidden />
              </span>
              <div className="flex-1">
                <p className="font-mono text-[10px] tracking-[0.18em] text-slate2">AI SWARM · 25 CREDITS</p>
                <h3 className="mt-1.5 font-display text-[1.35rem] font-semibold text-bone">
                  And when the popup isn't enough — send in the swarm.
                </h3>
                <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-body/85">
                  Nine specialist agents probe autonomously and report back with findings, chains,
                  suggested fixes and a 0–100 security score.
                </p>
              </div>
              <a
                href="#swarm"
                className="shrink-0 rounded-xl border border-mint/30 bg-mint/10 px-4 py-2.5 text-sm font-semibold text-mint transition-colors hover:bg-mint/20"
              >
                Meet them ↓
              </a>
            </article>
          </Spotlight>
        </Reveal>
      </div>

    </section>
  );
}

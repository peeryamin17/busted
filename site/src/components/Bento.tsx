import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import {
  Bug,
  Cookie,
  Crosshair,
  FileKey2,
  Radar,
  ShieldAlert,
  ShoppingCart,
  Sparkles,
  Wrench,
  type LucideIcon,
} from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { Reveal } from './Reveal';
import { ExpandableTabs } from './fx/ExpandableTabs';
import { Spotlight } from './fx/Spotlight';
import { springQuiet } from '../lib/motion';

type Mode = 'passive' | 'active' | 'swarm';

interface Cell {
  icon: LucideIcon;
  tag: string;
  title: string;
  body: string;
  span: string;
  children?: ReactNode;
}

function Chip({ children, tone = 'white' }: { children: ReactNode; tone?: 'white' | 'data' | 'plain' }) {
  const tones = {
    white: 'border-white/25 bg-white/10 text-bone',
    data: 'border-amber2/30 bg-amber2/10 text-amber2',
    plain: 'border-white/10 bg-white/5 text-body/80',
  } as const;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[11px] ${tones[tone]}`}>
      {children}
    </span>
  );
}

function CellCard({ c }: { c: Cell }) {
  return (
    <Spotlight className="h-full overflow-hidden rounded-3xl border border-white/10 bg-panel">
      <article className="relative flex h-full flex-col p-6 sm:p-7">
        <div className="flex items-center justify-between gap-3">
          <span className="flex h-11 w-11 items-center justify-center rounded-2xl border border-white/20 bg-white/5 text-white">
            <c.icon className="h-5 w-5" aria-hidden />
          </span>
          <span className="font-mono text-[10px] tracking-[0.18em] text-slate2">{c.tag}</span>
        </div>
        <h3 className="mt-5 font-display text-[1.35rem] font-semibold leading-snug text-bone">{c.title}</h3>
        <p className="mt-2 flex-1 text-sm leading-relaxed text-body/85">{c.body}</p>
        {c.children && <div className="mt-5 flex flex-wrap gap-2">{c.children}</div>}
      </article>
    </Spotlight>
  );
}

const PASSIVE_CELLS: Cell[] = [
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
];

const ACTIVE_CELLS: Cell[] = [
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
        <Chip tone="data">/.git/HEAD → 200</Chip>
        <Chip tone="data">/.env → KEY NAMES ONLY</Chip>
      </>
    ),
  },
  {
    icon: ShoppingCart,
    tag: 'COMMERCE CHECKS',
    title: 'The book-it-free playbook',
    body: 'Client-controlled price fields, cart/checkout/coupon mapping, and the payment-replay surface — identifiers in URLs, bearer order-pay links, long-lived payment cookies. It maps the loaded gun and writes the exact manual checks. It never places an order.',
    span: '',
    children: (
      <>
        <Chip>hidden input: price</Chip>
        <Chip tone="plain">order-pay link = bearer credential</Chip>
        <Chip tone="plain">coupon: reuse? stacking?</Chip>
      </>
    ),
  },
];

const SWARM_CELLS: Cell[] = [
  {
    icon: Sparkles,
    tag: 'AI SWARM · 25 CREDITS',
    title: "When the popup isn't enough — send in the swarm",
    body: 'A head agent deploys nine specialist workers against the target and stitches their findings into one report: deduped, CVSS-scored, chained, and closed out with a 0–100 security score.',
    span: 'md:col-span-2',
    children: (
      <>
        <Chip>Recon</Chip>
        <Chip>Secret Hunter</Chip>
        <Chip>XSS Hunter</Chip>
        <Chip>Source-Map Miner</Chip>
        <Chip tone="plain">+ 5 more specialists</Chip>
      </>
    ),
  },
  {
    icon: ShieldAlert,
    tag: 'TRAPS & CHAINS',
    title: 'It saves you from yourself',
    body: 'Honeypots get flagged as possible traps instead of reported as wins, and lone findings get linked into attack-chain narratives.',
    span: '',
    children: (
      <>
        <Chip tone="data">⚑ possible trap — verify manually</Chip>
      </>
    ),
  },
  {
    icon: Wrench,
    tag: 'REMEDIATION',
    title: 'Fixes, not gospel',
    body: 'Reports include AI-suggested code fixes for the worst findings — clearly labelled as suggestions for a human to review, never as verified patches.',
    span: 'md:col-span-3',
  },
];

const MODE_CELLS: Record<Mode, Cell[]> = {
  passive: PASSIVE_CELLS,
  active: ACTIVE_CELLS,
  swarm: SWARM_CELLS,
};

const TABS = [
  { title: 'Passive recon', icon: Radar },
  { title: 'Active testing', icon: Crosshair },
  { title: 'AI swarm', icon: Bug },
];
const MODES: Mode[] = ['passive', 'active', 'swarm'];

/**
 * The toolkit, switched by Expandable Tabs (21st.dev pattern): three
 * modes — passive, active, swarm — each with its own bento layout of
 * spotlight cards. Click outside the tab bar and it collapses to icons.
 */
export function Bento() {
  const reduce = useReducedMotion();
  const [tab, setTab] = useState(0);
  const mode = MODES[tab];
  const cells = MODE_CELLS[mode];

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
          handle the boring parts in between. Pick a mode:
        </p>
      </Reveal>

      <Reveal delay={0.08} className="mt-10">
        <ExpandableTabs tabs={TABS} active={tab} onChange={setTab} ariaLabel="BugSeek modes" />
      </Reveal>

      <div className="relative mt-10">
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={mode}
            initial={reduce ? { opacity: 0 } : { opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            exit={reduce ? { opacity: 0 } : { opacity: 0, y: -12 }}
            transition={springQuiet}
            className="grid gap-5 md:grid-cols-3"
          >
            {cells.map((c) => (
              <div key={c.title} className={c.span}>
                <CellCard c={c} />
              </div>
            ))}

            {mode === 'swarm' && (
              <div className="md:col-span-3">
                <a
                  href="#swarm"
                  className="group flex items-center justify-center gap-2 rounded-3xl border border-dashed border-white/20 px-6 py-5 text-sm font-semibold text-body transition-colors hover:border-white/40 hover:text-bone"
                >
                  Meet the whole crew
                  <span aria-hidden className="transition-transform duration-300 group-hover:translate-y-0.5">↓</span>
                </a>
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>
    </section>
  );
}

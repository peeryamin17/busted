import { motion } from 'framer-motion';
import { Reveal } from './Reveal';
import { springQuiet } from '../lib/motion';

interface Pillar {
  n: string;
  tag: string;
  title: string;
  hook: string;
  points: string[];
  foot: string;
}

const PILLARS: Pillar[] = [
  {
    n: '01',
    tag: 'PASSIVE · NO BACKEND NEEDED',
    title: 'Passive recon',
    hook: 'Reads the room before touching anything.',
    points: [
      'DOM analysis — forms, inputs, hidden fields, XSS sinks',
      'Secret scanning in JavaScript — AWS keys, Stripe keys, tokens',
      'Cookie audits & security headers vs OWASP best practices',
      'Tech fingerprinting — frameworks, CMS, servers',
      'One-click Markdown report, severity-grouped',
    ],
    foot: '1 credit a scan. Basically free.',
  },
  {
    n: '02',
    tag: 'AUTHORIZATION-GATED',
    title: 'Active testing',
    hook: 'Powerful — and it knows it.',
    points: [
      'Confirm authorization first: bounty program, contract, or ownership',
      'You define the scope; every request is scope-checked & rate-limited',
      'CORS, GraphQL, reflected XSS, IDOR, auth posture, API discovery',
      'CVSS v3.1 on every finding, honeypot/trap detection',
      'Attack-chain narratives that link findings into bigger stories',
    ],
    foot: "Nothing fires without your say-so. Ever.",
  },
  {
    n: '03',
    tag: 'HEAD AGENT + CREW',
    title: 'AI swarm',
    hook: 'Send in the team.',
    points: [
      'A head agent deploys specialist workers that probe autonomously',
      'Recon · Secret Hunter · Headers & Cookies · CORS Analyst',
      'XSS Hunter · IDOR Hunter · Auth Analyst · GraphQL Prober',
      'Source-Map Miner — rebuilds original sources from exposed .maps',
      'Head dedupes, chain-links, and writes the executive summary',
    ],
    foot: '25 credits a run. They work while you sleep.',
  },
];

export function Pillars() {
  return (
    <section id="what" className="relative mx-auto max-w-6xl scroll-mt-24 px-4 py-24 sm:px-6 sm:py-32">
      <Reveal>
        <p className="font-mono text-xs tracking-[0.2em] text-mint">THE TOOLKIT</p>
        <h2 className="mt-3 font-display text-4xl font-bold tracking-tight text-bone sm:text-5xl">
          Three ways to hunt.
        </h2>
        <p className="mt-4 max-w-2xl text-lg text-body/85">
          Start quiet, go loud only when you're allowed to, and let the agents
          handle the boring parts in between.
        </p>
      </Reveal>

      <div className="mt-12 grid gap-6 md:grid-cols-3">
        {PILLARS.map((p, i) => (
          <Reveal key={p.n} delay={i * 0.1} className="h-full">
            <motion.article
              whileHover={{ y: -8 }}
              transition={springQuiet}
              className="glass relative flex h-full flex-col overflow-hidden rounded-3xl p-7"
            >
              <span
                aria-hidden
                className="pointer-events-none absolute -right-2 -top-6 font-display text-[7rem] font-bold leading-none text-white/[0.05]"
              >
                {p.n}
              </span>
              <span className="inline-flex w-fit rounded-full border border-mint/25 bg-mint/10 px-3 py-1 font-mono text-[10px] tracking-wider text-mint">
                {p.tag}
              </span>
              <h3 className="mt-5 font-display text-2xl font-semibold text-bone">{p.title}</h3>
              <p className="mt-1.5 text-[15px] italic text-body/75">{p.hook}</p>
              <ul className="mt-5 flex-1 space-y-2.5">
                {p.points.map((pt) => (
                  <li key={pt} className="flex gap-2.5 text-sm leading-relaxed text-body/85">
                    <span className="mt-0.5 shrink-0 text-mint">▸</span>
                    <span>{pt}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-6 border-t border-white/10 pt-4 font-mono text-xs text-mintlight/90">
                {p.foot}
              </p>
            </motion.article>
          </Reveal>
        ))}
      </div>
    </section>
  );
}

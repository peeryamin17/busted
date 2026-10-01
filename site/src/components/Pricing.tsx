import { motion } from 'framer-motion';
import { Reveal } from './Reveal';
import { pressable, springQuiet } from '../lib/motion';

interface Tier {
  name: string;
  price: string;
  per: string;
  blurb: string;
  credits: string;
  features: string[];
  cta: string;
  featured?: boolean;
}

const TIERS: Tier[] = [
  {
    name: 'Scout',
    price: '$0',
    per: 'free forever',
    blurb: 'For the curious.',
    credits: '50 credits / month',
    features: ['Passive recon scans', 'Markdown reports', 'CVSS scoring', 'Community support'],
    cta: 'Start free',
  },
  {
    name: 'Hunter',
    price: '$29',
    per: 'per month',
    blurb: 'For the serious.',
    credits: '300 credits / month',
    features: [
      'Everything in Scout',
      'Authorization-gated active testing',
      'AI agent swarm scans',
      'Attack-chain narratives',
      'All report formats',
    ],
    cta: 'Hunt harder',
    featured: true,
  },
  {
    name: 'Pro',
    price: '$99',
    per: 'per month',
    blurb: 'For the obsessed.',
    credits: '1,500 credits / month',
    features: [
      'Everything in Hunter',
      'Priority swarm queue',
      'Deeper per-scan budgets',
      'Early access to new agents',
    ],
    cta: 'Go pro',
  },
];

export function Pricing() {
  return (
    <section id="pricing" className="mx-auto max-w-6xl scroll-mt-24 px-4 py-24 sm:px-6 sm:py-32">
      <Reveal>
        <p className="font-mono text-xs tracking-[0.2em] text-mint">PRICING</p>
        <h2 className="mt-3 font-display text-4xl font-bold tracking-tight text-bone sm:text-5xl">
          Priced for students.
        </h2>
        <p className="mt-4 max-w-2xl text-lg text-body/85">
          No sales call. No “contact us”. Just credits — built by a student, priced
          like one.
        </p>
      </Reveal>

      <div className="mt-12 grid gap-6 md:grid-cols-3">
        {TIERS.map((t, i) => (
          <Reveal key={t.name} delay={i * 0.1} className="h-full">
            <motion.article
              whileHover={{ y: -8 }}
              transition={springQuiet}
              className={`relative flex h-full flex-col rounded-3xl p-7 ${
                t.featured
                  ? 'glass border-mint/30'
                  : 'rounded-3xl border border-white/10 bg-panel/60'
              }`}
            >
              {t.featured && (
                <span className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-mint px-3.5 py-1 font-mono text-[10px] font-semibold tracking-wider text-ink">
                  MOST POPULAR
                </span>
              )}
              <h3 className="font-display text-xl font-semibold text-bone">{t.name}</h3>
              <p className="mt-1 text-sm italic text-body/70">{t.blurb}</p>
              <p className="mt-5 font-display text-5xl font-bold tracking-tight text-bone">
                {t.price}
                <span className="ml-2 align-middle font-sans text-sm font-normal text-slate2">
                  {t.per}
                </span>
              </p>
              <p className="mt-2 font-mono text-xs text-mint">{t.credits}</p>
              <ul className="mt-6 flex-1 space-y-2.5">
                {t.features.map((f) => (
                  <li key={f} className="flex gap-2.5 text-sm text-body/85">
                    <span className="mt-0.5 shrink-0 text-mint">✓</span>
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
              <motion.a
                href="#download"
                {...pressable}
                className={`mt-8 rounded-2xl px-6 py-3 text-center font-display text-base font-semibold ${
                  t.featured
                    ? 'bg-mint text-ink shadow-[0_16px_40px_-12px_rgba(52,211,153,0.55)]'
                    : 'border border-white/10 bg-white/5 text-bone hover:bg-white/10'
                }`}
              >
                {t.cta}
              </motion.a>
            </motion.article>
          </Reveal>
        ))}
      </div>

      <Reveal delay={0.15}>
        <div className="mt-10 rounded-2xl border border-white/10 bg-ink p-6 text-center">
          <p className="font-mono text-sm text-body/85">
            <span className="text-bone">The math:</span> passive scan ={' '}
            <span className="text-mint">1 credit</span> · AI agent scan ={' '}
            <span className="text-mint">25 credits</span>
          </p>
          <p className="mt-2 text-sm text-slate2">
            A Hunter plan is 300 passive scans — or 12 full swarm runs — every month.
          </p>
        </div>
      </Reveal>
    </section>
  );
}

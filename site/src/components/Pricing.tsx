import { motion } from 'framer-motion';
import { Check, Coins, Crown, MousePointerClick, Rocket } from 'lucide-react';
import { Reveal } from './Reveal';
import { pressable, springQuiet } from '../lib/motion';

interface Tier {
  name: string;
  price: string;
  per: string;
  blurb: string;
  credits: string;
  creditAmount: number;
  features: string[];
  cta: string;
  icon: typeof Rocket;
  featured?: boolean;
}

const TIERS: Tier[] = [
  {
    name: 'Scout',
    price: '$0',
    per: 'free forever',
    blurb: 'For the curious.',
    credits: '50 credits / month',
    creditAmount: 50,
    features: ['Passive recon scans', 'Markdown reports', 'CVSS scoring', 'Community support'],
    cta: 'Start free',
    icon: MousePointerClick,
  },
  {
    name: 'Hunter',
    price: '$29',
    per: 'per month',
    blurb: 'For the serious.',
    credits: '300 credits / month',
    creditAmount: 300,
    features: [
      'Everything in Scout',
      'Authorization-gated active testing',
      'AI agent swarm scans',
      'Attack-chain narratives',
      'All report formats',
    ],
    cta: 'Hunt harder',
    icon: Rocket,
    featured: true,
  },
  {
    name: 'Pro',
    price: '$99',
    per: 'per month',
    blurb: 'For the obsessed.',
    credits: '1,500 credits / month',
    creditAmount: 1500,
    features: [
      'Everything in Hunter',
      'Priority swarm queue',
      'Deeper per-scan budgets',
      'Early access to new agents',
    ],
    cta: 'Go pro',
    icon: Crown,
  },
];

/** Credits visualised against the Pro ceiling — log-ish, honest, labelled. */
function meterWidth(amount: number) {
  return `${Math.max(4, Math.round((Math.log10(amount) / Math.log10(1500)) * 100))}%`;
}

/**
 * Pricing with a shine-border hero card (Magic UI shine-border) and a
 * credit meter per tier — same honest numbers, louder suit.
 */
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

      <div className="mt-12 grid items-stretch gap-6 md:grid-cols-3">
        {TIERS.map((t, i) => {
          const card = (
            <motion.article
              whileHover={{ y: -8 }}
              transition={springQuiet}
              className={`relative flex h-full flex-col p-7 ${
                t.featured
                  ? 'rounded-[calc(1.5rem-1.5px)] bg-panel'
                  : 'rounded-3xl border border-white/10 bg-panel/60'
              }`}
            >
              {t.featured && (
                <span className="absolute -top-3 left-1/2 z-10 -translate-x-1/2 whitespace-nowrap rounded-full bg-mint px-3.5 py-1 font-mono text-[10px] font-semibold tracking-wider text-ink">
                  MOST POPULAR
                </span>
              )}
              <div className="flex items-center justify-between">
                <h3 className="font-display text-xl font-semibold text-bone">{t.name}</h3>
                <t.icon className={`h-5 w-5 ${t.featured ? 'text-mint' : 'text-slate2'}`} aria-hidden />
              </div>
              <p className="mt-1 text-sm italic text-body/70">{t.blurb}</p>
              <p className="mt-5 font-display text-5xl font-bold tracking-tight text-bone">
                {t.price}
                <span className="ml-2 align-middle font-sans text-sm font-normal text-slate2">{t.per}</span>
              </p>

              {/* credit meter */}
              <div className="mt-5">
                <p className="flex items-center gap-1.5 font-mono text-xs text-mint">
                  <Coins className="h-3.5 w-3.5" aria-hidden /> {t.credits}
                </p>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/10">
                  <motion.div
                    className="h-full rounded-full bg-mint"
                    initial={{ width: 0 }}
                    whileInView={{ width: meterWidth(t.creditAmount) }}
                    viewport={{ once: true, margin: '-40px' }}
                    transition={{ ...springQuiet, delay: 0.15 }}
                  />
                </div>
              </div>

              <ul className="mt-6 flex-1 space-y-2.5">
                {t.features.map((f) => (
                  <li key={f} className="flex gap-2.5 text-sm text-body/85">
                    <Check className="mt-0.5 h-4 w-4 shrink-0 text-mint" aria-hidden />
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
              <motion.a
                href="#download"
                {...pressable}
                className={`mt-8 rounded-2xl px-6 py-3 text-center font-display text-base font-semibold ${
                  t.featured
                    ? 'btn-shimmer text-ink shadow-[0_16px_40px_-12px_rgba(52,211,153,0.55)]'
                    : 'border border-white/10 bg-white/5 text-bone hover:bg-white/10'
                }`}
              >
                {t.cta}
              </motion.a>
            </motion.article>
          );

          return (
            <Reveal key={t.name} delay={i * 0.1} className="h-full">
              {t.featured ? (
                <div className="relative h-full rounded-3xl p-[1.5px]">
                  <div aria-hidden className="shine-border-layer absolute inset-0 rounded-3xl" />
                  {card}
                </div>
              ) : (
                card
              )}
            </Reveal>
          );
        })}
      </div>

      <Reveal delay={0.15}>
        <div className="mt-10 rounded-2xl border border-white/10 bg-ink p-6 text-center">
          <p className="font-mono text-sm text-body/85">
            <span className="text-bone">The math:</span> passive scan ={' '}
            <span className="text-mint">1 credit</span> · AI swarm scan ={' '}
            <span className="text-mint">25 credits</span>
          </p>
          <p className="mt-2 text-sm text-slate2">
            A Hunter plan is 300 passive scans — or 12 full swarm runs — every month.
            Credits never buy permission, though: authorization is always on you.
          </p>
        </div>
      </Reveal>
    </section>
  );
}

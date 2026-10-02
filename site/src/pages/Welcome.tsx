import { motion, useReducedMotion, useScroll, useTransform } from 'framer-motion';
import {
  Braces,
  Check,
  ChevronDown,
  Crosshair,
  FileCode2,
  FileText,
  FileType,
  Radar,
  ScanSearch,
  ShieldCheck,
} from 'lucide-react';
import { useRef, type ReactNode } from 'react';
import { Nav } from '../components/Nav';
import { Footer } from '../components/Footer';
import { Reveal } from '../components/Reveal';
import { LiquidGlassButton } from '../components/fx/LiquidGlassButton';
import { ScoreRing } from '../components/fx/ScoreRing';
import { navigate } from '../lib/router';

interface Stage {
  n: string;
  tag: string;
  icon: typeof Radar;
  title: string;
  body: string;
  visual: ReactNode;
}

function Chip({ children, data = false }: { children: ReactNode; data?: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[11px] ${
        data ? 'border-amber2/30 bg-amber2/10 text-amber2' : 'border-white/10 bg-white/5 text-body/85'
      }`}
    >
      {children}
    </span>
  );
}

function MonoLine({ children }: { children: ReactNode }) {
  return (
    <p className="flex items-baseline justify-between gap-4 border-b border-white/5 py-2 font-mono text-xs last:border-0">
      {children}
    </p>
  );
}

const STAGES: Stage[] = [
  {
    n: '01',
    tag: 'PASSIVE RECON · 1 CREDIT',
    icon: Radar,
    title: 'Point it at a tab. It reads the room.',
    body: 'No probes, no noise. BugSeek reads the page the way a senior hunter does on first contact — DOM, scripts, headers — and writes it all down.',
    visual: (
      <div className="flex flex-wrap gap-2">
        <Chip>secrets in bundle.js</Chip>
        <Chip>headers vs OWASP</Chip>
        <Chip>tech fingerprint</Chip>
        <Chip>DOM & forms mapped</Chip>
        <Chip>Markdown report, 1 click</Chip>
      </div>
    ),
  },
  {
    n: '02',
    tag: 'DEEP SURFACE',
    icon: ScanSearch,
    title: 'The DevTools dive, automated.',
    body: 'Everything you would dig through DevTools for, inventoried in seconds — with values reduced to shapes, never copied raw.',
    visual: (
      <div>
        <MonoLine>
          <span className="text-body/85">session cookie · PHPSESSID</span>
          <span className="text-slate2">HttpOnly ✓ · Secure ✓</span>
        </MonoLine>
        <MonoLine>
          <span className="text-body/85">localStorage · auth_token</span>
          <span className="text-slate2">JWT · alg HS256 · no exp ⚠</span>
        </MonoLine>
        <MonoLine>
          <span className="text-body/85">payment gateway</span>
          <span className="text-slate2">Stripe, via hosted iframe</span>
        </MonoLine>
        <MonoLine>
          <span className="text-body/85">third parties</span>
          <span className="text-slate2">analytics · chat · CDN — mapped</span>
        </MonoLine>
      </div>
    ),
  },
  {
    n: '03',
    tag: 'ACTIVE TESTING · GATED',
    icon: Crosshair,
    title: 'Loud — but only with permission.',
    body: 'Active checks unlock behind your authorization and a scope you define. Every request is scope-checked, rate-limited and non-destructive.',
    visual: (
      <div className="space-y-2.5">
        {[
          'CORS, GraphQL, DOM-confirmed XSS, IDOR, auth posture',
          'Sensitive files: /.git, /.env, backups — signature-verified',
          'Commerce: price fields, coupon mapping, payment-replay surface',
        ].map((t) => (
          <p key={t} className="flex gap-2.5 text-sm leading-relaxed text-body/85">
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-white" aria-hidden />
            <span>{t}</span>
          </p>
        ))}
      </div>
    ),
  },
  {
    n: '04',
    tag: 'THE AI SWARM · 25 CREDITS',
    icon: Radar,
    title: 'Or hand it to the swarm.',
    body: 'A head agent deploys nine specialists, dedupes their findings, links them into attack chains and closes the run with a 0–100 security score.',
    visual: (
      <div className="flex flex-col items-center gap-6 sm:flex-row sm:gap-8">
        <ScoreRing value={72} grade="C" size={132} />
        <div className="flex flex-wrap justify-center gap-1.5 sm:justify-start">
          {['Recon', 'Secrets', 'Headers', 'CORS', 'XSS', 'IDOR', 'Auth', 'GraphQL', 'Src Maps'].map(
            (s) => (
              <span
                key={s}
                className="rounded-lg border border-white/10 bg-ink px-2.5 py-1.5 text-[11px] font-semibold text-bone"
              >
                {s}
              </span>
            ),
          )}
        </div>
      </div>
    ),
  },
  {
    n: '05',
    tag: 'REPORTS',
    icon: FileText,
    title: 'Evidence that reads like a pro wrote it.',
    body: 'Every finding ships with CVSS v3.1, repro steps and an AI-suggested fix — labelled a suggestion, never gospel. Suspected honeypots are flagged, not reported as wins.',
    visual: (
      <div className="flex flex-wrap gap-2">
        <Chip>
          <FileText className="h-3.5 w-3.5" aria-hidden /> report.md
        </Chip>
        <Chip>
          <Braces className="h-3.5 w-3.5" aria-hidden /> report.json
        </Chip>
        <Chip>
          <FileType className="h-3.5 w-3.5" aria-hidden /> report.pdf
        </Chip>
        <Chip>
          <FileCode2 className="h-3.5 w-3.5" aria-hidden /> report.docx
        </Chip>
        <Chip data>⚑ trap flagged — verify manually</Chip>
      </div>
    ),
  },
];

/**
 * One sticky stage of the scroll tour: the card parks near the top of
 * the viewport while the next stage slides over it, and shrinks/dims
 * slightly as it gets covered — the deck-of-cards scroll feel.
 */
function ScrollStage({
  stage,
  index,
  total,
}: {
  stage: Stage;
  index: number;
  total: number;
}) {
  const reduce = useReducedMotion();
  const wrapRef = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: wrapRef,
    offset: ['start start', 'end start'],
  });
  const scale = useTransform(scrollYProgress, [0, 1], [1, 0.93]);
  const dim = useTransform(scrollYProgress, [0, 1], [1, 0.45]);
  const isLast = index === total - 1;

  const card = (
    <article className="overflow-hidden rounded-[1.75rem] border border-white/10 bg-panel shadow-[0_40px_80px_-32px_rgba(0,0,0,0.9)]">
      <div className="grid gap-0 md:grid-cols-[0.9fr_1.1fr]">
        <div className="relative p-7 sm:p-9">
          <span
            aria-hidden
            className="pointer-events-none absolute -right-2 -top-7 select-none font-display text-[7rem] font-bold leading-none text-white/[0.05]"
          >
            {stage.n}
          </span>
          <p className="relative flex items-center gap-2 font-mono text-[10px] tracking-[0.22em] text-slate2">
            <stage.icon className="h-4 w-4 text-white" aria-hidden />
            {stage.tag}
          </p>
          <h2 className="relative mt-4 font-display text-3xl font-bold leading-tight tracking-tight text-bone">
            {stage.title}
          </h2>
          <p className="relative mt-3 text-[15px] leading-relaxed text-body/85">{stage.body}</p>
          <p className="relative mt-6 font-mono text-[11px] text-slate2">
            {stage.n} / {String(total).padStart(2, '0')}
            {!isLast && ' — keep scrolling'}
          </p>
        </div>
        <div className="flex items-center border-t border-white/10 bg-ink/60 p-7 sm:p-9 md:border-l md:border-t-0">
          <div className="w-full">{stage.visual}</div>
        </div>
      </div>
    </article>
  );

  if (reduce || isLast) {
    return (
      <div className="mx-auto max-w-5xl px-4 pb-10 sm:px-6">
        <Reveal>{card}</Reveal>
      </div>
    );
  }

  return (
    <div ref={wrapRef} className="relative h-[165vh]">
      <div className="sticky top-24 px-4 sm:px-6">
        <motion.div style={{ scale, opacity: dim }} className="mx-auto max-w-5xl origin-top">
          {card}
        </motion.div>
      </div>
    </div>
  );
}

/**
 * /welcome — the third screen (after 21st.dev's @jh3yy "you can scroll"):
 * a scroll-driven tour that tells the signed-in user what BugSeek does,
 * one sticky stage at a time, ending at the download.
 */
export function Welcome() {
  const reduce = useReducedMotion();

  return (
    <div className="min-h-screen bg-ink text-body">
      <Nav home={false} signedIn />

      {/* intro */}
      <section className="relative overflow-hidden px-4 pb-14 pt-40 text-center sm:px-6 sm:pt-48">
        <div aria-hidden className="grid-bg grid-mask pointer-events-none absolute inset-0" />
        <div className="relative mx-auto max-w-3xl">
          <motion.p
            initial={reduce ? false : { opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
            className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/5 px-3.5 py-1.5 font-mono text-xs text-bone"
          >
            <span className="flex h-4 w-4 items-center justify-center rounded-full bg-white text-ink">
              <Check className="h-2.5 w-2.5" aria-hidden />
            </span>
            SIGNED IN
          </motion.p>
          <motion.h1
            initial={reduce ? false : { opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, delay: 0.08 }}
            className="mt-6 font-display text-5xl font-bold leading-[1.02] tracking-tight text-bone sm:text-6xl"
          >
            You're in.
            <br />
            <span className="text-slate2">Now, what does this thing do?</span>
          </motion.h1>
          <motion.p
            initial={reduce ? false : { opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, delay: 0.16 }}
            className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-body/85"
          >
            Five stops, one scroll. By the bottom you'll know exactly what
            you've just armed yourself with.
          </motion.p>
          <motion.div
            aria-hidden
            animate={reduce ? undefined : { y: [0, 8, 0] }}
            transition={{ duration: 1.8, repeat: Infinity, ease: 'easeInOut' }}
            className="mt-10 flex justify-center text-slate2"
          >
            <ChevronDown className="h-6 w-6" />
          </motion.div>
          <p className="mt-2 font-mono text-[10px] tracking-[0.3em] text-slate2">
            YOU CAN SCROLL
          </p>
        </div>
      </section>

      {/* the tour */}
      <main className="relative pb-6">
        {STAGES.map((s, i) => (
          <ScrollStage key={s.n} stage={s} index={i} total={STAGES.length} />
        ))}
      </main>

      {/* the drop */}
      <section className="relative px-4 pb-28 pt-8 sm:px-6">
        <Reveal className="mx-auto max-w-3xl">
          <div className="glass rounded-[2rem] p-8 text-center sm:p-10">
            <img src="/bug.svg" alt="" className="mx-auto h-16 w-16" />
            <h2 className="mt-5 font-display text-3xl font-bold tracking-tight text-bone sm:text-4xl">
              Last stop: the extension.
            </h2>
            <p className="mx-auto mt-3 max-w-md text-[15px] leading-relaxed text-body/85">
              Everything you just scrolled past lives in one Chrome popup.
              It's landing on the Chrome Web Store soon — your account is
              ready for it.
            </p>
            <div className="mt-7 flex flex-wrap items-center justify-center gap-3.5">
              <LiquidGlassButton href="/#download" size="lg">
                Coming soon to the Chrome Web Store
              </LiquidGlassButton>
              <LiquidGlassButton
                href="/"
                variant="glass"
                size="lg"
                onClick={(e) => {
                  e.preventDefault();
                  navigate('/');
                }}
              >
                Back to the homepage
              </LiquidGlassButton>
            </div>
          </div>
        </Reveal>
      </section>

      <Footer home={false} />
    </div>
  );
}

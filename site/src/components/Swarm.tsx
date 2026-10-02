import { motion, useReducedMotion } from 'framer-motion';
import {
  Cookie,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Map as MapIcon,
  Network,
  Radar,
  Shuffle,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { Reveal } from './Reveal';
import { ScoreRing } from './fx/ScoreRing';
import { springPop } from '../lib/motion';

interface Specialist {
  name: string;
  short: string;
  icon: LucideIcon;
  x: number; // % across the diagram
  y: number; // % down the diagram
}

const SPECIALISTS: Specialist[] = [
  { name: 'Recon', short: 'Recon', icon: Radar, x: 16, y: 42 },
  { name: 'Secret Hunter', short: 'Secrets', icon: KeyRound, x: 50, y: 42 },
  { name: 'Headers & Cookies', short: 'Headers', icon: Cookie, x: 84, y: 42 },
  { name: 'CORS Analyst', short: 'CORS', icon: Shuffle, x: 16, y: 68 },
  { name: 'XSS Hunter', short: 'XSS', icon: Zap, x: 50, y: 68 },
  { name: 'IDOR Hunter', short: 'IDOR', icon: Fingerprint, x: 84, y: 68 },
  { name: 'Auth Analyst', short: 'Auth', icon: LockKeyhole, x: 16, y: 94 },
  { name: 'GraphQL Prober', short: 'GraphQL', icon: Network, x: 50, y: 94 },
  { name: 'Source-Map Miner', short: 'Src Maps', icon: MapIcon, x: 84, y: 94 },
];

const HEAD = { x: 50, y: 10 };

function beamPath(x: number, y: number) {
  const midY = HEAD.y + (y - HEAD.y) * 0.55;
  return `M ${HEAD.x} ${HEAD.y + 5} C ${HEAD.x} ${midY}, ${x} ${midY}, ${x} ${y - 4}`;
}

const POINTS = [
  'Head agent plans the run and deploys whoever the target calls for',
  'Findings get deduped, scored with CVSS, and linked into attack chains',
  'Reports include AI-suggested fixes — labelled as suggestions, not gospel',
];

/**
 * The swarm, drawn: a head agent wired to nine specialists by animated
 * beams (Magic UI animated-beam treatment). Dashes flow along every wire;
 * under reduced motion the wires simply sit there, fully drawn.
 */
export function Swarm() {
  const reduce = useReducedMotion();

  return (
    <section id="swarm" className="relative scroll-mt-24 overflow-hidden border-y border-white/10 bg-panel/30 py-24 sm:py-32">
      <div aria-hidden className="grid-bg grid-mask-center pointer-events-none absolute inset-0 opacity-70" />
      <div className="relative mx-auto max-w-6xl px-4 sm:px-6">
        <Reveal className="mx-auto max-w-2xl text-center">
          <p className="font-mono text-xs tracking-[0.2em] text-mint">THE SWARM</p>
          <h2 className="mt-3 font-display text-4xl font-bold tracking-tight text-bone sm:text-5xl">
            One head agent. Nine specialists.
            <span className="text-slate2"> Zero chill.</span>
          </h2>
          <p className="mt-4 text-lg text-body/85">
            The backend swarm doesn't run a checklist — it runs a team. Each specialist
            probes its own corner of the target and reports back to the head agent.
          </p>
        </Reveal>

        <div className="mt-14 grid items-center gap-12 lg:grid-cols-[1.3fr_0.7fr]">
          {/* ——— diagram ——— */}
          <Reveal>
            <div className="relative mx-auto aspect-[4/4.4] w-full max-w-2xl sm:aspect-[16/12.5] lg:aspect-[4/3.6]">
              <svg
                viewBox="0 0 100 100"
                preserveAspectRatio="none"
                className="absolute inset-0 h-full w-full"
                aria-hidden
              >
                {SPECIALISTS.map((s) => (
                  <g key={s.name}>
                    <path
                      d={beamPath(s.x, s.y)}
                      fill="none"
                      stroke="rgba(234,246,240,0.10)"
                      strokeWidth="0.7"
                      vectorEffect="non-scaling-stroke"
                    />
                    <path
                      d={beamPath(s.x, s.y)}
                      fill="none"
                      stroke="rgba(255,255,255,0.45)"
                      strokeWidth="1.4"
                      vectorEffect="non-scaling-stroke"
                      className="beam-flow"
                    />
                  </g>
                ))}
              </svg>

              {/* head agent */}
              <motion.div
                initial={reduce ? false : { opacity: 0, scale: 0.8 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true, margin: '-60px' }}
                transition={springPop}
                className="absolute z-10 -translate-x-1/2 -translate-y-1/2"
                style={{ left: `${HEAD.x}%`, top: `${HEAD.y}%` }}
              >
                <div className="flex items-center gap-2 rounded-2xl bg-mint px-4 py-2.5 font-display text-sm font-bold text-ink shadow-[0_16px_40px_-10px_rgba(255,255,255,0.35)]">
                  <img src="/bug.svg" alt="" className="h-5 w-5" />
                  HEAD AGENT
                </div>
              </motion.div>

              {/* specialists */}
              {SPECIALISTS.map((s, i) => (
                <motion.div
                  key={s.name}
                  initial={reduce ? false : { opacity: 0, scale: 0.75, y: 8 }}
                  whileInView={{ opacity: 1, scale: 1, y: 0 }}
                  viewport={{ once: true, margin: '-60px' }}
                  transition={{ ...springPop, delay: 0.15 + i * 0.07 }}
                  className="absolute z-10 -translate-x-1/2 -translate-y-1/2"
                  style={{ left: `${s.x}%`, top: `${s.y}%` }}
                >
                  <div className="flex items-center gap-1.5 whitespace-nowrap rounded-xl border border-white/15 bg-ink px-2.5 py-1.5 text-[11px] font-semibold text-bone shadow-lg sm:gap-2 sm:px-3 sm:py-2 sm:text-xs">
                    <s.icon className="h-3.5 w-3.5 shrink-0 text-mint" aria-hidden />
                    <span className="sm:hidden">{s.short}</span>
                    <span className="hidden sm:inline">{s.name}</span>
                  </div>
                </motion.div>
              ))}
            </div>
          </Reveal>

          {/* ——— score + how a run lands ——— */}
          <Reveal delay={0.1}>
            <div className="flex flex-col items-center gap-7 lg:items-start">
              <ScoreRing value={72} grade="C" caption="ILLUSTRATIVE — YOUR TARGET EARNS ITS OWN" />
              <div>
                <h3 className="text-center font-display text-2xl font-semibold text-bone lg:text-left">
                  Every run ends with a score.
                </h3>
                <ul className="mt-4 space-y-3">
                  {POINTS.map((p) => (
                    <li key={p} className="flex gap-2.5 text-sm leading-relaxed text-body/85">
                      <span className="mt-0.5 shrink-0 text-mint">▸</span>
                      <span>{p}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-5 font-mono text-xs text-slate2">
                  25 credits a run · suspected honeypots never drag the score down
                </p>
              </div>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}

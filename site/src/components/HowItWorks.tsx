import { Reveal } from './Reveal';

const STEPS = [
  {
    n: '1',
    title: 'Install',
    body: "Add it to Chrome. Thirty seconds, no account needed to start poking around.",
    code: 'chrome web store → add → pin it',
  },
  {
    n: '2',
    title: 'Scan',
    body: "Open a target you're allowed to test and hit “Scan this page”. Passive recon runs right in the popup.",
    code: '1 click · 1 credit · 0 probes fired',
  },
  {
    n: '3',
    title: 'Authorize',
    body: 'Want active tests? Confirm your authorization — bounty program, pentest contract, or ownership — and set the scope. Nothing fires without it.',
    code: 'scope-checked · rate-limited · non-destructive',
  },
  {
    n: '4',
    title: 'Report',
    body: 'One click exports a Markdown report with CVSS scores and repro steps. Paste it into HackerOne and look like a pro.',
    code: 'markdown · json · pdf · docx',
  },
];

export function HowItWorks() {
  return (
    <section id="how" className="scroll-mt-24 border-y border-white/10 bg-panel/30 py-24 sm:py-32">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <Reveal>
          <p className="font-mono text-xs tracking-[0.2em] text-mint">THE MANUAL (SHORT)</p>
          <h2 className="mt-3 font-display text-4xl font-bold tracking-tight text-bone sm:text-5xl">
            Zero to report in four steps.
          </h2>
          <p className="mt-4 max-w-2xl text-lg text-body/85">
            That's the whole learning curve. If you can browse, you can hunt.
          </p>
        </Reveal>

        <ol className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {STEPS.map((s, i) => (
            <Reveal key={s.n} delay={i * 0.08} className="h-full">
              <li className="flex h-full flex-col rounded-3xl border border-white/10 bg-ink p-6">
                <span className="font-display text-5xl font-bold text-mint/25">{s.n}</span>
                <h3 className="mt-4 font-display text-xl font-semibold text-bone">{s.title}</h3>
                <p className="mt-2 flex-1 text-sm leading-relaxed text-body/85">{s.body}</p>
                <p className="mt-5 rounded-lg bg-white/5 px-3 py-2 font-mono text-[11px] text-mintlight/90">
                  {s.code}
                </p>
              </li>
            </Reveal>
          ))}
        </ol>

        <Reveal delay={0.1}>
          <div className="mt-10 flex items-start gap-4 rounded-2xl border border-amber2/25 bg-amber2/10 p-5">
            <span aria-hidden className="text-2xl leading-none">⚑</span>
            <p className="text-sm leading-relaxed text-body/90">
              <span className="font-semibold text-amber2">It'll also save you from yourself.</span>{' '}
              If something looks like a honeypot — say, /admin accepting admin:admin on the
              first try — BugSeek flags it as a possible trap instead of letting you
              report a canary and embarrass yourself. You're welcome.
            </p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

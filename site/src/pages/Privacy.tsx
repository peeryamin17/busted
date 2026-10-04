import { Nav } from '../components/Nav';
import { Footer } from '../components/Footer';
import { Reveal } from '../components/Reveal';
import { SonarGrid } from '../components/fx/SonarGrid';

/**
 * Privacy — the public summary page. This is the short version, written to
 * be read. The full policy (every category, purpose, retention period and
 * right) is a plain page at /privacy-policy.html, mirrored from
 * docs/privacy-policy.md; keep all three in step when any changes.
 */

function Section({ kicker, title, children }: { kicker: string; title: string; children: React.ReactNode }) {
  return (
    <Reveal>
      <section className="mt-14">
        <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">{kicker}</p>
        <h2 className="mt-2 font-display text-2xl font-bold tracking-tight text-bone">{title}</h2>
        <div className="mt-4 space-y-4 leading-relaxed text-body/85">{children}</div>
      </section>
    </Reveal>
  );
}

function FullPolicyCard() {
  return (
    <Reveal>
      <div className="mt-14 rounded-3xl border border-white/10 bg-white/5 px-6 py-7 sm:px-8">
        <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">THE WHOLE THING</p>
        <h2 className="mt-2 font-display text-2xl font-bold tracking-tight text-bone">
          This page is the summary.
        </h2>
        <p className="mt-3 max-w-2xl leading-relaxed text-body/85">
          The full privacy policy — every category of data, what it is for, how long we keep it
          and the rights you have over it — is written out on one plain page. No summaries of
          summaries.
        </p>
        <a
          href="/privacy-policy.html"
          target="_blank"
          rel="noreferrer"
          className="mt-5 inline-flex items-center gap-2 rounded-full bg-bone px-6 py-3 font-display text-sm font-bold tracking-tight text-ink transition-transform duration-300 hover:scale-[1.03]"
        >
          Read the full privacy policy
          <span aria-hidden="true">→</span>
        </a>
      </div>
    </Reveal>
  );
}

export function Privacy() {
  return (
    <div className="min-h-screen bg-ink text-body">
      <SonarGrid />
      <Nav />
      <main className="relative z-10 mx-auto max-w-4xl px-4 pb-24 pt-28 sm:px-6 sm:pt-32">
        <Reveal>
          <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">PRIVACY POLICY — SUMMARY</p>
          <h1 className="mt-3 font-display text-4xl font-bold tracking-tight text-bone sm:text-5xl">
            What we keep, and what we never touch.
          </h1>
          <p className="mt-4 max-w-2xl leading-relaxed text-body/85">
            BugSeek AI is a security-checking tool — a browser extension, a members' website and
            the service behind them. It helps people check websites they own or are authorised
            to test, and it can warn you when an address looks like a phishing trap. This page
            is the summary; the full policy is one click below.
          </p>
          <p className="mt-4 font-mono text-xs text-slate2">
            EFFECTIVE 4 OCTOBER 2026 · OPERATED BY PEER, THE MAKER OF BUGSEEK AI · PRIVACY
            QUESTIONS: TEMPOACER67@GMAIL.COM
          </p>
          <p className="mt-6 rounded-2xl border border-white/10 bg-white/5 px-5 py-4 text-sm leading-relaxed">
            The short version: no advertising, no analytics trackers, no data brokerage. We never
            sell personal data.
          </p>
          <p className="mt-4 max-w-2xl leading-relaxed text-body/85">
            BugSeek AI&rsquo;s use of information received from Google APIs adheres to the Chrome
            Web Store User Data Policy, including the Limited Use requirements.
          </p>
        </Reveal>

        <FullPolicyCard />

        <Section kicker="01" title="What we collect, in one breath">
          <ul className="list-disc space-y-2 pl-6">
            <li>
              <strong className="text-bone">Waitlist:</strong> your email address, only to tell
              you when BugSeek launches.
            </li>
            <li>
              <strong className="text-bone">Sign-in:</strong> through Google only — your name,
              email, profile picture address and Google's account identifier, plus sign-in times.
              Session tokens are stored as cryptographic hashes, never readable.
            </li>
            <li>
              <strong className="text-bone">Web patrols:</strong> the address you asked us to
              patrol, your authorisation tick, the findings and the site information gathered —
              plus your IP address and the coarse location it implies. Your device's GPS
              position is added <strong className="text-bone">only if you allow the browser's location prompt</strong>;
              decline and everything works the same without it.
            </li>
            <li>
              <strong className="text-bone">The extension:</strong> standard checks run on your
              device and stay in local browser storage. Deeper scans send the material needed
              for the analysis to our backend over an encrypted connection — and the extension
              asks for your agreement before the first collection, and again before the first
              backend run.
            </li>
          </ul>
        </Section>

        <Section kicker="02" title="What we never store">
          <ul className="list-disc space-y-2 pl-6">
            <li>Secret values. An exposed secrets file is recorded as variable <em>names</em>, and secrets found in code as pattern <em>types</em> — never the values.</li>
            <li>Cookie values, passwords, or personal data belonging to a patrolled site's visitors. We describe weaknesses; we don't harvest what they might expose.</li>
            <li>Your GPS position without your permission.</li>
          </ul>
        </Section>

        <Section kicker="03" title="Cookies">
          <p>
            Two, both strictly necessary for sign-in: one keeps your session, one protects the
            Google sign-in round-trip. There are no advertising or optional cookies, so there
            is no consent banner — the full list, with lifetimes, is in the policy.
          </p>
        </Section>

        <Section kicker="04" title="Who else touches the data">
          <p>
            A small set of providers, each with one job: an identity provider for sign-in, an AI
            service that helps analyse scan material, cloud hosting for the site, service and
            database, geolocation services for coarse places, and domain and DNS data services
            for facts about patrolled sites. Public phishing blocklists are downloaded and
            compared on our own server — the address you patrol is never sent to them. Apart
            from these, data is disclosed only if the law requires it.
          </p>
        </Section>

        <Section kicker="05" title="AI processing">
          <p>
            Scan material sent to our backend may be passed to third-party AI models to analyse
            and explain findings. We do not train our own models on your scans, findings or
            history, and we never sell or share them for advertising.
          </p>
        </Section>

        <Section kicker="06" title="Keeping it, deleting it, your rights">
          <p>
            Account data and your runs are kept while your account exists; waitlist emails until
            launch mailings are done. Everything travels over TLS, and tokens and keys are
            stored as hashes. Email the privacy contact above to see, correct, delete or export
            your data — a real person handles it, normally within 30 days. If a breach ever
            exposes personal data, affected users are told promptly. BugSeek is not directed at
            children, and if what we collect ever changes, this page and the policy change
            first, with signed-in users told before material changes take effect.
          </p>
        </Section>

        <FullPolicyCard />
      </main>
      <Footer home={false} />
    </div>
  );
}

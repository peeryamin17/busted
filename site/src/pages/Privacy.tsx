import { Nav } from '../components/Nav';
import { Footer } from '../components/Footer';
import { Reveal } from '../components/Reveal';
import { SonarGrid } from '../components/fx/SonarGrid';

/**
 * Privacy policy — the public page. Text mirrors docs/privacy-policy.md;
 * keep the two in step when either changes.
 */

const COOKIES: Array<{ name: string; does: string; type: string; life: string }> = [
  {
    name: 'bs_session',
    does: 'Keeps you signed in',
    type: 'Strictly necessary · first-party · httpOnly',
    life: '30 days; also ends after 5 minutes of inactivity or when you sign in elsewhere',
  },
  {
    name: 'bs_oauth_state',
    does: 'Protects the Google sign-in round-trip against forgery',
    type: 'Strictly necessary · first-party · httpOnly',
    life: '10 minutes',
  },
];

const PROCESSORS: Array<{ who: string; job: string; gets: string }> = [
  { who: 'Google', job: 'Sign-in; AI analysis (Gemini); optionally phishing checks (Safe Browsing)', gets: 'Your Google identity at sign-in; scan context you send for analysis; addresses being trust-checked (when Safe Browsing is enabled)' },
  { who: 'Neon', job: 'Database hosting', gets: 'Account and patrol data, at rest' },
  { who: 'Render', job: 'Backend hosting', gets: 'Data passing through the API' },
  { who: 'Vercel', job: 'Website hosting', gets: 'Page requests' },
  { who: 'ipwho.is', job: 'Turns an IP address into a coarse location', gets: "The requester's IP address" },
  { who: 'BigDataCloud', job: 'Turns GPS coordinates into a place name', gets: 'Coordinates, only when you shared your location' },
  { who: 'rdap.org / Cloudflare', job: 'Domain and DNS lookups about patrolled sites', gets: 'The patrolled domain — nothing about you' },
];

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

export function Privacy() {
  return (
    <div className="min-h-screen bg-ink text-body">
      <SonarGrid />
      <Nav />
      <main className="relative z-10 mx-auto max-w-4xl px-4 pb-24 pt-28 sm:px-6 sm:pt-32">
        <Reveal>
          <p className="font-mono text-[11px] tracking-[0.24em] text-slate2">PRIVACY POLICY</p>
          <h1 className="mt-3 font-display text-4xl font-bold tracking-tight text-bone sm:text-5xl">
            What we keep, and what we never touch.
          </h1>
          <p className="mt-4 max-w-2xl leading-relaxed text-body/85">
            BugSeek AI is a Chrome extension, a backend API and this website. It helps people check
            websites they own or are authorised to test, and it can tell you whether an address
            looks like a phishing trap. This page covers all of it.
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

        <Section kicker="01" title="When you join the waitlist">
          <p>
            We store your email address and which page you signed up from. One purpose only:
            telling you when BugSeek launches. Nothing else is attached to it.
          </p>
        </Section>

        <Section kicker="02" title="When you sign in">
          <p>
            Sign-in is through Google only — BugSeek has no password of its own for you. From
            Google we receive and store your name, your email address, your profile picture
            address, and Google's identifier for your account, plus when you last signed in and
            when your account was created.
          </p>
          <p>
            We store a session record so the site recognises you. Only a cryptographic hash of
            your session token is stored — never the token itself. Sessions end after 30 days,
            after 5 minutes of inactivity, or when you sign in again (a new sign-in signs out
            your other sessions).
          </p>
          <div className="overflow-x-auto rounded-2xl border border-white/10">
            <table className="w-full min-w-[560px] text-left text-sm">
              <thead>
                <tr className="border-b border-white/10 font-mono text-[11px] tracking-[0.18em] text-slate2">
                  <th className="px-4 py-3 font-medium">COOKIE</th>
                  <th className="px-4 py-3 font-medium">WHAT IT DOES</th>
                  <th className="px-4 py-3 font-medium">TYPE</th>
                  <th className="px-4 py-3 font-medium">LIFETIME</th>
                </tr>
              </thead>
              <tbody>
                {COOKIES.map((c) => (
                  <tr key={c.name} className="border-b border-white/5 last:border-0">
                    <td className="px-4 py-3 font-mono text-bone">{c.name}</td>
                    <td className="px-4 py-3">{c.does}</td>
                    <td className="px-4 py-3">{c.type}</td>
                    <td className="px-4 py-3">{c.life}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p>
            That is the complete list. Both cookies are strictly necessary for sign-in to work,
            so BugSeek shows no cookie consent banner — there are no optional cookies to consent
            to. If optional cookies are ever added, this page names them first and consent is
            asked before they are set. The site also keeps one sessionStorage entry (not a
            cookie) so the intro animation plays once per visit; it holds no personal data and
            vanishes when the tab closes.
          </p>
        </Section>

        <Section kicker="03" title="When you run a web patrol">
          <p>For each patrol, we store:</p>
          <ul className="list-disc space-y-2 pl-6">
            <li>
              The address you asked us to patrol, the fact that you ticked the authorisation box,
              the date and time, the findings and scores, and the website information gathered
              (performance timings, server location, domain registration details, DNS records).
            </li>
            <li>
              Your IP address and the coarse location it implies (city, region, country). This is
              automatic, and the patrol form tells you before you run.
            </li>
            <li>
              Your device's GPS position — <strong className="text-bone">only if you allow the browser's location prompt</strong>:
              the coordinates, their accuracy, and the place they correspond to. Decline, and we
              record the IP-based location alone; the patrol runs exactly the same.
            </li>
            <li>How many patrols you have run, so plan limits can be applied.</li>
          </ul>
          <p>Your patrol history is private to your account. There is no public listing of it.</p>
        </Section>

        <Section kicker="04" title="When you use the extension and the AI swarm">
          <p>
            Passive checks run on your device. Results, your per-site authorisation records and
            your API key are stored in your browser's local extension storage and stay there
            unless you send a scan to the backend. If you run an AI swarm scan or an engine scan,
            the page context needed for the analysis (target address, page content, headers and
            similar technical material) is sent to our backend over an encrypted connection, and
            the scan, its findings and its credit cost are stored against your account.
          </p>
          <p>
            API keys are stored only as a cryptographic hash plus a short visible prefix, so a
            key can be recognised and revoked but never read back.
          </p>
        </Section>

        <Section kicker="05" title="What we deliberately never store">
          <ul className="list-disc space-y-2 pl-6">
            <li>
              The contents of secret files. An exposed <span className="font-mono text-bone">.env</span> is
              recorded as variable <em>names</em>, never values.
            </li>
            <li>Secret values found in JavaScript — only the type of pattern, never the value.</li>
            <li>
              Cookie values, passwords, or personal data belonging to a patrolled site's
              visitors. Our checks describe weaknesses; they do not harvest what those
              weaknesses might expose.
            </li>
            <li>Your GPS position without your permission.</li>
          </ul>
        </Section>

        <Section kicker="06" title="Who else touches the data">
          <div className="overflow-x-auto rounded-2xl border border-white/10">
            <table className="w-full min-w-[560px] text-left text-sm">
              <thead>
                <tr className="border-b border-white/10 font-mono text-[11px] tracking-[0.18em] text-slate2">
                  <th className="px-4 py-3 font-medium">SERVICE</th>
                  <th className="px-4 py-3 font-medium">ITS JOB</th>
                  <th className="px-4 py-3 font-medium">WHAT IT RECEIVES</th>
                </tr>
              </thead>
              <tbody>
                {PROCESSORS.map((p) => (
                  <tr key={p.who} className="border-b border-white/5 last:border-0">
                    <td className="px-4 py-3 font-medium text-bone">{p.who}</td>
                    <td className="px-4 py-3">{p.job}</td>
                    <td className="px-4 py-3">{p.gets}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p>
            Public phishing feeds (URLhaus and OpenPhish) are downloaded by our server and
            compared on our side; the address you patrol is not sent to them. Apart from these
            processors, we disclose data only if the law requires it.
          </p>
        </Section>

        <Section kicker="07" title="AI processing">
          <p>
            Scan context sent to our backend may be passed to Google's Gemini models to analyse
            and explain findings. We do not use your scans, findings or patrol history to train
            our own models, and we do not sell or share them for advertising.
          </p>
        </Section>

        <Section kicker="08" title="How long we keep things">
          <ul className="list-disc space-y-2 pl-6">
            <li>Account data and your runs: while your account exists.</li>
            <li>Session records: until they expire or are replaced, as described above.</li>
            <li>Waitlist emails: until launch mailings are done and any unsubscribe is honoured.</li>
            <li>
              If you ask us to delete your account, we delete the account and the runs, findings
              and keys attached to it. Aggregated, de-identified counts may survive, because
              they no longer point at you.
            </li>
          </ul>
        </Section>

        <Section kicker="09" title="Security">
          <p>
            All traffic uses TLS encryption. Session tokens and API keys are stored as
            cryptographic hashes, never in readable form. Access to account data is limited to
            the account it belongs to. No system is perfectly secure — if a breach ever exposes
            personal data, we will tell affected users promptly, as the law requires.
          </p>
        </Section>

        <Section kicker="10" title="Your rights">
          <p>
            Email the privacy contact above to see the personal data we hold about you, correct
            it, delete it (account and everything attached), or export your patrol history.
            There is no self-service button yet; a real person handles requests, normally within
            30 days. Depending on where you live (for example the EU/UK GDPR or India's DPDP
            Act), you may have additional rights, including complaining to your local
            data-protection authority.
          </p>
        </Section>

        <Section kicker="11" title="Children and changes">
          <p>
            BugSeek is a security-testing tool for people who own or are authorised to test
            websites. It is not directed at children, and you must be old enough in your country
            to agree to these terms to use it.
          </p>
          <p>
            If we change what we collect or who receives it, we will update this page, change the
            effective date, and — for material changes — tell signed-in users on the site before
            the change takes effect.
          </p>
        </Section>
      </main>
      <Footer home={false} />
    </div>
  );
}

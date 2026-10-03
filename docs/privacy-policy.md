# BugSeek AI — Privacy Policy

> **DRAFT — NOT LEGAL ADVICE. Requires review by a qualified lawyer before any public use, store listing, or paid launch.** This draft describes what the product actually does today, verified against the codebase. Bracketed items are for the operator to complete.

**Effective date:** [TO BE SET — do not publish without one]
**Operator:** [Legal entity / individual name, address — TO BE FILLED]
**Privacy contact:** [TO BE SET — an email you control and read]

---

## 1. What BugSeek AI is

BugSeek AI ("the Service", "we") is a Chrome extension, a companion backend API, and a website with a members' area. It helps people check websites they own or are authorised to test for security weaknesses, and it can tell you whether an address looks like a phishing trap. This policy covers the website, the web-based patrol (website checker), the extension, and the backend behind them.

BugSeek has no advertising, no analytics trackers, and no data brokerage. We never sell personal data.

## 2. What we collect, and why

### 2.1 When you join the waitlist
- **Your email address**, and where the signup came from (which page or form).
- Used for one purpose: telling you when BugSeek launches. Nothing else is attached to it.

### 2.2 When you sign in
Sign-in is through Google only — BugSeek has no password of its own for you.
- From Google we receive and store: **your name, your email address, your profile picture address (URL), and Google's identifier for your account**, plus **when you last signed in** and **when your account was created**.
- We store a **session record** so the site recognises you. Only a cryptographic hash of your session token is stored — never the token itself. Sessions end after 30 days, after 5 minutes of inactivity, or when you sign in again (a new sign-in signs out your other sessions). The account used to administer BugSeek is exempt from the inactivity and single-session rules.
- We use two strictly necessary cookies: one for your session, one short-lived cookie that protects the Google sign-in round-trip. No third-party or advertising cookies are set.

**Our complete cookie list** — this is every cookie BugSeek sets, gathered from the code:

| Cookie | What it does | Type | Lifetime |
|---|---|---|---|
| `bs_session` | Keeps you signed in | Strictly necessary (first-party, httpOnly) | 30 days; also ends after 5 minutes of inactivity or when you sign in elsewhere |
| `bs_oauth_state` | Protects the Google sign-in round-trip against forgery | Strictly necessary (first-party, httpOnly) | 10 minutes |

Because both cookies are strictly necessary for sign-in to work at all, BugSeek does not show a cookie consent banner — there are no optional cookies to consent to. If optional cookies are ever added, this policy will name them first, and consent will be asked before they are set. The site also uses one `sessionStorage` entry (not a cookie) so the intro animation plays once per visit; it holds no personal data and vanishes when the tab closes.

### 2.3 When you run a web patrol (the website checker)
For each patrol you run, we store:
- **The address you asked us to patrol**, the fact that you ticked the authorisation box, the date and time, the findings, the scores, and the website information the patrol gathered (performance timings, server location, domain registration details, DNS records).
- **Your IP address** and the coarse location it implies (city, region, country). This is automatic, and the patrol form tells you before you run.
- **Your device's GPS position — only if you allow the browser's location prompt** shown when you start a patrol: the coordinates, how accurate they are, and the city, region and country they correspond to. If you decline, or your browser cannot share a position, we record the IP-based location alone and the patrol runs exactly the same.
- How many patrols you have run, so plan limits can be applied.

Your patrol history is private to your account. Nobody else can see your runs, and there is no public listing of them.

### 2.4 When you use the extension and the AI swarm
- **Passive checks run on your device.** Results, your per-site authorisation records, and your API key are stored in your browser's local extension storage and stay there unless you send a scan to the backend.
- If you run an AI swarm scan or an engine scan, the **page context needed for the analysis** (the target address, page content, headers and similar technical material) is sent to our backend over an encrypted connection, and the scan, its findings and its credit cost are stored against your account.
- **API keys** for the extension are stored only as a cryptographic hash plus a short visible prefix, so a key can be recognised and revoked but never read back.

### 2.5 What we deliberately never store
- The **contents of secret files**. If a patrol finds an exposed `.env` file, we record the *names* of the variables, never their values.
- **Secret values found in JavaScript** — only the *type* of pattern (for example, "looks like an AWS key"), never the value itself.
- **Cookie values, passwords, or personal data belonging to a patrolled site's visitors.** Our checks describe weaknesses; they do not harvest the data those weaknesses might expose.
- Your GPS position without your permission (see 2.3).

## 3. Who else touches the data

We use a small number of processors, each for one job:

| Service | What it does for us | What it receives |
|---|---|---|
| Google | Sign-in; AI analysis (Gemini); optionally, phishing checks (Safe Browsing) | Your Google identity at sign-in; scan context you send for analysis; addresses being trust-checked (when Safe Browsing is enabled) |
| Neon | Our database hosting | Everything in section 2, at rest |
| Render | Our backend hosting | Data passing through the API |
| Vercel | Our website hosting | Page requests |
| ipwho.is | Turns an IP address into a coarse location | The requester's IP address |
| BigDataCloud | Turns GPS coordinates into a place name | Coordinates, only when you shared your location |
| rdap.org / Cloudflare | Domain registration and DNS lookups about **patrolled sites** | The patrolled domain — nothing about you |

Public phishing feeds (URLhaus and OpenPhish) are downloaded by our server and compared on our side; the address you patrol is not sent to them.

Apart from these processors, we disclose data only if the law requires it.

## 4. AI processing

Scan context sent to our backend may be passed to Google's Gemini models to analyse and explain findings. We do not use your scans, findings, or patrol history to train our own models, and we do not sell or share them for advertising.

## 5. How long we keep things

- **Account data and your runs** are kept while your account exists, so your history, limits and vault work as described.
- **Session records** expire as described in 2.2 and are removed when they lapse or are replaced.
- **Waitlist emails** are kept until launch mailings are done and any unsubscribe is honoured.
- If you ask us to delete your account, we delete the account and the runs, findings and keys attached to it. Aggregated, de-identified counts (for example, "patrols run this month") may survive deletion because they no longer point at you.

## 6. Security

- All traffic between you, the website, the extension and the backend uses TLS encryption.
- Session tokens and API keys are stored as cryptographic hashes, never in readable form.
- Access to account data is limited to the account it belongs to; administrative access is limited to the operator's account.

No system is perfectly secure, and we cannot guarantee absolute security — but we will tell affected users promptly if a breach exposes their personal data, as the law requires.

## 7. Your rights

You can ask us, via the privacy contact above, to:
- show you the personal data we hold about you,
- correct it,
- delete it (your account and everything attached to it),
- export your patrol history.

There is no self-service button for this yet; a real person (the operator) handles requests, normally within 30 days. Depending on where you live (for example the EU/UK GDPR or India's DPDP Act), you may have additional rights, including complaining to your local data-protection authority.

## 8. Children

BugSeek is a security-testing tool for people who own or are authorised to test websites. It is not directed at children, and you must be old enough in your country to enter into these terms to use it.

## 9. Changes to this policy

If we change what we collect or who receives it, we will update this page, change the effective date, and — for material changes — tell signed-in users on the site before the change takes effect. The version history lives with this document.

---

*A full legal review is required before launch. Companion document: `terms-of-service.md`.*

# BugSeek AI — Privacy Policy

**Effective date:** 4 October 2026
**Operator:** Peer, the maker of BugSeek AI
**Privacy contact:** tempoacer67@gmail.com

---

## 1. What BugSeek AI is

BugSeek AI ("the Service", "we") is a security-checking tool: a browser extension, a members' website, and the service behind them. It helps people check websites they own or are authorised to test for security weaknesses, and it can warn you when an address looks like a phishing trap. This policy covers the website, the web-based patrol (website checker), the extension, and the backend behind them.

BugSeek has no advertising, no analytics trackers, and no data brokerage. We never sell personal data.

BugSeek AI's use of information received from Google APIs will adhere to the Chrome Web Store User Data Policy, including the Limited Use requirements.

## 2. What we collect, and why

### 2.1 When you join the waitlist
- **Your email address**, and where the signup came from (which page or form).
- Used for one purpose: telling you when BugSeek launches. Nothing else is attached to it.

### 2.2 When you sign in
Sign-in is through Google only — BugSeek has no password of its own for you.
- From Google we receive and store: **your name, your email address, your profile picture address (URL), and Google's identifier for your account**, plus **when you last signed in** and **when your account was created**.
- We store a **session record** so the site recognises you. Only a cryptographic hash of your session token is stored — never the token itself. Sessions end after 30 days, after a short period of inactivity, or when you sign in again (a new sign-in signs out your other sessions).
- We use two strictly necessary cookies: one for your session, one short-lived cookie that protects the Google sign-in round-trip. No third-party or advertising cookies are set.

**Our complete cookie list** — this is every cookie BugSeek sets:

| Cookie | What it does | Type | Lifetime |
|---|---|---|---|
| `bs_session` | Keeps you signed in | Strictly necessary (first-party, httpOnly) | 30 days; also ends after a short period of inactivity or when you sign in elsewhere |
| `bs_oauth_state` | Protects the Google sign-in round-trip against forgery | Strictly necessary (first-party, httpOnly) | 10 minutes |

Because both cookies are strictly necessary for sign-in to work at all, BugSeek does not show a cookie consent banner — there are no optional cookies to consent to. If optional cookies are ever added, this policy will name them first, and consent will be asked before they are set. The site also uses one `sessionStorage` entry (not a cookie) so the intro animation plays once per visit; it holds no personal data and vanishes when the tab closes.

### 2.3 When you run a web patrol (the website checker)
For each patrol you run, we store:
- **The address you asked us to patrol**, the fact that you ticked the authorisation box, the date and time, the findings, the scores, and the website information the patrol gathered (performance timings, server location, domain registration details, DNS records).
- **Your IP address** and the coarse location it implies (city, region, country). This is automatic, and the patrol form tells you before you run.
- **Your device's GPS position — only if you allow the browser's location prompt** shown when you start a patrol: the coordinates, how accurate they are, and the city, region and country they correspond to. If you decline, or your browser cannot share a position, we record the IP-based location alone and the patrol runs exactly the same.
- How many patrols you have run, so plan limits can be applied.

Your patrol history is private to your account. Nobody else can see your runs, and there is no public listing of them.

### 2.4 When you use the extension and its deeper scans
- **Standard checks run on your device.** Results, your per-site authorisation records, and your API key are stored in your browser's local extension storage and stay there unless you send a scan to the backend. Before the extension collects anything, it shows you a short disclosure and waits for your agreement; the same happens again before the first backend run.
- If you run a deeper scan that uses our backend, the **material needed for the analysis** (the target address, page content, response headers and similar technical material) is sent to our backend over an encrypted connection, and the scan, its findings and its credit cost are stored against your account.
- **API keys** for the extension are stored only as a cryptographic hash plus a short visible prefix, so a key can be recognised and revoked but never read back.
- **Linking the extension to your account.** The website can generate a one-time link code for you to type into the extension, or — on your click — hand it a key automatically. A link code is exchanged once for an API key and is never stored by the extension; on our side, link codes are kept only as cryptographic hashes, expire after ten minutes, and generating a new one deletes unused older ones. The scans you send are shown back to you in your account home ("My reports").

### 2.5 What we deliberately never store
- The **contents of secret files**. If a patrol finds an exposed `.env` file, we record the *names* of the variables, never their values.
- **Secret values found in code** — only the *type* of pattern (for example, "looks like a cloud access key"), never the value itself.
- **Cookie values, passwords, or personal data belonging to a patrolled site's visitors.** Our checks describe weaknesses; they do not harvest the data those weaknesses might expose.
- Your GPS position without your permission (see 2.3).

## 3. Who else touches the data

We use a small number of service providers, each for one job:

| Provider type | What it does for us | What it receives |
|---|---|---|
| Identity provider (Google) | Sign-in | Your Google identity at sign-in |
| AI service provider | Analyses scan material and helps explain findings | Scan material you send for analysis |
| Cloud hosting providers | Host the website, the application and the database | Page requests; data passing through the service; account and patrol data at rest |
| Geolocation services | Turn an IP address — or, when you share it, GPS coordinates — into a coarse place | The requester's IP address; coordinates only when you shared your location |
| Domain and DNS data services | Registration and DNS lookups about **patrolled sites** | The patrolled domain — nothing about you |
| Public threat-intelligence feeds | Tell us whether an address is a known phishing or malware trap | Downloaded and compared on our server; the address you patrol is not sent to them |

Apart from these providers, we disclose data only if the law requires it.

## 4. AI processing

Scan material sent to our backend may be passed to third-party AI models to analyse and explain findings. We do not use your scans, findings, or patrol history to train our own models, and we do not sell or share them for advertising.

## 5. How long we keep things

- **Account data and your runs** are kept while your account exists, so your history, limits and vault work as described.
- **Session records** expire as described in 2.2 and are removed when they lapse or are replaced.
- **Link codes** expire after ten minutes and can each be used once; unused ones are deleted when a fresh code is generated.
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

*Companion document: `terms-of-service.md`.*

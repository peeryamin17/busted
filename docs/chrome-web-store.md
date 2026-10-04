# BugSeek AI — Chrome Web Store submission packet

Everything the store asks for, drafted ready to paste. The operator-side steps (developer account, trader declaration, screenshots, final submit) are marked **[you]**; everything else is done or written here.

Live policy URLs:
- Summary: https://bugseek-ai.vercel.app/privacy
- Full policy (use this as the store's privacy policy URL): https://bugseek-ai.vercel.app/privacy-policy.html

---

## 1. Listing copy

**Name:** BugSeek AI

**Short description (manifest + store summary, ≤132 chars):**
> Security recon for sites you own or may test: passive checks on your device, deeper AI scans when you ask.

**Category:** Developer Tools

**Detailed description:**

> BugSeek AI is a security reconnaissance companion for people who test websites they own or are allowed to test — bug bounty hunters, developers, and site owners.
>
> Open the popup on any page and BugSeek reads what the page is made of: content and scripts, cookies, response headers, source maps, storage inventories, payment-gateway fingerprints and the third-party services the page talks to. Standard checks run entirely on your device and the results stay in your browser.
>
> When you want to go further, you can send the target to the BugSeek backend for a deeper scan — an AI swarm of specialist agents, and open-source scanning engines — over an encrypted connection, against your account. Active testing that sends real requests to a target stays locked behind an explicit authorisation form and strict request throttling, and only ever runs when you say so.
>
> Before the extension collects anything it shows you a short disclosure of exactly what it reads and waits for your agreement — and asks again before the first backend run.
>
> BugSeek never records secret values: exposed secret files are reported by variable name, secrets in code by pattern type, and cookie values are never captured.

**Single purpose (dashboard):**
> Security reconnaissance and authorised security testing of websites the user owns or has permission to test.

---

## 2. Permission justifications (paste-ready)

**`cookies`**
> BugSeek audits the security attributes of the cookies a page sets (flags such as Secure, HttpOnly and SameSite, lifetimes, and session carriers) as part of its passive security checks. Cookie values are never read into reports or transmitted; only attributes and names are analysed, and results stay in local browser storage.

**`storage`**
> Scan results, per-site authorisation records, the user's disclosure-consent records, and an optional backend API key are stored in the browser's local extension storage so they persist between popup opens. Nothing in storage is transmitted except when the user explicitly runs a backend scan.

**`webRequest`**
> Used read-only to observe the main frame's response headers (for example Content-Security-Policy and Strict-Transport-Security) so the header checks can run without sending any additional requests of its own.

**`activeTab`**
> Grants access to the page the user is currently viewing only when the user opens the popup and starts a scan, so passive checks can read that page's content, scripts and storage inventories.

**`declarativeNetRequest`**
> Used by the CORS checker during user-initiated active scans: temporary session rules set a request header needed to test how the authorised target answers cross-origin requests. Rules are scoped to that target and removed after each test.

**Host permission `<all_urls>`**
> BugSeek's purpose is to check the security posture of whichever website the user is currently visiting and chooses to scan; the user supplies the target by navigating to it. The extension performs no background browsing monitoring: content access happens only on pages the user opens the popup on and scans.

**`debugger`**
> Required for Deep inspect, an explicit opt-in inside user-initiated active scans. Chrome does not offer `debugger` as an optional permission, so it is declared as a regular permission; it is only ever attached while a Deep inspect scan the user started is running, captures request/response bodies for the authorised target during that scan only (bodies stay in memory and are dropped when the scan ends), and Chrome shows its own debugging banner while attached.

**Content script on `<all_urls>`**
> Reads the page's DOM and script inventory at document idle so the passive checks (DOM analysis, secret-pattern types, source-map discovery) have data when the user opens the popup. It performs no network requests and no data leaves the device from the content script.

---

## 3. Data-disclosure answers (dashboard)

**Privacy policy URL:** https://bugseek-ai.vercel.app/privacy-policy.html

**Does the item use remote code?** No — all code is bundled in the package.

**Data the item handles (declare exactly this):**

| Dashboard category | Answer | Notes for the form |
|---|---|---|
| Website content | Yes | Page content, scripts, headers and storage key names are analysed on-device; sent to our backend only when the user runs a backend scan. |
| Authentication information | Yes | An optional backend API key the user pastes is stored locally in the extension; the server stores only a hash and a short prefix. |
| Personally identifiable information | No (extension) | Accounts (name, email via Google sign-in) live on the BugSeek website, not in the extension. Re-check this answer when sign-in sync ships. |
| Browsing activity / web history | No | No continuous collection or history is kept. Scans are user-initiated per page; results are stored locally per tab. |
| Location | No (extension) | GPS/IP requester stamps belong to the website patrol, not the extension. |
| Financial / health / personal communications | No | Payment-gateway *fingerprints* (which gateway a page uses) are detected; no payment data is read. |

**Data usage certifications (all true of the current code):**
- Data is used only for the item's single purpose.
- Data is not sold or transferred for purposes unrelated to the single purpose.
- Data is not used or transferred to determine creditworthiness or for lending.
- Data is transferred over TLS; API keys and session tokens are stored hashed server-side.

**Limited Use statement (for the website; already live on /privacy):**
> BugSeek AI's use of information received from Google APIs adheres to the Chrome Web Store User Data Policy, including the Limited Use requirements.

---

## 4. Screenshots **[you]** (1280×800, up to 5)

Capture from the unpacked `dist/` build in Chrome:

1. **The disclosure gate** — fresh profile, popup just opened. (The honesty shot; keep it first.)
2. **Passive results** — scan a page with findings; show the summary and finding cards.
3. **A clean page** — scan a well-configured site; show the all-clear state.
4. **Active testing locked** — the authorisation form, untouched.
5. **Swarm run record** — the worker cards and score ring after a backend run (needs your API key + a target you're authorised to test).

Rules of thumb: real product only, no mock data claims, black theme as-is.

---

## 5. Review notes (paste into "notes for reviewers")

> Passive checks need no account and work offline of any account: open the popup on any page, accept the first-run disclosure, and choose "Scan this page". Active testing is intentionally locked behind an in-product authorisation form. Backend features (AI swarm, engines) need a BugSeek API key (Hunter plan); a reviewer key can be supplied on request. One deliberate exception: when the connected key belongs to our own operator account, the popup records the same authorisation automatically instead of showing the form (a developer unlock for our own testing); the per-request scope checks still run.

---

## 6. Pre-submit checklist

- [x] First-run in-extension disclosure + stored consent (`src/lib/consent.ts`)
- [x] Full privacy policy on a public URL; summary page live; Limited Use line present
- [x] Manifest description within the 132-char store limit
- [x] Backend address defaults to production (no localhost in the store build)
- [x] Icons 16/32/48/128 present
- [ ] **[you]** Developer account ($5 one-time) + trader declaration (publishes your legal name, address and phone — use details you're comfortable making public)
- [ ] **[you]** Screenshots per §4
- [ ] **[you]** Paste §1–§3 into the dashboard; submit for review
- [ ] Plan for review time: days to weeks; permission questions (especially `cookies` and `<all_urls>`) are answered from §2

# BugSeek AI — Compliance checklist (working notes)

> Internal notes, not legal advice. Started from a social-media checklist ("20 things so your app doesn't get sued") and checked item by item against the actual codebase on 3 Oct 2026. Status is only ever claimed where the code was read.

## Documents
- [x] **Privacy policy** — `docs/privacy-policy.md` (draft; needs operator details + legal review before publication).
- [x] **Terms of service** — `docs/terms-of-service.md` (draft; same caveats).
- [x] **Cookie policy** — complete cookie table inside the privacy policy §2.2: `bs_session` (30 days) + `bs_oauth_state` (10 minutes), both strictly necessary, first-party, httpOnly. One `sessionStorage` flag for the intro animation. **No consent banner**: no optional cookies exist; if any are added, the policy names them first and consent is asked before they are set.
- [x] **Refund policy** — `docs/refund-policy.md` (draft stub: no payments are taken yet, so there is nothing to refund; window and process to be completed before paid plans open).

## Product behaviour
- [x] **Form consents checked** — the patrol authorisation tick is required server-side (`authorized` must be `true`) and is stored with every run. The waitlist promise ("one email at launch, nothing else") matches what the code does (no read-back route, no other mailings wired).
- [x] **Avoid unnecessary data collection** — verified design rules: `.env` evidence stores variable names only; JS secret findings store pattern types only; storage inventories store key names/shapes only; GPS only with the browser's permission. Known, disclosed exception: requester IP + coarse IP-location stored per patrol (stated on the patrol form before running).
- [x] **Third-party SDK audit** — site dependencies are only react, react-dom, framer-motion, lucide-react (no analytics, ads, or tracking SDKs). Backend processors are listed in the privacy policy §3.
- [x] **Dark patterns / hidden fees** — no pre-ticked extras, no fake countdowns; credit costs are stated on the pricing surface and charged exactly as displayed (25 credits/swarm run, 10/engine run, 1 patrol = plan quota, not credits).
- [x] **Fake reviews / unsupported claims** — no testimonials or review counts anywhere on the site. Claims discipline: the patrol score is labelled "configuration score — how the site is built, not whether it's honest"; known traps render 0 · TRAP.
- [ ] **Data deletion option** — available today by email (privacy policy §7, ~30 days). A self-service delete-account action is **not built**; it belongs with the Settings page (parked, awaiting Peer's pick from the MaxoPerf list).
- [ ] **Unsubscribe links** — nothing to unsubscribe from yet (no mailings are sent). Rule recorded: the first launch email ships with an unsubscribe link.
- [x] **Age consent / children's data** — service is not directed at children (privacy policy §8, terms eligibility). No child-directed features exist to gate.
- [ ] **Business details** — operator legal name, address and privacy contact are blank in the drafts. Peer's to supply; also required for the Chrome Web Store Trader declaration.

## Accessibility (checked 3 Oct 2026)
- [x] **Alt text** — every `<img>` on the site is a decorative mark with `alt=""` (correct for decoration) or sits beside visible text. No image carries information alone.
- [x] **Colour contrast** — muted text token `#8B8B8B` on `#050505` ≈ 5.9:1 (passes WCAG AA for normal text); body `#CFCFCF` and data colours (crit/amber) all pass.
- [x] **Keyboard navigation** — global `:focus-visible` ring in `index.css`; interactive elements are native buttons/links with `aria-expanded` / `aria-selected` where stateful. Small gaps closed in this pass: visible focus ring added to the expanding-tabs control and the two form inputs that previously relied on border change alone.

## Assets
- [x] **Font/image licensing** — fonts are Inter, Space Grotesk and Share Tech Mono from Google Fonts (SIL Open Font Licence). Icons are Lucide (ISC) plus first-party SVGs (`bug.svg`, `favicon.svg`, `icons.svg`). No stock photography or unlicensed imagery found on the site.

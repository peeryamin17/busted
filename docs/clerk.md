# Clerk authentication — how BugSeek uses it

BugSeek sign-in is provided by **Clerk** (Google social login). Clerk owns
the identity; BugSeek's backend only *verifies* Clerk session tokens and
maps them onto BugSeek users (plans, credits, API keys).

## Pieces

| Layer | What it does |
|---|---|
| Marketing site (`site/`) | `@clerk/clerk-react`. "Continue with Google" runs a real OAuth redirect (`oauth_google`) → `/sso-callback` → `/welcome`. Nav shows Clerk's `UserButton` when signed in. |
| Backend (`backend/`) | Verifies Clerk JWTs against the app's public JWKS (`{CLERK_FRONTEND_API}/.well-known/jwks.json`, RS256 + issuer + expiry — see `src/auth/clerk.ts`). **No Clerk secret key is held or needed for verification.** |
| Link step | First authenticated visit: the client POSTs `/api/auth/clerk/link` with the Clerk token + the profile email. Backend find-or-creates the BugSeek user keyed by the token's `sub` (`users.clerk_user_id`, migration `002_clerk.sql`). After that, Clerk tokens authenticate every API route directly. |
| Extension | Still authenticates with BugSeek API keys (`x-api-key`) — unchanged and working. See "Extension session sync" below for the planned upgrade. |

## Configuration

- Site: `VITE_CLERK_PUBLISHABLE_KEY` (publishable key — a public identifier,
  safe in browser code). On Vercel: Site project → Settings → Environment
  Variables. Optional `VITE_BACKEND_URL` (default `http://localhost:3000`).
- Backend: `CLERK_FRONTEND_API=https://<app>.clerk.accounts.dev` in `.env`.
  Unset → Clerk verification disabled, password/API-key auth unaffected.
- Clerk dashboard: enable **Google** under Social connections. If the app
  should be Google-only, disable email/password sign-in there too (the
  site's UI never offers it regardless). For production (`pk_live`), set
  the production domain in Clerk → Domains.

## Who logged in — the operator's view

Every sign-up and sign-in is recorded in **our own database**, two ways:

1. **Link step** (above) — fires when a signed-in user reaches /welcome.
2. **Clerk webhooks** — `POST /api/webhooks/clerk` receives Clerk's
   `user.created` / `user.updated` (email upsert) and `session.created`
   (stamps `users.last_login_at`) events, Svix-signature-verified
   (`src/auth/clerkWebhook.ts`). This catches everyone, whatever page
   they visited.

To switch webhooks on (needs a publicly reachable backend):

1. Clerk Dashboard → **Webhooks** → Add endpoint:
   `https://<your-backend-host>/api/webhooks/clerk`
2. Subscribe to `user.created`, `user.updated`, `session.created`.
3. Copy the endpoint's **Signing Secret** (`whsec_...`) into the backend
   env as `CLERK_WEBHOOK_SECRET`. Unset → the route answers 503.

To read the list: `GET /api/admin/users` with a normal session token —
only the account whose email matches the backend's `ADMIN_EMAIL` env var
gets in (everyone else 403s). Returns email, plan, join date, last login,
and whether the account came via Clerk. And the quick visual check is
always Clerk Dashboard → **Users**.

Durability note: records persist only when the backend runs against
Postgres (`DATABASE_URL`, migrations `001`–`003`). In-memory mode keeps
them until restart — fine for local testing, not for production.

## Extension session sync (planned, not yet built)

Clerk offers `@clerk/chrome-extension`, which syncs the session from a
signed-in **host web app** into the extension (`syncHost`), so a user who
signs in on the website is automatically signed in inside the popup.
Two prerequisites before building it:

1. The **deployed site URL** (the sync host) — extension builds need it
   baked in; local unpacked builds can point at the Vercel deployment.
2. The popup is currently vanilla TypeScript; Clerk's extension SDK is
   React-first (built for Plasmo-style popups). Options: (a) adopt the
   SDK in a small React island for the popup's account area, or
   (b) keep API keys as the extension credential and add a signed-in
   "Connect extension" page on the website that displays the user's API
   key (zero popup rework, works today with the backend as-is).

The publishable key + frontend API for the extension are already staged
in the repo-root `.env.local` (`PLASMO_PUBLIC_CLERK_PUBLISHABLE_KEY`,
`CLERK_FRONTEND_API`, gitignored).

## Update — 2 Oct 2026: development key pinned in code

Sign-in on the production domain kept breaking because the build depended
on the host's `VITE_CLERK_PUBLISHABLE_KEY` variable: first it carried the
pk_live value (whose sign-in host cannot resolve under vercel.app), later
it was absent entirely, which disabled Clerk in the build. The site now
pins the development instance's publishable key in `site/src/lib/clerk.ts`
(a publishable key is a public identifier, shipped in every bundle). A
`pk_test_` value from the environment still wins locally; anything else
falls back to the pin.

Launch step, when the custom domain's DNS points at Clerk: delete the pin
in `clerk.ts`, set the host variable to the pk_live value, redeploy.

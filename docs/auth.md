# Authentication — how BugSeek sign-in works now

BugSeek runs its **own** Google sign-in. No auth vendor: the backend
(Fastify, on Render) speaks OAuth 2.0 to Google directly, keeps sessions
in Postgres (Neon), and the marketing site (Vercel) reaches it through a
same-domain proxy. Google is the only credential — BugSeek stores no
passwords.

## The flow

1. Visitor clicks **Sign in with Google** on `/signin`. The browser
   navigates to `/api/auth/google` on the site's own domain; a Vercel
   rewrite proxies `/api/*` to the backend
   (`https://bugseek-backend.onrender.com`). Going through the site's
   domain is deliberate: the session cookie is host-only and
   `SameSite=Lax`, so it sticks to the site instead of stranding on the
   backend's domain.
2. The backend sets a signed `state` cookie (CSRF) and redirects to
   Google.
3. Google redirects back to `/api/auth/google/callback` (again through
   the proxy). The backend verifies the state, exchanges the code
   server-side (client secret never leaves the backend), reads the
   Google profile, find-or-creates the user by Google subject id
   (`users.google_sub`, migration `004_google_auth.sql`), and stamps
   `last_login_at`.
4. A session row is created — the database stores only a SHA-256 hash of
   the token — and the `bs_session` cookie is set (httpOnly,
   `Secure` in production, 30 days). The browser lands on
   `POST_LOGIN_REDIRECT` (`/app`).
5. The site probes `GET /api/me` (200 → user + credit quota; 401 →
   signed out) to drive the nav (avatar/name/Sign out) and the `/app`
   guard. `POST /api/auth/logout` deletes the session row.

## Where the code lives

| Piece | Location |
|---|---|
| Google OAuth client (URL builder, code exchange, userinfo) | `backend/src/auth/google.ts` |
| Session + state primitives (hashing, cookie signing) | `backend/src/auth/session.ts` |
| Routes (`/api/auth/google`, callback, `/api/me`, `/api/auth/logout`) | `backend/src/routes/googleAuth.ts` |
| Users/sessions schema | `backend/migrations/004_google_auth.sql` |
| Site session probe + context | `site/src/lib/auth.tsx` |
| Sign-in page / guarded members' home | `site/src/pages/SignIn.tsx`, `site/src/pages/MemberApp.tsx` |
| `/api` proxy (deploy + local dev) | `site/vercel.json`, `site/vite.config.ts` |

## Configuration

Backend env (Render dashboard; secrets exist nowhere else):

- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` — from the Google Cloud
  OAuth client. The secret is used only in the server-side code
  exchange.
- `GOOGLE_REDIRECT_URI` — must byte-match an authorised redirect URI on
  that client: `https://bugseek-ai.vercel.app/api/auth/google/callback`
  (the proxied address, **not** the `onrender.com` one).
- `POST_LOGIN_REDIRECT` — `https://bugseek-ai.vercel.app/app`.
- `SESSION_SECRET` — signs the OAuth state cookie (falls back to
  `JWT_SECRET` when unset). `JWT_SECRET` is mandatory in production;
  the boot refuses without it.
- `ALLOWED_ORIGINS` — CORS allowlist, must include
  `https://bugseek-ai.vercel.app` (credentials are enabled; production
  refuses `*`).
- `ADMIN_EMAIL` — the only account allowed into `GET /api/admin/users`
  (email, plan, join date, last login).
- `DATABASE_URL` — Neon pooled connection string. Unset → in-memory
  store (local testing only).

The site needs **no** auth configuration: it only calls relative
`/api/...` URLs. If the Google env is absent, the backend still boots
and the auth routes answer `503 {"error":"Google sign-in is not
configured on this backend"}`.

## Extension

The extension still authenticates with BugSeek API keys
(`x-api-key: bs_…`, stored hashed, revocable, plan-gated) — unchanged.
Planned upgrade (piece 6): a signed-in **Connect extension** page on the
website hands the extension a token tied to the user's account, so
extension runs bill the same identity as the website. See the API-key
regression tests in `backend/test/google-auth.test.ts` for the current
guarantees.

## History

Clerk (Oct 1–2) and then Appwrite (Oct 2–3) were both tried and
discarded; their code is fully removed (no references remain in the
site or backend). The old `docs/clerk.md` was replaced by this file.

# BugSeek AI site

The public site and members' app for BugSeek AI, a Chrome extension for
AI-powered security reconnaissance. React 19 + Vite + Tailwind, with a
tiny client router (see `src/lib/router.ts`) and the backend reached
through the `/api` proxy (see `vercel.json` / `vite.config.ts`).

## Run it

```sh
npm install
npm run dev
```

## Checks

```sh
npm run build   # typecheck + production build
npm test        # pure-helper unit tests (node:test, no framework)
```

## Layout

- `src/pages/` — Landing, SignIn, MemberApp (`/app`), WebCheck
  (`/app/check`), TasksPage (`/tasks`), Privacy
- `src/components/` — the site sections and member panels
- `src/lib/` — auth session probe, router, motion presets, and the
  pure helpers covered by `src/lib/pure.test.ts`

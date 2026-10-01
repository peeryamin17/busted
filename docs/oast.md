# OAST — out-of-band security testing (Phase 3 blueprint)

**Status:** code scaffolding is in place (`backend/src/oast/`, `/api/oast/*` routes).
The always-on listener infrastructure described here is **not built yet**.

## Why

Blind vulnerabilities — stored XSS that fires in an admin panel, SSRF that makes
the target's backend call you back — are where serious bounties hide, and no
in-browser scanner can observe them directly. OAST closes the loop: probes embed
a unique canary hostname, and if the target ever resolves or requests it, we
know the injection landed server-side.

## How it works (once built)

1. User starts a scan → backend mints a canary: `<scanid>-<rand>.oast.bugseek.ai`
   (`POST /api/oast/canary`, or automatically per swarm scan).
2. Blind-payload probes embed the canary (e.g. `<img src="https://<canary>/x">`).
3. The OAST listener — wildcard DNS + HTTP(S) server you operate — observes the
   lookup/request and POSTs to `/api/oast/callback` with the shared
   `OAST_INGEST_TOKEN`.
4. `GET /api/oast/callbacks?scanId=` returns hits; the UI shows
   **"blind hit observed"** and the swarm promotes it to a high-severity finding.

## Infrastructure needed

- A domain (e.g. `oast.bugseek.ai`) with wildcard DNS (`*.oast.bugseek.ai`)
  pointed at your listener. ~$10/year.
- An always-on listener: a tiny Node service handling DNS (UDP 53) and HTTP(S)
  (wildcard cert via Let's Encrypt). A $5/month VPS is plenty.
- Env on the API server: `OAST_DOMAIN=oast.bugseek.ai`,
  `OAST_INGEST_TOKEN=<long random secret>`.

A minimal DNS listener can be ~100 lines with the `dns2` npm package; the HTTP
side is a plain Fastify/Express app that POSTs every request to the callback
route. Until this exists, `oastConfigured()` returns false and minted canaries
are inert — by design, never silently.

## First integration point

Blind XSS. The current `xssTester` is reflection-only (GET params), so canary
probes need the stored-input prober first: submit the canary payload into
forms/comment fields the scanner discovers, then poll
`GET /api/oast/callbacks?scanId=` for up to N hours after the scan. SSRF/RCE
probes don't exist yet — OAST gives them a reason to.

## Security notes

- Canary hostnames carry 32 bits of randomness plus the scan prefix: not
  guessable, not enumerable.
- The callback route requires `OAST_INGEST_TOKEN`; without it, ingest is 503.
- Never exfiltrate target data through the canary channel — hostname and
  path only, no query strings with target internals.
- The listener must rate-limit and never act as an open resolver/proxy.

---
name: api-security
description: Test an API's auth and access controls — authentication, authorisation, CORS, and GraphQL — with benign canaries and read-only proofs.
when-to-use: When the inventory is built and the task turns to access control: who may call what, with whose credentials, and what the server leaks when they should not.
roles:
  - planner
  - worker
tools:
  - auth-probe
  - cors-probe
  - idor-probe
  - graphql-probe
  - guarded-fetch
---

# API security

Access control is tested by trying the wrong access and watching
what the server does — with the operator's own test accounts, on the
operator's own target, through the depth ladder, with benign
canaries. Never with real user data, never with stolen credentials,
never against a target the operator has not authorised.

## Authentication

- Test the login surface the way the guardrailed brute-force module
  allows: default credentials and a short weak-password list, only
  against the operator's own accounts, rate-limited, stopping at
  the first lockout, CAPTCHA, or 429. A lockout is a result, not an
  obstacle — record that the defence fired.
- Check session handling: does a token survive logout, does it work
  from a different origin, does it carry more privilege than the
  account it was issued to? A token that outlives its session is a
  finding; a token that works everywhere is a finding about scope.

## Authorisation (IDOR and privilege)

- For every identifier the inventory recorded, try the same request
  with another account's identifier — the canary account's own id,
  never a real user's. A response that returns the other account's
  data is a finding; a response that returns an error is the
  control working.
- Try the same request with a lower-privilege account: an admin
  endpoint that answers a reader is a privilege-escalation finding,
  even if the response looks harmless. The check is whether the
  server enforced the role, not whether the data looked sensitive.
- Confirm every candidate through the depth ladder: one response
  is a hint, a reproduced canary response is a verified finding.

## CORS and GraphQL

- For CORS, check what the server actually allows: which origins,
  whether credentials ride along, whether a reflected origin plus
  credentials turns a cross-origin read into a data leak. An
  overly permissive CORS policy on an endpoint that serves private
  data is the finding — the header alone, on a public endpoint,
  is not.
- For GraphQL, read the schema first: introspection, if the server
  offers it, is a map, not an attack. Then test the shapes the
  schema exposes — deep nesting, field-level authorisation, and
  queries that ask for another user's fields. A field that returns
  another user's data is the same IDOR finding wearing a GraphQL
  shape; report it once, with the query that produced it.

## What this skill never does

- It never tries credentials that are not the operator's own test
  accounts, never brute-forces beyond the guardrailed list, never
  evades a rate limit or CAPTCHA, and never uses a found key or
  token against a third-party service. A defence that fires is a
  pass for the defence, not a challenge to beat.

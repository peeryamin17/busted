---
name: api-recon
description: Map an API surface before testing it — enumerate endpoints, parameters, and auth from traffic and docs, then hand the swarm a complete inventory.
when-to-use: At the start of any task whose target is an API, or when the swarm keeps finding endpoints it had not seen before.
roles:
  - planner
  - worker
tools:
  - guarded-fetch
  - endpoint-scan
  - header-probe
  - traffic-capture
---

# API recon

Recon comes before testing. A finding about an endpoint nobody mapped
is luck; a finding about an endpoint on the inventory is coverage.

## Build the inventory first

- Start from what the target itself declares: its OpenAPI or Swagger
  document, its GraphQL schema if one is advertised, and the links
  and forms on its own pages. Declared surface is the floor, not the
  ceiling.
- Then watch the target's own traffic: the extension's passive
  capture records the requests the site makes while it is used
  normally. Every endpoint the site calls on itself is in scope and
  belongs on the inventory.
- Then probe the gaps: common paths the docs do not mention, version
  prefixes (`/v1`, `/v2`, `/api`), and admin or debug paths the site
  links to but never calls. A probe is a read-only request through
  guarded fetch — never a state-changing call, never a request
  outside the pinned target and its scope.

## Record each endpoint properly

For every endpoint, record method, path, parameters (path, query,
body), auth requirement, and what a normal response looks like. Note
which parameters are identifiers (user ids, order ids, file ids) —
those are the IDOR candidates — and which endpoints return more
fields than the UI shows, because over-exposed fields are the
mass-assignment candidates.

## Hand over, then stop

- Hand the planner an inventory with a count: how many endpoints
  found, how many authenticated, how many untested. An endpoint with
  no entry is unexamined, never clean — say so plainly.
- Do not start testing while recon is still finding new endpoints.
  New endpoints found mid-test go back on the inventory and get
  tested in their own turn, through the depth ladder, with benign
  canaries — never as an ad-hoc live probe.
- If the inventory keeps growing because the target is a single-page
  app that calls new endpoints on every click, record a skill gap
  (`spa-endpoint-discovery`) instead of chasing it by hand: the
  capability backlog is where that gap belongs, not in a longer
  recon loop.

## What this skill never does

- It never calls an endpoint outside the task's pinned target or
  scope, never sends credentials, and never treats a 200 response
  as proof of anything — a status code is a hint, a bound proof
  through the depth ladder is evidence.

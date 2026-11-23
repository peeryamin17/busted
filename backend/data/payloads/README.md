# Payload packs

Curated subsets of PayloadsAllTheThings (MIT, Swissky 2019), extracted by
`backend/scripts/extract-payloads.ts`. The zip is never copied into the repo;
regenerate any time with:

```
npx tsx scripts/extract-payloads.ts
```

## Layout

- `packs/` — small line lists for the depth ladder. Every pack is capped at
  20 KB. Each manifest entry carries a `maxRequestsPerEndpoint` budget; the
  ladder must enforce it (pinCheck, approvals, noise governor) when it
  eventually reads these.
- `playbooks/` — methodology READMEs chunked to 120 lines max, with the
  source path in a header comment. Retrieval material for the skills layer.
- `signatures/` — deterministic JSON for the scanners: secret patterns,
  SCM exposure paths, deserialization sinks. No key material is stored here.
- `manifest.json` — per-pack source path, sha256 of the source file, byte
  and line counts, budget notes.
- `NOTICE.md` — license attribution.

## Not wired in yet

Nothing here is read by the swarm, the skills registry, the depth ladder,
or any scanner. That wiring lands after PR 1 (0.4.0-a). What is still open
for that follow-up:

- a retriever over `playbooks/` for swarm specialists (chunked, on demand)
- `packs/` loading in `depthLadder.ts` / `agent/tools.ts` with budget caps
- `signatures/` loading in `codeIntake/analyzer.ts` and `secretScanner.ts`
- the adversarial self-test suite (layer 4) that uses the archive as
  hostile fixtures against the boundary, scope guard, CSV export and
  workspace confinement

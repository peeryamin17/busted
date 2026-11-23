---
name: codeaudit
description: Audit source code the operator supplied — trace taint from sources to sinks, read the bundle, and turn code paths into testable findings.
when-to-use: When a task includes operator-supplied code (a ZIP or JAR through code-intake, a JS bundle, or a repo the operator owns) and the swarm needs to reason from code, not just from HTTP responses.
roles:
  - worker
tools:
  - taint-engine
  - js-bundle-scan
  - code-intake
---

# Code audit

Code the operator supplied is the one place the swarm may read
implementation instead of guessing from responses. Treat it as
evidence, not as ground truth: code shows what could happen, the
depth ladder shows what does happen.

## Start with taint, not with reading

- Run the taint engine first: it tracks data from sources (request
  parameters, headers, cookies, file reads, database rows) to sinks
  (HTML rendering, SQL queries, shell calls, redirects, eval). A
  complete source-to-sink path is a candidate finding; a sink with
  no reachable source is a note, not a finding.
- Read the engine's path, then read the code around it yourself.
  The engine can miss a sanitiser written in an unusual way, and it
  can flag a path the application never reaches. Your job is to
  confirm which one it is, with the actual lines in front of you.

## Bundles and archives

- For a JavaScript bundle, use the bundle scanner: it recovers
  source maps when the operator supplied them, lists the modules
  and the secrets-shaped strings inside them, and maps bundle
  offsets back to original files. A secret-shaped string in a
  bundle is a lead, not a finding — check whether the value is a
  real credential, a test fixture, or a public key before reporting
  it, and never validate a found key against a third-party service.
- For a ZIP or JAR through code-intake, the constant-pool string
  scan lists the literal strings the bytecode carries. That is a
  string scan, not decompilation: report what the strings show
  (endpoints, keys, SQL fragments) and say plainly what it cannot
  show (control flow the strings do not reveal).

## From code path to finding

- A code path becomes a finding only when the depth ladder confirms
  it against the live target with a benign canary: the code says the
  parameter flows into a query, the ladder shows the response
  changing with a canary value. Code alone is a hint; code plus a
  reproduced canary is a verified finding.
- When a sink looks dangerous but you cannot reach it from any
  source, record the shape (file, function, sink) as a hint with
  its reason, and move on. Do not invent a source to complete the
  path.
- When the code is in a language or format the taint engine cannot
  follow, record a skill gap (`taint-language-<name>`) with the
  file type and the path you were trying to trace, and fall back to
  black-box testing of the endpoints the code exposes.

## What this skill never does

- It never runs the supplied code, never executes a binary, and
  never sends anything it read in the code to a third party. It
  never treats a string that looks like a secret as a credential
  to try.

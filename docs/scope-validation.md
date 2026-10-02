# Programme scope validation

Before BugSeek runs active checks, it can confirm the target sits inside the
published scope of the public bug bounty programme you're hunting under. Pick a
programme on HackerOne or Bugcrowd, and BugSeek checks the host against that
programme's own scope list — so the swarm never spends its energy (or your
credits) on a target the programme won't accept reports for.

## How it works

- In the extension's Active testing pane, choose a platform and start typing a
  programme name or handle. BugSeek looks it up and checks the current tab's
  host against the programme's published scope.
- A verdict chip tells you where you stand: **in scope**, **out of scope**, or
  **unknown** (no programme chosen, the programme not found, or a check that
  couldn't be completed).
- When a programme says the host is out of scope, the active checks pause and
  say why. Switch to the right programme — or to "No programme" if your
  authorisation comes from a contract or from owning the target — and you're
  moving again.
- Naming a programme on a swarm or engine scan records the verdict, the
  published scope line that matched, and the time of the check on the scan
  itself — a tidy evidence trail next to your authorisation record. A scan
  whose target falls outside the named programme's scope is turned away before
  any credits are charged.

## How verdicts are reached

Scope matching follows the conventions both platforms use:

- A listed host covers itself and its subdomains (`example.org` also covers
  `www.example.org`); a `*.example.org` listing covers subdomains only.
- A listing published with a path (`https://shop.example.net/store`) covers
  that path and everything beneath it.
- Out-of-scope listings always win over in-scope ones.
- Matching ignores case, ports, and trailing dots, so pasted URLs just work.

Assets that aren't websites — mobile apps, source repositories, hardware —
can't be matched to a host, so programmes that only list those return
"unknown" rather than a judgement either way. Nothing is ever guessed: if
BugSeek can't see a web scope it can check, it says so.

## Where the data comes from

Programme scopes come from the community-run
[bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) project,
which mirrors the public HackerOne and Bugcrowd scope listings. BugSeek's
backend fetches the latest data at runtime and keeps it fresh in memory
(refreshed every six hours). No dataset snapshots live in this repository, and
if the data can't be fetched, checks simply report "unknown" — scope validation
never stands between you and the rest of the product.

## One rule that never bends

A scope verdict is evidence, never authorisation. Being in a programme's scope
doesn't grant anyone permission to test — your confirmed authorisation record
still governs every active check, exactly as before. Scope validation exists to
keep honest hunters inside the lines they already agreed to hunt within.

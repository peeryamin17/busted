---
name: patch-diff
description: Review a patch the operator supplied — read the diff line by line, judge whether it fixes the finding it claims to fix, and check what it breaks.
when-to-use: When the operator supplies a patch or a pull request and asks whether a reported finding is actually fixed, or when the retester needs to judge a fix.
roles:
  - worker
  - main
tools:
  - code-intake
  - diff-review
---

# Patch diff

A patch is a claim: "this change fixes that finding." Your job is to
test the claim against the diff, not to trust the commit message.

## Read the diff before the message

- Read every hunk. The commit message says what the author intended;
  the diff says what changed. Start with the hunks that touch the
  vulnerable code path, then the hunks that touch its callers, then
  everything else.
- For each hunk, ask: does this change the data flow the finding
  relied on, or does it only move it? A sanitiser added at the sink
  fixes the sink; a sanitiser added on one caller leaves the other
  callers open. A check added after the dangerous call is no check
  at all.

## Judge the fix on its own terms

- A fix is complete when every path the finding used is closed: all
  callers, all parameter variants, all encodings the sink accepts.
  If the patch closes one encoding and leaves another open, say so
  and name the open one.
- A fix is incomplete when it changes behaviour the tests do not
  cover: a new branch with no test, an error path that now returns
  a different status, a validation that rejects input the product
  legitimately accepts. Name the uncovered branch.
- A fix that introduces a new sink — a new query, a new redirect, a
  new render of user input — is a new finding, not a fix. Report it
  as its own item with its own severity.

## Verify, do not assume

- A patch that looks complete is still a hint until the retester
  confirms it against the live target: the finding's proof, run
  again, must come back fixed. Say which proof you would re-run
  and what a fixed result looks like.
- When the diff is too large to review in one pass, review the
  security-relevant hunks first and say which files you did not
  review, instead of pretending the whole patch was covered.
- When the patch touches code outside the finding's scope, flag the
  out-of-scope change separately — it may be fine, but it is not
  part of this fix and the operator should know it is there.

## What this skill never does

- It never applies a patch, never commits, and never edits the
  operator's code. It reads and judges. It never approves a fix on
  the strength of the commit message alone.

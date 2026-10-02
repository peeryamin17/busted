-- BugSeek AI — programme scope evidence on scans.
--
-- When a swarm or engine scan names a HackerOne/Bugcrowd programme, the
-- scope verdict captured at creation time (verdict, matched published
-- asset, reason, timestamp) is stored on the scan as authorisation
-- evidence — see docs/scope-validation.md. Nullable: scans that don't
-- name a programme simply have no evidence recorded.

alter table scans add column if not exists scope_evidence jsonb;

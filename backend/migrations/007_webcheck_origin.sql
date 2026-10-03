-- 007_webcheck_origin.sql — who asked for each patrol, and roughly where from.
--
-- requester_ip/geo stamp the run with its owner's address and coarse
-- location (city/country granularity, never finer). The patrol form
-- discloses this before the run; the stamp shows in the owner's patrol
-- history so they can see exactly what was recorded.

alter table web_checks add column if not exists requester_ip text;
alter table web_checks add column if not exists requester_geo jsonb;

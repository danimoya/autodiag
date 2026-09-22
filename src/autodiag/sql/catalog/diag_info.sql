-- name: diag_info
-- desc: ADR locations of the instance (diag base, ADR home, alert log, trace directory)
-- scope: cdb
-- pack: none
-- params:
select name, value from v$diag_info order by name

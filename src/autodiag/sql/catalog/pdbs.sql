-- name: pdbs
-- desc: Pluggable databases and their open mode
-- scope: cdb
-- pack: none
-- params:
select con_id, name, open_mode, restricted, total_size from v$pdbs order by con_id

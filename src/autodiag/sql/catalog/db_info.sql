-- name: db_info
-- desc: Database and instance identity, version, role, startup time, host
-- scope: cdb
-- pack: none
-- params:
select d.name as db_name, d.db_unique_name, d.database_role, d.open_mode, d.cdb,
       i.instance_name, i.host_name, i.version_full, i.startup_time, i.status,
       (select count(*) from gv$instance) as instance_count
  from v$database d, v$instance i

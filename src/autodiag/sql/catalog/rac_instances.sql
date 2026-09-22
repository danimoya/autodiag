-- name: rac_instances
-- desc: All instances of the database with status and startup time (GV$INSTANCE)
-- scope: cdb
-- pack: none
-- params:
select inst_id, instance_number, instance_name, host_name, status, startup_time, version_full
  from gv$instance order by inst_id

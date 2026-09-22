-- name: sqlpatch_registry
-- desc: Patch history of the database (DBA_REGISTRY_SQLPATCH)
-- scope: cdb
-- pack: none
-- params:
select patch_id, patch_type, action, status, action_time, source_version, target_version, description
  from dba_registry_sqlpatch
 order by action_time desc

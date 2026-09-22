-- name: diag_incident_detail
-- desc: All columns of one incident (V$DIAG_INCIDENT)
-- scope: cdb
-- pack: none
-- params: incident_id:int
select * from v$diag_incident where incident_id = :incident_id

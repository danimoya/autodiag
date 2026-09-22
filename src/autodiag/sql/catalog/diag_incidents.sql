-- name: diag_incidents
-- desc: Incidents of one ADR problem (V$DIAG_INCIDENT joined to its problem key)
-- scope: cdb
-- pack: none
-- params: problem_id:int
select i.incident_id, i.problem_id, p.problem_key, i.create_time, i.status, i.error_facility,
       i.error_number, i.error_arg1, i.error_arg2, i.error_arg3, i.flood_controlled,
       i.signalling_component, i.con_id
  from v$diag_incident i left join v$diag_problem p on p.problem_id = i.problem_id
 where i.problem_id = :problem_id
 order by i.create_time desc

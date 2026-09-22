-- name: diag_problems
-- desc: ADR problems whose last incident is within the last N hours (V$DIAG_PROBLEM)
-- scope: cdb
-- pack: none
-- params: since_hours:int=168
select problem_id, problem_key, first_incident, firstinc_time, last_incident, lastinc_time,
       service_request, bug_number, con_id
  from v$diag_problem
 where lastinc_time > systimestamp - numtodsinterval(:since_hours, 'HOUR')
 order by lastinc_time desc

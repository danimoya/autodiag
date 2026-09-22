-- name: blocking_tree_now
-- desc: Sessions currently blocked and their blockers (V$SESSION)
-- scope: pdb
-- pack: none
-- params:
select level as depth, sid, serial#, username, event, seconds_in_wait, sql_id,
       blocking_session, blocking_instance, con_id
  from v$session
 start with blocking_session is null and sid in (select blocking_session from v$session where blocking_session is not null)
 connect by prior sid = blocking_session

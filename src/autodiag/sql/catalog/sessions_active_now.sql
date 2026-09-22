-- name: sessions_active_now
-- desc: Active foreground sessions with current wait and SQL (V$SESSION)
-- scope: pdb
-- pack: none
-- params:
select sid, serial#, username, status, program, module, sql_id, event, wait_class,
       seconds_in_wait, blocking_session, con_id
  from v$session
 where status = 'ACTIVE' and type = 'USER'
 order by seconds_in_wait desc

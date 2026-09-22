-- name: rac_blocking_now
-- desc: Sessions blocked right now across all instances with their blockers (GV$SESSION)
-- scope: cdb
-- pack: none
-- params:
select w.inst_id, w.sid, w.serial#, w.username, w.event, w.seconds_in_wait, w.sql_id,
       w.blocking_instance, w.blocking_session, b.username as blocker_user, b.status as blocker_status,
       b.event as blocker_event, w.con_id
  from gv$session w
  left join gv$session b on b.inst_id = w.blocking_instance and b.sid = w.blocking_session
 where w.blocking_session is not null
 order by w.seconds_in_wait desc

-- name: performance_sessions
-- desc: Active foreground sessions and blockers for one or all instances
-- scope: cdb
-- pack: none
-- params: instance_id:int=0, top:int=30
select * from (
  select inst_id, con_id, sid, serial#, sql_id, state, event, wait_class,
         seconds_in_wait, blocking_instance, blocking_session, final_blocking_instance,
         final_blocking_session, module
  from gv$session
  where type = 'USER' and status = 'ACTIVE'
    and (:instance_id = 0 or inst_id = :instance_id)
    and (state <> 'WAITING' or wait_class <> 'Idle')
  order by case when blocking_session is not null then 0 else 1 end, seconds_in_wait desc
) where rownum <= :top

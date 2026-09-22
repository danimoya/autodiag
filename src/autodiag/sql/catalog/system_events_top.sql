-- name: system_events_top
-- desc: Top non-idle wait events since instance start (V$SYSTEM_EVENT)
-- scope: cdb
-- pack: none
-- params: top:int=30
select * from (
  select event, wait_class, total_waits, time_waited_micro / 1e6 as time_waited_s,
         average_wait * 10 as average_wait_ms
    from v$system_event
   where wait_class <> 'Idle'
   order by time_waited_micro desc)
 where rownum <= :top

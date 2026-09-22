-- name: exa_cell_events
-- desc: Exadata cell / smart scan related wait events since instance start (V$SYSTEM_EVENT)
-- scope: cdb
-- pack: none
-- params:
select event, wait_class, total_waits, time_waited_micro / 1e6 as time_waited_s,
       average_wait * 10 as average_wait_ms
  from v$system_event
 where lower(event) like 'cell%' or lower(event) like '%smart%'
 order by time_waited_micro desc

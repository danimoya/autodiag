-- name: rac_gc_events
-- desc: Global cache (gc) and cluster wait events per instance since startup (GV$SYSTEM_EVENT)
-- scope: cdb
-- pack: none
-- params:
select inst_id, event, wait_class, total_waits, time_waited_micro / 1e6 as time_waited_s,
       average_wait * 10 as average_wait_ms
  from gv$system_event
 where wait_class in ('Cluster', 'Other') and (lower(event) like 'gc%' or lower(event) like '%ges%' or lower(event) like '%ipc%')
 order by time_waited_micro desc

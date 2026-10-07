-- name: performance_counters
-- desc: Per-instance cumulative time model, waits and throughput with startup identity
-- scope: cdb
-- pack: none
-- params: instance_id:int=0
select c.inst_id, i.instance_name, to_char(i.startup_time, 'YYYY-MM-DD HH24:MI:SS') startup_time,
       c.category, c.metric, c.value
from (
  select inst_id, 'time_us' category, stat_name metric, value
    from gv$sys_time_model where stat_name in ('DB time', 'DB CPU') and con_id = 0
  union all
  select inst_id, 'wait_us', event, time_waited_micro
    from gv$system_event where wait_class <> 'Idle' and con_id = 0
  union all
  select inst_id, 'wait_count', event, total_waits
    from gv$system_event where wait_class <> 'Idle' and con_id = 0
  union all
  select inst_id, 'stat_count', name, value from gv$sysstat
    where name in ('execute count', 'user commits', 'user rollbacks', 'redo size',
                   'physical read total bytes', 'physical write total bytes',
                   'session logical reads', 'parse count (hard)') and con_id = 0
) c join gv$instance i on i.inst_id = c.inst_id
where (:instance_id = 0 or c.inst_id = :instance_id)
order by c.inst_id, c.category, c.metric

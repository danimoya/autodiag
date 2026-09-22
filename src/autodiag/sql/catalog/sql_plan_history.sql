-- name: sql_plan_history
-- desc: Plans seen for a sql_id in AWR with first/last snapshot (Diagnostics Pack)
-- scope: pdb
-- pack: diagnostics
-- params: sql_id:str
select s.sql_id, s.plan_hash_value, min(sn.begin_interval_time) as first_seen,
       max(sn.end_interval_time) as last_seen, sum(s.executions_delta) as executions,
       round(sum(s.elapsed_time_delta) / nullif(sum(s.executions_delta), 0) / 1000, 2) as avg_elapsed_ms,
       round(sum(s.buffer_gets_delta) / nullif(sum(s.executions_delta), 0)) as avg_buffer_gets
  from dba_hist_sqlstat s join dba_hist_snapshot sn
    on sn.snap_id = s.snap_id and sn.dbid = s.dbid and sn.instance_number = s.instance_number
 where s.sql_id = :sql_id
 group by s.sql_id, s.plan_hash_value
 order by last_seen desc

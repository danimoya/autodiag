-- name: performance_sql
-- desc: Top SQL by cumulative elapsed time since cursor load, not sampled interval usage
-- scope: cdb
-- pack: none
-- params: instance_id:int=0, top:int=15
select * from (
  select inst_id, con_id, sql_id, plan_hash_value, executions,
         elapsed_time / 1e6 elapsed_s, cpu_time / 1e6 cpu_s, buffer_gets, disk_reads,
         rows_processed, last_active_time
  from gv$sqlstats
  where (:instance_id = 0 or inst_id = :instance_id)
  order by elapsed_time desc
) where rownum <= :top

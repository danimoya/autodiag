-- name: ash_top_sql_window
-- desc: Top SQL by ASH samples in a window (needs Diagnostics Pack)
-- scope: pdb
-- pack: diagnostics
-- params: from_ts:str, to_ts:str, top:int=20
select * from (
  select sql_id, sql_plan_hash_value, count(*) as samples,
         sum(case when session_state = 'ON CPU' then 1 else 0 end) as cpu_samples,
         count(distinct session_id) as sessions, max(module) as module
    from v$active_session_history
   where sql_id is not null
     and sample_time between to_timestamp(:from_ts, 'YYYY-MM-DD HH24:MI:SS')
                         and to_timestamp(:to_ts, 'YYYY-MM-DD HH24:MI:SS')
   group by sql_id, sql_plan_hash_value
   order by samples desc)
 where rownum <= :top

-- name: ash_top_events_window
-- desc: Top wait events / CPU from ASH in a window (needs Diagnostics Pack); timestamps 'YYYY-MM-DD HH24:MI:SS'
-- scope: pdb
-- pack: diagnostics
-- params: from_ts:str, to_ts:str, top:int=20
select * from (
  select nvl(event, 'ON CPU') as event, wait_class, count(*) as samples,
         count(distinct session_id) as sessions
    from v$active_session_history
   where sample_time between to_timestamp(:from_ts, 'YYYY-MM-DD HH24:MI:SS')
                         and to_timestamp(:to_ts, 'YYYY-MM-DD HH24:MI:SS')
   group by nvl(event, 'ON CPU'), wait_class
   order by samples desc)
 where rownum <= :top

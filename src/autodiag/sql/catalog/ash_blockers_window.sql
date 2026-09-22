-- name: ash_blockers_window
-- desc: Sessions that blocked others most often in a window (ASH, Diagnostics Pack)
-- scope: pdb
-- pack: diagnostics
-- params: from_ts:str, to_ts:str, top:int=20
select * from (
  select blocking_session, blocking_session_serial#, count(*) as blocked_samples,
         count(distinct session_id) as blocked_sessions, max(event) as sample_event
    from v$active_session_history
   where blocking_session is not null
     and sample_time between to_timestamp(:from_ts, 'YYYY-MM-DD HH24:MI:SS')
                         and to_timestamp(:to_ts, 'YYYY-MM-DD HH24:MI:SS')
   group by blocking_session, blocking_session_serial#
   order by blocked_samples desc)
 where rownum <= :top

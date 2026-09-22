-- name: awr_snapshots_window
-- desc: AWR snapshots covering a window (Diagnostics Pack)
-- scope: cdb
-- pack: diagnostics
-- params: from_ts:str, to_ts:str
select snap_id, instance_number, begin_interval_time, end_interval_time, startup_time
  from dba_hist_snapshot
 where end_interval_time >= to_timestamp(:from_ts, 'YYYY-MM-DD HH24:MI:SS')
   and begin_interval_time <= to_timestamp(:to_ts, 'YYYY-MM-DD HH24:MI:SS')
 order by snap_id

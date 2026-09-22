-- name: diag_trace_files
-- desc: Trace files modified in the last N hours (V$DIAG_TRACE_FILE)
-- scope: cdb
-- pack: none
-- params: since_hours:int=24
select adr_home, trace_filename, modify_time, con_id
  from v$diag_trace_file
 where modify_time > systimestamp - numtodsinterval(:since_hours, 'HOUR')
 order by modify_time desc

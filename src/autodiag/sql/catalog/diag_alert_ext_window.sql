-- name: diag_alert_ext_window
-- desc: Alert-log entries in a time window from the XML alert log (V$DIAG_ALERT_EXT); timestamps are 'YYYY-MM-DD HH24:MI:SS' in UTC
-- scope: cdb
-- pack: none
-- params: from_ts:str, to_ts:str
select originating_timestamp, message_type, message_level, message_group, problem_key,
       con_id, process_id, message_text
  from v$diag_alert_ext
 where originating_timestamp between to_timestamp_tz(:from_ts || ' +00:00', 'YYYY-MM-DD HH24:MI:SS TZH:TZM')
                                 and to_timestamp_tz(:to_ts || ' +00:00', 'YYYY-MM-DD HH24:MI:SS TZH:TZM')
 order by originating_timestamp

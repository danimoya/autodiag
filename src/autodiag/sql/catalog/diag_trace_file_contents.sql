-- name: diag_trace_file_contents
-- desc: Lines of a trace file read through the database (V$DIAG_TRACE_FILE_CONTENTS), no SSH needed
-- scope: cdb
-- pack: none
-- params: adr_home:str, trace_filename:str, line_from:int=1, line_to:int=2000
select line_number, timestamp, section_name, payload
  from v$diag_trace_file_contents
 where adr_home = :adr_home
   and trace_filename = :trace_filename
   and line_number between :line_from and :line_to
 order by line_number

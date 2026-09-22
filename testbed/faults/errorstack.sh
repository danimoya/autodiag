#!/usr/bin/env bash
# Errorstack level 3 dump of the current session (call stack without an incident).
. "$(dirname "$0")/_lib.sh"
trace=$(tb_sysdba <<SQL | grep -E '\.trc' | tail -1 | tr -d ' '
set heading off feedback off pagesize 0
alter session set container = $TB_PDB;
alter session set tracefile_identifier = 'AUTODIAG_ERRORSTACK';
select count(*) from autodiag_test.orders where customer_id = 42;
alter session set events 'immediate trace name errorstack level 3';
select value from v\$diag_info where name = 'Default Trace File';
exit
SQL
)
# a level-3 dump may continue into <name>_1.trc, <name>_2.trc ...
if [ -n "$trace" ] && tb_run "grep -qE 'Error Stack Dump|Call Stack Trace' ${trace%.trc}*.trc"; then
    tb_report errorstack "errorstack" "" "$trace" ok
else
    tb_report errorstack "errorstack" "" "$trace" MISSING; exit 1
fi

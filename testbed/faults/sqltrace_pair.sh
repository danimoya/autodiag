#!/usr/bin/env bash
# Two 10046 level-12 traces of the same workload: NORMAL (index visible) and ANOMALY
# (customer index invisible -> full scans). Used by the SQL-trace profile diff.
. "$(dirname "$0")/_lib.sh"
run_trace() {
    tb_testuser <<SQL | grep -E '\.trc' | tail -1 | tr -d ' '
set heading off feedback off pagesize 0
alter session set tracefile_identifier = 'AUTODIAG_$1';
alter session set events '10046 trace name context forever, level 12';
exec pkg_orders.run_workload(200)
alter session set events '10046 trace name context off';
select value from v\$diag_info where name = 'Default Trace File';
exit
SQL
}
toggle() {
    tb_sysdba <<SQL >/dev/null
alter session set container = $TB_PDB;
exec autodiag_test.pkg_orders.slow_toggle($1)
exit
SQL
}
toggle false
normal=$(run_trace NORMAL)
toggle true
anomaly=$(run_trace ANOMALY)
toggle false
if [ -n "$normal" ] && [ -n "$anomaly" ] && tb_run "grep -q 'PARSING IN CURSOR' $normal && grep -q 'PARSING IN CURSOR' $anomaly"; then
    tb_report sqltrace_pair "10046" "" "$normal $anomaly" ok
else
    tb_report sqltrace_pair "10046" "" "$normal $anomaly" MISSING; exit 1
fi

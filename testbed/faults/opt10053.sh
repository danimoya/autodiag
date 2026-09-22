#!/usr/bin/env bash
# 10053 optimizer trace of a fresh (uniquely commented) query.
. "$(dirname "$0")/_lib.sh"
tag=$(date +%s)
trace=$(tb_testuser <<SQL | grep -E '\.trc' | tail -1 | tr -d ' '
set heading off feedback off pagesize 0
alter session set tracefile_identifier = 'AUTODIAG_10053';
alter session set events '10053 trace name context forever, level 1';
select /* autodiag_10053_$tag */ count(*) from orders o join order_items oi on oi.order_id = o.order_id
 where o.customer_id between 10 and 20;
alter session set events '10053 trace name context off';
select value from v\$diag_info where name = 'Default Trace File';
exit
SQL
)
if [ -n "$trace" ] && tb_run "grep -q 'PARAMETERS USED BY THE OPTIMIZER' $trace"; then
    tb_report opt10053 "10053" "" "$trace" ok
else
    tb_report opt10053 "10053" "" "$trace" MISSING; exit 1
fi

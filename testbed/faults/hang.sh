#!/usr/bin/env bash
# Blocker/waiter on one row, then hanganalyze level 3 + systemstate 266 as SYSDBA.
. "$(dirname "$0")/_lib.sh"
tb_put /tmp/autodiag_hold.sql <<'SQL'
update lock_demo set val = 'held' where id = 1;
exec dbms_session.sleep(40)
rollback;
exit
SQL
tb_put /tmp/autodiag_wait.sql <<'SQL'
update lock_demo set val = 'wait' where id = 1;
rollback;
exit
SQL
tb_bg "sqlplus -s $TB_CONNECT @/tmp/autodiag_hold.sql" /tmp/autodiag_hold.log
sleep 4
tb_bg "sqlplus -s $TB_CONNECT @/tmp/autodiag_wait.sql" /tmp/autodiag_wait.log
sleep 6
trace=$(tb_sysdba <<'SQL' | grep -E '\.trc' | tail -1 | tr -d ' '
oradebug setmypid
oradebug unlimit
oradebug hanganalyze 3
oradebug dump systemstate 266
oradebug tracefile_name
exit
SQL
)
if [ -n "$trace" ] && tb_run "grep -q 'HANG ANALYSIS' $trace && grep -q 'SYSTEM STATE' $trace"; then
    tb_report hang "hanganalyze+systemstate" "" "$trace" ok
else
    tb_report hang "hanganalyze+systemstate" "" "$trace" MISSING; exit 1
fi

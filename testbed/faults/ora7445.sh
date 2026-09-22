#!/usr/bin/env bash
# ORA-7445: send SIGSEGV to a busy foreground process of the test user. Oracle's signal
# handler turns it into ORA-07445 [<func>()+n] [SIGSEGV] with a call stack and incident.
. "$(dirname "$0")/_lib.sh"
before=$(tb_incident_ids)
tb_put /tmp/autodiag_busy.sql <<'SQL'
exec pkg_orders.busy_loop(120)
exit
SQL
tb_bg "sqlplus -s $TB_CONNECT @/tmp/autodiag_busy.sql" /tmp/autodiag_busy.log
sleep 6
spid=$(tb_sysdba <<SQL | tr -d ' \n'
set heading off feedback off pagesize 0
select max(p.spid) from v\$session s join v\$process p on p.addr = s.paddr
 where s.username = 'AUTODIAG_TEST' and s.status = 'ACTIVE';
exit
SQL
)
if [ -z "$spid" ]; then tb_report ora7445 "ORA 7445" "" "" "MISSING(no busy session)"; exit 1; fi
tb_run "kill -SEGV $spid"
new=$(tb_wait_incident "$before" 60)
if [ -n "$new" ]; then
    tb_report ora7445 "$(tb_key_for "$new")" "$new" "$(tb_traces_for "$new")" ok
else
    tb_report ora7445 "ORA 7445" "" "" "MISSING(spid=$spid)"; exit 1
fi

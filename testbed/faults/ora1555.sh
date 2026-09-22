#!/usr/bin/env bash
# ORA-1555 (best effort): tiny undo tablespace + undo_retention=1, a slow consistent
# read over ORDERS while another session churns undo with update/commit loops.
. "$(dirname "$0")/_lib.sh"
dir=$(tb_datafile_dir); UNDO="${dir}autodiag_undo_tiny01.dbf"
before_len=$(tb_alert_len)
orig_undo=$(tb_sysdba <<SQL | tr -d ' \n'
set heading off feedback off pagesize 0
alter session set container = $TB_PDB;
select value from v\$parameter where name = 'undo_tablespace';
exit
SQL
)
tb_sysdba <<SQL >/dev/null
alter session set container = $TB_PDB;
create undo tablespace undo_tiny datafile '$UNDO' size 8M autoextend off;
alter system set undo_tablespace = undo_tiny scope = memory;
alter system set undo_retention = 1 scope = memory;
exit
SQL
tb_put /tmp/autodiag_scan.sql <<'SQL'
exec pkg_orders.slow_scan(90)
exit
SQL
tb_put /tmp/autodiag_churn.sql <<'SQL'
begin
  for i in 1 .. 300 loop
    update orders set amount = amount + 0.01 where mod(order_id, 5) = i mod 5;
    commit;
  end loop;
end;
/
exit
SQL
tb_bg "sqlplus -s $TB_CONNECT @/tmp/autodiag_scan.sql" /tmp/autodiag_scan.log
sleep 3
tb_run "sqlplus -s $TB_CONNECT @/tmp/autodiag_churn.sql > /tmp/autodiag_churn.log 2>&1" || true
sleep 5
scan=$(tb_run "cat /tmp/autodiag_scan.log 2>/dev/null")
lines=$(tb_alert_since "$before_len")
tb_sysdba <<SQL >/dev/null
alter session set container = $TB_PDB;
alter system set undo_tablespace = $orig_undo scope = memory;
alter system set undo_retention = 900 scope = memory;
exit
SQL
for i in 1 2 3 4 5 6; do
    if tb_sysdba <<SQL | grep -q 'dropped'; then break; fi
alter session set container = $TB_PDB;
drop tablespace undo_tiny including contents and datafiles;
exit
SQL
    sleep 10
done
if grep -q 'ORA-01555' <<< "$scan$lines"; then
    tb_report ora1555 "ORA-01555" "" "$(grep -oE '/[^ ]+\.trc' <<< "$lines" | head -1)" ok
else
    tb_report ora1555 "ORA-01555" "" "" "UNPROVEN(best effort)"; exit 1
fi

#!/usr/bin/env bash
# ORA-60 deadlock between two sessions (alert-log entry + deadlock trace, no incident).
. "$(dirname "$0")/_lib.sh"
before_len=$(tb_alert_len)
tb_put /tmp/autodiag_dl_a.sql <<'SQL'
exec pkg_orders.deadlock_a
exit
SQL
tb_put /tmp/autodiag_dl_b.sql <<'SQL'
exec pkg_orders.deadlock_b
exit
SQL
tb_run "sqlplus -s $TB_CONNECT @/tmp/autodiag_dl_a.sql > /tmp/autodiag_dl_a.log 2>&1 &
        sqlplus -s $TB_CONNECT @/tmp/autodiag_dl_b.sql > /tmp/autodiag_dl_b.log 2>&1 & wait" || true
sleep 3
lines=$(tb_alert_since "$before_len")
trace=$(grep -oE '/[^ ]+\.trc' <<< "$lines" | head -1)
if grep -q 'ORA-00060' <<< "$lines"; then
    tb_report ora60 "ORA-00060" "" "$trace" ok
else
    tb_report ora60 "ORA-00060" "" "" MISSING; exit 1
fi

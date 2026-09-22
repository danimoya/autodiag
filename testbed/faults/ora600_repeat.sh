#!/usr/bin/env bash
# Three ORA-600 incidents sharing one problem key (for stack-frequency analysis).
. "$(dirname "$0")/_lib.sh"
ARG="${1:-autodiag_repeat}"
before=$(tb_incident_ids)
for i in 1 2 3; do
    tb_sysdba <<SQL >/dev/null 2>&1
oradebug setmypid
oradebug unit_test dbke_test dde_flow_kge_ora $ARG $i 0
exit
SQL
    sleep 3
done
new=$(tb_wait_incident "$before" 30)
n=$(wc -w <<< "$new")
if [ "$n" -ge 2 ]; then
    tb_report ora600_repeat "$(tb_key_for "$new")" "$new" "$(tb_traces_for "$new")" "ok(count=$n)"
else
    tb_report ora600_repeat "ORA 600 [$ARG]" "$new" "" "MISSING(count=$n)"; exit 1
fi

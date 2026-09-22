#!/usr/bin/env bash
# Real ORA-600 with an ADR incident, via the DDE unit test hook (as SYSDBA).
. "$(dirname "$0")/_lib.sh"
ARG="${1:-autodiag_test}"; NAME="${2:-ora600}"
before=$(tb_incident_ids)
tb_sysdba <<SQL >/dev/null 2>&1
oradebug setmypid
oradebug unit_test dbke_test dde_flow_kge_ora $ARG 0 0
exit
SQL
new=$(tb_wait_incident "$before" 30)
if [ -n "$new" ]; then
    tb_report "$NAME" "$(tb_key_for "$new")" "$new" "$(tb_traces_for "$new")" ok
else
    tb_report "$NAME" "ORA 600 [$ARG]" "" "" MISSING; exit 1
fi

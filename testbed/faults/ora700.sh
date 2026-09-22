#!/usr/bin/env bash
# ORA-700 "soft" internal error with an incident (DDE soft assert hook).
. "$(dirname "$0")/_lib.sh"
before=$(tb_incident_ids)
tb_sysdba <<'SQL' >/dev/null 2>&1
oradebug setmypid
oradebug unit_test dbke_test dde_flow_kge_soft foo bar baz
exit
SQL
new=$(tb_wait_incident "$before" 30)
if [ -n "$new" ]; then
    tb_report ora700 "$(tb_key_for "$new")" "$new" "$(tb_traces_for "$new")" ok
else
    tb_report ora700 "ORA 700 [foo]" "" "" MISSING; exit 1
fi

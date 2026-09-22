#!/usr/bin/env bash
# Shared helpers for the fault-injection kit. Source this from each fault script.
# Every script prints one proof line:
#   AUTODIAG_FAULT name=<n> problem_key="<k>" incident_ids=[..] traces=[..] status=<ok|MISSING|...>
set -uo pipefail
FAULTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTBED_DIR="$(dirname "$FAULTS_DIR")"
OUT_DIR="${AUTODIAG_FAULT_OUT:-$FAULTS_DIR/out}"
mkdir -p "$OUT_DIR"
if [ -f "$TESTBED_DIR/.env" ]; then set -a; . "$TESTBED_DIR/.env"; set +a; fi

TB_HOST="${AUTODIAG_TESTBED_HOST:-autodiag-testbed}"
TB_SSH_CONFIG="${AUTODIAG_SSH_CONFIG:-$TESTBED_DIR/ssh_config}"
TB_ADR_BASE="${AUTODIAG_ADR_BASE:-/opt/oracle}"
TB_ADR_HOME="${AUTODIAG_ADR_HOME:-diag/rdbms/free/FREE}"
TB_INSTANCE="${AUTODIAG_INSTANCE:-FREE}"
TB_PDB="${AUTODIAG_PDB:-FREEPDB1}"
TB_TEST_USER="autodiag_test"
TB_TEST_PWD="${AUTODIAG_TEST_PWD:-AutoDiag_Test_1}"
TB_CONNECT="$TB_TEST_USER/\"$TB_TEST_PWD\"@//localhost:1521/$TB_PDB"

tb_ssh()      { ssh -F "$TB_SSH_CONFIG" "$TB_HOST" "$@"; }
tb_run()      { tb_ssh ". ~/.autodiag_env 2>/dev/null; $*"; }
tb_put()      { tb_ssh "cat > $1"; }                       # stdin -> remote file
tb_sysdba()   { tb_run "sqlplus -s / as sysdba"; }         # stdin -> SQL*Plus as SYSDBA
tb_testuser() { tb_run "sqlplus -s $TB_CONNECT"; }         # stdin -> SQL*Plus as test user
tb_bg()       { tb_run "nohup bash -c '$1' > ${2:-/dev/null} 2>&1 &"; }
tb_adrci()    { tb_run "adrci exec=\"set home $TB_ADR_HOME; $1\""; }

# adrci prints incidents either as a fixed-width table (INCIDENT_ID first column) or as
# "INCIDENT INFO RECORD" key/value blocks (23ai); handle both, ignore the "rows fetched" footer.
tb_incident_ids() {
    tb_adrci "show incident -mode brief" \
      | awk '/^ +INCIDENT_ID +[0-9]+/ {print $2; next} /^[0-9]+[[:space:]]/ && !/rows fetched/ {print $1}' \
      | sort -n
}
tb_new_ids()      { comm -13 <(echo "$1" | sort -n) <(echo "$2" | sort -n) | tr '\n' ' ' | sed 's/ *$//'; }
tb_problem_key()  {
    tb_adrci "show incident -mode detail -p \"incident_id=$1\"" \
      | awk '/^ +PROBLEM_KEY +/ {sub(/^ +PROBLEM_KEY +/, ""); print; exit}'
}
tb_incident_trace() { tb_run "ls $TB_ADR_BASE/$TB_ADR_HOME/incident/incdir_$1/*.trc 2>/dev/null | head -1"; }
tb_alert_log()      { echo "$TB_ADR_BASE/$TB_ADR_HOME/trace/alert_$TB_INSTANCE.log"; }
tb_alert_len()      { tb_run "wc -l < $(tb_alert_log)" | tr -d ' '; }
tb_alert_since()    { tb_run "tail -n +$(( $1 + 1 )) $(tb_alert_log)"; }

# Poll ADR for incidents that were not in "$1" (max $2 seconds); prints the new ids.
tb_wait_incident() {
    local before="$1" limit="${2:-30}" new="" i
    for ((i = 0; i < limit; i += 2)); do
        new=$(tb_new_ids "$before" "$(tb_incident_ids)")
        [ -n "$new" ] && break
        sleep 2
    done
    echo "$new"
}
tb_traces_for() { local t=""; for id in $1; do t="$t $(tb_incident_trace "$id")"; done; echo "${t# }"; }
tb_key_for()    { for id in $1; do tb_problem_key "$id"; return; done; }

tb_report() {
    local line="AUTODIAG_FAULT name=$1 problem_key=\"$2\" incident_ids=[$3] traces=[$4] status=${5:-ok}"
    echo "$line"
    echo "$line" >> "$OUT_DIR/faults.log"
}
tb_datafile_dir() {
    tb_sysdba <<SQL | tr -d ' \n'
set heading off feedback off pagesize 0
alter session set container = $TB_PDB;
select regexp_replace(file_name, '[^/]+\$', '') from dba_data_files where rownum = 1;
exit
SQL
}

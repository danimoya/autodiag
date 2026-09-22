#!/usr/bin/env bash
# Startup hook: the pre-built Free image never runs the one-time setup directory, so
# create the diagnostic user and test schema on first start (idempotent check).
set -u
n=$("$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<'SQL' | tr -d ' \n'
set heading off feedback off pagesize 0
select count(*) from dba_users where username = 'C##AUTODIAG';
exit
SQL
)
if [ "$n" = "0" ]; then
    echo "autodiag: running one-time setup"
    /opt/oracle/scripts/setup/01_users.sh
    # The Free edition ships with ORADEBUG disabled (ORA-32519). The fault kit needs it to
    # raise ORA-600/ORA-700 test incidents. The parameter is static, so bounce once.
    if [ "${AUTODIAG_ENABLE_ORADEBUG:-true}" = "true" ]; then
        echo "autodiag: enabling oradebug for the fault kit (instance restart)"
        "$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<'SQL'
alter system set "_disable_oradebug_commands" = none scope = spfile;
shutdown immediate
startup
exit
SQL
    fi
else
    echo "autodiag: setup already done"
fi

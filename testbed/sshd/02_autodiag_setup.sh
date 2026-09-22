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
else
    echo "autodiag: setup already done"
fi

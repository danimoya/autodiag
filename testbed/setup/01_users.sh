#!/usr/bin/env bash
# Setup hook (runs once when the database is first created, as the oracle user).
# Creates the read-only diagnostic user and the AUTODIAG_TEST schema with data.
set -euo pipefail
AUTODIAG_USER_PWD="${AUTODIAG_USER_PWD:-AutoDiag_Ro_1}"
AUTODIAG_TEST_PWD="${AUTODIAG_TEST_PWD:-AutoDiag_Test_1}"
D=/opt/oracle/scripts/setup/sql
for f in 01_users.sql 02_schema.sql 03_data.sql 04_pkg.sql; do
    echo "autodiag setup: $f"
    "$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<SQL
WHENEVER SQLERROR EXIT SQL.SQLCODE
@$D/$f "$AUTODIAG_USER_PWD" "$AUTODIAG_TEST_PWD"
EXIT
SQL
done
echo "autodiag setup: done"

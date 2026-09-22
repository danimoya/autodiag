# The read-only diagnostic database user

AutoDiag queries each database over SQL*Net with a dedicated account that can read
diagnostic views and nothing else. The testbed creates it as `C##AUTODIAG`
(`testbed/setup/sql/01_users.sql`); production databases need the same grants.

## Why a common user

ADR (`V$DIAG_*`), patch inventory (`DBA_REGISTRY_SQLPATCH`), instance-wide waits and the
alert log are instance-level, so the account is created in `CDB$ROOT` with
`CONTAINER=ALL`. PDB-scoped views (ASH, AWR, sessions of one PDB) are reached with
`ALTER SESSION SET CONTAINER`, which is why `SET CONTAINER` is granted. AutoDiag only
switches container for catalog queries marked `scope: pdb`.

## Which service to connect to

Connect the diagnostic user to the **CDB root service** (the database service, not a PDB
service). `V$DIAG_PROBLEM`, `V$DIAG_INCIDENT` and the alert-log views are filtered by
container: a session in a PDB sees only that PDB's incidents and none of the CDB-level
ones (background processes, instance-wide problems). AutoDiag switches to a PDB with
`ALTER SESSION SET CONTAINER` only for queries marked `scope: pdb`.

## Grants

```sql
CREATE USER c##autodiag IDENTIFIED BY "<password>" CONTAINER=ALL;
GRANT CREATE SESSION, SET CONTAINER, SELECT_CATALOG_ROLE TO c##autodiag CONTAINER=ALL;
-- Explicit READ grants keep the tool working where roles are disabled in some contexts.
GRANT READ ON sys.v_$diag_info, sys.v_$diag_problem, sys.v_$diag_incident,
              sys.v_$diag_alert_ext, sys.v_$diag_trace_file,
              sys.v_$diag_trace_file_contents, sys.v_$active_session_history,
              sys.v_$session, sys.v_$process, sys.v_$system_event, sys.v_$sql,
              sys.v_$cell, sys.dba_hist_snapshot, sys.dba_hist_sqlstat,
              sys.dba_hist_sql_plan, sys.dba_hist_system_event,
              sys.dba_hist_active_sess_history, sys.dba_registry_sqlpatch
   TO c##autodiag CONTAINER=ALL;
```

`V$ACTIVE_SESSION_HISTORY` and `DBA_HIST_*` require the Diagnostics Pack
(`control_management_pack_access = DIAGNOSTIC+TUNING`). On databases without the pack,
set `diagnostics_pack: false` on the target and AutoDiag skips those queries.

## PDB-local alternative

Sites that do not allow common users can create a local `AUTODIAG` user inside each PDB
with the same grants (without `CONTAINER=ALL`). ADR and instance-level views remain
readable from a PDB, but the account then sees only that PDB's sessions and history.

## Password handling

AutoDiag never stores passwords in its database or configuration files. Each target
names an environment variable (`password_env`) or an Oracle wallet; see
`docs/architecture.md`.

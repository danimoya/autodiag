-- &1 = password of the common read-only diagnostic user, &2 = password of the test schema
SET VERIFY OFF FEEDBACK OFF
DEFINE autodiag_pwd = &1
DEFINE test_pwd = &2

ALTER SESSION SET CONTAINER = CDB$ROOT;
-- Common user: ADR, incidents, patches and instance-wide waits are instance-level.
CREATE USER c##autodiag IDENTIFIED BY "&autodiag_pwd" CONTAINER=ALL;
GRANT CREATE SESSION, SET CONTAINER, SELECT_CATALOG_ROLE TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.v_$diag_info                 TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.v_$diag_problem              TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.v_$diag_incident             TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.v_$diag_alert_ext            TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.v_$diag_trace_file           TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.v_$diag_trace_file_contents  TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.v_$active_session_history    TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.v_$session                   TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.v_$process                   TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.v_$system_event              TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.v_$sql                       TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.v_$cell                      TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.dba_hist_snapshot            TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.dba_hist_sqlstat             TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.dba_hist_sql_plan            TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.dba_hist_system_event        TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.dba_hist_active_sess_history TO c##autodiag CONTAINER=ALL;
GRANT READ ON sys.dba_registry_sqlpatch        TO c##autodiag CONTAINER=ALL;

ALTER SESSION SET CONTAINER = FREEPDB1;
CREATE USER autodiag_test IDENTIFIED BY "&test_pwd"
    DEFAULT TABLESPACE users QUOTA UNLIMITED ON users;
GRANT CREATE SESSION, ALTER SESSION, CREATE TABLE, CREATE PROCEDURE, CREATE SEQUENCE
    TO autodiag_test;
GRANT READ ON sys.v_$diag_info TO autodiag_test;
GRANT READ ON sys.v_$session   TO autodiag_test;
GRANT EXECUTE ON sys.dbms_session TO autodiag_test;

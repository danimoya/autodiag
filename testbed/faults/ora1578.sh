#!/usr/bin/env bash
# ORA-1578 block corruption: overwrite part of a data block of a throwaway table with
# random bytes, then read it. The tablespace is dropped afterwards.
. "$(dirname "$0")/_lib.sh"
dir=$(tb_datafile_dir); DBF="${dir}autodiag_corrupt01.dbf"
before=$(tb_incident_ids); before_len=$(tb_alert_len)
tb_sysdba <<SQL >/dev/null
alter session set container = $TB_PDB;
create tablespace autodiag_corrupt datafile '$DBF' size 32M;
create table autodiag_test.corrupt_me tablespace autodiag_corrupt as
  select level id, rpad('x', 200, 'x') pad from dual connect by level <= 5000;
alter system checkpoint;
exit
SQL
read -r blk bsz < <(tb_sysdba <<SQL | tr -s ' \n' ' '
set heading off feedback off pagesize 0
alter session set container = $TB_PDB;
select dbms_rowid.rowid_block_number(rowid), (select value from v\$parameter where name = 'db_block_size')
  from autodiag_test.corrupt_me where id = 100;
exit
SQL
)
tb_sysdba <<'SQL' >/dev/null
alter system checkpoint;
alter system flush buffer_cache;
exit
SQL
tb_run "dd if=/dev/urandom of=$DBF bs=1 seek=\$(( $blk * $bsz + 64 )) count=200 conv=notrunc 2>/dev/null"
out=$(tb_sysdba <<SQL
alter session set container = $TB_PDB;
select count(*) from autodiag_test.corrupt_me;
exit
SQL
)
sleep 2
new=$(tb_new_ids "$before" "$(tb_incident_ids)")
lines=$(tb_alert_since "$before_len")
trace=$(grep -oE '/[^ ]+\.trc' <<< "$lines" | head -1)
tb_sysdba <<SQL >/dev/null
alter session set container = $TB_PDB;
drop tablespace autodiag_corrupt including contents and datafiles;
exit
SQL
if grep -q 'ORA-01578' <<< "$out"; then
    tb_report ora1578 "ORA-01578 block $blk" "$new" "$(tb_traces_for "$new") $trace" ok
else
    tb_report ora1578 "ORA-01578" "$new" "$trace" MISSING; exit 1
fi

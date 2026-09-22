-- name: exa_offload_by_sql
-- desc: Smart scan offload efficiency per SQL from V$SQL (Exadata columns)
-- scope: pdb
-- pack: none
-- params: top:int=20
select * from (
  select sql_id, plan_hash_value, executions, elapsed_time / 1e6 as elapsed_s,
         io_cell_offload_eligible_bytes, io_interconnect_bytes, io_cell_uncompressed_bytes,
         optimized_phy_read_requests, physical_read_requests
    from v$sql
   where io_cell_offload_eligible_bytes > 0
   order by io_cell_offload_eligible_bytes desc)
 where rownum <= :top

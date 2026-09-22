-- name: params_nondefault
-- desc: Non-default instance parameters (V$PARAMETER)
-- scope: cdb
-- pack: none
-- params:
select name, value, ismodified, isdefault
  from v$parameter
 where isdefault = 'FALSE' or ismodified <> 'FALSE'
 order by name

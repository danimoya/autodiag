---
description: Compare a normal and an anomalous 10046 trace (autodiag)
agent: autodiag-triage
---
Load the autodiag-oracle skill. Run the performance playbook on 10046 trace artifacts
`$1` (normal) and `$2` (anomaly): `sql_trace_profile` on both, `compare_sql_profiles`,
then interpret the tags and wait deltas. Record findings in the case with evidence ids.

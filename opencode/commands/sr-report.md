---
description: Draft the Oracle Support SR for a case (autodiag)
agent: autodiag-triage
---
Load the autodiag-oracle skill. For case `$1`: `get_case`, make sure environment facts are
captured (`capture_environment`), then `render_report(case_id, "sr")`. Show the DBA the
`<fill in>` placeholders they must complete and offer `create_ips_package` for the
problem.

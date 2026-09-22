---
description: Compare the call stacks of two incident artifacts (autodiag)
agent: autodiag-triage
---
Load the autodiag-oracle skill. Compare incident artifacts `$1` (left / earlier or
baseline) and `$2` (right / anomaly) with `compare_call_stacks`, then `get_call_stack`
on each if you need details, and `kb_lookup` with the divergent frames. Explain where and
in which kernel component the stacks diverge and what that suggests.

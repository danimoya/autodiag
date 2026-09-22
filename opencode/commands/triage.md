---
description: Triage an ADR problem key on a target (autodiag)
agent: autodiag-triage
---
Load the autodiag-oracle skill. Run the ADR problem playbook for target `$1` and problem
key `$2` (if `$2` is empty, list the problems of `$1` first and pick the most recent).
Start with `standard_triage`, then decide the next tool calls. Record findings with
evidence ids in the case and finish with the answer format from the skill.

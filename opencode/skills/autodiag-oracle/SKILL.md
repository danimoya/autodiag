---
name: autodiag-oracle
description: Use when diagnosing Oracle Database problems (ADR incidents, ORA-600/ORA-7445, trace files, alert logs, deadlocks, hangs, slow SQL) on ExaCC or any Oracle 19c/23ai database; drives the autodiag MCP tools and produces evidence-backed findings and an SR draft.
---

# AutoDiag Oracle diagnostics playbook

You investigate Oracle Database problems with the `autodiag` MCP tools. The tools do the
deterministic work (adrci, parsing, statistics, diffs, knowledge base); you interpret,
form hypotheses, decide the next tool call and write findings. Never guess a fact a tool
can establish.

## Rules

1. Every finding must cite `evidence_id` values returned by tools (`add_finding` rejects
   findings without evidence). Quote the evidence, don't paraphrase numbers from memory.
2. Outputs are capped (200 lines / 16 KiB by default). Page with `offset` / `max_lines`
   and only ask for raw lines (`read_trace_lines`) when a summary is not enough. Never
   pull more than 200 raw lines without saying why.
3. Only quote My Oracle Support material that the knowledge base returned (`mos_search`
   strings). Do not invent note or bug numbers. Say "unknown" when a fact is unknown.
4. Suggest actions; never propose destructive commands (drop, delete, kill instance,
   clear logs). Restart or patch advice must state prerequisites.
5. Work inside a case: open one (`open_case`) or use the one `standard_triage` created, so
   artifacts, evidence and findings stay together for the report.
6. Data that reaches you may be redacted (`<redacted>`, `<str>`, `<host>`); do not try to
   recover the original values.

## Playbook for an ADR problem (ORA-600 / ORA-7445 / ORA-7xx)

1. `list_targets`, then `list_problems(target)`; pick the problem key.
2. `standard_triage(target, problem_key)`: incidents, newest incident trace summary,
   knowledge-base guidance, alert-log window around it, stack frequency. Read the
   `newest_incident.trace.summary` and `first_app_frame`.
3. If several incidents: `stack_frequency` tells whether the stack is consistent
   (signature frames). Consistent = one bug/path; variable = memory or hardware.
4. If a baseline or older incident exists: `compare_call_stacks(left, right)` and
   explain the divergence frame and components.
5. `alert_log_window(target, t-30min, t+30min, errors_only=true)` for related errors
   (corruption, memory, redo, RAC reconfiguration) seconds before the incident.
6. `run_query(target, "ash_top_events_window" / "ash_top_sql_window", {from_ts, to_ts})`
   around the incident when the Diagnostics Pack is licensed (`list_queries` shows
   `pack: diagnostics`); use `container` for PDB-scoped queries.
7. `kb_lookup(problem_key, frames=<first frames>)` if `standard_triage` did not answer.
8. `capture_environment(target, case_id)` for version and patch level.
9. `add_finding` per hypothesis: kind `root_cause` / `contributing` / `observation` /
   `action`, honest `confidence`, all `evidence_ids`.
10. `render_report(case_id, "dba")`; when the DBA wants to escalate:
    `render_report(case_id, "sr")` and `create_ips_package(target, problem_id, case_id=...)`
    then `job_status(job_id)`.

## Playbook for a performance anomaly (slow SQL, 10046 traces)

1. Get the normal and anomalous 10046 traces as artifacts (`parse_trace` with target+path
   or `add_artifact_to_case` for uploaded files; `list_baselines(target, "sqltrace")`).
2. `sql_trace_profile` on each; then `compare_sql_profiles(normal, anomaly)`.
3. Read `tags` per cursor: `PLAN_CHANGE` (plan hash changed), `IO_INCREASE`,
   `LOGICAL_IO_INCREASE_SAME_PLAN` (stale stats / growth), `HARD_PARSE`,
   `EXEC_COUNT_CHANGE` (application), `NEW_WAIT`, `CONCURRENCY`, `NETWORK`, `ERRORS`.
4. For plan changes: `run_query(target, "sql_plan_history", {sql_id})` and, when
   available, a 10053 trace (`parse_trace`) for optimizer parameters and statistics.
5. Check wait deltas and `kb_lookup(wait_events=[...])` for the meaning of new waits.
6. Findings: what changed, why (evidence), what to do (statistics, index visibility,
   SQL patch/baseline, parameters), and how to verify.

## Playbook for deadlocks, hangs, alert-log noise

- Deadlock: `parse_trace` on the deadlock trace → `classification`, `cycle`, both SQL
  statements and rows waited on. TM locks point to unindexed foreign keys.
- Hang: `parse_trace` on the hanganalyze/systemstate trace → chains, final blocker,
  wait events, short stacks; `run_query blocking_tree_now` for the live picture.
- Alert-log noise: `alert_log_stats(target, hours)` then `compare_alert_rates` between a
  quiet window and the anomaly window; `kb_lookup(alert_signature=<line>)` per top
  signature.

## ExaCC specifics (platform = exacc)

`kb_lookup(..., platform="exacc")` lists Exadata checks: smart scan offload
(`run_query exa_offload_by_sql`), cell wait latencies (`exa_cell_events`), AHF
collection (`collect_ahf`), exachk findings, patch level, RAC correlation
(`list_problems` per node), OSWatcher. Correlate incidents across nodes before blaming
one node.

## Answer format

Summary (2-4 sentences) / Evidence (evidence ids with one line each) / Likely cause
(confidence) / Suggested actions (ordered, with prerequisites) / Open questions.

# MCP tool reference

The MCP server is named `autodiag`. OpenCode shows its tools as `autodiag_<tool>`; the REST
API exposes every tool as `POST /api/v1/tools/<tool>` with the same parameters as a JSON
body (see `docs/gui.md`). Run it with `autodiag mcp stdio` (local agent), `autodiag mcp
http` (HTTP at `/mcp`) or as part of `autodiag serve`.

## Result envelope

Every tool returns a JSON object. On success it carries:

| Field | Meaning |
|---|---|
| `evidence_id` | The call is recorded as evidence in the case store; findings cite this id |
| `truncated` | `true` when the output was cut by a cap; page with `offset` where offered |
| `next_offset` | Where to continue when paging is possible |

On failure it returns `{"error": "<message>", "error_type": "<Python exception name>"}`
instead of raising, so an agent can react. Unknown targets, refused paths, adrci or SQL*Net
failures and store errors all arrive this way.

Caps: text outputs default to `tool_max_lines` (200) lines and `tool_max_bytes` (16 KiB),
hard cap `tool_max_lines_hard_cap` (1000). For targets with `redact: true` (the default)
and `redact_for_llm` on, strings pass through the redaction described in `docs/safety.md`
before they leave the server; paths, ids and versions are kept.

Most tools that touch a target take an optional `case_id`; without it artifacts and
evidence land in the target's scratch case (`scratch: <target>`).

## Automated diagnosis

| Tool | Parameters | Returns |
|---|---|---|
| `diagnose_problem` | `target`, `problem_key` or `incident_id`, `case_id`, `assess=false`, `record=false`, `max_incidents=5`, `max_bytes=24000` | Dossier items (each with an `id` to cite, `kind`, `severity_hint`, `ts`, `node`, `title`, `text`), `noise` counts, `counts`, `stats`, `errors`, the `assessment`, `finding_ids`, a rendered `text` |
| `diagnose_alert` | `target`, `hours=24` or `since`/`until` (ISO 8601), `case_id`, `assess`, `record`, `max_bytes` | same shape |
| `diagnose_instance` | `target`, `days=7`, `hours=24`, `live` (null = auto when SQL*Net is configured), `case_id`, `assess`, `record`, `max_bytes` | same shape |

`assess=false` (the default for agents) returns the rules ranking as `assessment`; the
calling agent is expected to be the assessor and to cite item ids. `assess=true` asks the
local Ollama model and returns its verified assessment (`model`, `proofs_total`,
`proofs_verified`, `grounded`, `notes`). `record=true` stores proven concerns as findings.
`max_bytes` trims item texts to fit the caller's output limit (OpenCode truncates tool
output at 50 KB); omitted texts say so and remain readable through `get_case` evidence.

`standard_triage` (`target`, `problem_key`, `case_id`) is the older deterministic first pass
(incidents, newest trace summary, KB, alert window, stack frequency); `diagnose_problem`
supersedes it.

## Targets and ADR

| Tool | Parameters | Returns |
|---|---|---|
| `list_targets` | – | name, kind, platform, version, nodes, whether SQL*Net is configured |
| `list_problems` | `target`, `since_hours=168`, `offset=0`, `limit=50` | ADR problems (`adrci show problem`) across the target's nodes |
| `list_incidents` | `target`, `problem_id` or `problem_key`, `limit=50` | incidents of one problem; a key is resolved to ids first |
| `get_incident` | `target`, `incident_id`, `case_id` | adrci detail plus the parsed incident trace, fetched into the case as an artifact |
| `capture_environment` | `target`, `case_id` | version, opatch and SQL patch registry, non-default parameters, instances, node facts |
| `create_ips_package` | `target`, `problem_id` or `incident_id`, `case_id` | starts a job: `adrci ips create` + `ips generate`; the zip is fetched into the case |
| `collect_ahf` | `target`, `from_ts`, `to_ts`, `case_id` | starts a job: `tfactl diagcollect` on the first node; output stays on the node |
| `job_status` | `job_id` | status and result of a job |

## Alert log

| Tool | Parameters | Returns |
|---|---|---|
| `alert_log_window` | `target`, `from_ts`, `to_ts`, `offset=0`, `max_lines=200`, `errors_only=false` | entries in the window, paged |
| `alert_log_grep` | `target`, `pattern`, `context=3`, `max_lines=200` | remote fixed-string grep with line numbers; nothing is copied |
| `alert_log_stats` | `target`, `hours=24`, `top=30` | ORA histogram, top normalised signatures, per-hour counts, lifecycle events |
| `compare_alert_rates` | `target`, `from_a`, `to_a`, `from_b`, `to_b`, `top=30` | per-signature rate ratios between two windows, new and vanished messages |
| `timeline` | `case_id` or `target` + `from_ts`/`to_ts`, `max_items=200` | ordered alert-log errors and incidents |

## Traces

| Tool | Parameters | Returns |
|---|---|---|
| `parse_trace` | `artifact_id`, or `target` + `path` (+ `case_id`) | kind (incident, 10046, 10053, deadlock, hang, systemstate, errorstack), header, sections, summary specific to the kind |
| `read_trace_lines` | `artifact_id`, `offset=0`, `max_lines=200`, `grep` | raw lines of a stored artifact, paged, optional fixed-string filter |
| `get_call_stack` | `artifact_id` | normalised kernel stack of an incident trace (prelude removed) with components |
| `sql_trace_profile` | `artifact_id`, `top=20` | tkprof-style profile of a 10046 trace: totals, top cursors, top waits; bind values never stored |

## Comparisons

| Tool | Parameters | Returns |
|---|---|---|
| `compare_call_stacks` | `left_artifact`, `right_artifact` | aligned frames, similarity, divergence index, unique frames, first application frames and components |
| `stack_frequency` | `artifact_ids` | share of incidents containing each frame; signature frames appear in at least 80 % |
| `compare_sql_profiles` | `left_artifact`, `right_artifact`, `top=15` | per-sql_id deltas and ratios, plan changes, tags, wait deltas, explanation hints |
| `kb_lookup` | `problem_key`, `frames`, `alert_signature`, `wait_events`, `platform` | knowledge-base hits: meaning, typical causes, checks, actions, a My Oracle Support search string |

## SQL over SQL*Net

| Tool | Parameters | Returns |
|---|---|---|
| `list_queries` | – | the catalog below with parameters, scope and pack |
| `run_query` | `target`, `name`, `params`, `container`, `max_rows=200` | rows of one catalog query, run as the read-only user; `container` switches to a PDB only for `scope: pdb` queries |

The catalog (`src/autodiag/sql/catalog/*.sql`). `pack: diagnostics` queries are refused
when the target has `diagnostics_pack: false`.

| Query | Scope | Pack | Parameters | What it returns |
|---|---|---|---|---|
| `db_info` | cdb | none | – | database and instance identity, version, role, startup time, host |
| `diag_info` | cdb | none | – | ADR locations of the instance |
| `diag_problems` | cdb | none | `since_hours=168` | V$DIAG_PROBLEM rows with a recent incident |
| `diag_incidents` | pdb | none | `problem_id` | incidents of one problem (V$DIAG_INCIDENT) |
| `diag_incident_detail` | pdb | none | `incident_id` | all columns of one incident |
| `diag_trace_files` | cdb | none | `since_hours=24` | trace files modified recently (V$DIAG_TRACE_FILE) |
| `diag_trace_file_contents` | pdb | none | `adr_home`, `trace_filename`, `line_from=1`, `line_to=2000` | trace lines read through the database, no SSH needed |
| `diag_alert_ext_window` | cdb | none | `from_ts`, `to_ts` | XML alert-log entries in a window (V$DIAG_ALERT_EXT) |
| `pdbs` | cdb | none | – | pluggable databases and open modes |
| `params_nondefault` | cdb | none | – | non-default instance parameters |
| `sqlpatch_registry` | cdb | none | – | patch history (DBA_REGISTRY_SQLPATCH) |
| `rac_instances` | cdb | none | – | all instances with status and startup time (GV$INSTANCE) |
| `rac_blocking_now` | cdb | none | – | blocked sessions across all instances with their blockers (GV$SESSION) |
| `rac_gc_events` | cdb | none | – | global cache and cluster waits per instance (GV$SYSTEM_EVENT) |
| `sessions_active_now` | pdb | none | – | active foreground sessions with wait and SQL |
| `blocking_tree_now` | pdb | none | – | blocked sessions and blockers of the current instance |
| `system_events_top` | cdb | none | `top=30` | top non-idle waits since instance start |
| `exa_cell_events` | cdb | none | – | Exadata cell and smart-scan waits |
| `exa_offload_by_sql` | pdb | none | `top=20` | smart-scan offload efficiency per SQL |
| `ash_top_events_window` | pdb | diagnostics | `from_ts`, `to_ts`, `top=20` | ASH top events / CPU in a window |
| `ash_top_sql_window` | pdb | diagnostics | `from_ts`, `to_ts`, `top=20` | ASH top SQL in a window |
| `ash_blockers_window` | pdb | diagnostics | `from_ts`, `to_ts`, `top=20` | sessions that blocked others most in a window |
| `awr_snapshots_window` | cdb | diagnostics | `from_ts`, `to_ts` | AWR snapshots covering a window |
| `sql_plan_history` | pdb | diagnostics | `sql_id` | plans seen for a sql_id in AWR |

Timestamps for the window queries are strings `YYYY-MM-DD HH24:MI:SS` in database time.

## Cases, findings, reports

| Tool | Parameters | Returns |
|---|---|---|
| `open_case` | `target`, `title`, `problem_keys` | a new case |
| `get_case` | `case_id` | the case with artifacts, evidence, findings, reports |
| `add_artifact_to_case` | `case_id`, `path`, `kind='trace'`, `label` | registers a local file (already on the AutoDiag host) as an artifact, sha256-deduplicated |
| `add_finding` | `case_id`, `kind`, `title`, `detail`, `confidence`, `evidence_ids`, `kb_refs` | a finding; `kind` is `root_cause`, `contributing`, `observation` or `action`; at least one existing evidence id is required |
| `set_baseline` | `target`, `kind`, `artifact_id`, `label` | marks an artifact as the normal reference of its kind for later comparisons |
| `list_baselines` | `target`, `kind` | stored baselines |
| `render_report` | `case_id`, `kind='dba'` or `'sr'`, `capture_env=false` | the report Markdown, also stored in the case; `capture_env` queries the target for version and patches |

## Reading the tools from OpenCode

The skill `autodiag-oracle` (in `opencode/skills/`) holds the playbooks. Its rules: cite
`evidence_id`s, page instead of pulling raw lines, quote only knowledge-base material
about My Oracle Support, say "unknown" rather than invent, suggest and never execute
destructive actions. Tool output is truncated by OpenCode at 2000 lines / 50 KB, which is
why the diagnosis tools take `max_bytes`.

# Guardrails and safety

AutoDiag is a read-only observer of Oracle databases that hands evidence to a language
model and keeps the model honest. This page lists what it does, what it refuses, and
where data flows, so that a DBA, a security reviewer or an auditor can decide whether and
how to run it.

## What AutoDiag never does

- It never runs a statement or command that changes a database, an instance or a host:
  no DDL, DML, `ALTER SYSTEM`, kills, restarts, log deletion or patching.
- It never executes free-form shell commands or free-form SQL, from any interface, on
  any node: not from the CLI, not from the web UI, not from an agent.
- It never invents facts. Knowledge-base entries carry My Oracle Support *search strings*,
  never note or bug numbers; the model is instructed to say "unknown"; and a model claim
  that cannot be proven with a quote from the collected evidence is not presented as a
  finding.
- It never sends stored artifacts to a model: only bounded, redacted excerpts.

The fault-injection kit in `testbed/` is the one place that deliberately damages a
database. It targets a throwaway container and must never be pointed at a real target.

## The agent has no shell

The bundled OpenCode agent `autodiag-triage` denies `bash`, `edit`, `write` and
`webfetch` and only enables the `autodiag_*` tools plus read-only file tools. Everything
the agent can do to a database is therefore one of the tools below.

## SSH: a closed allowlist

`src/autodiag/transport/allowlist.py` is the complete set of commands AutoDiag can run
on a database node. Each has a fixed argument vector, typed and validated parameters
(integers, ADR home names, problem keys, choices, fixed-string patterns), a timeout and an
output cap. Paths are accepted only under the target's allowed roots: `<adr_base>/diag`,
the configured `extra_roots` (AHF, OSWatcher) and `ips_dest`, with `..` rejected.
Connections use `BatchMode=yes` (no password prompts) as the configured user, normally
`oracle`, so nothing runs with more privilege than the database owner already has.

| Command | Purpose |
|---|---|
| `hostname`, `uptime` | node identity and load |
| `adrci_show_homes` | ADR homes |
| `adrci_show_problem`, `adrci_show_problem_by_key` | ADR problems (last N days, or one key) |
| `adrci_show_incident`, `adrci_show_incident_by_id` | incidents of a problem, one incident in detail |
| `adrci_show_alert_tail` | last N alert-log lines through adrci |
| `adrci_show_tracefile` | trace files matching a name pattern |
| `adrci_ips_create_problem`, `adrci_ips_create_incident`, `adrci_ips_generate` | build and zip an IPS package for Oracle Support |
| `list_dir`, `stat_file`, `read_range`, `grep_file`, `sha256`, `cat_file` | read files under the allowed roots (listing, metadata, byte range, fixed-string grep with context, checksum, full copy into the artifact store) |
| `opatch_lspatches` | installed interim patches of an ORACLE_HOME |
| `tfactl_status`, `tfactl_diagcollect`, `tfactl_analyze` | AHF status, collection and analysis for a window |
| `oswatcher_list` | OSWatcher archive files |

Adding a command means adding a `CommandSpec` with validators and a unit test; there is no
generic "run this" entry and none will be added.

## SQL: a catalog of read-only queries

Database access goes through python-oracledb (thin mode) as a dedicated user with
`CREATE SESSION`, `SET CONTAINER`, `SELECT_CATALOG_ROLE` and explicit `READ` on the
diagnostic views (`docs/sql-user.md`). The only statements AutoDiag issues are the named
queries in `src/autodiag/sql/catalog/` (listed in `docs/mcp.md`) and, for queries marked
`scope: pdb`, `ALTER SESSION SET CONTAINER` to a validated PDB name. Parameters are bind
variables; nothing is interpolated into SQL. Queries that read AWR or ASH are marked
`pack: diagnostics` and are refused for targets with `diagnostics_pack: false`, so an
unlicensed database is never queried for licensed views. Each call has a `call_timeout`.

## Redaction at the model boundary

`redact_for_llm` runs on every tool result for targets with `redact: true` (the default)
and on every dossier before it is sent to Ollama. It masks bind values and literal values
(`value=...` becomes `value=<redacted>`), IP addresses, and multi-label host names, while
keeping error codes, file paths, versions, sql_ids and problem keys, because those are
what a diagnosis needs. Stored artifacts and the case database are never redacted; they
stay on the AutoDiag host. The redaction is heuristic: review a dossier with
`autodiag diagnose ... --dossier` before pointing AutoDiag at a cloud model.

## Proof or nothing

- Every tool result is recorded as evidence with an id. `add_finding` rejects a finding
  that does not cite at least one existing evidence id.
- In an automated diagnosis every dossier item is evidence before the model sees it. The
  model must return, for each concern, quotes copied from named items; AutoDiag checks
  each quote against the text the model actually received. Concerns without a verified
  quote are demoted to open questions and the overall severity is the worst *proven*
  concern. The assessment records the model name and the verified/total proof counts;
  when no model answers, the ranking is produced by rules and labelled `rules`.
- Report templates and the skill instruct the model to suggest, never to execute, and
  to state prerequisites for restart or patch advice.

## Where data goes

| Flow | What leaves where |
|---|---|
| SSH to database nodes | commands from the allowlist; files under the diagnostic roots are copied to the AutoDiag host's `data_dir` |
| SQL*Net | catalog queries; rows are stored as evidence summaries in the case database |
| Ollama (`ollama_primary_url`, `ollama_fallback_url`) | the redacted dossier text and the system prompt; nothing else. Use an on-premises Ollama for production |
| OpenCode or another MCP client | whatever tool results the agent requests, redacted; the model configured in that client sees them. Cloud providers (used during development on synthetic data) receive tool outputs; keep them off production targets |
| IPS packages and AHF collections | created on the node with Oracle's own tools; the IPS zip is fetched into the case for the DBA to hand to Oracle Support. These contain unredacted traces |
| Notifications | one line per new problem key to `notifications.log` and the optional `notify_command` |

Nothing is sent anywhere unless a target is configured and a command, a page or a tool is
invoked; there is no telemetry.

## Network exposure and authentication

The service binds to `127.0.0.1:8790` by default. `/api/*` and `/mcp` require
`Authorization: Bearer <mcp_token>` when a token is configured; set one before binding to
a non-loopback address. The HTML pages have no authentication of their own: expose them
only through a reverse proxy that authenticates users, and treat anyone who can reach the
pages as able to trigger reads against every configured target.

## Secrets

Database passwords and tokens are read from environment variables named in the
configuration (`password_env`) and populated from `~/.config/autodiag/autodiag.env`
(mode 600). They are never stored in the case database, never logged, never part of a
tool result, and `SqlNetConfig` hides the password from its `repr`. The repository ships
only `*.example` files; the hygiene check refuses commits that contain environment
identifiers.

## Retention

Closed cases and their artifacts are deleted after `retention_days` (default 90) by
`autodiag scan purge` or the scheduler; open cases are kept. Fetched files in
`cache/<target>/` are overwritten on the next fetch of the same name.

## Operational limits worth knowing

- Timeouts: SSH connect 10 s, SSH commands 120 s (IPS and AHF up to 60 min as jobs),
  SQL 60 s per call, model 300 s. Caps keep a single tool call under 16 KiB by default.
- Alert logs are fetched up to 64 MiB from the start of the file; on a bigger,
  never-rotated alert log the newest entries would be missing, so rotate alert logs
  (ADR purge or logrotate) on the nodes.
- The diagnosis runs synchronously in the web UI; a long RAC sweep can take a minute.
- The severity rules are heuristics tuned on 23ai wording; an unmatched message is
  never dropped, it is shown as informational.

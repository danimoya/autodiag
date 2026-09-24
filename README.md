# AutoDiag

<p align="center">
  <img src="docs/demo/autodiag.gif" alt="AutoDiag: automated diagnosis of an ADR problem" width="800">
</p>

Oracle Database diagnostic assistant for 19c / 23ai on Exadata Cloud@Customer and any
other Oracle estate. It reads what a DBA would read by hand, ADR problems and incidents,
multi-megabyte trace files, alert logs, ASH and instance views, and turns it into a short,
evidence-backed assessment of what is wrong and what to do next.

The centre is an **automated diagnosis**. Deterministic collectors gather a bounded dossier
of evidence; a local LLM (Ollama) decides what matters and what is noise; and every concern
it reports must be proven by quotes that AutoDiag verifies against the dossier before the
DBA sees them. Without a model the same dossier is ranked by rules and labelled as such.

```bash
autodiag diagnose problem  -t prod01 -k 'ORA 600 [kkslgop1]'   # one ADR problem
autodiag diagnose alert    -t prod01 --hours 24                 # the alert log(s)
autodiag diagnose instance -t prod01 --live                     # instance / whole RAC
```

The same core is exposed three ways from one process: an **MCP server** for AI agents
(OpenCode, Claude Code, any MCP client) with a bundled OpenCode skill, a **web UI + REST
API** on `127.0.0.1:8790`, and the **CLI** for scripts and cron with no LLM at all.

## Quick guide

1. **Install** on the DBA host (Python 3.11):
   ```bash
   git clone https://github.com/danimoya/autodiag && cd autodiag
   python3.11 -m venv .venv && .venv/bin/pip install -e .
   ```
2. **Describe the databases** in `~/.config/autodiag/targets.yaml` (nodes with SSH
   aliases, ADR base and homes, optional SQL*Net DSN with a read-only user; see
   `tests/fixtures/config/targets.yaml` for the shape) and the settings in
   `~/.config/autodiag/config.toml` (Ollama URL and model, listen address, caps). Passwords
   and tokens go in `~/.config/autodiag/autodiag.env` (mode 600), referenced by name.
3. **Give access**: passwordless SSH as the `oracle` user to every node (an `ssh_config`
   file can be pointed to with `ssh_config`), and the read-only diagnostic database user
   from `docs/sql-user.md` when you want live queries.
4. **Check**: `autodiag targets list`, `autodiag adr problems -t <name>`,
   `autodiag mcp selftest`.
5. **Diagnose**: `autodiag diagnose instance -t <name> --live`. Add `--case new` to keep
   the proven concerns as findings, `--markdown out.md` to save the write-up.
6. **Serve** the UI, REST and MCP endpoint: `autodiag serve`, or install
   `systemd/autodiag.service` as a user unit. Open `http://127.0.0.1:8790/targets`.
7. **Plug in an agent**: `opencode/install.sh --merge` installs the skill, the restricted
   `autodiag-triage` agent and the commands into OpenCode (`docs/opencode.md`).

Every command answers `-h`. The Oracle Database Free container in `testbed/` with its
fault-injection kit gives you real ORA-600, ORA-7445, deadlock, hang and 10046 material to
try all of this without touching production (`docs/testbed.md`).

## What you get

- **Minutes instead of hours on an incident.** A 120,000-line incident trace becomes the
  error, its arguments, the first application frame and component, the current SQL and
  PL/SQL unit, and the signalling call stack, in seconds and without a model.
- **Noise removed, not hidden.** Alert-log entries are classified by ordered rules;
  routine messages are counted per signature and reported as counts, so the DBA sees the
  twelve lines that matter and knows the four hundred that did not.
- **Anomaly versus normal.** Kernel call stacks are normalised, aligned and diffed;
  10046 SQL traces are aggregated tkprof-style and compared per statement with tags
  (`PLAN_CHANGE`, `IO_INCREASE`, `HARD_PARSE`, `NEW_WAIT`, `CONCURRENCY`); alert-log
  message rates are compared between windows; frame frequency across incidents tells
  whether a recurring problem key is one bug or several.
- **RAC and Exadata aware.** Every node's alert log is swept, the same message on
  several nodes within two minutes is correlated, GV$ views cover all instances, and
  cell and smart-scan waits are collected on ExaCC.
- **An assessment you can audit.** Every tool result and dossier item is evidence with
  an id in a case. The model's concerns carry verified quotes; unproven claims are
  demoted to open questions; the fallback ranking is labelled as rules-only.
- **A Service Request in one step.** DBA and SR-draft reports render from the case
  (timeline, evidence, findings, environment, patch level), and an ADRCI IPS package or
  an AHF collection can be produced for Oracle Support.
- **Works when the model does not.** Scheduled scans, notifications, the CLI and the
  rules ranking need no LLM.

## Use cases

| Situation | Command or tool |
|---|---|
| A new ORA-600 or ORA-7445 appeared overnight | `diagnose problem -k '<key>'`, then `report render --kind sr` and `create_ips_package` |
| "Something was wrong between 02:00 and 03:00" | `diagnose alert --since ... --until ...`, `compare_alert_rates` against the day before |
| Health check of an instance or a whole RAC before a change window | `diagnose instance --live` |
| A batch job became slow after a release | `sql_trace_profile` on both 10046 traces, `compare_sql_profiles`, `sql_plan_history` |
| Deadlocks or a hang reported by the application | `parse_trace` on the deadlock or hanganalyze trace, `blocking_tree_now` |
| Is this problem key one bug or several? | `stack_frequency`, `compare_call_stacks` newest vs oldest |
| Unattended watch over forty databases | `scan run` on a timer, notifications on new problem keys |
| An engineer wants to investigate interactively | OpenCode with the `autodiag-oracle` skill: `/triage <target> "<key>"` |

## Guardrails and safety

AutoDiag reads; it never changes a database. The full description is in `docs/safety.md`.

- **No shell for the agent.** The OpenCode agent has bash, edit, write and webfetch
  denied and can only call `autodiag_*` tools.
- **SSH is a closed allowlist** of named commands with validated parameters; file paths
  must lie under the target's diagnostic roots; nothing outside the table can execute.
- **SQL is a catalog** of named read-only queries with bind variables only, run as a
  dedicated read-only user; queries that need the Diagnostics Pack are gated per target.
- **Redaction at the model boundary**: bind values, literals, hostnames and IP addresses
  are masked before anything reaches an LLM; stored artifacts stay intact.
- **Proof or nothing**: findings must cite evidence ids, model concerns must quote the
  dossier, and My Oracle Support note numbers are never invented.
- **Suggestions only**: actions are advice with prerequisites; no destructive command is
  ever proposed or run.
- **Loopback by default** with an optional bearer token on `/api` and `/mcp`; put a
  reverse proxy with authentication in front for multi-user access.

## Documentation

| Document | Content |
|---|---|
| `docs/cli.md` | CLI reference with walkthroughs |
| `docs/mcp.md` | Every MCP tool with parameters, result envelope, caps; the SQL catalog |
| `docs/gui.md` | Web UI pages and the REST API |
| `docs/safety.md` | Guardrails: allowlist, read-only SQL, redaction, proof verification, data flows |
| `docs/architecture.md` | Modules, data flow, the diagnosis engine |
| `docs/opencode.md` | Using AutoDiag from OpenCode (skill, agent, commands, MCP config) |
| `docs/sql-user.md` | The read-only diagnostic database user and its grants |
| `docs/testbed.md` | The Oracle Free test container and the fault-injection kit |
| `docs/roadmap.md` | Pending work and known limitations |

Environment-specific values (hosts, models, credentials) never live in this repository.

## Development

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest                    # unit tests
.venv/bin/pytest -m integration     # needs the testbed container (docs/testbed.md)
.venv/bin/pytest -m llm             # needs a reachable Ollama
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

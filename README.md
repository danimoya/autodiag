# AutoDiag

Oracle Database diagnostic assistant for 19c / 23ai, designed for Exadata Cloud@Customer
estates. It lists ADR problems and incidents, interprets long trace files, greps and
summarises alert logs, and compares an anomalous capture with a normal one (kernel call
stacks from ORA-600 / ORA-7445 incidents, 10046 SQL-trace profiles, alert-log message
rates) to surface the divergence and likely root causes.

The deterministic core is exposed three ways from one process:

- **MCP server** `autodiag` for AI agents (OpenCode, Claude Code, any MCP client); the
  bundled OpenCode skill `autodiag-oracle` holds the diagnostic playbook.
- **Web UI + REST API** on `127.0.0.1:8790` to browse targets, problems, traces, diffs,
  cases, findings and reports.
- **CLI** `autodiag` for scripted use with no LLM at all.

Data access is agentless: SSH with an allowlist of named commands and SQL*Net with a
read-only diagnostic user. Nothing is installed on the database nodes.

Environment-specific values (hosts, models, credentials) never live in this repository.
Copy `.env.example` to `.env` and create `~/.config/autodiag/config.toml` and
`~/.config/autodiag/targets.yaml` from the examples in `docs/`.

## Using it

Every command has `-h` / `--help`; `docs/cli.md` is the CLI reference with two
walkthroughs (an ORA-600 and a 10046 comparison). `docs/opencode.md` covers the agent
side, `docs/architecture.md` the service, `docs/testbed.md` the Oracle Free test
container and fault kit, `docs/roadmap.md` what is still pending.

```bash
autodiag targets list
autodiag adr problems --target <name> --days 7
autodiag adr incident --target <name> --id <incident> --fetch
autodiag diff stacks anomaly.trc normal.trc
```

## Development

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest            # unit tests
.venv/bin/pytest -m integration   # needs the testbed container (see docs/testbed.md)
.venv/bin/ruff check .
```

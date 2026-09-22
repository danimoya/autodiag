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

## Development

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest            # unit tests
.venv/bin/pytest -m integration   # needs the testbed container (see docs/testbed.md)
.venv/bin/ruff check .
```

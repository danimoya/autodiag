# Web UI and REST API

`autodiag serve` (or the systemd user unit) runs one process on `listen_host:listen_port`
(default `127.0.0.1:8790`) that serves the HTML pages, the REST API under `/api/v1`, the
OpenAPI description at `/api/openapi.json` with Swagger at `/api/docs`, and the MCP
endpoint at `/mcp`. The pages need no JavaScript; every action is a form.

## Authentication

Set `mcp_token` (or `AUTODIAG_MCP_TOKEN`) to require `Authorization: Bearer <token>` on
`/api/*` and `/mcp`. The HTML pages are not protected: they bind to loopback by default,
and multi-user access is meant to go through a reverse proxy that authenticates. See
`docs/safety.md`.

## Pages

| Page | Shows | Actions |
|---|---|---|
| `/` | redirects to `/cases` | |
| `/targets` | the inventory: name, kind, platform, version, nodes, SQL*Net | |
| `/targets/{name}` and `/targets/{name}/problems?days=7` | ADR problems of the last days across the nodes | **diagnose instance** (live checks auto / yes / no), **diagnose alert log** (hours), per problem **diagnose** and **triage** |
| `/targets/{name}/problems/{problem_id}` | incidents of one problem: id, key, time, error, arguments, flood control | |
| `/targets/{name}/alertlog?hours=24&grep=&context=3&top=20` | alert-log statistics for the window (ORA histogram, top signatures, per-hour, lifecycle) and grep hits with context | change the window and the pattern |
| `/cases?target=` | cases, open or closed | open a case (target, title, problem keys) |
| `/cases/{case_id}` | the case: artifacts, evidence, findings, baselines, reports | upload an artifact (file, kind, label), add manual evidence, add a finding (kind, title, detail, confidence, evidence ids), confirm or reject a finding, set a baseline, render a DBA or SR report (optionally capturing the environment), close the case |
| `/artifacts/{artifact_id}` | the parsed trace: header, summary card, section index, kind-specific tables (stack, deadlock graph, hang chains, 10046 cursors, optimizer paths) | jump to raw lines |
| `/artifacts/{artifact_id}/lines?offset=0&n=200&grep=` | raw lines, paged, optional filter | |
| `/artifacts/{artifact_id}/raw` | the whole artifact as text | |
| `/diff/stacks?left=&right=` | two incident stacks aligned side by side, divergence highlighted, notes | |
| `/diff/sqlprofile?left=&right=&top=15` | per-statement comparison of two 10046 profiles with ratios, tags and wait deltas | |
| `/reports/{report_id}` | a rendered report (DBA, SR draft or diagnosis) | download as `/reports/{report_id}.md` |

The **diagnose** buttons run the collectors and the model synchronously (typically 30
to 90 seconds), open a case titled after the diagnosis, store proven concerns as
findings, save the write-up as a report of kind `diagnosis` and redirect to it. The
**triage** button runs the older deterministic first pass and opens the case.

## Form endpoints

| Method and path | Form fields |
|---|---|
| `POST /targets/{name}/diagnose` | `mode` (`problem`, `alert`, `instance`), `problem_key`, `hours`, `days`, `live` (`auto`, `yes`, `no`) |
| `POST /targets/{name}/problems/{problem_id}/triage` | `problem_key` |
| `POST /cases` | `target`, `title`, `problem_keys` (comma separated) |
| `POST /cases/{case_id}/upload` | `file` (multipart), `kind`, `label` |
| `POST /cases/{case_id}/evidence` | `summary`, `tool` |
| `POST /cases/{case_id}/findings` | `kind`, `title`, `detail`, `confidence`, `evidence_ids` (comma separated) |
| `POST /cases/{case_id}/findings/{finding_id}` | `status`, `confidence` |
| `POST /cases/{case_id}/baselines` | `artifact_id`, `kind`, `label` |
| `POST /cases/{case_id}/reports` | `kind` (`dba`, `sr`), `capture_env` |
| `POST /cases/{case_id}/close` | – |

## REST API

| Method and path | Purpose |
|---|---|
| `GET /healthz` | `{"status": "ok", "version": ..., "targets": [...]}` |
| `GET /api/v1/tools` | the MCP tools with descriptions |
| `POST /api/v1/tools/{name}` | call one MCP tool; the JSON body holds its parameters, the response is the tool's result envelope (`docs/mcp.md`); unknown tool is 404, wrong parameters 422 |
| `GET /reports/{report_id}.md` | a report as Markdown |
| `GET /artifacts/{artifact_id}/raw` | an artifact as text |
| `GET /api/docs`, `GET /api/openapi.json` | interactive and machine-readable API description |
| `/mcp` | the MCP endpoint (streamable HTTP, stateless, JSON responses) for remote agents |

Example, a diagnosis from a script:

```bash
curl -s -H "Authorization: Bearer $AUTODIAG_MCP_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"target": "prod01", "hours": 24, "assess": true}' \
     http://127.0.0.1:8790/api/v1/tools/diagnose_alert | jq -r .text
```

## Where things are stored

`data_dir` (default `~/.local/share/autodiag`): `autodiag.db` (SQLite: targets seen,
problems, incidents, cases, artifacts, evidence, findings, baselines, reports, jobs,
scans), `cases/` (artifact files, deduplicated by sha256), `cache/<target>/` (fetched
traces and alert logs), `notifications.log`. `scan purge` (or the scheduler once a day)
deletes closed cases older than `retention_days`.

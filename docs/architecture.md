# Architecture

AutoDiag is one Python process with three faces over one deterministic core:

```
 OpenCode / Claude Code / any MCP client ──MCP (stdio or HTTP /mcp)──┐
 Browser (DBA) ────────────────────────────HTML pages ───────────────┤  autodiag serve
 Scripts / other systems ──────────────────REST /api/v1/tools/<tool>─┤  (FastAPI + FastMCP)
                                                                     │
        core: transport (SSH allowlist) · adr (adrci) · sql (catalog over SQL*Net)
              alertlog · trace parsers · diff engine · kb · case store · report
                                                                     │
                     SSH (oracle user) ──── database nodes ──── SQL*Net (read-only user)
```

Principle: **tools do the deterministic work** (adrci, parsing, statistics, diffs,
knowledge base, storage); **the model narrates**, forms hypotheses and chooses the next
tool. Every tool result carries an `evidence_id`; findings must cite evidence ids.

## Modules (`src/autodiag`)

| Module | Role |
|---|---|
| `core/` | settings (TOML + env + private secrets file), target inventory, redaction at the model boundary |
| `transport/` | the closed allowlist of SSH commands (validated parameters, paths under allowed roots) and the SSH runner |
| `adr/` | adrci output parsers (table and key/value forms) and the ADR source over a target's nodes |
| `sql/` | python-oracledb thin runner, the catalog of named read-only queries, container-aware helpers |
| `alertlog/` | text and XML alert-log parsers, signature normalisation, window/grep/stats |
| `trace/` | header, call stacks, incident (ORA-600/7445), deadlock, hang/systemstate, errorstack, 10046, 10053 |
| `diff/` | call-stack alignment and frame frequency, 10046 profile comparison with tags, alert-rate comparison |
| `kb/` | YAML knowledge base (ORA-600/7445 keys, alert signatures, wait events, Exadata checks) and lookup |
| `case/` | SQLite case store: cases, artifacts (hashed copies), evidence, findings, baselines, reports, jobs, problem snapshots |
| `report/` | timeline merge, environment capture, Jinja2 DBA and SR templates, context builder |
| `mcp/` | the `autodiag` MCP server: 31 tools with caps, paging, redaction, background jobs, `standard_triage` |
| `web/` | HTML UI, `/api/v1/tools/<name>` REST endpoint, bearer middleware, MCP mount |
| `cli/` | `autodiag` command groups: targets, adr, alert, trace, diff, case, report, kb, mcp, serve |

## Data flow for an incident

1. `list_problems` runs `adrci show problem` over SSH (or `V$DIAG_PROBLEM` over SQL*Net).
2. `get_incident` runs `adrci show incident -mode detail`, fetches the incident trace into
   the case (artifact with sha256), parses it and returns the summary: error, arguments,
   first application frame (from the incident context frames), current SQL, PL/SQL stack.
3. `compare_call_stacks` / `stack_frequency` work on stored artifacts.
4. `kb_lookup`, `run_query` (ASH/AWR around the time), `capture_environment` add context.
5. `add_finding` records the hypothesis with evidence ids; `render_report` produces the
   DBA report or the SR draft; `create_ips_package` packages the problem with ADRCI IPS.

## Security model

- SSH: only the commands in `transport/allowlist.py` can run; paths must sit under the
  target's diagnostic root, extra roots or the IPS destination; no shell metacharacters
  reach the remote side unquoted.
- SQL*Net: read-only user, catalog queries with bind variables only, per-query timeout,
  row cap, container switch only for `scope: pdb` queries, Diagnostics Pack gate.
- Model boundary: bind values, string literals, IPs, hosts and e-mails are masked in tool
  output when the target has `redact: true` (stored artifacts are never altered).
- Service: loopback bind by default; `/api` and `/mcp` require the bearer token when
  `AUTODIAG_MCP_TOKEN` is set; HTML pages are meant for a reverse proxy with its own auth.

## Configuration (all outside the repository)

- `~/.config/autodiag/config.toml`: service, Ollama, caps, timeouts (`AUTODIAG_*` env
  variables override).
- `~/.config/autodiag/targets.yaml`: the databases (nodes, ADR base/homes, SQL*Net DSN
  to the **CDB root service**, `password_env`).
- `~/.config/autodiag/autodiag.env`: private variables such as the passwords named by
  `password_env`, loaded at startup (mode 600).

## Deployment

`python3.11 -m venv .venv && .venv/bin/pip install -e .` then `systemd/autodiag.service`
as a user unit (`systemctl --user enable --now autodiag`). The unit uses `%h`, so it needs
no editing per host.


## Automated diagnosis (`autodiag.diagnose`, `autodiag.llm`)

The model is the centre of a diagnosis; the code around it exists to feed it well and to
keep it honest.

1. **Collect** (`diagnose/collect.py`). One collector per mode builds a `Dossier`: a list of
   `DossierItem`s (incident, problem, alert, alert_group, alert_burst, alert_rate,
   lifecycle, stack_frequency, stack_diff, kb, query, env, correlation), each recorded as
   evidence in the case store first so its id can be cited. Alert-log entries go through
   `diagnose/rules.py`: ordered regex rules from `kb/data/severity_rules.yaml` map each
   entry to critical / warning / info / noise. Noise is only counted per signature, info
   is folded to one item per signature, warning and critical keep up to three entries per
   signature, and a signature that grows ten-fold against the previous window is a
   burst. On RAC the same non-info message on several nodes within two minutes becomes a
   correlation item; a message seen on one node only is flagged too. Live checks over
   SQL*Net are catalog queries whose rows are judged by small deterministic functions
   (an instance not OPEN is critical, a PDB not open or a blocked session is a warning).
2. **Assess** (`llm/assess.py`, `llm/ollama.py`). The dossier is rendered highest severity
   first inside a byte budget derived from `ollama_num_ctx`, redacted at that boundary,
   and sent to Ollama with a JSON schema (`AssessmentDraft`) and thinking disabled. The
   answer is verified: every proof must quote text that occurs in the cited item (or in
   another item, which is then cited instead). Concerns with no verified proof are
   demoted to open questions, the overall severity is the worst proven concern, and the
   result records how many proofs were verified. If no endpoint answers or the JSON is
   invalid, `rules_assessment` ranks the dossier by the rule severities and says so.
3. **Record and present** (`diagnose/engine.py`, `diagnose/render.py`). The diagnosis is
   evidence in the case; with `record=True` proven concerns become findings (author
   `agent`, or `rule` for the fallback) and actions become action findings. The CLI
   prints text, the web UI stores a Markdown report of kind `diagnosis`, the MCP tools
   return the dossier items and the assessment so an agent such as OpenCode can be the
   assessor itself (`assess=false`, the default there) or ask for the local model
   (`assess=true`).

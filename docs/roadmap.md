# Roadmap and known gaps

Reviewed against source and tests on 2026-10-06. The package version is **0.1.0**;
earlier v1.0/v1.1 phase labels were planning labels, not package releases.

## Implemented

- ADR collection, trace parsers, stack/10046/alert-rate comparisons, SQL catalog,
  cases and evidence, DBA/SR reports, environment capture and baselines.
- CLI, web/REST, MCP tools, OpenCode integration, scheduled scans,
  notifications and retention.
- Automated `diagnose problem|alert|instance|performance`: bounded dossiers,
  Ollama/OpenAI-compatible assessment, quote verification and an explicit rules fallback.
- `diagnose performance`: sampled instance counters, live sessions/blockers and
  cursor-lifetime top SQL without ASH/AWR; CLI, MCP/REST and GUI. See [CLI reference](cli.md#autodiag-diagnose).
- SSH/sudo discovery of running local DB/ASM/CRS ADR targets. CRS/ASM discovery and
  rules-only diagnosis passed for all six targets on the two-node 26ai 23.26.1 lab
  on 2026-10-06. Both DB instances and their PDBs are open; sampled performance
  collection was also checked across both instances and for instance 2 alone.
  Follow-up checks passed custom DB/ASM ADR destinations, node-2 restart recovery,
  file-based CRS/ASM IPS packages on both nodes and a fresh wheel installation.
  This does not validate 19c, Oracle Restart or real-incident extraction/IPS workflows.
  See [testbed status](testbed.md#26ai-rac-lab).
- RAC alert correlation within two minutes and grouping ADR problems by problem key.
  Individual incident sequences are not yet correlated by time across instances.
- Oracle Free containers with real ORA-600/700/7445, deadlock, hang and SQL-trace
  material, parser tests and evaluation scenarios.

## Reliability corrections implemented

| Priority | Correction | Verification |
|---|---|---|
| 1 | Knowledge-base YAML and model prompt included in source/wheel distributions; root-only data ignore rule | Build sdist, build wheel from sdist, install outside source tree, load resources and invoke CLI; CI runs this check |
| 2 | Shared bearer middleware for `serve` and standalone `mcp http` | Missing/incorrect tokens rejected; authenticated MCP initialization succeeds |
| 2 | Redact node labels, omitted titles and noise metadata; enforce the complete prompt's UTF-8 byte budget | Synthetic sensitive data across prompt sections and small/multibyte budgets |
| 3 | Store identity as target + node + ADR home + numeric ID; explicit selectors, ambiguity rejection, isolated cache paths | Colliding IDs, selected-node lookups, preserved v1 records and repeatable schema migration |
| 3 | Read newest alert bytes and expose omitted-history coverage; reject truncated trace/package artifacts | Recent error retained from a >64 MiB sparse log; coverage exposed in CLI, MCP, GUI and diagnosis |

Case databases migrate to schema version 2 on opening. Back up the database and restart
all processes using it together when upgrading. Legacy snapshots retain unknown node/home
fields as empty strings; migration cannot reconstruct discarded origins or recover records
already overwritten by ID collisions.

## Next work, in priority order

1. **Real-estate validation:** anonymised 19c traces and alert logs, real RAC/ExaCC
   integration coverage, severity-rule tuning, per-target rule overrides and ASH
   timezone alignment. Single-instance 23ai/26ai and the two-node 26ai RAC lab have
   bounded runtime evidence above; this does not establish other-version RAC,
   Oracle Restart or ExaCC compatibility.
2. **Collection and workflow:** asynchronous web diagnosis, historical alert-log
   rotation/window retrieval, and `diagnose sql` for paired 10046 traces.
3. **Diagnostic integrations:** complete the partial collectors below.

| Item | Notes |
|---|---|
| AHF ingestion | `collect_ahf` runs `tfactl diagcollect` as a job; parsing `tfactl analyze` output and attaching the collection zip to the case is not done. |
| exachk / orachk ingestion | Summarise FAIL / WARNING items from the HTML or JSON report into the case. |
| OSWatcher window extraction | `oswatcher_list` is allowlisted; no dedicated `oswatcher_read` exists. Add window extraction and vmstat/ps/netstat parsers. |
| RAC incident correlation | Time-correlate incidents across homes; key grouping and alert correlation already exist. |
| "Investigate with OpenCode" button | The web UI does not yet spawn `opencode run --agent autodiag-triage` for a case. |
| Case-level `autodiag advise` | Summarise an existing case; direct Ollama assessment already works through `diagnose`. |
| ORA-4031 / ORA-4030 fault scripts | Write and validate these scripts; no placeholders exist in the kit. |
| RAC IPS orchestration | Explicit node/home selection now packages one chosen home and rejects ambiguity. Automatic packaging/aggregation across homes remains pending. |
| dbaascli patch inventory | Allowlist entry planned (`dbaascli_patch_list`); needs `opc` + sudo on ExaCC. |
| Embeddings over KB and findings | Optional similarity search using an embedding model. |

## Known limitations

- **Fixture versions**: the historical `tests/fixtures/23ai/` directory contains 26ai
  captures (the banners report 23.26.3), despite its name. Fresh 23ai 23.9 evidence was
  validated separately on 2026-10-05; it has not replaced those fixtures. The parsers
  accept 19c layouts by design, but no real 19c incident, 10046 or deadlock trace is in
  the fixture set yet. Add anonymised 19c traces under
   `tests/fixtures/19c/` and extend the parametrised parser tests. An official 19c
   Enterprise container candidate was identified on 2026-10-05, but the registry
   manifest check failed authentication; see [19c access prerequisites and validation
   plan](testbed.md#oracle-19c-candidate-not-yet-validated). No 19c runtime validation
   or three-version compatibility is claimed yet.
- **ORA-600 / ORA-700 generation** needs ORADEBUG, which the Free edition ships disabled;
  the testbed enables it on first start (see `docs/testbed.md`). Real incidents from the
  kit exist for ORA-600, ORA-700 and ORA-7445.
- **ORA-1578 and ORA-1555 scripts** are best effort and did not fire on the 23ai Free
  build in the first run; they stay in the kit but are not counted as failures.
- **Web UI authentication**: HTML pages are open on the loopback bind; only `/api` and
  `/mcp` honour the bearer token. Put a reverse proxy with authentication in front for
  shared use.
- **Redaction heuristics**: bind values, string literals, IPs, e-mails and host names are
  masked at the model boundary; dotted SQL identifiers and versions are preserved by
  heuristics that may occasionally misclassify an unusual token.
- **Evidence interpretation**: quote verification checks citation text exists, not causal
  validity. Headlines, dismissals and suggested actions are not independently verified.
- **Alert history**: reads retain the newest 64 MiB and report omitted history explicitly.
  Historical/baseline windows can be incomplete; tail line numbers are relative to the
  collected tail. Timeline construction refuses truncated history.
- **OpenCode compatibility**: integration is exercised with 1.18.x. Model identifiers must
  exist in `opencode models`; `AUTODIAG_EVAL_OPENCODE_MODEL` overrides the eval default.

## Live verification on 2026-10-04

- Default regression suite: 212 passed; the 13 live tests are excluded by default.
  Distribution install smoke, lint, formatting and repository hygiene checks passed.
- All 11 Oracle integration checks passed against the original Oracle Free Docker testbed
  (subsequently verified as 26ai 23.26.3, not the release implied by its `23ai` image tag):
  SSH/ADR, incident/trace roundtrip, alert logs, SQL*Net, PDB switching, ASH and diagnosis.
- The configured 27B Ollama model produced a verified assessment of the repeated ORA-600.
- OpenCode 1.18.32 completed the MCP investigation using `deepseek/deepseek-flash`.
  Its first run failed because the configured `deepseek/deepseek-v4-flash` identifier no
  longer appeared in the client's model catalog. An explicit test override fixed the run.
- Live runs used temporary case storage. These results do not validate 19c or real RAC.

## Pinned 23ai verification on 2026-10-05

- Separate AMD64 testbed in `testbed/compose.23ai.yaml`, pinned to the Oracle 23.9 image
  digest. SQL confirmed **Oracle Database 23ai Free, version 23.9.0.25.07**. The original
  26ai container and its storage were not changed.
- Nine fault-kit scenarios produced fresh evidence: ORA-600, repeated ORA-600, ORA-700,
  ORA-7445, deadlock, errorstack, hang/systemstate, paired 10046 and 10053 traces.
- A separately guarded disposable-datafile test produced a real ORA-01578; AutoDiag
  detected it in the alert log. The test tablespace and datafile were removed afterwards.
- **13 live tests passed**, including direct Ollama and OpenCode. The latter now uses
  the fresh ORA-7445 proof and verifies a completed MCP result contains the incident
  and expected database version, in addition to checking the answer.
- **136 extended checks passed**, covering all 34 MCP tool invocations, 24 SQL catalog
  queries, reports, diagnosis, baselines, scans, GUI/REST and a valid IPS ZIP. AHF job
  failure handling worked, but AHF collection itself remains unavailable in this image.
- **25 CLI checks passed**. Both combined and standalone HTTP services rejected missing
  and incorrect tokens and executed authenticated MCP queries against the real database.
- **219 default regression tests passed**. Testbed fixes handle tab-padded SQL*Plus
  schema probes and mixed-width incident-ID sorting. The image now includes `zip`.
- Real RAC/Exadata/ExaCC, 19c, ORA-1555, ORA-4030 and ORA-4031 are not established by
  this run. Successful catalog execution on a single instance is not RAC validation.

```bash
.venv/bin/pytest -q
.venv/bin/python scripts/check_dist.py
.venv/bin/pytest -v -m integration
.venv/bin/pytest -v -m llm
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

Set `AUTODIAG_DATA_DIR` to a temporary directory for live evaluations to keep test cases
separate from operational cases. Default tests exclude live Oracle and LLM checks.

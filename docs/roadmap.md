# Roadmap and known gaps

Status of the plan's phases as of the first public release: phases 0 to 6 are complete
and the v1 items of phase 7 (environment capture, timeline, Exadata queries, baselines,
retention, scheduled scans with notifications, golden evals) are in place.

## Pending v1.1

| Item | Notes |
|---|---|
| AHF ingestion | `collect_ahf` runs `tfactl diagcollect` as a job; parsing `tfactl analyze` output and attaching the collection zip to the case is not done. |
| exachk / orachk ingestion | Summarise FAIL / WARNING items from the HTML or JSON report into the case. |
| OSWatcher window extraction | `oswatcher_list` / `oswatcher_read` are allowlisted; the parser for vmstat / ps / netstat archives around an incident time is not written. |
| RAC cross-instance correlation | `list_problems` runs per node; grouping the same problem key across instances by time and flagging simultaneous incidents is pending. |
| "Investigate with OpenCode" button | The web UI does not yet spawn `opencode run --agent autodiag-triage` for a case. |
| Direct-Ollama `autodiag advise` | Non-interactive summary of a case without an agent runtime. |
| ORA-4031 / ORA-4030 fault scripts | Best effort scripts exist as placeholders in the kit; not validated. |
| IPS job on RAC | `create_ips_package` uses the first node; per-instance packaging for RAC is pending. |
| dbaascli patch inventory | Allowlist entry planned (`dbaascli_patch_list`); needs `opc` + sudo on ExaCC. |
| Embeddings over KB and findings | Optional similarity search using an embedding model. |

## Known limitations

- **19c fixtures**: the testbed runs Oracle Database Free 23ai, so all trace fixtures are
  23ai. The parsers accept the 19c layouts by design, but no real 19c incident, 10046 or
  deadlock trace is in the fixture set yet. Add anonymised 19c traces under
  `tests/fixtures/19c/` and extend the parametrised parser tests.
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
- **OpenCode version pin**: the integration was verified with OpenCode 1.18.x; the config
  directory conventions may change in the v2 line.


## Delivered after v1.0

- Automated diagnosis (`autodiag diagnose problem|alert|instance`, MCP `diagnose_*`, UI
  button): rule-based noise suppression, bounded dossier, model assessment with verified
  proofs, rules fallback. Pending refinements: tune `severity_rules.yaml` on real ExaCC
  alert logs (19c wording), per-target rule overrides, asynchronous diagnosis in the web
  UI, ASH time-zone alignment, a `diagnose sql` mode for 10046 pairs.
- Alert-log fetch is capped at the first 64 MiB; read the tail (or use `adrci_show_alert_tail`) for huge unrotated logs.

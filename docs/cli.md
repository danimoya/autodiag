# AutoDiag CLI reference

The `autodiag` command exposes the deterministic core with no LLM involved. Every
command accepts `-h` / `--help`, and most accept `--json` for machine-readable output.
The same functions back the MCP tools and the web UI, so anything you see here can be
scripted, browsed or driven by an agent.

Run it from the virtualenv (`.venv/bin/autodiag …`) or as a module
(`.venv/bin/python -m autodiag …`). Configuration comes from
`~/.config/autodiag/config.toml` (override with `AUTODIAG_CONFIG`) and the targets file
`~/.config/autodiag/targets.yaml`; see `docs/architecture.md` for the settings.

## Command groups

| Group | Purpose | Needs |
|---|---|---|
| `targets` | Show the inventory of databases AutoDiag may reach | targets file |
| `diagnose` | Automated diagnosis: collect evidence, model assessment with verified proofs, ranked concerns | SSH (+SQL*Net, Ollama) |
| `adr` | ADR problems, incidents and remote files through `adrci` | SSH |
| `alert` | Alert-log grep and statistics | SSH |
| `trace` | Parse and summarise a local trace file | nothing |
| `diff` | Compare anomaly vs normal: call stacks, 10046 profiles, alert-log rates | nothing |
| `case` | Cases: artifacts, evidence, findings | local store |
| `report` | DBA and Service Request reports for a case | local store (SQL*Net for `--env`) |
| `kb` | Knowledge-base lookups | nothing |
| `scan` | LLM-free scan for new ADR problems, scan history, retention purge | SSH |
| `mcp` | Run the MCP server (stdio for OpenCode, HTTP for the shared service) | – |
| `serve` | Web UI + REST API + MCP endpoint in one process | – |

## Start here: `autodiag diagnose`

One command per question, each ending in an assessment that states what matters, what was
dismissed and why, with every concern proven by quotes from the collected evidence:

```bash
autodiag diagnose problem  -t prod01 -k 'ORA 600 [kkslgop1]'     # or --incident 10195
autodiag diagnose alert    -t prod01 --hours 24                  # or --since/--until
autodiag diagnose instance -t prod01 --live                      # whole RAC, all nodes
```

The collectors are deterministic and record every item as evidence in a case. The model
(Ollama, `ollama_advisor_model`) reads a bounded, redacted dossier and returns JSON; each
proof it cites is checked against the dossier and unproven claims are demoted to open
questions. Without a reachable model, or with `--no-assess`, the same dossier is ranked by
the severity rules and labelled as such. `--case new` records the proven concerns as
findings; `--markdown FILE` writes the diagnosis; `--dossier` prints every item; `--json`
returns everything.

## Walkthrough: an ORA-600 on a target

```bash
autodiag targets list
autodiag adr problems --target prod01 --days 7
autodiag adr incidents --target prod01 --problem-key 'ORA 600 [kkslgop1]'
autodiag adr incident  --target prod01 --id 10195 --fetch      # downloads + summarises the trace
autodiag alert grep    --target prod01 'incident=10195' -C 5
autodiag alert stats   --target prod01 --hours 24

autodiag case open "ORA-600 kkslgop1 on prod01" --target prod01 -k 'ORA 600 [kkslgop1]'
autodiag case collect-incident case_xxxx --id 10195            # artifact + evidence in one step
autodiag case collect-incident case_xxxx --id 10193
autodiag diff stacks ~/.local/share/autodiag/cache/prod01/FREE_ora_15724.trc \
                     ~/.local/share/autodiag/cache/prod01/FREE_ora_15662.trc
autodiag kb lookup -k 'ORA 600 [kkslgop1]' -f kkslgop1
autodiag case finding case_xxxx --kind root_cause --title "…" -e ev_xxxx --confidence 0.7
autodiag report render case_xxxx --kind sr --env --out /tmp/sr.md
```

The cache directory is `<data_dir>/cache/<target>/`; `adr fetch` and
`adr incident --fetch` print the local path they wrote.

## Walkthrough: a slow SQL with 10046 traces

```bash
autodiag adr fetch --target prod01 /u01/app/oracle/diag/rdbms/prod/PROD1/trace/PROD1_ora_1_NORMAL.trc
autodiag adr fetch --target prod01 /u01/app/oracle/diag/rdbms/prod/PROD1/trace/PROD1_ora_2_ANOMALY.trc
autodiag trace profile PROD1_ora_1_NORMAL.trc --top 10
autodiag diff sqltrace PROD1_ora_1_NORMAL.trc PROD1_ora_2_ANOMALY.trc --top 10
```

The diff lists statements by elapsed delta with tags such as `PLAN_CHANGE`,
`IO_INCREASE`, `HARD_PARSE`, `NEW_WAIT` or `CONCURRENCY`, wait-event deltas, and
explanation hints.

## Commands

### `autodiag targets`

| Command | What it does |
|---|---|
| `autodiag targets list` | List the configured targets (name, kind, platform, version, nodes, SQL*Net). |
| `autodiag targets show NAME` | Nodes, SSH aliases, ADR base and homes, allowed roots for one target. |

### `autodiag adr`

| Command | What it does |
|---|---|
| `autodiag adr problems -t TARGET [--days 7]` | ADR problems of the last N days (`adrci show problem`). |
| `autodiag adr incidents -t TARGET (-p ID \| -k KEY)` | Incidents of one problem. |
| `autodiag adr incident -t TARGET --id N [--fetch]` | One incident in detail; `--fetch` downloads the trace and prints the summary (error, arguments, first application frame, current SQL, PL/SQL top, session). |
| `autodiag adr fetch -t TARGET PATH [--out FILE] [--node HOST]` | Copy a remote file that lies under the target's diagnostic root. Paths outside the allowed roots are refused. |

### `autodiag alert`

| Command | What it does |
|---|---|
| `autodiag alert grep -t TARGET PATTERN [-C 3] [--max-lines 200]` | Fixed-string grep of the alert log, run remotely; nothing is copied. |
| `autodiag alert stats -t TARGET [--hours 24] [--top 20]` | Fetch the alert log and summarise a window: ORA code counts, top normalised message signatures, per-hour rates, instance lifecycle events. |

### `autodiag trace`

| Command | What it does |
|---|---|
| `autodiag trace parse FILE` | Sniff the kind (incident, 10046, 10053, deadlock, hang / systemstate, errorstack) and print the summary and section index. |
| `autodiag trace profile FILE [--top 10]` | tkprof-style aggregation of a 10046 trace: per-cursor parse/exec/fetch, CPU, elapsed, disk, query, rows, plan hashes, top waits. Bind values are never stored. |

### `autodiag diagnose`

| Command | What it does |
|---|---|
| `autodiag diagnose problem -t TARGET (-k KEY \| --incident N) [--max-incidents 5] [--window-minutes 30]` | All incidents of the problem, parsed traces (error, first application frame, SQL, PL/SQL, stack), stack consistency and newest-vs-oldest diff, alert-log entries around the incidents with noise removed, knowledge base, version and patches, ASH around the incident. Then the assessment. |
| `autodiag diagnose alert -t TARGET [--hours 24 \| --since ISO --until ISO]` | Every node's alert log in the window: entries classified by rules, noise counted not shown, duplicates folded, bursts vs the previous window, lifecycle events, rate change, ADR problems in the period, cross-node correlation on RAC, knowledge base per signature. Then the assessment. |
| `autodiag diagnose instance -t TARGET [--days 7] [--hours 24] [--live/--no-live]` | The alert sweep plus ADR problems of the last days and, with live checks, the current state over SQL*Net: instances (GV$INSTANCE), PDB open modes, blocked sessions (all instances on RAC), top waits, ASH last hour, RAC global-cache waits, Exadata cell waits. Default: live when the target has SQL*Net. |

Common options: `--case ID|new`, `--no-assess`, `--model NAME`, `--json`, `--dossier`,
`--markdown FILE`.

On a terminal the diagnosis is coloured (severity, verified proofs, sections) and a
progress line goes to stderr while evidence is collected; piped output is plain text.
A recorded session is in `docs/demo/`.

### `autodiag diff`

| Command | What it does |
|---|---|
| `autodiag diff stacks LEFT.trc RIGHT.trc` | Normalise both incident call stacks (prelude and common tail stripped), align them, report similarity, divergence index, first application frame and component per side. |
| `autodiag diff sqltrace NORMAL.trc ANOMALY.trc [--top 10]` | Per-sql_id comparison of two 10046 profiles with ratios, tags, wait deltas and hints. |
| `autodiag diff alertrate LOG_A LOG_B [--split ISO] [--hours-a H] [--hours-b H]` | Message-rate comparison between two alert-log periods; `--split` cuts one log in two. |

### `autodiag case`

| Command | What it does |
|---|---|
| `autodiag case open TITLE -t TARGET [-k KEY …]` | Open a case. |
| `autodiag case list [-t TARGET]` | List cases. |
| `autodiag case show CASE_ID` | Artifacts, evidence, findings and reports of a case. |
| `autodiag case close CASE_ID` | Close a case (eligible for `scan purge` after the retention period). |
| `autodiag case add CASE_ID FILE [--kind trace] [--label …]` | Attach a local file as an artifact (sha256-deduplicated). |
| `autodiag case analyze CASE_ID ARTIFACT_ID` | Parse a trace artifact and store its summary as evidence. |
| `autodiag case collect-incident CASE_ID --id N` | Fetch an incident's trace from the case's target, attach it, parse it, record evidence. |
| `autodiag case evidence CASE_ID "text" [--tool manual]` | Record a manual observation as evidence. |
| `autodiag case finding CASE_ID --kind K --title T [-e EV_ID …] [--confidence 0.5] [--kb-ref …]` | Record a finding; every finding must cite at least one existing evidence id. |

### `autodiag report`

| Command | What it does |
|---|---|
| `autodiag report render CASE_ID [--kind dba\|sr] [--env] [--out FILE]` | Render Markdown from the case (timeline, evidence, findings, environment). `--env` queries the target for version, patches and non-default parameters. The report is stored in the case. |
| `autodiag report list CASE_ID` | Stored reports. |
| `autodiag report show REPORT_ID` | Print one. |

### `autodiag kb`

| Command | What it does |
|---|---|
| `autodiag kb lookup [-k KEY] [-f FRAME …] [--alert TEXT] [-w EVENT …] [--platform generic\|exacc]` | Match the YAML knowledge base: ORA-600/7445 first arguments, kernel components by frame prefix, alert-log signatures, wait events, Exadata specifics. Returns meaning, checks, actions and a My Oracle Support search string; it never invents note numbers. |

### `autodiag scan`

| Command | What it does |
|---|---|
| `autodiag scan run [-t TARGET] [--days 7]` | Scan targets for ADR problems and record new problem keys; notifications go to `<data_dir>/notifications.log` and the optional `notify_command`. |
| `autodiag scan list [-t TARGET]` | Scan history. |
| `autodiag scan purge [--days N]` | Delete closed cases older than N days (default: `retention_days`). |

### `autodiag mcp`

| Command | What it does |
|---|---|
| `autodiag mcp stdio` | MCP over stdio; what a local OpenCode MCP entry launches. |
| `autodiag mcp http [--host] [--port]` | MCP over streamable HTTP at `/mcp`. |
| `autodiag mcp selftest` | List the tools and call `list_targets`. |

### `autodiag serve`

`autodiag serve [--host] [--port]` runs the web UI, `/api/v1` and `/mcp` in one process
(loopback by default). The systemd user unit in `systemd/` runs this command.

## Exit codes and output

- Exit code 1 with a message on stderr for unknown targets, missing incidents, refused
  paths and SSH or SQL*Net failures.
- `--json` prints the pydantic model of the result, which is the same shape the REST API
  and the MCP tools return.

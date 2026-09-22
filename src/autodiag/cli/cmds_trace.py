from pathlib import Path

import typer

from autodiag.cli import common
from autodiag.trace.registry import parse_trace
from autodiag.trace.sqltrace import parse_sqltrace

app = typer.Typer(help="Parse and summarise trace files (local paths).")


@app.command("parse")
def parse(
    path: Path = typer.Argument(..., exists=True), as_json: bool = typer.Option(False, "--json")
) -> None:
    doc = parse_trace(path.read_text(errors="replace"))
    h = doc.header
    lines = [
        f"{path}: kind={doc.kind.value} lines={doc.line_count} version={h.oracle_version} "
        f"instance={h.instance_name} ospid={h.ospid} session={h.session_id}.{h.session_serial}",
    ]
    if hasattr(doc, "summary_lines"):
        lines += ["  " + ln for ln in doc.summary_lines()]
    elif doc.kind.value == "deadlock":
        lines.append(f"  {doc.deadlock_type}: {doc.classification}; cycle {doc.cycle}")
        lines += [
            f"  session {s.sid} ({s.user}@{s.pdb}, ospid {s.ospid}): {s.current_sql}"
            for s in doc.sessions
        ]
    elif doc.kind.value in {"hang", "systemstate"}:
        for ch in doc.chains:
            fb = ch.final_blocker
            lines.append(
                f"  chain {ch.number} {'(likely cause) ' if ch.likely_cause else ''}"
                f"{ch.signature}; final blocker sid {fb.session_id if fb else '-'} "
                f"waiting on {fb.wait_event if fb else '-'}"
            )
        if doc.systemstate:
            lines.append(
                f"  systemstate level {doc.systemstate.level}: "
                f"{len(doc.systemstate.processes)} processes"
            )
    elif doc.kind.value == "optimizer":
        lines.append(
            f"  sql_id={doc.sql_id} tables={[t.name for t in doc.table_stats]} "
            f"final cost={doc.final_cost}"
        )
        lines += [f"  access path {a.table}: {a.best} (cost {a.cost})" for a in doc.access_paths]
    elif doc.kind.value == "sqltrace":
        lines.append(
            f"  cursors={doc.cursor_count} exec={doc.totals.exec_count} "
            f"elapsed={common.us(doc.totals.elapsed_us)}"
        )
    if doc.ora_lines:
        lines += ["  " + ln for ln in doc.ora_lines[:5]]
    lines += [f"  section {s.kind} @{s.start_line}" for s in doc.sections[:12]]
    common.emit(doc, as_json=as_json, lines=lines)


@app.command("profile")
def profile(
    path: Path = typer.Argument(..., exists=True),
    top: int = typer.Option(10, "--top"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    prof = parse_sqltrace(path.read_text(errors="replace"))
    t = prof.totals
    lines = [
        f"{path}: cursors={prof.cursor_count} wall={prof.wall_seconds:.3f}s "
        f"parse={t.parse_count} exec={t.exec_count} fetch={t.fetch_count} "
        f"cpu={common.us(t.cpu_us)} elapsed={common.us(t.elapsed_us)} "
        f"disk={t.disk} query={t.query} rows={t.rows}",
    ]
    rows = []
    for c in prof.top_cursors(top):
        tt = c.total
        rows.append(
            [
                c.sql_id,
                c.dep,
                c.exec.count,
                c.fetch.count,
                common.us(tt.elapsed_us),
                tt.disk,
                tt.query,
                tt.rows,
                ",".join(str(p) for p in c.plan_hashes),
                c.sql_text.replace("\n", " ")[:60],
            ]
        )
    lines += common.table(
        rows, ["sql_id", "dep", "exec", "fetch", "elapsed", "disk", "query", "rows", "plan", "sql"]
    )
    lines.append("top waits:")
    lines += [
        f"  {common.us(w.total_ela_us):>10}  {w.count:6d}  {ev}" for ev, w in prof.top_waits(8)
    ]
    common.emit(prof, as_json=as_json, lines=lines)

from datetime import UTC, datetime
from pathlib import Path

import typer

from autodiag.alertlog.text import parse_alert_text
from autodiag.alertlog.window import window
from autodiag.cli import common
from autodiag.diff.alertrate import compare_alert_rates
from autodiag.diff.callstack import compare_stacks, stack_from_incident
from autodiag.diff.sqlprofile import compare_profiles
from autodiag.trace.incident import parse_incident
from autodiag.trace.sqltrace import parse_sqltrace

app = typer.Typer(help="Compare anomaly vs normal: call stacks, 10046 profiles, alert-log rates.")


@app.command("stacks")
def stacks(
    left: Path = typer.Argument(..., exists=True, help="Incident trace (e.g. the anomaly)."),
    right: Path = typer.Argument(..., exists=True, help="Incident trace (e.g. the baseline)."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of text."),
) -> None:
    """Align the call stacks of two incident traces and show where they diverge."""
    a = stack_from_incident(parse_incident(left.read_text(errors="replace")))
    b = stack_from_incident(parse_incident(right.read_text(errors="replace")))
    d = compare_stacks(a.frames, b.frames)
    lines = [
        f"similarity {d.similarity}  divergence at {d.divergence_index}  "
        f"common prefix {d.common_prefix} suffix {d.common_suffix}",
        f"left  first app frame: {d.left_first_app_frame} [{d.left_component}]",
        f"right first app frame: {d.right_first_app_frame} [{d.right_component}]",
        *[f"note: {n}" for n in d.notes],
        f"unique left : {d.unique_left}",
        f"unique right: {d.unique_right}",
        "",
        f"{'op':8} {'left':40} right",
    ]
    lines += [f"{f.op:8} {f.left or '':40} {f.right or ''}" for f in d.aligned[:60]]
    common.emit(d, as_json=as_json, lines=lines)


@app.command("sqltrace")
def sqltrace(
    normal: Path = typer.Argument(..., exists=True, help="10046 trace of the good run."),
    anomaly: Path = typer.Argument(..., exists=True, help="10046 trace of the bad run."),
    top: int = typer.Option(10, "--top", help="Statements to show, by elapsed delta."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of text."),
) -> None:
    """Compare two 10046 profiles per sql_id: elapsed and I/O ratios, plan changes, waits."""
    n = parse_sqltrace(normal.read_text(errors="replace"))
    a = parse_sqltrace(anomaly.read_text(errors="replace"))
    d = compare_profiles(n, a, top=top)
    lines = [f"totals: {d.summary}", ""]
    rows = [
        [
            it.sql_id,
            it.present_in,
            it.left.exec_count,
            it.right.exec_count,
            common.us(it.left.elapsed_us),
            common.us(it.right.elapsed_us),
            f"x{it.ratio_elapsed}",
            it.left.query,
            it.right.query,
            f"x{it.ratio_query}",
            "yes" if it.plan_change else "",
            ",".join(it.tags),
            it.sql_text.replace("\n", " ")[:40],
        ]
        for it in d.items
    ]
    lines += common.table(
        rows,
        [
            "sql_id",
            "in",
            "exec_n",
            "exec_a",
            "ela_n",
            "ela_a",
            "ratio",
            "cr_n",
            "cr_a",
            "ratio",
            "plan",
            "tags",
            "sql",
        ],
    )
    lines.append("")
    lines.append("wait deltas:")
    for w in d.wait_deltas[:10]:
        flag = "NEW " if w.new_in_right else ("GONE" if w.gone_in_right else "    ")
        lines.append(
            f"  {flag} {common.us(w.left.total_ela_us):>10} -> "
            f"{common.us(w.right.total_ela_us):>10}  {w.event}"
        )
    lines += ["", "hints:"] + [f"  - {h}" for h in d.explanation_hints]
    common.emit(d, as_json=as_json, lines=lines)


@app.command("alertrate")
def alertrate(
    log_a: Path = typer.Argument(..., exists=True, help="Alert log of the reference period."),
    log_b: Path = typer.Argument(..., exists=True, help="Alert log of the period under review."),
    split: str = typer.Option(
        None, "--split", help="Split time (ISO 8601, offset optional) when both paths are one file"
    ),
    hours_a: float = typer.Option(None, "--hours-a", help="Span of A in hours (default: auto)."),
    hours_b: float = typer.Option(None, "--hours-b", help="Span of B in hours (default: auto)."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of text."),
) -> None:
    """Compare alert-log message rates between two logs, or one log split at --split."""
    ra = parse_alert_text(log_a.read_text(errors="replace"))
    rb = parse_alert_text(log_b.read_text(errors="replace"))
    if split is not None:
        at = datetime.fromisoformat(split)
        if at.tzinfo is None:
            at = at.replace(tzinfo=UTC)
        ra, rb = window(ra, None, at), window(rb, at, None)
    d = compare_alert_rates(
        ra, rb, hours_a=hours_a or _span_hours(ra), hours_b=hours_b or _span_hours(rb)
    )
    common.emit(d, as_json=as_json, lines=d.summary_lines(top=25))


def _span_hours(records) -> float:
    ts = [r.ts for r in records if r.ts is not None]
    if len(ts) < 2:
        return 1.0
    return max((max(ts) - min(ts)).total_seconds() / 3600, 1 / 60)

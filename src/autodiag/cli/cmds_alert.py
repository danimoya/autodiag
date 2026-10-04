from datetime import UTC, datetime, timedelta

import typer

from autodiag.alertlog.stats import alert_stats
from autodiag.alertlog.window import window
from autodiag.cli import common

app = typer.Typer(help="Alert log: grep with context, statistics, fetch.")


@app.command("grep")
def grep(
    pattern: str = typer.Argument(..., help="Fixed string to search for (grep -F)."),
    target: str = typer.Option(..., "--target", "-t", help="Target name (see 'targets list')."),
    context: int = typer.Option(3, "-C", "--context", help="Context lines around a match."),
    max_lines: int = typer.Option(200, "--max-lines", help="Stop after this many lines."),
) -> None:
    """Search the alert log in place on the primary node (remote grep, nothing copied)."""
    src = common.source(common.target(target))
    node, home = src.primary_ref()
    out = src.grep_file(
        node, src.alert_log_path(node, home), pattern, context=context, max_lines=max_lines
    )
    typer.echo(out.rstrip() or "(no match)")


@app.command("stats")
def stats(
    target: str = typer.Option(..., "--target", "-t", help="Target name (see 'targets list')."),
    hours: float = typer.Option(24.0, "--hours", help="Window ending now, in hours."),
    top: int = typer.Option(20, "--top", help="Number of top message signatures."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of text."),
) -> None:
    """Summarise the last N hours of the alert log: ORA counts, top signatures, lifecycle."""
    s = common.settings()
    t = common.target(target, s)
    src = common.source(t, s)
    node, home = src.primary_ref()
    read = src.read_alert(node, home, common.cache_dir(s, t))
    records = read.records
    since = datetime.now(UTC) - timedelta(hours=hours)
    sel = window(records, since, None)
    st = alert_stats(sel, top=top)
    lines = [
        f"records {st.record_count} between {common.fmt_ts(st.first_ts)} "
        f"and {common.fmt_ts(st.last_ts)}; "
        f"incidents {st.incident_count}",
        "ORA codes: "
        + (
            ", ".join(
                f"ORA-{c:05d} x{n}" for c, n in sorted(st.ora_counts.items(), key=lambda kv: -kv[1])
            )
            or "none"
        ),
        "top signatures:",
    ]
    lines += [f"  {n:5d}  {sig}" for sig, n in st.top_signatures]
    lines.append("lifecycle events:")
    lines += [f"  {common.fmt_ts(e.ts)}  {e.text}" for e in st.lifecycle_events[-15:]]
    if read.truncated:
        lines.insert(0, "WARNING: " + read.coverage["warning"])
    common.emit({**st.model_dump(), "coverage": read.coverage}, as_json=as_json, lines=lines)

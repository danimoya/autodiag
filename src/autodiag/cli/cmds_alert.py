from datetime import UTC, datetime, timedelta

import typer

from autodiag.alertlog.stats import alert_stats
from autodiag.alertlog.text import parse_alert_text
from autodiag.alertlog.window import window
from autodiag.cli import common

app = typer.Typer(help="Alert log: grep with context, statistics, fetch.")


@app.command("grep")
def grep(
    pattern: str = typer.Argument(...),
    target: str = typer.Option(..., "--target", "-t"),
    context: int = typer.Option(3, "-C", "--context"),
    max_lines: int = typer.Option(200, "--max-lines"),
) -> None:
    src = common.source(common.target(target))
    node, home = src.primary_ref()
    out = src.grep_file(
        node, src.alert_log_path(node, home), pattern, context=context, max_lines=max_lines
    )
    typer.echo(out.rstrip() or "(no match)")


@app.command("stats")
def stats(
    target: str = typer.Option(..., "--target", "-t"),
    hours: float = typer.Option(24.0, "--hours"),
    top: int = typer.Option(20, "--top"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    s = common.settings()
    t = common.target(target, s)
    src = common.source(t, s)
    node, home = src.primary_ref()
    dest = common.cache_dir(s, t) / f"alert_{node.instance or 'db'}.log"
    src.fetch_file(node, src.alert_log_path(node, home), dest, max_bytes=64 * 1024 * 1024)
    records = parse_alert_text(dest.read_text(errors="replace"))
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
    common.emit(st, as_json=as_json, lines=lines)

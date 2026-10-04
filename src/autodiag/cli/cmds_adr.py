from pathlib import Path

import typer

from autodiag.cli import common
from autodiag.trace.registry import parse_trace

app = typer.Typer(help="ADR problems, incidents and files (via adrci over SSH).")


@app.command("problems")
def problems(
    target: str = typer.Option(..., "--target", "-t", help="Target name (see 'targets list')."),
    days: int = typer.Option(7, "--days", help="Look back this many days."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of a table."),
) -> None:
    """List ADR problems of the last N days (adrci 'show problem' over SSH)."""
    src = common.source(common.target(target))
    rows = src.list_problems(days=days)
    common.emit(
        {"problems": [p.model_dump() for p in rows]},
        as_json=as_json,
        lines=common.table(
            [
                [
                    p.problem_id,
                    p.problem_key,
                    p.last_incident or "-",
                    common.fmt_ts(p.lastinc_time),
                    p.instance or p.node,
                    p.adr_home,
                ]
                for p in rows
            ],
            ["id", "problem_key", "last_incident", "last_time", "instance", "adr_home"],
        ),
    )


@app.command("incidents")
def incidents(
    target: str = typer.Option(..., "--target", "-t", help="Target name (see 'targets list')."),
    problem_key: str = typer.Option(
        None, "--problem-key", "-k", help="Problem key as printed by 'adr problems'."
    ),
    problem_id: int = typer.Option(None, "--problem-id", "-p", help="ADR problem id."),
    node: str = typer.Option(None, "--node", help="Node host, SSH alias or instance."),
    adr_home: str = typer.Option(None, "--adr-home", help="ADR home from the problem listing."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of a table."),
) -> None:
    """List the incidents of one problem, selected by --problem-id or --problem-key."""
    if problem_key is None and problem_id is None:
        typer.echo("give --problem-id or --problem-key", err=True)
        raise typer.Exit(code=1)
    src = common.source(common.target(target))
    rows = src.list_incidents(
        problem_id=problem_id, problem_key=problem_key, node=node, adr_home=adr_home
    )
    common.emit(
        {"incidents": [i.model_dump() for i in rows]},
        as_json=as_json,
        lines=common.table(
            [
                [
                    i.incident_id,
                    i.problem_key,
                    common.fmt_ts(i.create_time),
                    i.instance or i.node,
                    i.adr_home,
                ]
                for i in rows
            ],
            ["incident", "problem_key", "created", "instance", "adr_home"],
        ),
    )


@app.command("incident")
def incident(
    target: str = typer.Option(..., "--target", "-t", help="Target name (see 'targets list')."),
    incident_id: int = typer.Option(..., "--id", help="ADR incident id."),
    node: str = typer.Option(None, "--node", help="Node host, SSH alias or instance."),
    adr_home: str = typer.Option(None, "--adr-home", help="ADR home from the incident listing."),
    fetch: bool = typer.Option(
        False, "--fetch", help="Fetch the incident trace into the cache and summarise it"
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of text."),
) -> None:
    """Show one incident; with --fetch, download its trace into the cache and summarise it."""
    s = common.settings()
    t = common.target(target, s)
    src = common.source(t, s)
    inc = src.get_incident(incident_id, node=node, adr_home=adr_home)
    if inc is None:
        typer.echo(f"incident {incident_id} not found on {target}", err=True)
        raise typer.Exit(code=1)
    lines = [
        f"incident {inc.incident_id}  {inc.problem_key}  created {common.fmt_ts(inc.create_time)}",
        f"  error {inc.error_facility}-{inc.error_number} args={inc.error_args} "
        f"flood_controlled={inc.flood_controlled}",
        f"  trace {inc.trace_file}",
        f"  owner trace {inc.owner_trace_file}",
    ]
    lines += [f"  {k}: {v}" for k, v in inc.keys.items()]
    if fetch and inc.trace_file:
        selected_node = src.incident_node(inc)
        dest = src.cache_path(common.cache_dir(s, t), selected_node, inc.trace_file)
        src.fetch_file(selected_node, inc.trace_file, dest)
        doc = parse_trace(dest.read_text(errors="replace"))
        lines.append(f"  fetched -> {dest} ({doc.line_count} lines, kind={doc.kind.value})")
        if hasattr(doc, "summary_lines"):
            lines += ["  " + ln for ln in doc.summary_lines()]
    common.emit(inc, as_json=as_json, lines=lines)


@app.command("fetch")
def fetch_file(
    target: str = typer.Option(..., "--target", "-t", help="Target name (see 'targets list')."),
    path: str = typer.Argument(..., help="Absolute remote path under the target's diagnostic root"),
    out: Path = typer.Option(None, "--out", help="Destination file (default: cache dir)"),
    node: str = typer.Option(None, "--node", help="Node host (default: first node)"),
) -> None:
    """Copy one remote file under the target's diagnostic root to the cache (or --out)."""
    s = common.settings()
    t = common.target(target, s)
    candidates = [n for n in t.nodes if node is None or node in (n.host, n.ssh_alias, n.instance)]
    if len(candidates) != 1:
        raise typer.BadParameter("Select one target node with --node")
    n = candidates[0]
    src = common.source(t, s)
    dest = out or src.cache_path(common.cache_dir(s, t), n, path)
    src.fetch_file(n, path, dest)
    typer.echo(str(dest))

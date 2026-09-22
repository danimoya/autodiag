from pathlib import Path

import typer

from autodiag.cli import common
from autodiag.trace.registry import parse_trace

app = typer.Typer(help="ADR problems, incidents and files (via adrci over SSH).")


@app.command("problems")
def problems(
    target: str = typer.Option(..., "--target", "-t"),
    days: int = typer.Option(7, "--days"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
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
                ]
                for p in rows
            ],
            ["id", "problem_key", "last_incident", "last_time", "instance"],
        ),
    )


@app.command("incidents")
def incidents(
    target: str = typer.Option(..., "--target", "-t"),
    problem_key: str = typer.Option(..., "--problem-key", "-k"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    src = common.source(common.target(target))
    rows = src.list_incidents(problem_key=problem_key)
    common.emit(
        {"incidents": [i.model_dump() for i in rows]},
        as_json=as_json,
        lines=common.table(
            [
                [i.incident_id, i.problem_key, common.fmt_ts(i.create_time), i.instance or i.node]
                for i in rows
            ],
            ["incident", "problem_key", "created", "instance"],
        ),
    )


@app.command("incident")
def incident(
    target: str = typer.Option(..., "--target", "-t"),
    incident_id: int = typer.Option(..., "--id"),
    fetch: bool = typer.Option(
        False, "--fetch", help="Fetch the incident trace into the cache and summarise it"
    ),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    s = common.settings()
    t = common.target(target, s)
    src = common.source(t, s)
    inc = src.get_incident(incident_id)
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
        node = (
            t.node_for_instance(inc.instance)
            if inc.instance and any(n.instance == inc.instance for n in t.nodes)
            else t.nodes[0]
        )
        dest = common.cache_dir(s, t) / Path(inc.trace_file).name
        src.fetch_file(node, inc.trace_file, dest)
        doc = parse_trace(dest.read_text(errors="replace"))
        lines.append(f"  fetched -> {dest} ({doc.line_count} lines, kind={doc.kind.value})")
        if hasattr(doc, "summary_lines"):
            lines += ["  " + ln for ln in doc.summary_lines()]
    common.emit(inc, as_json=as_json, lines=lines)


@app.command("fetch")
def fetch_file(
    target: str = typer.Option(..., "--target", "-t"),
    path: str = typer.Argument(..., help="Absolute remote path under the target's diagnostic root"),
    out: Path = typer.Option(None, "--out", help="Destination file (default: cache dir)"),
    node: str = typer.Option(None, "--node", help="Node host (default: first node)"),
) -> None:
    s = common.settings()
    t = common.target(target, s)
    n = next((x for x in t.nodes if x.host == node), t.nodes[0]) if node else t.nodes[0]
    dest = out or common.cache_dir(s, t) / Path(path).name
    common.source(t, s).fetch_file(n, path, dest)
    typer.echo(str(dest))

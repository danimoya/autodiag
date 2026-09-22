from pathlib import Path

import typer

from autodiag.cli import common
from autodiag.report.build import build_context
from autodiag.report.render import render_report

app = typer.Typer(help="Render DBA and Service Request reports for a case.")


@app.command("render")
def render(
    case_id: str,
    kind: str = typer.Option("dba", "--kind"),
    out: Path = typer.Option(None, "--out"),
    capture_env: bool = typer.Option(
        False, "--env", help="Query the target for version/patches/parameters"
    ),
) -> None:
    s = common.settings()
    st = common.store(s)
    case = st.get_case(case_id)
    t = common.target(case.target, s)
    ctx = build_context(
        st,
        case_id,
        target=t,
        transport_factory=common.transport_factory(s, t),
        runner=common.sql_runner(s, t) if capture_env else None,
        capture_env=capture_env,
    )
    md = render_report(kind, ctx)
    st.add_report(case_id, kind=kind, markdown=md)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md)
        typer.echo(str(out))
    else:
        typer.echo(md)


@app.command("list")
def list_reports(case_id: str) -> None:
    for r in common.store().list_reports(case_id):
        typer.echo(f"{r.id}  {r.kind}  {common.fmt_ts(r.rendered_at)}  {len(r.markdown)} chars")


@app.command("show")
def show_report(report_id: str) -> None:
    typer.echo(common.store().get_report(report_id).markdown)

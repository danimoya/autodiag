import typer

from autodiag.cli import common
from autodiag.mcp.server import default_context
from autodiag.scheduler.scan import scan_all, scan_target

app = typer.Typer(
    help="Scan targets for new ADR problems (no LLM); notifications go to notifications.log."
)


@app.command("run")
def run(
    target: str = typer.Option(None, "--target", "-t"), days: int = typer.Option(7, "--days")
) -> None:
    s = common.settings()
    ctx = default_context(s, common.inventory(s))
    results = (
        [scan_target(ctx, ctx.target(target), days=days)] if target else scan_all(ctx, days=days)
    )
    for r in results:
        typer.echo(
            f"{r.target}: "
            + (r.error or f"{r.problem_count} problems, new: {r.new_problem_keys or []}")
        )


@app.command("list")
def list_scans(target: str = typer.Option(None, "--target", "-t")) -> None:
    for sc in common.store().list_scans(target):
        typer.echo(f"{sc.id}  {sc.target}  {common.fmt_ts(sc.started_at)}  {sc.summary}")


@app.command("purge")
def purge_cases(days: int = typer.Option(None, "--days")) -> None:
    from autodiag.case.retention import purge

    s = common.settings()
    res = purge(common.store(s), days=days or s.retention_days)
    typer.echo(f"deleted {res.cases_deleted} closed cases and {res.files_deleted} files")

"""AutoDiag command line entry point."""

from __future__ import annotations

import typer

from autodiag import __version__
from autodiag.cli import (
    cmds_adr,
    cmds_alert,
    cmds_case,
    cmds_diff,
    cmds_kb,
    cmds_report,
    cmds_scan,
    cmds_serve,
    cmds_target,
    cmds_trace,
    cmds_web,
)

app = typer.Typer(
    name="autodiag",
    help="AutoDiag: Oracle Database diagnostic assistant (ADR, traces, alert logs, diffs).",
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(cmds_target.app, name="targets")
app.add_typer(cmds_adr.app, name="adr")
app.add_typer(cmds_alert.app, name="alert")
app.add_typer(cmds_trace.app, name="trace")
app.add_typer(cmds_diff.app, name="diff")
app.add_typer(cmds_case.app, name="case")
app.add_typer(cmds_report.app, name="report")
app.add_typer(cmds_kb.app, name="kb")
app.add_typer(cmds_serve.app, name="mcp")
app.add_typer(cmds_scan.app, name="scan")
app.add_typer(cmds_web.app, name="serve")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"autodiag {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show the AutoDiag version and exit.",
    ),
) -> None:
    """AutoDiag: Oracle Database diagnostic assistant."""

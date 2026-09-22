"""AutoDiag command line entry point."""

from __future__ import annotations

import typer

from autodiag import __version__

app = typer.Typer(
    name="autodiag",
    help="AutoDiag: Oracle Database diagnostic assistant (ADR, traces, alert logs, diffs).",
    no_args_is_help=True,
    add_completion=False,
)


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

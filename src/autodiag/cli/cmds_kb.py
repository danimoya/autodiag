import typer

from autodiag.cli import common
from autodiag.kb.lookup import kb_lookup

app = typer.Typer(help="Knowledge base lookups.")


@app.command("lookup")
def lookup(
    problem_key: str = typer.Option(None, "--problem-key", "-k"),
    frame: list[str] = typer.Option([], "--frame", "-f"),
    alert: str = typer.Option(None, "--alert"),
    wait: list[str] = typer.Option([], "--wait", "-w"),
    platform: str = typer.Option("generic", "--platform"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    hits = kb_lookup(
        problem_key=problem_key,
        frames=list(frame) or None,
        alert_signature=alert,
        wait_events=list(wait) or None,
        platform=platform,
    )
    common.emit(
        [h.model_dump() for h in hits],
        as_json=as_json,
        lines=[h.as_text() for h in hits] or ["(no match)"],
    )

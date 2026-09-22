from datetime import UTC, datetime
from pathlib import Path

import typer

from autodiag.cli import common
from autodiag.diagnose.engine import diagnose
from autodiag.diagnose.models import Diagnosis
from autodiag.diagnose.render import diagnosis_lines, diagnosis_markdown

app = typer.Typer(
    help="Automated diagnosis: collect evidence, let the model assess it with proofs, "
    "report what matters."
)

_T = typer.Option(..., "--target", "-t", help="Target name (see 'targets list').")
_CASE = typer.Option(
    None, "--case", help="Record evidence and findings in this case ('new' opens one)."
)
_NO_ASSESS = typer.Option(False, "--no-assess", help="Skip the model; rank by rules only.")
_MODEL = typer.Option(None, "--model", help="Ollama model (default: ollama_advisor_model).")
_JSON = typer.Option(False, "--json", help="Emit the full diagnosis as JSON.")
_DOSSIER = typer.Option(False, "--dossier", help="Also print every dossier item.")
_MD = typer.Option(None, "--markdown", help="Write the diagnosis as Markdown to this file.")


def _run(**kw) -> Diagnosis:
    s = common.settings()
    ctx = common.context(s)
    case = kw.pop("case")
    kw["record"] = case is not None
    kw["case_id"] = None if case in (None, "new") else case
    return diagnose(ctx, **kw)


def _emit(d: Diagnosis, *, as_json: bool, dossier: bool, markdown: Path | None) -> None:
    if markdown:
        markdown.write_text(diagnosis_markdown(d))
    common.emit(d, as_json=as_json, lines=diagnosis_lines(d, dossier=dossier))


def _iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


@app.command("problem")
def problem(
    target: str = _T,
    problem_key: str = typer.Option(None, "--problem-key", "-k", help="ADR problem key."),
    incident: int = typer.Option(None, "--incident", help="Or one incident id of it."),
    max_incidents: int = typer.Option(5, "--max-incidents", help="Traces to fetch and parse."),
    window: int = typer.Option(30, "--window-minutes", help="Alert-log window around it."),
    case: str = _CASE,
    no_assess: bool = _NO_ASSESS,
    model: str = _MODEL,
    as_json: bool = _JSON,
    dossier: bool = _DOSSIER,
    markdown: Path = _MD,
) -> None:
    """Diagnose one ADR problem (ORA-600, ORA-7445, ...) from its incidents, traces, stacks,
    alert-log context, knowledge base and live ASH."""
    if problem_key is None and incident is None:
        typer.echo("give --problem-key or --incident", err=True)
        raise typer.Exit(code=1)
    d = _run(
        mode="problem",
        target=target,
        problem_key=problem_key,
        incident_id=incident,
        max_incidents=max_incidents,
        window_minutes=window,
        case=case,
        assess=not no_assess,
        model=model,
    )
    _emit(d, as_json=as_json, dossier=dossier, markdown=markdown)


@app.command("alert")
def alert(
    target: str = _T,
    hours: float = typer.Option(24.0, "--hours", help="Window ending now (or at --until)."),
    since: str = typer.Option(None, "--since", help="ISO 8601 start instead of --hours."),
    until: str = typer.Option(None, "--until", help="ISO 8601 end (default: now)."),
    case: str = _CASE,
    no_assess: bool = _NO_ASSESS,
    model: str = _MODEL,
    as_json: bool = _JSON,
    dossier: bool = _DOSSIER,
    markdown: Path = _MD,
) -> None:
    """Diagnose the alert log of every node in a window: classify, suppress noise, detect
    bursts, correlate across nodes, link ADR problems, then assess."""
    d = _run(
        mode="alert",
        target=target,
        hours=hours,
        since=_iso(since),
        until=_iso(until),
        case=case,
        assess=not no_assess,
        model=model,
    )
    _emit(d, as_json=as_json, dossier=dossier, markdown=markdown)


@app.command("instance")
def instance(
    target: str = _T,
    days: int = typer.Option(7, "--days", help="ADR problems to look back."),
    hours: float = typer.Option(24.0, "--hours", help="Alert-log window."),
    live: bool = typer.Option(
        None,
        "--live/--no-live",
        help="Live SQL*Net checks (instances, PDBs, blocking, waits, RAC gc, cells). "
        "Default: on when the target has SQL*Net.",
    ),
    case: str = _CASE,
    no_assess: bool = _NO_ASSESS,
    model: str = _MODEL,
    as_json: bool = _JSON,
    dossier: bool = _DOSSIER,
    markdown: Path = _MD,
) -> None:
    """Diagnose a database instance or a whole RAC: recent ADR problems, alert logs of all
    nodes, cross-node correlation and, with --live, the current state over SQL*Net."""
    d = _run(
        mode="instance",
        target=target,
        days=days,
        hours=hours,
        live=live,
        case=case,
        assess=not no_assess,
        model=model,
    )
    _emit(d, as_json=as_json, dossier=dossier, markdown=markdown)

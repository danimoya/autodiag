from pathlib import Path

import typer

from autodiag.cli import common
from autodiag.trace.registry import parse_trace

app = typer.Typer(help="Cases: collect artifacts, record evidence and findings.")


@app.command("open")
def open_case(
    title: str = typer.Argument(...),
    target: str = typer.Option(..., "--target", "-t"),
    problem_key: list[str] = typer.Option([], "--problem-key", "-k"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    s = common.settings()
    common.target(target, s)
    c = common.store(s).open_case(target, title, problem_keys=list(problem_key))
    common.emit(c, as_json=as_json, lines=[f"opened {c.id}: {c.title} ({c.target})"])


@app.command("list")
def list_cases(
    target: str = typer.Option(None, "--target", "-t"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    cases = common.store().list_cases(target=target)
    common.emit(
        {"cases": [c.model_dump() for c in cases]},
        as_json=as_json,
        lines=common.table(
            [[c.id, c.target, c.status, common.fmt_ts(c.created_at), c.title] for c in cases],
            ["id", "target", "status", "created", "title"],
        ),
    )


@app.command("show")
def show_case(case_id: str, as_json: bool = typer.Option(False, "--json")) -> None:
    st = common.store()
    c = st.get_case(case_id)
    arts, evs, fnds, reps = (
        st.list_artifacts(c.id),
        st.list_evidence(c.id),
        st.list_findings(c.id),
        st.list_reports(c.id),
    )
    lines = [
        f"{c.id} [{c.status}] {c.title} on {c.target}; problem keys {c.problem_keys}",
        "artifacts:",
    ]
    lines += [f"  {a.id} {a.kind} {a.path} ({a.size} bytes)" for a in arts] or ["  (none)"]
    lines.append("evidence:")
    lines += [f"  {e.id} {e.tool}: {e.summary[:100]}" for e in evs] or ["  (none)"]
    lines.append("findings:")
    lines += [
        f"  {f.id} [{f.kind} {common.pct(f.confidence)} {f.status}] {f.title}: {f.detail[:100]}"
        for f in fnds
    ] or ["  (none)"]
    lines.append("reports:")
    lines += [f"  {r.id} {r.kind} {common.fmt_ts(r.rendered_at)}" for r in reps] or ["  (none)"]
    payload = {
        "case": c.model_dump(),
        "artifacts": [a.model_dump() for a in arts],
        "evidence": [e.model_dump() for e in evs],
        "findings": [f.model_dump() for f in fnds],
    }
    common.emit(payload, as_json=as_json, lines=lines)


@app.command("close")
def close_case(case_id: str) -> None:
    common.store().close_case(case_id)
    typer.echo(f"closed {case_id}")


@app.command("add")
def add_artifact(
    case_id: str,
    path: Path = typer.Argument(..., exists=True),
    kind: str = typer.Option("trace", "--kind"),
    label: str = typer.Option("", "--label"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    a = common.store().add_artifact(
        case_id, kind=kind, path=path, origin={"source": "local", "path": str(path)}, label=label
    )
    common.emit(a, as_json=as_json, lines=[f"{a.id} {a.kind} {a.path} sha256={a.sha256[:12]}"])


@app.command("analyze")
def analyze_artifact(
    case_id: str, artifact_id: str, as_json: bool = typer.Option(False, "--json")
) -> None:
    """Parse a trace artifact and record the summary as evidence."""
    st = common.store()
    a = st.get_artifact(artifact_id)
    doc = parse_trace(Path(a.path).read_text(errors="replace"))
    summary = (
        "; ".join(doc.summary_lines())
        if hasattr(doc, "summary_lines")
        else f"{doc.kind.value} trace, {doc.line_count} lines"
    )
    ev = st.record_evidence(
        "parse_trace",
        {"artifact_id": a.id},
        summary,
        case_id=case_id,
        artifact_id=a.id,
        line_from=doc.sections[0].start_line if doc.sections else None,
    )
    common.emit(
        {"evidence_id": ev.id, "kind": doc.kind.value, "summary": summary},
        as_json=as_json,
        lines=[f"{ev.id}: {summary}"],
    )


@app.command("finding")
def add_finding(
    case_id: str,
    kind: str = typer.Option(..., "--kind"),
    title: str = typer.Option(..., "--title"),
    detail: str = typer.Option("", "--detail"),
    confidence: float = typer.Option(0.5, "--confidence"),
    evidence: list[str] = typer.Option([], "--evidence", "-e"),
    kb_ref: list[str] = typer.Option([], "--kb-ref"),
    author: str = typer.Option("human", "--author"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    f = common.store().add_finding(
        case_id,
        kind=kind,
        title=title,
        detail=detail,
        confidence=confidence,
        evidence_ids=list(evidence),
        kb_refs=list(kb_ref),
        author=author,
    )
    common.emit(f, as_json=as_json, lines=[f"{f.id} [{f.kind}] {f.title}"])


@app.command("evidence")
def add_evidence(
    case_id: str,
    summary: str = typer.Argument(...),
    tool: str = typer.Option("manual", "--tool"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    ev = common.store().record_evidence(tool, {}, summary, case_id=case_id)
    common.emit(ev, as_json=as_json, lines=[f"{ev.id}: {summary}"])


@app.command("collect-incident")
def collect_incident(
    case_id: str,
    incident_id: int = typer.Option(..., "--id"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Fetch an incident's trace from the case's target, store it as an artifact, parse it and
    record the summary as evidence."""
    s = common.settings()
    st = common.store(s)
    c = st.get_case(case_id)
    t = common.target(c.target, s)
    src = common.source(t, s)
    inc = src.get_incident(incident_id)
    if inc is None or not inc.trace_file:
        typer.echo(f"incident {incident_id} not found on {c.target}", err=True)
        raise typer.Exit(code=1)
    node = next((n for n in t.nodes if n.instance == inc.instance), t.nodes[0])
    dest = common.cache_dir(s, t) / Path(inc.trace_file).name
    src.fetch_file(node, inc.trace_file, dest)
    a = st.add_artifact(
        c.id,
        kind="incident_trace",
        path=dest,
        origin={
            "source": "ssh",
            "node": node.host,
            "remote": inc.trace_file,
            "incident_id": incident_id,
        },
    )
    doc = parse_trace(dest.read_text(errors="replace"))
    summary = (
        "; ".join(doc.summary_lines())
        if hasattr(doc, "summary_lines")
        else f"{doc.kind.value} trace"
    )
    ev = st.record_evidence(
        "get_incident", {"incident_id": incident_id}, summary, case_id=c.id, artifact_id=a.id
    )
    st.upsert_incidents(c.target, [inc])
    if inc.problem_key and inc.problem_key not in c.problem_keys:
        st.update_case(c.id, problem_keys=[*c.problem_keys, inc.problem_key])
    common.emit(
        {
            "artifact_id": a.id,
            "evidence_id": ev.id,
            "incident": inc.model_dump(),
            "summary": summary,
        },
        as_json=as_json,
        lines=[f"artifact {a.id}, evidence {ev.id}", f"  {summary}"],
    )

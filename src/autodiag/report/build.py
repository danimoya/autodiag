"""Assemble a ReportContext from the case store (and optionally the live target)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from autodiag.case.store import CaseStore
from autodiag.core.settings import Settings
from autodiag.kb.lookup import kb_lookup
from autodiag.report.env import capture_environment
from autodiag.report.render import ReportContext
from autodiag.report.timeline import TimelineEvent
from autodiag.trace.models import TraceKind
from autodiag.trace.registry import parse_trace


def build_context(
    store: CaseStore, case_id: str, *, settings: Settings, capture_env: bool = False
) -> ReportContext:
    from autodiag.cli import common  # local import: the CLI module wires transports/runners

    case = store.get_case(case_id)
    target = common.target(case.target, settings)
    artifacts = store.list_artifacts(case.id)
    incidents: list[dict[str, Any]] = []
    stack_notes: list[str] = []
    for a in artifacts:
        if a.kind not in {"trace", "incident_trace"}:
            continue
        try:
            doc = parse_trace(Path(a.path).read_text(errors="replace"))
        except OSError:
            continue
        if doc.kind is TraceKind.INCIDENT:
            incidents.append(
                {
                    "incident_id": doc.incident_id,
                    "problem_key": doc.problem_key,
                    "create_time": doc.timestamps[0] if doc.timestamps else None,
                    "trace_file": a.origin.get("remote", a.path),
                    "first_app_frame": doc.first_app_frame,
                    "sql_id": doc.sql_id,
                }
            )
    incidents.sort(key=lambda i: i["create_time"] or datetime.min.replace(tzinfo=UTC), reverse=True)
    env: dict[str, Any] = {}
    if capture_env:
        env = capture_environment(
            target,
            transport_factory=common.transport_factory(settings, target),
            runner=common.sql_runner(settings, target),
        )
    kb_hits: list[dict[str, Any]] = []
    for key in case.problem_keys:
        kb_hits += [
            h.model_dump() for h in kb_lookup(problem_key=key, platform=target.platform.value)
        ]
    timeline = [
        TimelineEvent(
            ts=i["create_time"],
            source="incident",
            text=f"{i['problem_key']} incident {i['incident_id']}",
            ref=str(i["incident_id"]),
            is_error=True,
        )
        for i in incidents
        if i["create_time"]
    ]
    timeline.sort(key=lambda e: e.ts)
    return ReportContext(
        case=case.model_dump(),
        target={
            "name": target.name,
            "platform": target.platform.value,
            "kind": target.kind.value,
            "oracle_version": target.oracle_version,
            "db_unique_name": target.db_unique_name,
            "nodes": [n.host for n in target.nodes],
        },
        environment=env,
        problems=[p.model_dump() for p in store.list_problems(case.target)],
        incidents=incidents,
        findings=[f.model_dump() for f in store.list_findings(case.id)],
        evidence=[e.model_dump() for e in store.list_evidence(case.id)],
        artifacts=[a.model_dump() for a in artifacts],
        timeline=timeline,
        kb_hits=kb_hits,
        stack_notes=stack_notes,
        generated_at=datetime.now(UTC).replace(microsecond=0),
    )

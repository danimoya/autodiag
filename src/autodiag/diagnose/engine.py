"""The diagnose entry point: collect -> assess (LLM, verified) -> record -> Diagnosis."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

import httpx

from autodiag.core.settings import Settings
from autodiag.diagnose.collect import collect_alert, collect_instance, collect_problem
from autodiag.diagnose.models import Assessment, Diagnosis, Dossier
from autodiag.llm.assess import OllamaAssessor, rules_assessment
from autodiag.llm.ollama import OllamaClient, OllamaError

MODES = ("problem", "alert", "instance")
Assessor = Callable[[Dossier], Assessment]


def default_assessor(
    settings: Settings, *, model: str | None = None, redact: bool = True
) -> OllamaAssessor:
    client = OllamaClient(
        settings.ollama_primary_url,
        settings.ollama_fallback_url,
        timeout=settings.ollama_request_timeout,
        num_ctx=settings.ollama_num_ctx,
        health_cache_seconds=settings.ollama_health_cache_seconds,
    )
    # leave room for the answer and the system prompt: ~3 bytes per token, 60 % of the window
    max_bytes = int(settings.ollama_num_ctx * 3 * 0.6)
    return OllamaAssessor(
        client, model or settings.ollama_advisor_model, redact=redact, max_bytes=max_bytes
    )


def _scope_title(mode: str, dossier: Dossier) -> str:
    s = dossier.scope
    if mode == "problem":
        return f"diagnose problem: {s.get('problem_key')}"
    if mode == "alert":
        return f"diagnose alert log: {str(s.get('since'))[:16]} to {str(s.get('until'))[:16]}"
    return f"diagnose instance: {s.get('days')}d problems, {s.get('hours')}h alert" + (
        ", live" if s.get("live") else ""
    )


def diagnose(
    ctx: Any,
    *,
    mode: str,
    target: str,
    problem_key: str | None = None,
    incident_id: int | None = None,
    hours: float = 24.0,
    since: datetime | None = None,
    until: datetime | None = None,
    days: int = 7,
    live: bool | None = None,
    case_id: str | None = None,
    record: bool = False,
    assess: bool = True,
    assessor: Assessor | None = None,
    model: str | None = None,
    max_incidents: int = 5,
    window_minutes: int = 30,
) -> Diagnosis:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    t = ctx.target(target)
    st = ctx.store
    if case_id:
        case = st.get_case(case_id)
    elif record:
        case = st.open_case(
            t.name, f"diagnose {mode}", problem_keys=[problem_key] if problem_key else []
        )
    else:
        case = ctx.scratch_case(t)
    if mode == "problem":
        dossier = collect_problem(
            ctx,
            t,
            case_id=case.id,
            problem_key=problem_key,
            incident_id=incident_id,
            max_incidents=max_incidents,
            window_minutes=window_minutes,
        )
    elif mode == "alert":
        dossier = collect_alert(ctx, t, case_id=case.id, hours=hours, since=since, until=until)
    else:
        dossier = collect_instance(ctx, t, case_id=case.id, days=days, hours=hours, live=live)
    title = _scope_title(mode, dossier)
    if record and not case_id:
        st.update_case(case.id, title=title)

    prompt_bytes = 0
    if assess:
        fn = assessor or default_assessor(
            ctx.settings, model=model, redact=t.redact and ctx.settings.redact_for_llm
        )
        try:
            assessment = fn(dossier)
        except (OllamaError, httpx.HTTPError, ValueError) as exc:
            assessment = rules_assessment(dossier, note=f"model assessment unavailable: {exc}")
        prompt_bytes = len(getattr(fn, "last_prompt", "") or "")
    else:
        assessment = rules_assessment(dossier)

    ev = st.record_evidence(
        f"diagnose_{mode}",
        {"target": t.name, **{k: v for k, v in dossier.scope.items() if v is not None}},
        f"[{assessment.severity.value}] {assessment.headline}"[:200],
        case_id=case.id,
    )
    finding_ids: list[str] = []
    if record:
        author = "rule" if assessment.model == "rules" else "agent"
        for c in assessment.concerns:
            if not c.proven:
                continue
            f = st.add_finding(
                case.id,
                kind=c.kind,
                title=c.title,
                detail=c.assessment
                + ("\nnext checks: " + "; ".join(c.next_checks) if c.next_checks else ""),
                confidence=assessment.confidence,
                evidence_ids=[p.evidence_id for p in c.proofs if p.verified],
                author=author,
            )
            finding_ids.append(f.id)
        for a in assessment.actions:
            f = st.add_finding(
                case.id,
                kind="action",
                title=a[:200],
                detail="",
                confidence=assessment.confidence,
                evidence_ids=[ev.id],
                author=author,
            )
            finding_ids.append(f.id)
    return Diagnosis(
        dossier=dossier,
        assessment=assessment,
        case_id=case.id,
        evidence_id=ev.id,
        finding_ids=finding_ids,
        prompt_bytes=prompt_bytes,
    )

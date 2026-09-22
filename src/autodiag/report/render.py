"""Render DBA and SR (Oracle Support) reports from a case context with Jinja2."""

from __future__ import annotations

from datetime import datetime
from importlib import resources
from typing import Any

from jinja2 import Environment, FunctionLoader, select_autoescape
from pydantic import BaseModel, Field

from autodiag.report.timeline import TimelineEvent

REPORT_KINDS = {"dba": "dba_report.md.j2", "sr": "sr_report.md.j2"}


class ReportContext(BaseModel):
    case: dict[str, Any]
    target: dict[str, Any]
    environment: dict[str, Any] = Field(default_factory=dict)
    problems: list[dict[str, Any]] = Field(default_factory=list)
    incidents: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    kb_hits: list[dict[str, Any]] = Field(default_factory=list)
    stack_notes: list[str] = Field(default_factory=list)
    profile_summary: str | None = None
    generated_at: datetime


def _load_template(name: str) -> str | None:
    try:
        return resources.files("autodiag.report").joinpath("templates").joinpath(name).read_text()
    except FileNotFoundError:
        return None


def _env() -> Environment:
    env = Environment(
        loader=FunctionLoader(_load_template),
        autoescape=select_autoescape([]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["ts"] = lambda v: (
        v.strftime("%Y-%m-%d %H:%M:%S %Z") if isinstance(v, datetime) else (v or "-")
    )
    env.filters["pct"] = lambda v: f"{round(float(v) * 100)}%" if v is not None else "-"
    return env


def render_report(kind: str, ctx: ReportContext) -> str:
    if kind not in REPORT_KINDS:
        raise ValueError(f"report kind must be one of {sorted(REPORT_KINDS)}")
    tpl = _env().get_template(REPORT_KINDS[kind])
    return tpl.render(**ctx.model_dump(), ctx=ctx).strip() + "\n"

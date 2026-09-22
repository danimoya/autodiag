"""Sniff a trace file's kind and dispatch to the right parser."""

from __future__ import annotations

from autodiag.trace import common
from autodiag.trace.deadlock import parse_deadlock
from autodiag.trace.errorstack import parse_errorstack
from autodiag.trace.hang import parse_hang
from autodiag.trace.header import parse_header, parse_timestamp_marker
from autodiag.trace.incident import parse_incident
from autodiag.trace.models import TraceBase, TraceKind
from autodiag.trace.opt10053 import parse_opt10053
from autodiag.trace.sqltrace import parse_sqltrace

_SNIFF_LINES = 400


def sniff_kind(text: str) -> TraceKind:
    head = text.splitlines()[:_SNIFF_LINES]
    joined = "\n".join(head)
    if "Dump for incident " in joined or "----- Incident Context Dump -----" in joined:
        return TraceKind.INCIDENT
    if "DEADLOCK DETECTED" in joined:
        return TraceKind.DEADLOCK
    if "HANG ANALYSIS:" in joined:
        return TraceKind.HANG
    if "SYSTEM STATE (level=" in joined:
        return TraceKind.SYSTEMSTATE
    if "PARAMETERS USED BY THE OPTIMIZER" in joined or "QUERY BLOCK SIGNATURE" in joined:
        return TraceKind.OPTIMIZER
    if "PARSING IN CURSOR #" in joined or "\nWAIT #" in joined or "\nEXEC #" in joined:
        return TraceKind.SQLTRACE
    if "----- Error Stack Dump -----" in joined:
        return TraceKind.ERRORSTACK
    # look a little further for slow-starting traces
    rest = "\n".join(text.splitlines()[_SNIFF_LINES : _SNIFF_LINES * 5])
    if "Dump for incident " in rest:
        return TraceKind.INCIDENT
    if "PARSING IN CURSOR #" in rest:
        return TraceKind.SQLTRACE
    if "PARAMETERS USED BY THE OPTIMIZER" in rest:
        return TraceKind.OPTIMIZER
    if "----- Error Stack Dump -----" in rest:
        return TraceKind.ERRORSTACK
    return TraceKind.GENERIC


class GenericTrace(TraceBase):
    kind: TraceKind = TraceKind.GENERIC


def parse_trace(text: str, kind: TraceKind | None = None) -> TraceBase:
    kind = kind or sniff_kind(text)
    if kind is TraceKind.INCIDENT:
        return parse_incident(text)
    if kind is TraceKind.DEADLOCK:
        return parse_deadlock(text)
    if kind in (TraceKind.HANG, TraceKind.SYSTEMSTATE):
        doc = parse_hang(text)
        doc.kind = kind
        return doc
    if kind is TraceKind.OPTIMIZER:
        return parse_opt10053(text)
    if kind is TraceKind.SQLTRACE:
        return parse_sqltrace(text)
    if kind is TraceKind.ERRORSTACK:
        return parse_errorstack(text)
    lines = text.splitlines()
    doc = GenericTrace(header=parse_header(lines), line_count=len(lines))
    doc.timestamps = [t for t in (parse_timestamp_marker(ln) for ln in lines) if t]
    doc.ora_lines = common.ora_lines(lines)
    return doc

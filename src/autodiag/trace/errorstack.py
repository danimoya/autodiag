"""``errorstack`` dumps (level 1-3): error, current SQL, call stack; no incident."""

from __future__ import annotations

from pydantic import BaseModel, Field

from autodiag.trace import common
from autodiag.trace.callstack import parse_call_stack_trace
from autodiag.trace.header import parse_header, parse_timestamp_marker
from autodiag.trace.models import CallStack, PlsqlFrame, Section, TraceBase, TraceKind


class ErrorstackTrace(TraceBase):
    kind: TraceKind = TraceKind.ERRORSTACK
    sql_id: str | None = None
    current_sql: str | None = None
    plsql_stack: list[PlsqlFrame] = Field(default_factory=list)
    call_stack: CallStack | None = None


class _Marker(BaseModel):
    line: int
    text: str


def parse_errorstack(text: str) -> ErrorstackTrace:
    lines = text.splitlines()
    es = ErrorstackTrace(header=parse_header(lines), line_count=len(lines))
    sections: list[Section] = []
    for i, line in enumerate(lines):
        ts = parse_timestamp_marker(line)
        if ts:
            es.timestamps.append(ts)
        if line.startswith("----- Error Stack Dump -----"):
            sections.append(
                Section(kind="error_stack", title=line, start_line=i + 1, end_line=i + 1)
            )
        elif common.CURRENT_SQL_NOID.match(line) and es.current_sql is None:
            es.sql_id, es.current_sql = common.parse_current_sql(lines, i)
            sections.append(
                Section(kind="current_sql", title=line, start_line=i + 1, end_line=i + 1)
            )
        elif line.startswith(common.PLSQL_STACK) and not es.plsql_stack:
            es.plsql_stack = common.parse_plsql_stack(lines, i)
        elif line.startswith("----- Call Stack Trace -----") and es.call_stack is None:
            es.call_stack = parse_call_stack_trace(lines, i)
            sections.append(
                Section(
                    kind="call_stack", title=line, start_line=i + 1, end_line=es.call_stack.end_line
                )
            )
    es.sections = sections
    es.ora_lines = common.ora_lines(lines)
    return es

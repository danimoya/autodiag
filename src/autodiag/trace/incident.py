"""Incident traces (ORA-600 / ORA-7445 / ORA-7xx) under ``incident/incdir_*``."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from autodiag.trace import common
from autodiag.trace.callstack import parse_call_stack_trace, parse_context_frames
from autodiag.trace.header import parse_header, parse_timestamp_marker
from autodiag.trace.models import (
    CallStack,
    ContextFrame,
    PlsqlFrame,
    Section,
    TraceBase,
    TraceKind,
)

_DUMP_FOR = re.compile(r"^========= Dump for incident (\d+) \((.+?)\) ========")
_ORA_LINE = re.compile(r"^ORA-(\d{5}): (.*)$")
_BRACKETS = re.compile(r"\[([^\]]*)\]")
_EXCEPTION = re.compile(
    r"^Exception \[type: (\w+), ([^\]]*)\] \[ADDR:(0x[0-9A-Fa-f]+)\] "
    r"\[PC:(0x[0-9A-Fa-f]+), (\S+?)\(\)\+(\d+)\]"
)
_CONTINUED = re.compile(r"^Dump continued from file: (.+)$")
_PROBLEM_KEY = re.compile(r"^Problem Key: (.+)$")
_INCIDENT_ID = re.compile(r"^Incident ID: (\d+)$")
_PRELUDE = {
    "ksedst1",
    "ksedst",
    "dbkedDefDump",
    "ksedmp",
    "dbgexPhaseII",
    "dbgexProcessError",
    "dbgeExecuteForError",
    "dbgePostErrorKGE",
    "dbkePostKGE_kgsf",
    "kgeade",
    "kgerelv",
    "kgerev",
    "kgeasnmierr",
    "kgesinv",
    "kgesin",
    "kgesinva",
    "dbgexExplicitEndInc",
    "dbgeEndDDEInvocationImpl",
    "ssexhd",
    "sslssSynchHdlr",
    "sslsshandler",
    "__sighandler",
    "__restore_rt",
    "skgesigOSErr",
    "skgesig_sigactionHandler",
    "kgeasi",
    "ksfdmp",
}


class ExceptionInfo(BaseModel):
    signal: str
    detail: str
    addr: str
    pc: str
    function: str
    offset: int


class IncidentTrace(TraceBase):
    kind: TraceKind = TraceKind.INCIDENT
    incident_id: int | None = None
    problem_key: str | None = None
    error_line: str | None = None
    error_code: int | None = None
    error_args: list[str] = Field(default_factory=list)
    exception: ExceptionInfo | None = None
    continued_from: str | None = None
    sql_id: str | None = None
    current_sql: str | None = None
    plsql_stack: list[PlsqlFrame] = Field(default_factory=list)
    call_stack: CallStack | None = None
    context_frames: list[ContextFrame] = Field(default_factory=list)

    @property
    def first_app_frame(self) -> str | None:
        """First frame that is not part of the error-handling / signal prelude."""
        sig = next((c.func for c in self.context_frames if c.signaling), None)
        if sig:
            return sig
        for c in self.context_frames:
            if c.func not in _PRELUDE:
                return c.func
        if self.call_stack:
            for f in self.call_stack.frames:
                if f.func not in _PRELUDE:
                    return f.func
        return None

    def summary_lines(self) -> list[str]:
        out = [f"{self.problem_key or 'unknown problem key'} (incident {self.incident_id})"]
        if self.error_line:
            out.append(self.error_line)
        if self.first_app_frame:
            comp = next(
                (c.component for c in self.context_frames if c.func == self.first_app_frame), ""
            )
            out.append(
                f"first application frame: {self.first_app_frame}" + (f" [{comp}]" if comp else "")
            )
        if self.sql_id:
            out.append(f"current SQL: sql_id={self.sql_id}")
        if self.plsql_stack:
            out.append(f"PL/SQL top: {self.plsql_stack[0].name} line {self.plsql_stack[0].line}")
        h = self.header
        if h.session_id:
            out.append(
                f"session {h.session_id}.{h.session_serial} module={h.module} "
                f"service={h.service_name} container={h.container_name or h.container_id}"
            )
        return out


def parse_incident(text: str) -> IncidentTrace:
    lines = text.splitlines()
    inc = IncidentTrace(header=parse_header(lines), line_count=len(lines))
    sections: list[Section] = []
    for i, line in enumerate(lines):
        ts = parse_timestamp_marker(line)
        if ts:
            inc.timestamps.append(ts)
        m = _CONTINUED.match(line)
        if m:
            inc.continued_from = m.group(1).strip()
            continue
        m = _DUMP_FOR.match(line)
        if m:
            inc.incident_id = int(m.group(1))
            inc.problem_key = m.group(2)
            sections.append(
                Section(kind="dump_for_incident", title=line, start_line=i + 1, end_line=i + 1)
            )
            continue
        m = _ORA_LINE.match(line)
        if (
            m
            and inc.error_line is None
            and int(m.group(1)) in {600, 7445}
            or (m and inc.error_line is None and 700 <= int(m.group(1)) < 800)
        ):
            inc.error_line = line.strip()
            inc.error_code = int(m.group(1))
            inc.error_args = [a for a in _BRACKETS.findall(m.group(2)) if a.strip()]
            continue
        m = _EXCEPTION.match(line)
        if m and inc.exception is None:
            inc.exception = ExceptionInfo(
                signal=m.group(1),
                detail=m.group(2),
                addr=m.group(3),
                pc=m.group(4),
                function=m.group(5),
                offset=int(m.group(6)),
            )
            continue
        if common.CURRENT_SQL_NOID.match(line) and inc.current_sql is None:
            inc.sql_id, inc.current_sql = common.parse_current_sql(lines, i)
            sections.append(
                Section(kind="current_sql", title=line, start_line=i + 1, end_line=i + 1)
            )
            continue
        if line.startswith(common.PLSQL_STACK) and not inc.plsql_stack:
            inc.plsql_stack = common.parse_plsql_stack(lines, i)
            sections.append(
                Section(kind="plsql_stack", title=line, start_line=i + 1, end_line=i + 1)
            )
            continue
        if line.startswith("----- Call Stack Trace -----") and inc.call_stack is None:
            inc.call_stack = parse_call_stack_trace(lines, i)
            sections.append(
                Section(
                    kind="call_stack",
                    title=line,
                    start_line=i + 1,
                    end_line=inc.call_stack.end_line,
                )
            )
            continue
        if line.startswith("----- Incident Context Dump -----"):
            sections.append(
                Section(kind="incident_context", title=line, start_line=i + 1, end_line=i + 1)
            )
            for j in range(i + 1, min(i + 12, len(lines))):
                pm = _PROBLEM_KEY.match(lines[j])
                if pm and inc.problem_key is None:
                    inc.problem_key = pm.group(1).strip()
                im = _INCIDENT_ID.match(lines[j])
                if im and inc.incident_id is None:
                    inc.incident_id = int(im.group(1))
            if not inc.context_frames:
                first = next(
                    (k for k in range(i, min(i + 40, len(lines))) if lines[k].startswith("[00]: ")),
                    None,
                )
                if first is not None:
                    inc.context_frames = parse_context_frames(lines, first)
    inc.sections = sections
    inc.ora_lines = common.ora_lines(lines)
    return inc

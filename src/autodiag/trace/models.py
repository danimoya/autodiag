"""Models shared by the trace parsers."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class TraceKind(StrEnum):
    INCIDENT = "incident"
    SQLTRACE = "sqltrace"
    OPTIMIZER = "optimizer"
    DEADLOCK = "deadlock"
    HANG = "hang"
    SYSTEMSTATE = "systemstate"
    ERRORSTACK = "errorstack"
    GENERIC = "generic"


class TraceHeader(BaseModel):
    trace_file: str | None = None
    oracle_version: str | None = None
    build_label: str | None = None
    oracle_home: str | None = None
    node_name: str | None = None
    os_release: str | None = None
    instance_name: str | None = None
    db_name: str | None = None
    db_unique_name: str | None = None
    oracle_pid: int | None = None
    ospid: int | None = None
    image: str | None = None
    session_id: int | None = None
    session_serial: int | None = None
    client_id: str | None = None
    service_name: str | None = None
    module: str | None = None
    action: str | None = None
    client_driver: str | None = None
    container_id: int | None = None
    container_name: str | None = None
    client_ip: str | None = None
    first_ts: datetime | None = None
    header_lines: int = 0


class Frame(BaseModel):
    func: str
    offset: int | None = None
    call_type: str | None = None
    entry: str | None = None
    raw: str = ""


class CallStack(BaseModel):
    frames: list[Frame] = Field(default_factory=list)
    source: str = "call_stack_trace"
    start_line: int = 0
    end_line: int = 0

    @property
    def funcs(self) -> list[str]:
        return [f.func for f in self.frames]


class ContextFrame(BaseModel):
    """One ``[NN]: func [component]`` line of an Incident Context Dump."""

    index: int
    func: str
    component: str = ""
    signaling: bool = False


class PlsqlFrame(BaseModel):
    handle: str
    line: int
    name: str


class Section(BaseModel):
    kind: str
    title: str
    start_line: int
    end_line: int


class TraceBase(BaseModel):
    kind: TraceKind
    header: TraceHeader
    sections: list[Section] = Field(default_factory=list)
    line_count: int = 0
    ora_lines: list[str] = Field(default_factory=list)
    timestamps: list[datetime] = Field(default_factory=list)

"""One alert-log entry, regardless of whether it came from text, XML or V$DIAG_ALERT_EXT."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AlertRecord(BaseModel):
    ts: datetime | None
    lines: list[str]
    source_line: int = Field(description="1-based line number of the first line in the source")
    con_name: str | None = None
    ora_codes: list[int] = Field(default_factory=list)
    error_args: list[str] = Field(default_factory=list)
    incident_id: int | None = None
    problem_key: str | None = None
    trace_file: str | None = None
    incident_file: str | None = None
    msg_type: str | None = None
    group: str | None = None
    level: int | None = None
    pid: int | None = None
    args: dict[str, str] = Field(default_factory=dict)
    signature: str = ""

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    @property
    def is_error(self) -> bool:
        return bool(self.ora_codes) or self.msg_type in {"ERROR", "INCIDENT_ERROR"}

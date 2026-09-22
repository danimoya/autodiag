"""Parsers for ``adrci`` text output (show homes / problem / incident)."""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, Field

__all__ = [
    "AdrIncident",
    "AdrProblem",
    "parse_show_homes",
    "parse_show_incident",
    "parse_show_incident_brief",
    "parse_show_incident_detail",
    "parse_show_problem",
    "parse_timestamp",
]

_HOME_LINE = re.compile(r"^ADR Home = (.+?):\s*$")
_SEPARATOR = re.compile(r"^(-+\s*)+$")
_ROWS_FETCHED = re.compile(r"^\d+ rows? fetched")
_RECORD_START = re.compile(r"^INCIDENT INFO RECORD \d+", re.MULTILINE)
_KV = re.compile(r"^\s{3}([A-Z0-9_]+)\s{2,}(.*?)\s*$")
_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(\.\d+)? ?([+-]\d{2}:\d{2})?$")


class AdrProblem(BaseModel):
    adr_home: str
    problem_id: int
    problem_key: str
    last_incident: int | None = None
    lastinc_time: datetime | None = None


class AdrIncident(BaseModel):
    adr_home: str
    incident_id: int
    problem_key: str
    create_time: datetime | None = None
    problem_id: int | None = None
    status: str | None = None
    error_facility: str | None = None
    error_number: int | None = None
    error_args: list[str] = Field(default_factory=list)
    flood_controlled: bool = False
    trace_file: str | None = Field(default=None, description="Incident trace under incdir_*")
    owner_trace_file: str | None = Field(default=None, description="Owning process trace file")
    keys: dict[str, str] = Field(default_factory=dict)

    @property
    def incident_dir(self) -> str | None:
        if self.trace_file and "/incident/incdir_" in self.trace_file:
            return self.trace_file.rsplit("/", 1)[0]
        return None


def parse_timestamp(text: str | None) -> datetime | None:
    if not text:
        return None
    m = _TS.match(text.strip())
    if not m:
        return None
    date, time, frac, offset = m.groups()
    return datetime.fromisoformat(f"{date}T{time}{frac or ''}{offset or ''}")


def parse_show_homes(text: str) -> list[str]:
    homes: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("ADR Homes"):
            continue
        homes.append(s)
    return homes


def _sections(text: str) -> list[tuple[str, list[str]]]:
    """Split output into (adr_home, lines) chunks, one per ``ADR Home = ...:`` header."""
    out: list[tuple[str, list[str]]] = []
    current: list[str] | None = None
    for line in text.splitlines():
        m = _HOME_LINE.match(line)
        if m:
            current = []
            out.append((m.group(1), current))
        elif current is not None:
            current.append(line)
    return out


def _table_rows(lines: list[str]) -> list[dict[str, str]]:
    """Parse an adrci fixed-width table using the dashed separator to find columns."""
    header: str | None = None
    for idx, line in enumerate(lines):
        if _SEPARATOR.match(line) and idx > 0:
            header = lines[idx - 1]
            sep = line
            body = lines[idx + 1 :]
            break
    else:
        return []
    spans = [(m.start(), m.end()) for m in re.finditer(r"-+", sep)]
    names = [header[s:e].strip() for s, e in spans]
    rows: list[dict[str, str]] = []
    for line in body:
        if not line.strip() or _ROWS_FETCHED.match(line.strip()):
            continue
        row: dict[str, str] = {}
        for i, (s, e) in enumerate(spans):
            end = e if i < len(spans) - 1 else len(line)
            row[names[i]] = line[s:end].strip()
        rows.append(row)
    return rows


def _int(v: str | None) -> int | None:
    try:
        return int(v) if v not in (None, "", "<NULL>") else None
    except ValueError:
        return None


def parse_show_problem(text: str) -> list[AdrProblem]:
    problems: list[AdrProblem] = []
    for home, lines in _sections(text):
        for row in _table_rows(lines):
            pid = _int(row.get("PROBLEM_ID"))
            if pid is None:
                continue
            problems.append(
                AdrProblem(
                    adr_home=home,
                    problem_id=pid,
                    problem_key=row.get("PROBLEM_KEY", ""),
                    last_incident=_int(row.get("LAST_INCIDENT")),
                    lastinc_time=parse_timestamp(row.get("LASTINC_TIME")),
                )
            )
    return problems


def parse_show_incident_brief(text: str) -> list[AdrIncident]:
    incidents: list[AdrIncident] = []
    for home, lines in _sections(text):
        for row in _table_rows(lines):
            iid = _int(row.get("INCIDENT_ID"))
            if iid is None:
                continue
            incidents.append(
                AdrIncident(
                    adr_home=home,
                    incident_id=iid,
                    problem_key=row.get("PROBLEM_KEY", ""),
                    create_time=parse_timestamp(row.get("CREATE_TIME")),
                )
            )
    return incidents


def parse_show_incident(text: str) -> list[AdrIncident]:
    """Parse ``show incident`` output in either the table or the key/value form."""
    if _RECORD_START.search(text):
        return parse_show_incident_detail(text)
    return parse_show_incident_brief(text)


def parse_show_incident_detail(text: str) -> list[AdrIncident]:
    incidents: list[AdrIncident] = []
    for home, lines in _sections(text):
        records: list[list[tuple[str, str]]] = []
        for line in lines:
            if _RECORD_START.match(line.strip()):
                records.append([])
                continue
            m = _KV.match(line)
            if m and records:
                records[-1].append((m.group(1), m.group(2)))
        for rec in records:
            inc = _incident_from_record(home, rec)
            if inc is not None:
                incidents.append(inc)
    return incidents


def _derive_problem_key(facility: str | None, number: str | None, args: list[str]) -> str:
    """ADR problem keys are ``<FACILITY> <NUMBER> [<first argument>]``."""
    if not facility or not number:
        return ""
    return f"{facility} {number} [{args[0]}]" if args else f"{facility} {number}"


def _incident_from_record(home: str, rec: list[tuple[str, str]]) -> AdrIncident | None:
    fields = {k: v for k, v in rec if not k.startswith(("KEY_", "INCIDENT_FILE", "OWNER_ID"))}
    iid = _int(fields.get("INCIDENT_ID"))
    if iid is None:
        return None
    keys: dict[str, str] = {}
    pending: str | None = None
    files: list[str] = []
    for k, v in rec:
        if k == "KEY_NAME":
            pending = v
        elif k == "KEY_VALUE" and pending is not None:
            keys[pending] = v
            pending = None
        elif k == "INCIDENT_FILE":
            files.append(v)
    args = []
    for n in range(1, 13):
        v = fields.get(f"ERROR_ARG{n}")
        if v and v != "<NULL>":
            args.append(v)
    incident_trace = next((f for f in files if "/incident/incdir_" in f), None)
    owner_trace = next((f for f in files if f != incident_trace), None)
    problem_key = fields.get("PROBLEM_KEY") or _derive_problem_key(
        fields.get("ERROR_FACILITY"), fields.get("ERROR_NUMBER"), args
    )
    return AdrIncident(
        adr_home=home,
        incident_id=iid,
        problem_key=problem_key,
        create_time=parse_timestamp(fields.get("CREATE_TIME")),
        problem_id=_int(fields.get("PROBLEM_ID")),
        status=fields.get("STATUS"),
        error_facility=fields.get("ERROR_FACILITY"),
        error_number=_int(fields.get("ERROR_NUMBER")),
        error_args=args,
        flood_controlled=fields.get("FLOOD_CONTROLLED", "none").lower() != "none",
        trace_file=incident_trace,
        owner_trace_file=owner_trace,
        keys=keys,
    )

"""ORA-60 deadlock traces (``DEADLOCK DETECTED ( ORA-00060 )``)."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from autodiag.trace import common
from autodiag.trace.header import parse_header, parse_timestamp_marker
from autodiag.trace.models import PlsqlFrame, Section, TraceBase, TraceKind

_RESOURCE = re.compile(r"^([A-Z]{2})-([0-9A-Fa-f-]+)\s")
_SESSION_HDR = re.compile(r"^Session (\d+):\s*$")
_SID = re.compile(r"sid: (\d+) ser: (\d+) .*user: \d+/(\S+)")
_PDB = re.compile(r"pdb: \d+/(\S+)")
_PID = re.compile(r"pid: (\d+) ospid: (\d+)")
_PROGRAM = re.compile(r"program: (.+?) machine: (\S+)")
_CURSQL = re.compile(r"current SQL \(id: (\d+)\):")
_ROW_WAIT = re.compile(r"^\s*Session (\d+): obj - rowid = (\w+) - (\S+)")
_ROW_DETAIL = re.compile(r"dictionary objn - (\d+), file - (\d+), block - (\d+), slot - (\d+)")
_DEADLOCK_TYPE = re.compile(r"^\[(.+ Deadlock)\]")


class LockSide(BaseModel):
    process: int | None = None
    session: int | None = None
    holds: str = ""
    waits: str = ""
    serial: int | None = None


class GraphRow(BaseModel):
    resource: str
    lock_type: str
    blocker: LockSide
    waiter: LockSide


class DeadlockSession(BaseModel):
    sid: int
    serial: int | None = None
    user: str | None = None
    pdb: str | None = None
    pid: int | None = None
    ospid: int | None = None
    program: str | None = None
    machine: str | None = None
    holds: str | None = None
    current_sql: str | None = None


class RowWaited(BaseModel):
    session: int
    obj: str
    rowid: str
    objn: int | None = None
    file: int | None = None
    block: int | None = None
    slot: int | None = None


class DeadlockTrace(TraceBase):
    kind: TraceKind = TraceKind.DEADLOCK
    deadlock_type: str | None = None
    graph: list[GraphRow] = Field(default_factory=list)
    sessions: list[DeadlockSession] = Field(default_factory=list)
    rows_waited_on: list[RowWaited] = Field(default_factory=list)
    this_session_sql: str | None = None
    this_session_sql_id: str | None = None
    plsql_stack: list[PlsqlFrame] = Field(default_factory=list)

    @property
    def cycle(self) -> list[int]:
        order: list[int] = []
        for row in self.graph:
            for side in (row.blocker, row.waiter):
                if side.session is not None and side.session not in order:
                    order.append(side.session)
        return order

    @property
    def classification(self) -> str:
        types = {r.lock_type for r in self.graph}
        if types == {"TX"}:
            modes = {r.waiter.waits for r in self.graph}
            if modes <= {"X"}:
                return "TX row-lock cycle (application ordering)"
            if "S" in modes:
                return "TX share-mode wait (ITL / unique key / bitmap index)"
            return "TX enqueue deadlock"
        if "TM" in types:
            return "TM table-lock deadlock (unindexed foreign key?)"
        if "UL" in types:
            return "user lock (DBMS_LOCK) deadlock"
        return "enqueue deadlock: " + ", ".join(sorted(types))


def parse_deadlock(text: str) -> DeadlockTrace:
    lines = text.splitlines()
    dl = DeadlockTrace(header=parse_header(lines), line_count=len(lines))
    sections: list[Section] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        ts = parse_timestamp_marker(line)
        if ts:
            dl.timestamps.append(ts)
        m = _DEADLOCK_TYPE.match(line.strip())
        if m:
            dl.deadlock_type = m.group(1)
        elif line.startswith("Deadlock graph:"):
            sections.append(
                Section(kind="deadlock_graph", title=line, start_line=i + 1, end_line=i + 1)
            )
            i = _parse_graph(lines, i + 1, dl)
            continue
        elif line.startswith("----- Information for waiting sessions -----"):
            sections.append(
                Section(kind="waiting_sessions", title=line, start_line=i + 1, end_line=i + 1)
            )
            i = _parse_sessions(lines, i + 1, dl)
            continue
        elif line.startswith("Rows waited on:"):
            sections.append(
                Section(kind="rows_waited_on", title=line, start_line=i + 1, end_line=i + 1)
            )
            i = _parse_rows(lines, i + 1, dl)
            continue
        elif common.CURRENT_SQL_NOID.match(line) and dl.this_session_sql is None:
            dl.this_session_sql_id, dl.this_session_sql = common.parse_current_sql(lines, i)
        elif line.startswith(common.PLSQL_STACK) and not dl.plsql_stack:
            dl.plsql_stack = common.parse_plsql_stack(lines, i)
        i += 1
    dl.sections = sections
    dl.ora_lines = common.ora_lines(lines)
    return dl


def _parse_graph(lines: list[str], i: int, dl: DeadlockTrace) -> int:
    header_idx = next(
        (
            k
            for k in range(i, min(i + 5, len(lines)))
            if "process session holds waits serial" in lines[k]
        ),
        None,
    )
    if header_idx is None:
        return i
    header = lines[header_idx]
    cols = [(m.start(), m.end()) for m in re.finditer(r"\S+", header)]
    # first column is "Resource Name"; the next 10 are process/session/holds/waits/serial x2
    spans = cols[2:12] if len(cols) >= 12 else cols[1:11]
    k = header_idx + 1
    while k < len(lines) and _RESOURCE.match(lines[k]):
        row = lines[k]
        vals = [row[s : e + 1].strip() if e + 1 <= len(row) else "" for s, e in spans]
        # widen: values may extend left of the header word start (right-aligned numbers)
        vals = _right_aligned(row, spans)
        dl.graph.append(
            GraphRow(
                resource=row.split()[0],
                lock_type=row[:2],
                blocker=LockSide(
                    process=_i(vals[0]),
                    session=_i(vals[1]),
                    holds=vals[2],
                    waits=vals[3],
                    serial=_i(vals[4]),
                ),
                waiter=LockSide(
                    process=_i(vals[5]),
                    session=_i(vals[6]),
                    holds=vals[7],
                    waits=vals[8],
                    serial=_i(vals[9]),
                ),
            )
        )
        k += 1
    return k


def _right_aligned(row: str, spans: list[tuple[int, int]]) -> list[str]:
    """Values in the graph are right-aligned under each header word; take the token whose
    end lies within [start-2, end+1] of the header word."""
    tokens = [(m.start(), m.end(), m.group()) for m in re.finditer(r"\S+", row)][1:]
    out: list[str] = []
    for s, e in spans:
        hit = next((t for t in tokens if s - 8 <= t[1] - 1 <= e + 1), None)
        out.append(hit[2] if hit else "")
        if hit:
            tokens.remove(hit)
    return out


def _parse_sessions(lines: list[str], i: int, dl: DeadlockTrace) -> int:
    cur: DeadlockSession | None = None
    k = i
    while k < len(lines):
        line = lines[k]
        if line.startswith("----- End of information for waiting sessions"):
            break
        m = _SESSION_HDR.match(line)
        if m:
            cur = DeadlockSession(sid=int(m.group(1)))
            dl.sessions.append(cur)
        elif cur is not None:
            s = line.strip()
            if s.startswith("Holds resource"):
                cur.holds = s
            elif mm := _SID.search(s):
                cur.serial, cur.user = int(mm.group(2)), mm.group(3)
            elif mm := _PDB.search(s):
                cur.pdb = mm.group(1)
            elif mm := _PID.search(s):
                cur.pid, cur.ospid = int(mm.group(1)), int(mm.group(2))
            elif mm := _PROGRAM.search(s):
                cur.program, cur.machine = mm.group(1), mm.group(2)
            elif _CURSQL.search(s) and k + 1 < len(lines):
                cur.current_sql = lines[k + 1].strip()
                k += 1
        k += 1
    return k


def _parse_rows(lines: list[str], i: int, dl: DeadlockTrace) -> int:
    k = i
    while k < len(lines):
        m = _ROW_WAIT.match(lines[k])
        if m:
            rw = RowWaited(session=int(m.group(1)), obj=m.group(2), rowid=m.group(3))
            if k + 1 < len(lines):
                d = _ROW_DETAIL.search(lines[k + 1])
                if d:
                    rw.objn, rw.file, rw.block, rw.slot = (int(x) for x in d.groups())
                    k += 1
            dl.rows_waited_on.append(rw)
        elif dl.rows_waited_on and lines[k].strip() == "":
            pass
        elif dl.rows_waited_on and not lines[k].startswith("  "):
            break
        k += 1
    return k


def _i(v: str) -> int | None:
    try:
        return int(v)
    except ValueError:
        return None

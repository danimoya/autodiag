"""10046 SQL trace parser producing a tkprof-like profile per sql_id.

Cursor numbers are memory addresses reused after CLOSE, so calls are attributed to the
statement most recently parsed into that cursor. Bind values are never stored.
"""

from __future__ import annotations

import re
from collections import defaultdict

from pydantic import BaseModel, Field

from autodiag.trace.header import parse_header, parse_timestamp_marker
from autodiag.trace.models import Section, TraceBase, TraceKind

_PARSING = re.compile(
    r"^PARSING IN CURSOR #(\d+) len=(\d+) dep=(\d+) uid=(\d+) oct=(\d+) lid=(\d+) tim=(\d+) "
    r"hv=(\d+) ad='(\w+)' sqlid='(\w+)'"
)
_CALL = re.compile(r"^(PARSE|EXEC|FETCH|CLOSE|UNMAP|SORT UNMAP) #(\d+):(.*)$")
_WAIT = re.compile(r"^WAIT #(\d+): nam='([^']+)' ela=\s*(\d+) (.*?)tim=(\d+)")
_STAT = re.compile(r"^STAT #(\d+) id=(\d+) cnt=(\d+) pid=(\d+) pos=(\d+) obj=(\d+) op='(.*)'$")
_BINDS = re.compile(r"^BINDS #(\d+):")
_ERROR = re.compile(r"^ERROR #(\d+):err=(\d+)")
_XCTEND = re.compile(r"^XCTEND rlbk=(\d), rd_only=(\d)")
_OBJ = re.compile(r"obj#=(\d+)")


class CallStats(BaseModel):
    count: int = 0
    cpu_us: int = 0
    elapsed_us: int = 0
    disk: int = 0
    query: int = 0
    current: int = 0
    rows: int = 0
    misses: int = 0

    def add(self, kv: dict[str, int]) -> None:
        self.count += 1
        self.cpu_us += kv.get("c", 0)
        self.elapsed_us += kv.get("e", 0)
        self.disk += kv.get("p", 0)
        self.query += kv.get("cr", 0)
        self.current += kv.get("cu", 0)
        self.rows += kv.get("r", 0)
        self.misses += kv.get("mis", 0)

    def merged(self, other: CallStats) -> CallStats:
        return CallStats(
            **{k: getattr(self, k) + getattr(other, k) for k in type(self).model_fields}
        )


class WaitStats(BaseModel):
    count: int = 0
    total_ela_us: int = 0
    max_ela_us: int = 0
    objects: dict[int, int] = Field(default_factory=dict, description="obj# -> count")


class PlanLine(BaseModel):
    id: int
    parent_id: int
    rows: int
    obj: int
    op: str


class CursorProfile(BaseModel):
    sql_id: str
    sql_text: str
    dep: int
    hash_value: int | None = None
    parse: CallStats = Field(default_factory=CallStats)
    exec: CallStats = Field(default_factory=CallStats)
    fetch: CallStats = Field(default_factory=CallStats)
    plan_hashes: list[int] = Field(default_factory=list)
    plan_lines: list[PlanLine] = Field(default_factory=list)
    waits: dict[str, WaitStats] = Field(default_factory=dict)
    errors: list[int] = Field(default_factory=list)
    first_seen_line: int = 0

    @property
    def total(self) -> CallStats:
        return self.parse.merged(self.exec).merged(self.fetch)

    @property
    def elapsed_us(self) -> int:
        return self.total.elapsed_us


class Totals(BaseModel):
    parse_count: int = 0
    exec_count: int = 0
    fetch_count: int = 0
    cpu_us: int = 0
    elapsed_us: int = 0
    disk: int = 0
    query: int = 0
    rows: int = 0


class SqlTraceProfile(TraceBase):
    kind: TraceKind = TraceKind.SQLTRACE
    cursors: dict[str, CursorProfile] = Field(default_factory=dict)
    waits: dict[str, WaitStats] = Field(default_factory=dict)
    totals: Totals = Field(default_factory=Totals)
    wait_count: int = 0
    binds_seen: int = 0
    wall_seconds: float = 0.0
    commits: int = 0
    rollbacks: int = 0
    first_tim: int | None = None
    last_tim: int | None = None

    @property
    def cursor_count(self) -> int:
        return len(self.cursors)

    def top_waits(self, n: int = 10) -> list[tuple[str, WaitStats]]:
        return sorted(self.waits.items(), key=lambda kv: kv[1].total_ela_us, reverse=True)[:n]

    def top_cursors(self, n: int = 10) -> list[CursorProfile]:
        return sorted(self.cursors.values(), key=lambda c: c.elapsed_us, reverse=True)[:n]


def _kv(s: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for part in s.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip()
            try:
                out[k] = int(v)
            except ValueError:
                pass
    return out


def parse_sqltrace(text: str) -> SqlTraceProfile:
    lines = text.splitlines()
    prof = SqlTraceProfile(header=parse_header(lines), line_count=len(lines))
    cursor_to_sqlid: dict[str, str] = {}
    pending_sql: dict[str, list[str]] = {}
    current_parsing: str | None = None
    stat_seen: set[tuple[str, int]] = set()
    unknown = CursorProfile(sql_id="<unknown>", sql_text="", dep=0)
    sections: list[Section] = []

    def cursor(cnum: str) -> CursorProfile:
        sid = cursor_to_sqlid.get(cnum)
        return prof.cursors[sid] if sid else unknown

    for i, line in enumerate(lines):
        if current_parsing is not None:
            if line.startswith("END OF STMT"):
                cnum = current_parsing
                sql_text = "\n".join(pending_sql.pop(cnum, []))
                sid = cursor_to_sqlid[cnum]
                if not prof.cursors[sid].sql_text:
                    prof.cursors[sid].sql_text = sql_text
                current_parsing = None
            else:
                pending_sql.setdefault(current_parsing, []).append(line)
            continue
        ts = parse_timestamp_marker(line)
        if ts:
            prof.timestamps.append(ts)
            continue
        m = _PARSING.match(line)
        if m:
            cnum, dep, tim, hv, sqlid = (
                m.group(1),
                int(m.group(3)),
                int(m.group(7)),
                int(m.group(8)),
                m.group(10),
            )
            cursor_to_sqlid[cnum] = sqlid
            if sqlid not in prof.cursors:
                prof.cursors[sqlid] = CursorProfile(
                    sql_id=sqlid, sql_text="", dep=dep, hash_value=hv, first_seen_line=i + 1
                )
                sections.append(
                    Section(
                        kind="cursor",
                        title=f"sql_id={sqlid} dep={dep}",
                        start_line=i + 1,
                        end_line=i + 1,
                    )
                )
            current_parsing = cnum
            _tim(prof, tim)
            continue
        m = _CALL.match(line)
        if m:
            call, cnum, rest = m.group(1), m.group(2), m.group(3)
            kv = _kv(rest)
            c = cursor(cnum)
            if call == "PARSE":
                c.parse.add(kv)
                prof.totals.parse_count += 1
            elif call == "EXEC":
                c.exec.add(kv)
                prof.totals.exec_count += 1
            elif call == "FETCH":
                c.fetch.add(kv)
                prof.totals.fetch_count += 1
            if call in {"PARSE", "EXEC", "FETCH"}:
                prof.totals.cpu_us += kv.get("c", 0)
                prof.totals.elapsed_us += kv.get("e", 0)
                prof.totals.disk += kv.get("p", 0)
                prof.totals.query += kv.get("cr", 0)
                prof.totals.rows += kv.get("r", 0)
                plh = kv.get("plh")
                if plh and plh not in c.plan_hashes:
                    c.plan_hashes.append(plh)
            _tim(prof, kv.get("tim"))
            continue
        m = _WAIT.match(line)
        if m:
            cnum, event, ela, rest, tim = (
                m.group(1),
                m.group(2),
                int(m.group(3)),
                m.group(4),
                int(m.group(5)),
            )
            prof.wait_count += 1
            for bucket in (prof.waits, cursor(cnum).waits):
                w = bucket.setdefault(event, WaitStats())
                w.count += 1
                w.total_ela_us += ela
                w.max_ela_us = max(w.max_ela_us, ela)
                om = _OBJ.search(rest)
                if om and om.group(1) != "4294967295":
                    obj = int(om.group(1))
                    w.objects[obj] = w.objects.get(obj, 0) + 1
            _tim(prof, tim)
            continue
        m = _STAT.match(line)
        if m:
            c = cursor(m.group(1))
            key = (c.sql_id, int(m.group(2)))
            if key not in stat_seen:
                stat_seen.add(key)
                c.plan_lines.append(
                    PlanLine(
                        id=int(m.group(2)),
                        parent_id=int(m.group(4)),
                        rows=int(m.group(3)),
                        obj=int(m.group(6)),
                        op=m.group(7),
                    )
                )
            continue
        if _BINDS.match(line):
            prof.binds_seen += 1
            continue
        m = _ERROR.match(line)
        if m:
            cursor(m.group(1)).errors.append(int(m.group(2)))
            continue
        m = _XCTEND.match(line)
        if m:
            if m.group(1) == "1":
                prof.rollbacks += 1
            else:
                prof.commits += 1
    if unknown.exec.count or unknown.fetch.count or unknown.parse.count:
        prof.cursors[unknown.sql_id] = unknown
    if prof.first_tim is not None and prof.last_tim is not None:
        prof.wall_seconds = (prof.last_tim - prof.first_tim) / 1_000_000
    prof.sections = sections
    return prof


def _tim(prof: SqlTraceProfile, tim: int | None) -> None:
    if tim is None:
        return
    if prof.first_tim is None or tim < prof.first_tim:
        prof.first_tim = tim
    if prof.last_tim is None or tim > prof.last_tim:
        prof.last_tim = tim


def merge_waits(a: dict[str, WaitStats], b: dict[str, WaitStats]) -> dict[str, WaitStats]:
    out: dict[str, WaitStats] = defaultdict(WaitStats)
    for src in (a, b):
        for k, v in src.items():
            o = out[k]
            o.count += v.count
            o.total_ela_us += v.total_ela_us
            o.max_ela_us = max(o.max_ela_us, v.max_ela_us)
    return dict(out)

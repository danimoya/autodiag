"""Helpers shared by several trace parsers: current SQL, PL/SQL stack, ORA lines."""

from __future__ import annotations

import re
from collections.abc import Sequence

from autodiag.trace.models import PlsqlFrame

CURRENT_SQL = re.compile(r"^----- Current SQL Statement for this session \(sql_id=(\w+)\) -----")
CURRENT_SQL_NOID = re.compile(r"^----- Current SQL Statement for this session")
PLSQL_STACK = "----- PL/SQL Call Stack -----"
_PLSQL_ROW = re.compile(r"^(0x[0-9a-f]+)\s+(\d+)\s+(.+?)\s*$")
_ORA = re.compile(r"^ORA-\d{5}:")


def find(lines: Sequence[str], prefix: str, start: int = 0) -> int | None:
    for i in range(start, len(lines)):
        if lines[i].startswith(prefix):
            return i
    return None


def find_re(lines: Sequence[str], rx: re.Pattern[str], start: int = 0) -> int | None:
    for i in range(start, len(lines)):
        if rx.match(lines[i]):
            return i
    return None


def parse_current_sql(lines: Sequence[str], start: int) -> tuple[str | None, str]:
    """Return (sql_id, sql_text) for the section starting at ``lines[start]``."""
    m = CURRENT_SQL.match(lines[start])
    sql_id = m.group(1) if m else None
    body: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("-----") or line.startswith("[TOC") or line.startswith("====="):
            break
        body.append(line.rstrip())
    return sql_id, "\n".join(body).strip()


def parse_plsql_stack(lines: Sequence[str], start: int) -> list[PlsqlFrame]:
    out: list[PlsqlFrame] = []
    for line in lines[start + 1 :]:
        m = _PLSQL_ROW.match(line.strip())
        if m:
            out.append(PlsqlFrame(handle=m.group(1), line=int(m.group(2)), name=m.group(3)))
        elif out or line.startswith("-----") or line.startswith("[TOC"):
            if out:
                break
    return out


def ora_lines(lines: Sequence[str], *, limit: int = 50) -> list[str]:
    out: list[str] = []
    for line in lines:
        if _ORA.match(line):
            out.append(line.strip())
            if len(out) >= limit:
                break
    return out

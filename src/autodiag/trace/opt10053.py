"""10053 optimizer trace: parameters, statistics, access paths, join orders, final cost."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from autodiag.trace import common
from autodiag.trace.header import parse_header, parse_timestamp_marker
from autodiag.trace.models import Section, TraceBase, TraceKind

_PARAM = re.compile(r"^\s*(\*?_?[a-z][a-z0-9_]*)\s+=\s+(\S.*?)\s*$")
_TABLE = re.compile(r"^\s+Table:\s+(\S+)\s+Alias:\s*(\S*)")
_ROWS = re.compile(r"#Rows:\s*(\d+)")
_BLKS = re.compile(r"#Blks:\s*(\d+)")
_AVGRLEN = re.compile(r"AvgRowLen:\s*([\d.]+)")
_INDEX = re.compile(r"^\s+Index:\s+(\S+)\s+Col#:\s*(.*)$")
_INDEX_STATS = re.compile(r"LVLS:\s*(\d+)\s+#LB:\s*(\d+)\s+#DK:\s*(\d+)")
_BEST = re.compile(r"^\s+Best::\s+AccessPath:\s+(\S+)")
_BEST_COST = re.compile(r"Cost:\s*([\d.]+)")
_JOIN_ORDER = re.compile(r"^Join order\[(\d+)\]:\s+(.*)$")
_FINAL_COST = re.compile(r"^Final cost for query block (\S+) \(#(\d+)\)")
_COST_LINE = re.compile(r"Best join order: (\d+)")
_COST_VALUE = re.compile(r"Cost: ([\d.]+)\s+Degree: (\d+)\s+Card: ([\d.]+)\s+Bytes: ([\d.]+)")
_PLAN_HASH = re.compile(
    r"plan_hash_value:?\s*(\d+)|Plan hash value:\s*(\d+)|PLAN_HASH_VALUE\s*=\s*(\d+)", re.IGNORECASE
)


class TableStats(BaseModel):
    name: str
    alias: str = ""
    rows: int | None = None
    blocks: int | None = None
    avg_row_len: float | None = None


class IndexStats(BaseModel):
    name: str
    table: str
    columns: str = ""
    levels: int | None = None
    leaf_blocks: int | None = None
    distinct_keys: int | None = None


class AccessPath(BaseModel):
    table: str
    alias: str = ""
    best: str
    cost: float | None = None


class OptimizerTrace(TraceBase):
    kind: TraceKind = TraceKind.OPTIMIZER
    sql_id: str | None = None
    sql_text: str | None = None
    parameters: dict[str, str] = Field(default_factory=dict)
    table_stats: list[TableStats] = Field(default_factory=list)
    index_stats: list[IndexStats] = Field(default_factory=list)
    access_paths: list[AccessPath] = Field(default_factory=list)
    join_orders: int = 0
    best_join_order: int | None = None
    final_cost_block: str | None = None
    final_cost: float | None = None
    final_card: float | None = None
    plan_hash: int | None = None
    outline: list[str] = Field(default_factory=list)
    peeked_binds: bool = False

    def nondefault_parameters(self, defaults: dict[str, str] | None = None) -> dict[str, str]:
        if not defaults:
            return {}
        return {k: v for k, v in self.parameters.items() if defaults.get(k) not in (None, v)}


def parse_opt10053(text: str) -> OptimizerTrace:
    lines = text.splitlines()
    opt = OptimizerTrace(header=parse_header(lines), line_count=len(lines))
    sections: list[Section] = []
    in_params = False
    in_outline = False
    current_table: str | None = None
    current_alias = ""
    pending_best: AccessPath | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        ts = parse_timestamp_marker(line)
        if ts:
            opt.timestamps.append(ts)
        if line.startswith("PARAMETERS USED BY THE OPTIMIZER"):
            in_params = True
            sections.append(
                Section(kind="parameters", title=line, start_line=i + 1, end_line=i + 1)
            )
            i += 1
            continue
        if in_params:
            if line.startswith("***") and opt.parameters:
                in_params = False
            else:
                m = _PARAM.match(line)
                if m:
                    opt.parameters.setdefault(m.group(1).lstrip("*"), m.group(2))
            i += 1
            continue
        if common.CURRENT_SQL_NOID.match(line) and opt.sql_text is None:
            opt.sql_id, opt.sql_text = common.parse_current_sql(lines, i)
            sections.append(
                Section(kind="current_sql", title=line, start_line=i + 1, end_line=i + 1)
            )
        elif line.startswith("Table Stats::"):
            sections.append(
                Section(kind="table_stats", title=line, start_line=i + 1, end_line=i + 1)
            )
            m = _TABLE.match(lines[i + 1]) if i + 1 < len(lines) else None
            if m:
                ts_ = TableStats(name=m.group(1), alias=m.group(2))
                for j in range(i + 2, min(i + 6, len(lines))):
                    rm, bm, am = (
                        _ROWS.search(lines[j]),
                        _BLKS.search(lines[j]),
                        _AVGRLEN.search(lines[j]),
                    )
                    if rm:
                        ts_.rows = int(rm.group(1))
                    if bm:
                        ts_.blocks = int(bm.group(1))
                    if am:
                        ts_.avg_row_len = float(am.group(1))
                    if rm or bm:
                        break
                opt.table_stats.append(ts_)
                current_table, current_alias = ts_.name, ts_.alias
        elif line.startswith("Index Stats::"):
            j = i + 1
            while j < len(lines) and (im := _INDEX.match(lines[j])):
                ix = IndexStats(
                    name=im.group(1), table=current_table or "", columns=im.group(2).strip()
                )
                for k in range(j + 1, min(j + 4, len(lines))):
                    sm = _INDEX_STATS.search(lines[k])
                    if sm:
                        ix.levels, ix.leaf_blocks, ix.distinct_keys = (int(x) for x in sm.groups())
                        break
                opt.index_stats.append(ix)
                j += 1
                while j < len(lines) and lines[j].startswith("    ") and not _INDEX.match(lines[j]):
                    j += 1
        elif line.startswith("SINGLE TABLE ACCESS PATH"):
            sections.append(
                Section(kind="access_path", title=line, start_line=i + 1, end_line=i + 1)
            )
            for j in range(i + 1, min(i + 40, len(lines))):
                tm = _TABLE.match(lines[j])
                if tm:
                    current_table, current_alias = tm.group(1), tm.group(2)
                    break
            pending_best = AccessPath(table=current_table or "", alias=current_alias, best="")
        elif (bm := _BEST.match(line)) and pending_best is not None:
            pending_best.best = bm.group(1)
            for j in range(i, min(i + 4, len(lines))):
                cm = _BEST_COST.search(lines[j])
                if cm:
                    pending_best.cost = float(cm.group(1))
                    break
            opt.access_paths.append(pending_best)
            pending_best = None
        elif _JOIN_ORDER.match(line):
            opt.join_orders += 1
        elif fm := _FINAL_COST.match(line):
            opt.final_cost_block = fm.group(1)
            sections.append(
                Section(kind="final_cost", title=line, start_line=i + 1, end_line=i + 1)
            )
            for j in range(i + 1, min(i + 8, len(lines))):
                bj = _COST_LINE.search(lines[j])
                if bj:
                    opt.best_join_order = int(bj.group(1))
                cv = _COST_VALUE.search(lines[j])
                if cv:
                    opt.final_cost = float(cv.group(1))
                    opt.final_card = float(cv.group(3))
                    break
        elif line.startswith("Peeked values of the binds"):
            opt.peeked_binds = True
            sections.append(
                Section(kind="peeked_binds", title=line, start_line=i + 1, end_line=i + 1)
            )
        elif line.strip() == "Outline Data:":
            in_outline = True
            sections.append(
                Section(kind="outline", title=line.strip(), start_line=i + 1, end_line=i + 1)
            )
        elif in_outline:
            s = line.strip()
            if s.startswith("*/") or s == "END_OUTLINE_DATA" or s.startswith("---"):
                in_outline = False
            elif s and not s.startswith("/*+") and not s.startswith("BEGIN_OUTLINE"):
                opt.outline.append(s)
        pm = _PLAN_HASH.search(line)
        if pm and opt.plan_hash is None:
            opt.plan_hash = int(next(g for g in pm.groups() if g))
        i += 1
    opt.sections = sections
    return opt

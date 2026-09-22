"""tkprof-style comparison of two 10046 profiles (normal vs anomaly), per sql_id."""

from __future__ import annotations

from pydantic import BaseModel, Field

from autodiag.trace.sqltrace import CallStats, CursorProfile, SqlTraceProfile, Totals, WaitStats

_CONCURRENCY_EVENTS = (
    "enq:",
    "latch",
    "buffer busy",
    "library cache",
    "cursor:",
    "row cache",
    "gc ",
)
_NETWORK_EVENTS = ("SQL*Net",)
_IDLE_EVENTS = ("SQL*Net message from client", "PL/SQL lock timer", "pmon timer")


class SideStats(BaseModel):
    parse_count: int = 0
    exec_count: int = 0
    fetch_count: int = 0
    cpu_us: int = 0
    elapsed_us: int = 0
    disk: int = 0
    query: int = 0
    current: int = 0
    rows: int = 0
    misses: int = 0
    wait_ela_us: int = 0

    @classmethod
    def of(cls, c: CursorProfile | None) -> SideStats:
        if c is None:
            return cls()
        t = c.total
        return cls(
            parse_count=c.parse.count,
            exec_count=c.exec.count,
            fetch_count=c.fetch.count,
            cpu_us=t.cpu_us,
            elapsed_us=t.elapsed_us,
            disk=t.disk,
            query=t.query,
            current=t.current,
            rows=t.rows,
            misses=t.misses,
            wait_ela_us=sum(w.total_ela_us for w in c.waits.values()),
        )


class CursorDelta(BaseModel):
    sql_id: str
    sql_text: str
    dep: int
    present_in: str  # both | left | right
    left: SideStats
    right: SideStats
    delta_elapsed_us: int
    ratio_elapsed: float
    delta_query: int
    ratio_query: float
    delta_disk: int
    delta_exec_count: int
    left_plan_hashes: list[int]
    right_plan_hashes: list[int]
    plan_change: bool
    tags: list[str]


class WaitDelta(BaseModel):
    event: str
    left: WaitStats
    right: WaitStats
    delta_ela_us: int
    new_in_right: bool = False
    gone_in_right: bool = False


class ProfileDiff(BaseModel):
    left_ref: str | None
    right_ref: str | None
    left_totals: Totals
    right_totals: Totals
    left_wall_seconds: float
    right_wall_seconds: float
    items: list[CursorDelta]
    wait_deltas: list[WaitDelta]
    explanation_hints: list[str] = Field(default_factory=list)
    summary: str = ""


def _ratio(left: int, right: int) -> float:
    return round((right + 1) / (left + 1), 3)


def classify(left: CursorProfile | None, right: CursorProfile | None) -> list[str]:
    tags: list[str] = []
    if left is None:
        return ["NEW_STATEMENT"]
    if right is None:
        return ["MISSING_STATEMENT"]
    ls, rs = SideStats.of(left), SideStats.of(right)
    plan_change = bool(
        left.plan_hashes and right.plan_hashes and set(left.plan_hashes) != set(right.plan_hashes)
    )
    if plan_change:
        tags.append("PLAN_CHANGE")
    if _ratio(ls.disk, rs.disk) > 3 and _ratio(ls.query, rs.query) > 2:
        tags.append("IO_INCREASE")
    if (
        not plan_change
        and _ratio(ls.query, rs.query) > 2
        and _ratio(ls.exec_count, rs.exec_count) < 1.5
    ):
        tags.append("LOGICAL_IO_INCREASE_SAME_PLAN")
    if rs.misses > ls.misses and rs.misses >= 3:
        tags.append("HARD_PARSE")
    if _ratio(ls.exec_count, rs.exec_count) > 2 or _ratio(rs.exec_count, ls.exec_count) > 2:
        tags.append("EXEC_COUNT_CHANGE")
    new_waits = [e for e in right.waits if e not in left.waits and not e.startswith(_IDLE_EVENTS)]
    if new_waits:
        tags.append("NEW_WAIT")
    lw = {e: w.total_ela_us for e, w in left.waits.items()}
    rw = {e: w.total_ela_us for e, w in right.waits.items()}
    if any(e.startswith(_CONCURRENCY_EVENTS) and rw[e] > 2 * lw.get(e, 0) for e in rw):
        tags.append("CONCURRENCY")
    net_r = sum(v for e, v in rw.items() if e.startswith(_NETWORK_EVENTS))
    if (
        net_r
        and net_r > 0.5 * max(rs.elapsed_us, 1)
        and net_r > 2 * sum(v for e, v in lw.items() if e.startswith(_NETWORK_EVENTS))
    ):
        tags.append("NETWORK")
    if right.errors and not left.errors:
        tags.append("ERRORS")
    return tags


def compare_profiles(
    left: SqlTraceProfile, right: SqlTraceProfile, *, top: int = 15
) -> ProfileDiff:
    ids = list(dict.fromkeys([*left.cursors, *right.cursors]))
    items: list[CursorDelta] = []
    for sid in ids:
        lc, rc = left.cursors.get(sid), right.cursors.get(sid)
        ls, rs = SideStats.of(lc), SideStats.of(rc)
        src = lc or rc
        assert src is not None
        items.append(
            CursorDelta(
                sql_id=sid,
                sql_text=src.sql_text[:400],
                dep=src.dep,
                present_in="both" if lc and rc else ("left" if lc else "right"),
                left=ls,
                right=rs,
                delta_elapsed_us=rs.elapsed_us - ls.elapsed_us,
                ratio_elapsed=_ratio(ls.elapsed_us, rs.elapsed_us),
                delta_query=rs.query - ls.query,
                ratio_query=_ratio(ls.query, rs.query),
                delta_disk=rs.disk - ls.disk,
                delta_exec_count=rs.exec_count - ls.exec_count,
                left_plan_hashes=lc.plan_hashes if lc else [],
                right_plan_hashes=rc.plan_hashes if rc else [],
                plan_change=bool(
                    lc
                    and rc
                    and lc.plan_hashes
                    and rc.plan_hashes
                    and set(lc.plan_hashes) != set(rc.plan_hashes)
                ),
                tags=classify(lc, rc),
            )
        )
    items.sort(key=lambda d: abs(d.delta_elapsed_us), reverse=True)
    items = items[:top]
    wait_deltas: list[WaitDelta] = []
    for ev in dict.fromkeys([*left.waits, *right.waits]):
        lw, rw = left.waits.get(ev, WaitStats()), right.waits.get(ev, WaitStats())
        wait_deltas.append(
            WaitDelta(
                event=ev,
                left=lw,
                right=rw,
                delta_ela_us=rw.total_ela_us - lw.total_ela_us,
                new_in_right=ev not in left.waits,
                gone_in_right=ev not in right.waits,
            )
        )
    wait_deltas.sort(key=lambda w: abs(w.delta_ela_us), reverse=True)
    hints = _hints(items, wait_deltas)
    lt, rt = left.totals, right.totals
    summary = (
        f"elapsed {lt.elapsed_us / 1e6:.3f}s -> {rt.elapsed_us / 1e6:.3f}s, "
        f"logical reads {lt.query} -> {rt.query}, "
        f"physical reads {lt.disk} -> {rt.disk}, executions {lt.exec_count} -> {rt.exec_count}"
    )
    return ProfileDiff(
        left_ref=left.header.trace_file,
        right_ref=right.header.trace_file,
        left_totals=lt,
        right_totals=rt,
        left_wall_seconds=left.wall_seconds,
        right_wall_seconds=right.wall_seconds,
        items=items,
        wait_deltas=wait_deltas[:top],
        explanation_hints=hints,
        summary=summary,
    )


def _hints(items: list[CursorDelta], waits: list[WaitDelta]) -> list[str]:
    out: list[str] = []
    for it in items[:5]:
        if "PLAN_CHANGE" in it.tags:
            out.append(
                f"{it.sql_id}: execution plan changed "
                f"({it.left_plan_hashes} -> {it.right_plan_hashes}); logical reads "
                f"x{it.ratio_query}, elapsed x{it.ratio_elapsed}. Check invisible/dropped "
                "indexes, stale statistics, bind peeking / adaptive features, or a new "
                "optimizer parameter."
            )
        elif "LOGICAL_IO_INCREASE_SAME_PLAN" in it.tags:
            out.append(
                f"{it.sql_id}: same plan but logical reads x{it.ratio_query}: "
                "data growth or stale statistics likely."
            )
        elif "IO_INCREASE" in it.tags:
            out.append(
                f"{it.sql_id}: physical reads rose sharply "
                f"(x{_ratio(it.left.disk, it.right.disk)}): buffer cache pressure or a "
                "scan-heavy plan."
            )
        if "EXEC_COUNT_CHANGE" in it.tags:
            out.append(
                f"{it.sql_id}: execution count {it.left.exec_count} -> {it.right.exec_count}: "
                "the application issued a different amount of work."
            )
        if "HARD_PARSE" in it.tags:
            out.append(
                f"{it.sql_id}: more hard parses ({it.left.misses} -> {it.right.misses}): "
                "cursor invalidations or literal SQL."
            )
        if "NEW_STATEMENT" in it.tags:
            out.append(f"{it.sql_id}: statement only present in the anomaly trace.")
    for w in waits[:3]:
        if w.new_in_right and not w.event.startswith(_IDLE_EVENTS):
            out.append(
                f"new wait event in the anomaly trace: {w.event!r} "
                f"({w.right.total_ela_us / 1e6:.3f}s over {w.right.count} waits)."
            )
        elif (
            w.delta_ela_us > 0
            and w.left.total_ela_us
            and w.right.total_ela_us > 3 * w.left.total_ela_us
        ):
            out.append(
                f"wait {w.event!r} grew x{_ratio(w.left.total_ela_us, w.right.total_ela_us)}."
            )
    return out


__all__ = [
    "CursorDelta",
    "ProfileDiff",
    "SideStats",
    "WaitDelta",
    "classify",
    "compare_profiles",
    "CallStats",
]

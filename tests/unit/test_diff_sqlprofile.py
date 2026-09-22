from pathlib import Path

import pytest

from autodiag.diff.sqlprofile import compare_profiles
from autodiag.trace.sqltrace import parse_sqltrace


@pytest.fixture
def pair(fixtures_dir: Path):
    n = parse_sqltrace((fixtures_dir / "23ai/traces/AUTODIAG_NORMAL.trc").read_text())
    a = parse_sqltrace((fixtures_dir / "23ai/traces/AUTODIAG_ANOMALY.trc").read_text())
    return n, a


def test_report_cursor_is_flagged_as_plan_change(pair) -> None:
    n, a = pair
    d = compare_profiles(n, a, top=10)
    rep = next(i for i in d.items if "OI.QTY" in i.sql_text.upper())
    assert rep.present_in == "both"
    assert rep.plan_change is True and rep.left_plan_hashes != rep.right_plan_hashes
    assert "PLAN_CHANGE" in rep.tags
    assert rep.right.query > rep.left.query and rep.delta_query > 0
    assert rep.ratio_query > 1
    assert rep.left.exec_count == 200 and rep.right.exec_count == 200
    # the depth-0 PL/SQL call carries the recursive time, so the report cursor is top-2
    assert rep.sql_id in [i.sql_id for i in d.items[:2]]
    assert any("plan" in h.lower() for h in d.explanation_hints)


def test_missing_and_new_statements_are_reported(pair) -> None:
    n, a = pair
    d = compare_profiles(n, a, top=50)
    kinds = {i.present_in for i in d.items}
    assert "both" in kinds
    only_left = [i for i in d.items if i.present_in == "left"]
    assert all("MISSING_STATEMENT" in i.tags for i in only_left)
    assert d.left_totals.elapsed_us > 0 and d.right_totals.elapsed_us > 0
    assert d.summary


def test_wait_deltas(pair) -> None:
    n, a = pair
    d = compare_profiles(n, a)
    assert d.wait_deltas and all(w.event for w in d.wait_deltas)
    assert any(w.new_in_right or w.gone_in_right or w.delta_ela_us != 0 for w in d.wait_deltas)


def test_synthetic_tags() -> None:
    from autodiag.diff.sqlprofile import classify
    from autodiag.trace.sqltrace import CallStats, CursorProfile, WaitStats

    left = CursorProfile(
        sql_id="x",
        sql_text="select 1",
        dep=0,
        exec=CallStats(count=10, elapsed_us=1000, disk=0, query=100),
        plan_hashes=[1],
    )
    right = CursorProfile(
        sql_id="x",
        sql_text="select 1",
        dep=0,
        exec=CallStats(count=10, elapsed_us=9000, disk=500, query=5000, misses=5),
        plan_hashes=[1],
        waits={"db file sequential read": WaitStats(count=50, total_ela_us=8000)},
    )
    tags = classify(left, right)
    assert "IO_INCREASE" in tags and "HARD_PARSE" in tags and "NEW_WAIT" in tags
    assert "LOGICAL_IO_INCREASE_SAME_PLAN" in tags and "PLAN_CHANGE" not in tags
    right2 = right.model_copy(update={"exec": CallStats(count=100, elapsed_us=9000, query=5000)})
    assert "EXEC_COUNT_CHANGE" in classify(left, right2)
    right3 = left.model_copy(
        update={"waits": {"enq: TX - row lock contention": WaitStats(count=3, total_ela_us=900000)}}
    )
    assert "CONCURRENCY" in classify(left, right3)
    right4 = left.model_copy(
        update={"waits": {"SQL*Net message from client": WaitStats(count=3, total_ela_us=900000)}}
    )
    assert "NETWORK" in classify(left, right4)
    assert "ERRORS" in classify(left, left.model_copy(update={"errors": [1555]}))

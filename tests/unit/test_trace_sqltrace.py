from pathlib import Path

import pytest

from autodiag.trace.models import TraceKind
from autodiag.trace.sqltrace import parse_sqltrace


@pytest.fixture
def normal(fixtures_dir: Path):
    return parse_sqltrace((fixtures_dir / "23ai/traces/AUTODIAG_NORMAL.trc").read_text())


@pytest.fixture
def anomaly(fixtures_dir: Path):
    return parse_sqltrace((fixtures_dir / "23ai/traces/AUTODIAG_ANOMALY.trc").read_text())


def test_profile_counts(normal) -> None:
    assert normal.kind is TraceKind.SQLTRACE
    assert normal.cursor_count == 24
    assert normal.totals.exec_count == 301
    assert normal.totals.fetch_count == 367
    assert normal.wait_count == 34
    assert normal.binds_seen == 299
    assert normal.wall_seconds > 0


def test_report_cursor_is_aggregated_by_sql_id(normal, anomaly) -> None:
    rep = next(c for c in normal.cursors.values() if "OI.QTY" in c.sql_text.upper())
    assert rep.dep == 1
    assert rep.exec.count == 200
    assert rep.fetch.count == 200
    assert rep.exec.elapsed_us >= 0 and rep.fetch.query >= 0
    assert rep.plan_hashes and all(isinstance(p, int) for p in rep.plan_hashes)
    assert rep.plan_lines and rep.plan_lines[0].op
    rep2 = next(c for c in anomaly.cursors.values() if "OI.QTY" in c.sql_text.upper())
    assert rep2.sql_id == rep.sql_id
    assert rep2.plan_hashes != rep.plan_hashes  # index invisible -> different plan
    assert rep2.fetch.query > rep.fetch.query  # full scans do more logical I/O


def test_bind_values_are_never_kept(normal) -> None:
    text = normal.model_dump_json()
    assert "value=" not in text


def test_waits_by_event_and_top(normal) -> None:
    assert "SQL*Net message from client" in normal.waits
    w = normal.waits["SQL*Net message from client"]
    assert w.count >= 1 and w.total_ela_us > 0
    assert normal.top_waits(3)[0][0] in normal.waits


def test_cursor_reuse_after_close_maps_to_new_sql_id(normal) -> None:
    # the same cursor number is reused for different statements; aggregation is per sql_id
    ids = {c.sql_id for c in normal.cursors.values()}
    assert len(ids) == len(normal.cursors)

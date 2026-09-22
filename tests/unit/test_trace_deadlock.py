from pathlib import Path

import pytest

from autodiag.trace.deadlock import parse_deadlock
from autodiag.trace.models import TraceKind


@pytest.fixture
def deadlock_text(fixtures_dir: Path) -> str:
    return (fixtures_dir / "23ai/traces/deadlock_ora60.trc").read_text()


def test_parse_deadlock(deadlock_text: str) -> None:
    dl = parse_deadlock(deadlock_text)
    assert dl.kind is TraceKind.DEADLOCK
    assert dl.deadlock_type == "Transaction Deadlock"
    assert len(dl.graph) == 2
    row = dl.graph[0]
    assert row.resource == "TX-00020021-0000026C-CE1992F3-00000000"
    assert row.lock_type == "TX"
    assert row.blocker.process == 94 and row.blocker.session == 68 and row.blocker.serial == 14223
    assert row.blocker.holds == "X" and row.blocker.waits == ""
    assert row.waiter.process == 104 and row.waiter.session == 70 and row.waiter.serial == 58259
    assert row.waiter.holds == "" and row.waiter.waits == "X"
    assert [s.sid for s in dl.sessions] == [68, 70]
    s68 = dl.sessions[0]
    assert s68.user == "AUTODIAG_TEST" and s68.pdb == "FREEPDB1"
    assert s68.ospid == 1804 and s68.program.startswith("sqlplus@oradb-test")
    assert s68.current_sql == "UPDATE LOCK_DEMO SET VAL = 'a2' WHERE ID = 2"
    assert dl.rows_waited_on[0].session == 68
    assert dl.rows_waited_on[0].objn == 73132 and dl.rows_waited_on[0].rowid.startswith("AAAR2s")
    assert dl.this_session_sql == "UPDATE LOCK_DEMO SET VAL = 'a2' WHERE ID = 2"
    assert dl.this_session_sql_id == "9k37k1dgsxm6q"
    assert dl.plsql_stack[0].name.endswith("PKG_ORDERS.DEADLOCK_A")
    assert dl.classification == "TX row-lock cycle (application ordering)"
    assert dl.cycle == [68, 70]

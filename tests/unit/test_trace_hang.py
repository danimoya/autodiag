from pathlib import Path

import pytest

from autodiag.trace.hang import parse_hang
from autodiag.trace.models import TraceKind


@pytest.fixture
def hang(fixtures_dir: Path):
    return parse_hang((fixtures_dir / "23ai/traces/hanganalyze_systemstate.trc").read_text())


def test_hang_chains(hang) -> None:
    assert hang.kind is TraceKind.HANG
    assert hang.instances == "free.free"
    assert len(hang.chains) == 1
    ch = hang.chains[0]
    assert ch.number == 1
    assert ch.signature == "'PL/SQL lock timer'<='enq: TX - row lock contention'"
    assert ch.signature_hash == "0x1e720d31"
    assert ch.likely_cause is True
    assert [n.session_id for n in ch.nodes] == [178, 70]
    waiter, blocker = ch.nodes
    assert waiter.wait_event == "enq: TX - row lock contention"
    assert waiter.time_in_wait_s == pytest.approx(6.656485)
    assert waiter.os_id == 1905 and waiter.process_id == 33 and waiter.serial == 46065
    assert waiter.pdb == "FREEPDB1" and waiter.module == "SQL*Plus"
    assert waiter.sql_id == "65tdqpw2n1xhk"
    assert waiter.current_sql.startswith("update lock_demo")
    assert waiter.short_stack[:2] == ["ksedsts", "ksdxfstk"] and "ksqcmi" in waiter.short_stack
    assert waiter.blocked_by_os_id == 1896
    assert blocker.wait_event == "PL/SQL lock timer" and blocker.blocking_sessions == 1
    assert ch.final_blocker is blocker
    assert hang.nodes_state[1].state == "NLEAF" and hang.nodes_state[1].adjacent == [69]
    assert hang.nodes_state[0].sid == 70 and hang.nodes_state[0].state == "LEAF"


def test_systemstate_summary(hang) -> None:
    ss = hang.systemstate
    assert ss is not None
    assert ss.level == 10 and ss.with_short_stacks is True
    assert ss.process_summary[0].pid == 2 and ss.process_summary[0].name == "PMON"
    assert ss.process_summary[0].ospid == "167" and ss.process_summary[0].wait_event == "pmon timer"
    assert len(ss.process_summary) >= 10
    p2 = next(p for p in ss.processes if p.pid == 2)
    assert p2.name == "PMON" and p2.ospid == 167 and p2.sid == 1 and p2.serial == 51353
    assert p2.wait_event == "pmon timer"
    assert (
        p2.short_stack[:3] == ["ksedsts", "ksdxfstk", "ksdxcb"] and "ksucln_wait" in p2.short_stack
    )
    assert ss.wait_histogram["pmon timer"] >= 2

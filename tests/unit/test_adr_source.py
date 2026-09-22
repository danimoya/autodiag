from pathlib import Path

import pytest

from autodiag.adr.source import AdrSource
from autodiag.core.models import Node, Target


@pytest.fixture
def target() -> Target:
    return Target(
        name="tb",
        nodes=[Node(host="127.0.0.1", ssh_alias="autodiag-testbed", instance="FREE")],
        adr_base="/opt/oracle",
        adr_homes=["diag/rdbms/free/FREE"],
    )


@pytest.fixture
def source(target: Target, fake_transport_factory) -> AdrSource:
    return AdrSource(target, transport_factory=fake_transport_factory)


def test_list_homes_filters_rdbms_only(source: AdrSource) -> None:
    homes = source.list_homes(source.target.nodes[0])
    assert homes == ["diag/rdbms/free/FREE"]


def test_list_problems(source: AdrSource) -> None:
    problems = source.list_problems(days=7)
    assert [p.problem_key for p in problems][:2] == ["ORA 7445 [kglic0()+1223]", "ORA 700 [foo]"]
    assert problems[0].node == "127.0.0.1" and problems[0].instance == "FREE"
    t = source.transport_for(source.target.nodes[0])
    assert t.calls[-1][0] == "adrci_show_problem"
    assert t.calls[-1][1] == {"adr_home": "diag/rdbms/free/FREE", "days": 7}


def test_list_incidents_for_problem_key(source: AdrSource) -> None:
    incs = source.list_incidents(problem_key="ORA 600 [autodiag_test]")
    assert [i.incident_id for i in incs] == [8881, 8880, 8873]


def test_get_incident_detail(source: AdrSource) -> None:
    inc = source.get_incident(8873)
    assert inc is not None and inc.problem_key == "ORA 600 [autodiag_test]"
    assert inc.trace_file and inc.trace_file.endswith("_i8873.trc")


def test_alert_log_path_and_fetch(source: AdrSource, tmp_path: Path) -> None:
    node = source.target.nodes[0]
    assert source.alert_log_path(node, "diag/rdbms/free/FREE") == (
        "/opt/oracle/diag/rdbms/free/FREE/trace/alert_FREE.log"
    )
    dest = source.fetch_file(
        node, "/opt/oracle/diag/rdbms/free/FREE/trace/alert_FREE.log", tmp_path / "a.log"
    )
    assert "FREEPDB1" in dest.read_text()  # the fake serves the alert-log fixture


def test_transport_is_cached_per_node(source: AdrSource) -> None:
    n = source.target.nodes[0]
    assert source.transport_for(n) is source.transport_for(n)

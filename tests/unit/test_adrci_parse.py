from datetime import UTC
from pathlib import Path

import pytest

from autodiag.adr.adrci import (
    parse_show_homes,
    parse_show_incident_brief,
    parse_show_incident_detail,
    parse_show_problem,
    parse_timestamp,
)


@pytest.fixture
def adrci_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "23ai" / "adrci"


def test_parse_show_homes(adrci_dir: Path) -> None:
    homes = parse_show_homes((adrci_dir / "show_homes.txt").read_text())
    assert homes == [
        "diag/rdbms/free/FREE",
        "diag/tnslsnr/oradb-test/listener",
        "diag/clients/user_oracle/host_1234567890_110",
    ]


def test_parse_show_problem(adrci_dir: Path) -> None:
    problems = parse_show_problem((adrci_dir / "show_problem.txt").read_text())
    assert len(problems) == 3
    p = problems[2]
    assert p.problem_id == 1
    assert p.problem_key == "ORA 600 [autodiag_test]"
    assert p.last_incident == 8873
    assert p.adr_home == "/opt/oracle/diag/rdbms/free/FREE"
    assert p.lastinc_time.year == 2026 and p.lastinc_time.tzinfo is not None
    assert problems[0].problem_key == "ORA 7445 [kglic0()+1223]"


def test_parse_show_incident_brief(adrci_dir: Path) -> None:
    incs = parse_show_incident_brief((adrci_dir / "show_incident_brief.txt").read_text())
    assert [i.incident_id for i in incs] == [8881, 8880, 8873]
    assert incs[0].problem_key == "ORA 600 [autodiag_repeat] [3]"
    assert incs[2].create_time.isoformat() == "2026-09-22T11:02:55.501000+00:00"


def test_parse_show_incident_detail(adrci_dir: Path) -> None:
    incs = parse_show_incident_detail((adrci_dir / "show_incident_detail.txt").read_text())
    assert len(incs) == 1
    i = incs[0]
    assert i.incident_id == 8873
    assert i.problem_id == 1
    assert i.problem_key == "ORA 600 [autodiag_test]"
    assert i.error_facility == "ORA" and i.error_number == 600
    assert i.error_args == ["autodiag_test", "0", "0"]
    assert i.flood_controlled is False
    assert i.trace_file == (
        "/opt/oracle/diag/rdbms/free/FREE/incident/incdir_8873/FREE_ora_4021_i8873.trc"
    )
    assert i.incident_dir == "/opt/oracle/diag/rdbms/free/FREE/incident/incdir_8873"
    assert i.owner_trace_file == "/opt/oracle/diag/rdbms/free/FREE/trace/FREE_ora_4021.trc"
    assert i.keys["SID"] == "282.23751"
    assert i.keys["Client ProcId"].startswith("oracle@oradb-test")


def test_empty_result_sets() -> None:
    txt = "\nADR Home = /opt/oracle/diag/rdbms/free/FREE:\n" + "*" * 73 + "\n0 rows fetched\n\n"
    assert parse_show_problem(txt) == []
    assert parse_show_incident_brief(txt) == []
    assert parse_show_incident_detail(txt) == []


def test_parse_timestamp_variants() -> None:
    ts = parse_timestamp("2026-09-22 11:02:55.501000 +00:00")
    assert ts.tzinfo is not None and ts.utcoffset() == UTC.utcoffset(None)
    assert parse_timestamp("2026-09-22 11:02:55.501000 +02:00").utcoffset().total_seconds() == 7200
    assert parse_timestamp("<NULL>") is None
    assert parse_timestamp("") is None


def test_parse_show_incident_handles_key_value_brief_output(adrci_dir: Path) -> None:
    """23ai prints ``show incident -mode brief`` as INCIDENT INFO RECORD blocks."""
    from autodiag.adr.adrci import parse_show_incident

    incs = parse_show_incident((adrci_dir / "show_incident_brief_kv.txt").read_text())
    assert [i.incident_id for i in incs] == [8051, 8275]
    seg = incs[1]
    assert seg.error_number == 7445 and seg.problem_id == 2
    assert seg.error_args[:2] == ["qeilbk1", "SIGSEGV"]
    # no PROBLEM_KEY field in this output: derive it from facility/number/first argument
    assert seg.problem_key == "ORA 7445 [qeilbk1]"
    assert incs[0].problem_key == "ORA 800 [Set Priority Failed]"
    # the table form still works through the same entry point
    table = parse_show_incident((adrci_dir / "show_incident_brief.txt").read_text())
    assert [i.incident_id for i in table] == [8881, 8880, 8873]

import pytest

from autodiag.sql.diag import incidents_for_problem
from autodiag.sql.runner import SqlRunner

pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def runner(testbed_source) -> SqlRunner:
    t = testbed_source.target
    if t.sqlnet is None or not t.sqlnet.password():
        pytest.skip("testbed has no SQL*Net configuration or password")
    return SqlRunner(t.sqlnet, timeout=30, diagnostics_pack=t.diagnostics_pack)


def test_ping_and_diag_info(runner: SqlRunner) -> None:
    info = runner.ping()
    assert info["DB_NAME"] == "FREE" and info["VERSION_FULL"].startswith("23.")
    res = runner.run_named("diag_info")
    names = {r[0] for r in res.rows}
    assert {"ADR Base", "ADR Home", "Diag Trace"} <= names


def test_problems_and_trace_contents_over_sqlnet(runner: SqlRunner, testbed_source) -> None:
    probs = runner.run_named("diag_problems", {"since_hours": 24 * 30}).as_dicts()
    p = next(p for p in probs if str(p["PROBLEM_KEY"]).startswith("ORA 7445"))
    incs = incidents_for_problem(
        runner, p["PROBLEM_ID"]
    ).as_dicts()  # PDB incidents need a container switch
    assert incs and incs[0]["ERROR_NUMBER"] == 7445 and incs[0]["PROBLEM_KEY"] == p["PROBLEM_KEY"]
    # V$DIAG_TRACE_FILE lists only trace/, but incident traces are readable by base name
    files = runner.run_named("diag_trace_files", {"since_hours": 24 * 30}).as_dicts()
    assert files and all(str(f["TRACE_FILENAME"]).endswith(".trc") for f in files)
    inc = testbed_source.get_incident(incs[0]["INCIDENT_ID"])
    assert inc is not None and inc.trace_file
    adr_home, _, rest = inc.trace_file.partition("/incident/")
    lines = runner.run_named(
        "diag_trace_file_contents",
        {
            "adr_home": adr_home,
            "trace_filename": rest.rsplit("/", 1)[-1],
            "line_from": 1,
            "line_to": 60,
        },
        max_rows=100,
    )
    payload = "\n".join(str(r[3]) for r in lines.rows)
    assert "ORA-07445" in payload or "Dump for incident" in payload


def test_pdb_scoped_query_switches_container(runner: SqlRunner) -> None:
    res = runner.run_named("sessions_active_now", container="FREEPDB1")
    assert res.container == "FREEPDB1" and "SID" in res.columns


def test_ash_query_when_pack_licensed(runner: SqlRunner) -> None:
    res = runner.run_named(
        "ash_top_events_window",
        {"from_ts": "2000-01-01 00:00:00", "to_ts": "2100-01-01 00:00:00", "top": 5},
        container="FREEPDB1",
    )
    assert res.columns[0] == "EVENT"

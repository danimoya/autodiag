from autodiag.sql.diag import incidents_for_problem, open_pdbs, trace_file_lines
from autodiag.sql.runner import QueryResult


class FakeRunner:
    """Simulates container-scoped visibility: incidents live in FREEPDB1 only."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict, str | None]] = []

    def run_named(self, name, params=None, *, max_rows=200, container=None):
        params = params or {}
        self.calls.append((name, params, container))
        if name == "pdbs":
            return QueryResult(
                name=name,
                columns=["CON_ID", "NAME", "OPEN_MODE"],
                rows=[
                    [2, "PDB$SEED", "READ ONLY"],
                    [3, "FREEPDB1", "READ WRITE"],
                    [4, "CLOSEDPDB", "MOUNTED"],
                ],
            )
        if name == "diag_incidents":
            rows = (
                [[8275, params["problem_id"], "ORA 7445 [x]", 7445]]
                if container == "FREEPDB1"
                else []
            )
            return QueryResult(
                name=name,
                columns=["INCIDENT_ID", "PROBLEM_ID", "PROBLEM_KEY", "ERROR_NUMBER"],
                rows=rows,
                container=container,
            )
        if name == "diag_trace_file_contents":
            rows = [[1, None, "", "line one"]] if container == "FREEPDB1" else []
            return QueryResult(
                name=name,
                columns=["LINE_NUMBER", "TIMESTAMP", "SECTION_NAME", "PAYLOAD"],
                rows=rows,
                container=container,
            )
        raise AssertionError(name)


def test_open_pdbs_excludes_seed_and_closed() -> None:
    assert open_pdbs(FakeRunner()) == ["FREEPDB1"]


def test_incidents_fall_back_to_pdbs() -> None:
    r = FakeRunner()
    res = incidents_for_problem(r, 3)
    assert res.rows and res.container == "FREEPDB1"
    containers = [c for n, _, c in r.calls if n == "diag_incidents"]
    assert containers == [None, "FREEPDB1"]


def test_trace_lines_fall_back_to_pdbs() -> None:
    r = FakeRunner()
    res = trace_file_lines(r, "/adr", "x_i8275.trc", 1, 50)
    assert res.rows[0][3] == "line one" and res.container == "FREEPDB1"

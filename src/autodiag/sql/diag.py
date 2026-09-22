"""ADR queries over SQL*Net with container awareness.

``V$DIAG_PROBLEM`` is visible from the CDB root, but ``V$DIAG_INCIDENT`` and
``V$DIAG_TRACE_FILE_CONTENTS`` only show the current container's rows. These helpers try
the root first and then every open PDB.
"""

from __future__ import annotations

from functools import lru_cache

from autodiag.sql.runner import QueryResult, SqlRunner


def open_pdbs(runner: SqlRunner) -> list[str]:
    res = runner.run_named("pdbs", {}, max_rows=500)
    names: list[str] = []
    for row in res.as_dicts():
        name, mode = str(row.get("NAME", "")), str(row.get("OPEN_MODE", ""))
        if name == "PDB$SEED" or not mode.startswith("READ"):
            continue
        names.append(name)
    return names


def _first_with_rows(runner: SqlRunner, name: str, params: dict, *, max_rows: int) -> QueryResult:
    res = runner.run_named(name, params, max_rows=max_rows)
    if res.rows:
        return res
    for pdb in open_pdbs(runner):
        res = runner.run_named(name, params, max_rows=max_rows, container=pdb)
        if res.rows:
            return res
    return res


def incidents_for_problem(
    runner: SqlRunner, problem_id: int, *, max_rows: int = 200
) -> QueryResult:
    return _first_with_rows(runner, "diag_incidents", {"problem_id": problem_id}, max_rows=max_rows)


def incident_detail(runner: SqlRunner, incident_id: int) -> QueryResult:
    return _first_with_rows(
        runner, "diag_incident_detail", {"incident_id": incident_id}, max_rows=5
    )


def trace_file_lines(
    runner: SqlRunner,
    adr_home: str,
    trace_filename: str,
    line_from: int,
    line_to: int,
    *,
    max_rows: int = 2000,
) -> QueryResult:
    return _first_with_rows(
        runner,
        "diag_trace_file_contents",
        {
            "adr_home": adr_home,
            "trace_filename": trace_filename,
            "line_from": line_from,
            "line_to": line_to,
        },
        max_rows=max_rows,
    )


__all__ = ["incident_detail", "incidents_for_problem", "open_pdbs", "trace_file_lines", "lru_cache"]

from pathlib import Path

import pytest

from autodiag.sql.catalog import Query, load_catalog


def test_catalog_loads_and_validates() -> None:
    cat = load_catalog()
    assert len(cat) >= 12
    for name, q in cat.items():
        assert isinstance(q, Query) and q.name == name
        assert q.description and q.scope in {"cdb", "pdb"} and q.pack in {"none", "diagnostics"}
        assert q.sql.lstrip().lower().startswith(("select", "with"))
        # every bind in the SQL is a declared parameter and vice versa
        assert set(q.binds) == set(q.params), name


def test_specific_queries_present() -> None:
    cat = load_catalog()
    for name in [
        "diag_info",
        "db_info",
        "pdbs",
        "diag_problems",
        "diag_incidents",
        "diag_incident_detail",
        "diag_alert_ext_window",
        "diag_trace_files",
        "diag_trace_file_contents",
        "sqlpatch_registry",
        "params_nondefault",
        "sessions_active_now",
        "blocking_tree_now",
        "system_events_top",
        "ash_top_events_window",
        "ash_top_sql_window",
        "sql_plan_history",
    ]:
        assert name in cat, name
    assert cat["ash_top_sql_window"].pack == "diagnostics"
    assert cat["diag_trace_file_contents"].params["line_from"].type == "int"
    assert cat["diag_problems"].params["since_hours"].default == 168


def test_param_coercion_and_validation() -> None:
    q = load_catalog()["diag_trace_file_contents"]
    binds = q.bind_values(
        {"adr_home": "/x", "trace_filename": "a.trc", "line_from": "10", "line_to": 20}
    )
    assert binds == {"adr_home": "/x", "trace_filename": "a.trc", "line_from": 10, "line_to": 20}
    with pytest.raises(ValueError, match="line_from"):
        q.bind_values(
            {"adr_home": "/x", "trace_filename": "a.trc", "line_from": "ten", "line_to": 20}
        )
    with pytest.raises(ValueError, match="unknown parameter"):
        q.bind_values(
            {"adr_home": "/x", "trace_filename": "a.trc", "line_from": 1, "line_to": 2, "zz": 1}
        )
    d = load_catalog()["diag_problems"].bind_values({})
    assert d == {"since_hours": 168}


def test_catalog_dir_is_packaged(repo_root: Path) -> None:
    assert (repo_root / "src/autodiag/sql/catalog/diag_info.sql").is_file()

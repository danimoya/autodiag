import sqlite3
from importlib import resources

import pytest

from autodiag.adr.source import AdrSource, AdrSourceError, IncidentRow, ProblemRow
from autodiag.case.store import CaseStore
from autodiag.core.models import Node, Target


def test_colliding_ids_are_preserved_and_updates_stay_in_their_home(tmp_path):
    store = CaseStore(tmp_path / "case.db")
    rows = [
        ProblemRow(
            node=node,
            instance=node,
            adr_home="diag/rdbms/db/DB",
            problem_id=1,
            problem_key=f"ORA 600 [{node}]",
        )
        for node in ("a", "b")
    ]
    assert len(store.upsert_problem_rows("rac", rows)) == 2
    rows[1].problem_key = "ORA 700 [changed]"
    assert store.upsert_problem_rows("rac", rows) == []
    assert {p.node: p.problem_key for p in store.list_problems("rac")} == {
        "a": "ORA 600 [a]",
        "b": "ORA 700 [changed]",
    }
    incidents = [
        IncidentRow(
            node=p.node,
            adr_home=p.adr_home,
            incident_id=42,
            problem_id=1,
            problem_key=p.problem_key,
        )
        for p in rows
    ]
    store.upsert_incidents("rac", incidents)
    assert store._conn.execute("SELECT count(*) FROM incidents").fetchone()[0] == 2
    store.close()
    reopened = CaseStore(tmp_path / "case.db")
    assert len(reopened.list_problems("rac")) == 2
    reopened.close()


def test_v1_migration_preserves_existing_records(tmp_path):
    path = tmp_path / "legacy.db"
    db = sqlite3.connect(path)
    db.executescript(resources.files("autodiag.case").joinpath("schema/001_init.sql").read_text())
    db.execute("INSERT INTO schema_version VALUES (1)")
    db.execute(
        "INSERT INTO problems(target,problem_id,problem_key,adr_home,first_seen_at,last_seen_at)"
        " VALUES ('db',1,'ORA 600 [old]','diag/rdbms/db/DB','2026-01-01','2026-01-02')"
    )
    db.execute(
        "INSERT INTO incidents(target,incident_id,problem_key,seen_at)"
        " VALUES ('db',42,'ORA 600 [old]','2026-01-02')"
    )
    db.commit()
    db.close()
    store = CaseStore(path)
    old = store.list_problems("db")[0]
    assert old.problem_key == "ORA 600 [old]" and old.node == ""
    assert old.adr_home == "diag/rdbms/db/DB"
    assert store._conn.execute("SELECT count(*) FROM incidents").fetchone()[0] == 1
    assert store._conn.execute("SELECT version FROM schema_version").fetchone()[0] == 2
    store.close()


def test_incident_lookup_requires_identity_when_ambiguous(fake_transport_factory):
    target = Target(
        name="rac",
        nodes=[Node(host="a"), Node(host="b")],
        adr_base="/opt/oracle",
        adr_homes=["diag/rdbms/free/FREE"],
    )
    source = AdrSource(target, transport_factory=fake_transport_factory)
    with pytest.raises(AdrSourceError, match="ambiguous"):
        source.get_incident(8873)
    inc = source.get_incident(8873, node="b", adr_home="diag/rdbms/free/FREE")
    assert inc.node == "b" and source.incident_node(inc).host == "b"
    assert {i.node for i in source.list_incidents(problem_id=1, node="b")} == {"b"}
    with pytest.raises(AdrSourceError, match="Select one"):
        source.select_ref()
    with pytest.raises(AdrSourceError, match="No matching"):
        source.get_incident(8873, node="unknown")


def test_cache_paths_include_node_and_remote_path(tmp_path):
    a, b = Node(host="a"), Node(host="b")
    assert (
        len(
            {
                AdrSource.cache_path(tmp_path, n, p)
                for n in (a, b)
                for p in ("/diag/one/trace.trc", "/diag/two/trace.trc")
            }
        )
        == 4
    )

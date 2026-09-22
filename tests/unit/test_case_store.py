import hashlib
from pathlib import Path

import pytest

from autodiag.case.store import CaseStore, CaseStoreError


@pytest.fixture
def store(tmp_path: Path) -> CaseStore:
    return CaseStore(tmp_path / "autodiag.db", artifacts_dir=tmp_path / "cases")


def test_open_get_list_cases(store: CaseStore) -> None:
    c = store.open_case("testbed", "ORA-7445 in busy loop", problem_keys=["ORA 7445 [qeilbk1]"])
    assert c.id.startswith("case_") and c.status == "open" and c.target == "testbed"
    assert store.get_case(c.id).title == "ORA-7445 in busy loop"
    assert [x.id for x in store.list_cases(target="testbed")] == [c.id]
    store.close_case(c.id)
    assert store.get_case(c.id).status == "closed"
    with pytest.raises(CaseStoreError):
        store.get_case("case_nope")


def test_artifacts_are_copied_and_hashed(store: CaseStore, fixtures_dir: Path) -> None:
    c = store.open_case("testbed", "t")
    src = fixtures_dir / "23ai/traces/deadlock_ora60.trc"
    a = store.add_artifact(
        c.id, kind="trace", path=src, origin={"node": "127.0.0.1", "remote": "/x/y.trc"}
    )
    assert a.sha256 == hashlib.sha256(src.read_bytes()).hexdigest()
    assert a.size == src.stat().st_size and Path(a.path).exists() and Path(a.path) != src
    assert store.list_artifacts(c.id)[0].id == a.id
    assert store.get_artifact(a.id).origin["remote"] == "/x/y.trc"
    # same content again -> same artifact (dedup by sha256 within the case)
    b = store.add_artifact(c.id, kind="trace", path=src, origin={})
    assert b.id == a.id


def test_evidence_and_findings(store: CaseStore) -> None:
    c = store.open_case("testbed", "t")
    ev = store.record_evidence(
        "parse_trace", {"path": "/x"}, "ORA 7445 [qeilbk1] first frame qeilbk1", case_id=c.id
    )
    assert ev.id.startswith("ev_") and store.get_evidence(ev.id).tool == "parse_trace"
    f = store.add_finding(
        c.id,
        kind="root_cause",
        title="Index lookup crash",
        detail="SIGSEGV in qeilbk1 during index fetch",
        confidence=0.7,
        evidence_ids=[ev.id],
        kb_refs=["ora7445:qeilbk1"],
        author="agent",
    )
    assert f.id.startswith("fnd_") and store.list_findings(c.id)[0].confidence == 0.7
    with pytest.raises(CaseStoreError, match="evidence"):
        store.add_finding(
            c.id, kind="observation", title="x", detail="y", confidence=0.5, evidence_ids=[]
        )
    with pytest.raises(CaseStoreError, match="unknown evidence"):
        store.add_finding(
            c.id, kind="observation", title="x", detail="y", confidence=0.5, evidence_ids=["ev_zzz"]
        )
    with pytest.raises(CaseStoreError, match="kind"):
        store.add_finding(
            c.id, kind="guess", title="x", detail="y", confidence=0.5, evidence_ids=[ev.id]
        )
    store.update_finding(f.id, confidence=0.9, status="confirmed")
    assert (
        store.get_finding(f.id).confidence == 0.9 and store.get_finding(f.id).status == "confirmed"
    )


def test_baselines(store: CaseStore, fixtures_dir: Path) -> None:
    c = store.open_case("testbed", "t")
    a = store.add_artifact(
        c.id, kind="sqltrace", path=fixtures_dir / "23ai/traces/AUTODIAG_NORMAL.trc", origin={}
    )
    b = store.set_baseline("testbed", kind="sqltrace", artifact_id=a.id, label="normal workload")
    assert [x.id for x in store.list_baselines("testbed", kind="sqltrace")] == [b.id]
    assert store.list_baselines("other") == []


def test_reports(store: CaseStore) -> None:
    c = store.open_case("testbed", "t")
    r = store.add_report(c.id, kind="dba", markdown="# Report\nhello")
    assert store.get_report(r.id).markdown.startswith("# Report")
    assert store.list_reports(c.id)[0].kind == "dba"
    with pytest.raises(CaseStoreError, match="kind"):
        store.add_report(c.id, kind="pdf", markdown="x")


def test_problem_snapshots_and_new_since(store: CaseStore) -> None:
    from datetime import UTC, datetime

    from autodiag.adr.adrci import AdrProblem

    t0 = datetime(2026, 9, 22, 10, tzinfo=UTC)
    p1 = AdrProblem(
        adr_home="/a", problem_id=1, problem_key="ORA 600 [x]", last_incident=5, lastinc_time=t0
    )
    first = store.upsert_problems("testbed", [p1])
    assert first == [1]
    p2 = AdrProblem(
        adr_home="/a", problem_id=2, problem_key="ORA 7445 [y]", last_incident=9, lastinc_time=t0
    )
    assert store.upsert_problems("testbed", [p1, p2]) == [2]
    rows = store.list_problems("testbed")
    assert {r.problem_id for r in rows} == {1, 2}


def test_jobs(store: CaseStore) -> None:
    j = store.create_job("ips", {"problem_id": 3})
    assert j.status == "queued"
    store.update_job(j.id, status="running")
    store.update_job(j.id, status="done", result={"zip": "/x.zip"})
    got = store.get_job(j.id)
    assert got.status == "done" and got.result["zip"] == "/x.zip"

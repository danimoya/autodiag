from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from autodiag.core.settings import load_settings
from autodiag.core.targets import load_targets
from autodiag.mcp.server import AutoDiagContext
from autodiag.web.app import create_app

TR = Path("tests/fixtures/23ai/traces")


@pytest.fixture
def client(tmp_path: Path, fixtures_dir: Path, fake_transport_factory, monkeypatch):
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "none.toml"))
    monkeypatch.setenv("AUTODIAG_DATA_DIR", str(tmp_path / "data"))
    s = load_settings(env_file=None)
    inv = load_targets(fixtures_dir / "config" / "targets.yaml")
    ctx = AutoDiagContext(
        s, inv, transport_factory=lambda t: fake_transport_factory, runner_factory=lambda t: None
    )
    app = create_app(ctx)
    with TestClient(app) as c:
        yield c


def test_health_and_targets(client: TestClient) -> None:
    assert client.get("/healthz").json()["status"] == "ok"
    r = client.get("/targets")
    assert r.status_code == 200 and "testbed" in r.text and "prod-rac" in r.text
    r = client.get("/targets/testbed")
    assert r.status_code == 200 and "diag/rdbms/free/FREE" in r.text


def test_problems_incidents_pages(client: TestClient) -> None:
    r = client.get("/targets/testbed/problems?days=7")
    assert r.status_code == 200 and "ORA 600 [autodiag_test]" in r.text
    r = client.get("/targets/testbed/problems/1")
    assert r.status_code == 200 and "8873" in r.text


def test_alertlog_page(client: TestClient) -> None:
    r = client.get("/targets/testbed/alertlog?hours=100000&grep=ORA-00060&context=1")
    assert r.status_code == 200 and "ORA-00060" in r.text and "top signatures" in r.text.lower()


def test_case_flow_and_trace_viewer(client: TestClient) -> None:
    r = client.post(
        "/cases",
        data={"target": "testbed", "title": "web case", "problem_keys": "ORA 7445 [qeilbk1]"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    case_url = r.headers["location"]
    cid = case_url.rsplit("/", 1)[-1]
    with open(TR / "incident_ora7445.trc", "rb") as fh:
        r = client.post(
            f"/cases/{cid}/upload",
            files={"file": ("incident_ora7445.trc", fh, "text/plain")},
            data={"kind": "trace"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    page = client.get(case_url)
    assert page.status_code == 200 and "incident_ora7445.trc" in page.text
    art_id = next(
        part for part in page.text.split('"') if part.startswith("/artifacts/art_")
    ).split("/")[2]
    r = client.get(f"/artifacts/{art_id}")
    assert r.status_code == 200 and "ORA 7445 [qeilbk1]" in r.text and "qeilbk1" in r.text
    r = client.get(f"/artifacts/{art_id}/lines?offset=40&n=5")
    assert r.status_code == 200 and "ORA-07445" in r.text
    r = client.post(
        f"/cases/{cid}/evidence",
        data={"summary": "manual note", "tool": "manual"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    import re

    ev_id = re.search(r"ev_[0-9a-f]{10}", client.get(case_url).text).group(0)
    r = client.post(
        f"/cases/{cid}/findings",
        data={
            "kind": "root_cause",
            "title": "Crash in qeilbk1",
            "detail": "SIGSEGV",
            "confidence": "0.6",
            "evidence_ids": ev_id,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "Crash in qeilbk1" in client.get(case_url).text
    r = client.post(f"/cases/{cid}/reports", data={"kind": "dba"}, follow_redirects=False)
    assert r.status_code == 303
    rep = client.get(r.headers["location"])
    assert (
        rep.status_code == 200 and "AutoDiag report" in rep.text and "Crash in qeilbk1" in rep.text
    )
    md = client.get(r.headers["location"] + ".md")
    assert md.headers["content-type"].startswith("text/markdown") and md.text.startswith(
        "# AutoDiag report"
    )


def test_diff_pages(client: TestClient) -> None:
    cid = (
        client.post("/cases", data={"target": "testbed", "title": "d"}, follow_redirects=False)
        .headers["location"]
        .rsplit("/", 1)[-1]
    )
    ids = []
    for name in [
        "incident_ora7445.trc",
        "incident_ora7445_b.trc",
        "AUTODIAG_NORMAL.trc",
        "AUTODIAG_ANOMALY.trc",
    ]:
        with open(TR / name, "rb") as fh:
            client.post(
                f"/cases/{cid}/upload",
                files={"file": (name, fh, "text/plain")},
                data={"kind": "trace"},
                follow_redirects=False,
            )
    page = client.get(f"/cases/{cid}").text
    ids = [p.split("/")[2] for p in page.split('"') if p.startswith("/artifacts/art_")]
    ids = list(dict.fromkeys(ids))
    assert len(ids) == 4
    r = client.get(f"/diff/stacks?left={ids[0]}&right={ids[1]}")
    assert r.status_code == 200 and "kdxbrs1" in r.text and "diverge" in r.text.lower()
    r = client.get(f"/diff/sqlprofile?left={ids[2]}&right={ids[3]}")
    assert r.status_code == 200 and "PLAN_CHANGE" in r.text


def test_rest_tool_endpoint_and_auth(client: TestClient, monkeypatch) -> None:
    r = client.post("/api/v1/tools/list_targets", json={})
    assert r.status_code == 200 and r.json()["targets"][0]["name"] == "testbed"
    r = client.post("/api/v1/tools/kb_lookup", json={"problem_key": "ORA 600 [4194]"})
    assert r.json()["hits"][0]["title"].startswith("Undo record mismatch")
    r = client.post("/api/v1/tools/nope", json={})
    assert r.status_code == 404
    r = client.get("/api/v1/tools")
    assert r.status_code == 200 and "standard_triage" in [t["name"] for t in r.json()["tools"]]


def test_bearer_token_guards_api_and_mcp(
    tmp_path: Path, fixtures_dir: Path, fake_transport_factory, monkeypatch
) -> None:
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "none.toml"))
    monkeypatch.setenv("AUTODIAG_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AUTODIAG_MCP_TOKEN", "s3cret")
    s = load_settings(env_file=None)
    inv = load_targets(fixtures_dir / "config" / "targets.yaml")
    ctx = AutoDiagContext(
        s, inv, transport_factory=lambda t: fake_transport_factory, runner_factory=lambda t: None
    )
    with TestClient(create_app(ctx)) as c:
        assert c.post("/api/v1/tools/list_targets", json={}).status_code == 401
        assert (
            c.post(
                "/api/v1/tools/list_targets", json={}, headers={"Authorization": "Bearer s3cret"}
            ).status_code
            == 200
        )
        assert c.get("/targets").status_code == 200  # HTML stays open on loopback
        r = c.post("/mcp", json={}, headers={"Accept": "application/json, text/event-stream"})
        assert r.status_code == 401
        r = c.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "0"},
                },
            },
            headers={
                "Authorization": "Bearer s3cret",
                "Accept": "application/json, text/event-stream",
            },
        )
        assert r.status_code in (200, 400, 406)  # reached the MCP app, not a 404/401

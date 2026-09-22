import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from autodiag.cli import common
from autodiag.cli.main import app

runner = CliRunner()
TR = "tests/fixtures/23ai/traces"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path: Path, fixtures_dir: Path, fake_transport_factory) -> None:
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "none.toml"))
    monkeypatch.setenv("AUTODIAG_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AUTODIAG_TARGETS_FILE", str(fixtures_dir / "config" / "targets.yaml"))
    monkeypatch.setattr(
        common, "transport_factory", lambda settings, target: fake_transport_factory
    )
    monkeypatch.setattr(common, "sql_runner", lambda settings, target: None)


def _open() -> str:
    r = runner.invoke(
        app,
        [
            "case",
            "open",
            "--target",
            "testbed",
            "ORA-7445 investigation",
            "--problem-key",
            "ORA 7445 [qeilbk1]",
            "--json",
        ],
    )
    assert r.exit_code == 0, r.output
    return json.loads(r.output)["id"]


def test_case_lifecycle_and_report() -> None:
    cid = _open()
    r = runner.invoke(app, ["case", "list"])
    assert r.exit_code == 0 and cid in r.output
    r = runner.invoke(
        app, ["case", "add", cid, f"{TR}/incident_ora7445.trc", "--kind", "trace", "--json"]
    )
    assert r.exit_code == 0, r.output
    art = json.loads(r.output)
    assert art["sha256"] and art["id"].startswith("art_")
    r = runner.invoke(app, ["case", "analyze", cid, art["id"], "--json"])
    assert r.exit_code == 0, r.output
    ev = json.loads(r.output)
    assert ev["evidence_id"].startswith("ev_") and "qeilbk1" in ev["summary"]
    r = runner.invoke(
        app,
        [
            "case",
            "finding",
            cid,
            "--kind",
            "root_cause",
            "--title",
            "Index lookup crash",
            "--detail",
            "SIGSEGV in qeilbk1",
            "--confidence",
            "0.7",
            "--evidence",
            ev["evidence_id"],
        ],
    )
    assert r.exit_code == 0, r.output
    r = runner.invoke(app, ["case", "show", cid])
    assert r.exit_code == 0 and "Index lookup crash" in r.output and art["id"] in r.output
    r = runner.invoke(app, ["report", "render", cid, "--kind", "dba"])
    assert r.exit_code == 0, r.output
    assert (
        "# AutoDiag report" in r.output and "Index lookup crash" in r.output and "ev_" in r.output
    )
    r = runner.invoke(
        app,
        [
            "report",
            "render",
            cid,
            "--kind",
            "sr",
            "--out",
            str(Path(common.settings().data_dir) / "sr.md"),
        ],
    )
    assert r.exit_code == 0, r.output
    assert (Path(common.settings().data_dir) / "sr.md").read_text().startswith("# Service Request")
    r = runner.invoke(app, ["report", "list", cid])
    assert r.exit_code == 0 and "dba" in r.output and "sr" in r.output


def test_case_collect_incident_uses_target_transport() -> None:
    cid = _open()
    r = runner.invoke(app, ["case", "collect-incident", cid, "--id", "8873", "--json"])
    assert r.exit_code == 0, r.output
    out = json.loads(r.output)
    assert out["artifact_id"].startswith("art_") and out["evidence_id"].startswith("ev_")
    assert out["incident"]["problem_key"] == "ORA 600 [autodiag_test]"


def test_kb_lookup_command() -> None:
    r = runner.invoke(app, ["kb", "lookup", "--problem-key", "ORA 600 [4194]"])
    assert r.exit_code == 0 and "Undo record mismatch" in r.output
    r = runner.invoke(app, ["kb", "lookup", "--wait", "enq: TX - row lock contention", "--json"])
    assert r.exit_code == 0 and json.loads(r.output)[0]["kind"] == "wait_event"

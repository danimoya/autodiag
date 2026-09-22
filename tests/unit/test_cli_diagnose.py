import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from autodiag.cli import common
from autodiag.cli.main import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path: Path, fixtures_dir: Path, fake_transport_factory) -> None:
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "none.toml"))
    monkeypatch.setenv("AUTODIAG_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AUTODIAG_TARGETS_FILE", str(fixtures_dir / "config" / "targets.yaml"))
    monkeypatch.setattr(common, "transport_factory", lambda s, t: fake_transport_factory)
    monkeypatch.setattr(common, "sql_runner", lambda s, t: None)


def test_diagnose_alert_rules_only_text_and_json(tmp_path: Path) -> None:
    r = runner.invoke(
        app, ["diagnose", "alert", "-t", "testbed", "--hours", "99999", "--no-assess"]
    )
    assert r.exit_code == 0, r.output
    assert "Rules-only ranking" in r.output and "noise suppressed" in r.output
    assert "advanced to log sequence" not in r.output.split("Dismissed")[0]
    md = tmp_path / "d.md"
    r = runner.invoke(
        app,
        [
            "diagnose",
            "alert",
            "-t",
            "testbed",
            "--hours",
            "99999",
            "--no-assess",
            "--json",
            "--markdown",
            str(md),
        ],
    )
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert data["assessment"]["model"] == "rules" and data["dossier"]["mode"] == "alert"
    assert md.read_text().startswith("# Diagnosis: testbed (alert)")


def test_diagnose_problem_requires_key_and_records_case() -> None:
    r = runner.invoke(app, ["diagnose", "problem", "-t", "testbed", "--no-assess"])
    assert r.exit_code == 1 and "problem-key" in r.output
    r = runner.invoke(
        app,
        [
            "diagnose",
            "problem",
            "-t",
            "testbed",
            "-k",
            "ORA 600 [autodiag_test]",
            "--no-assess",
            "--case",
            "new",
            "--dossier",
        ],
    )
    assert r.exit_code == 0, r.output
    assert "Findings recorded" in r.output and "Dossier items:" in r.output


def test_diagnose_instance_no_live() -> None:
    r = runner.invoke(
        app,
        [
            "diagnose",
            "instance",
            "-t",
            "prod-rac",
            "--no-live",
            "--no-assess",
            "--days",
            "3650",
            "--hours",
            "99999",
            "--dossier",
        ],
    )
    assert r.exit_code == 0, r.output
    assert "live=False" in r.output and "Same message on 2 nodes" in r.output

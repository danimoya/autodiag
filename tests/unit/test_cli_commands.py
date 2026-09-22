import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from autodiag.cli import common
from autodiag.cli.main import app

runner = CliRunner()
TR = "tests/fixtures/23ai/traces"


@pytest.fixture(autouse=True)
def _isolated_config(
    monkeypatch, tmp_path: Path, fixtures_dir: Path, fake_transport_factory
) -> None:
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "none.toml"))
    monkeypatch.setenv("AUTODIAG_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AUTODIAG_TARGETS_FILE", str(fixtures_dir / "config" / "targets.yaml"))
    monkeypatch.setattr(
        common, "transport_factory", lambda settings, target: fake_transport_factory
    )


def test_targets_list() -> None:
    r = runner.invoke(app, ["targets", "list"])
    assert r.exit_code == 0, r.output
    assert "testbed" in r.output and "prod-rac" in r.output


def test_adr_problems_and_incidents() -> None:
    r = runner.invoke(app, ["adr", "problems", "--target", "testbed", "--days", "3"])
    assert r.exit_code == 0, r.output
    assert "ORA 600 [autodiag_test]" in r.output and "ORA 7445 [kglic0()+1223]" in r.output
    r = runner.invoke(
        app, ["adr", "incidents", "--target", "testbed", "--problem-key", "ORA 600 [autodiag_test]"]
    )
    assert r.exit_code == 0, r.output
    assert "8873" in r.output
    r = runner.invoke(app, ["adr", "incident", "--target", "testbed", "--id", "8873", "--json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert data["problem_key"] == "ORA 600 [autodiag_test]" and data["trace_file"].endswith(
        "_i8873.trc"
    )


def test_unknown_target_fails_cleanly() -> None:
    r = runner.invoke(app, ["adr", "problems", "--target", "nope"])
    assert r.exit_code == 1
    assert "unknown target" in r.output


def test_alert_grep_and_stats() -> None:
    r = runner.invoke(app, ["alert", "grep", "--target", "testbed", "ORA-00060", "-C", "2"])
    assert r.exit_code == 0, r.output
    assert "ORA-00060" in r.output
    r = runner.invoke(app, ["alert", "stats", "--target", "testbed", "--hours", "100000"])
    assert r.exit_code == 0, r.output
    assert "ORA-00060" in r.output or "60:" in r.output
    assert "records" in r.output


def test_trace_parse_and_profile() -> None:
    r = runner.invoke(app, ["trace", "parse", f"{TR}/incident_ora7445.trc"])
    assert r.exit_code == 0, r.output
    assert "ORA 7445 [qeilbk1]" in r.output and "qeilbk1" in r.output
    r = runner.invoke(app, ["trace", "parse", f"{TR}/deadlock_ora60.trc", "--json"])
    assert r.exit_code == 0 and json.loads(r.output)["kind"] == "deadlock"
    r = runner.invoke(app, ["trace", "profile", f"{TR}/AUTODIAG_NORMAL.trc", "--top", "3"])
    assert r.exit_code == 0, r.output
    assert "sql_id" in r.output.lower() and "elapsed" in r.output.lower()


def test_diff_commands() -> None:
    r = runner.invoke(
        app, ["diff", "stacks", f"{TR}/incident_ora7445.trc", f"{TR}/incident_ora7445_b.trc"]
    )
    assert r.exit_code == 0, r.output
    assert "qeilbk1" in r.output and "kdxbrs1" in r.output and "diverge" in r.output.lower()
    r = runner.invoke(
        app,
        [
            "diff",
            "sqltrace",
            f"{TR}/AUTODIAG_NORMAL.trc",
            f"{TR}/AUTODIAG_ANOMALY.trc",
            "--top",
            "5",
        ],
    )
    assert r.exit_code == 0, r.output
    assert "PLAN_CHANGE" in r.output
    a = "tests/fixtures/23ai/alertlog/alert_excerpt.log"
    r = runner.invoke(app, ["diff", "alertrate", a, a, "--split", "2026-09-22T12:00:00+00:00"])
    assert r.exit_code == 0, r.output
    assert "ORA-00060" in r.output

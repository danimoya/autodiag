from datetime import UTC, datetime, timedelta
from pathlib import Path

from autodiag.case.retention import purge
from autodiag.core.settings import load_settings
from autodiag.core.targets import load_targets
from autodiag.mcp.server import AutoDiagContext
from autodiag.scheduler.notify import notify
from autodiag.scheduler.scan import scan_all, scan_target


def _ctx(tmp_path, fixtures_dir, fake_transport_factory, monkeypatch, **env):
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "none.toml"))
    monkeypatch.setenv("AUTODIAG_DATA_DIR", str(tmp_path / "data"))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    s = load_settings(env_file=None)
    inv = load_targets(fixtures_dir / "config" / "targets.yaml")
    return AutoDiagContext(
        s, inv, transport_factory=lambda t: fake_transport_factory, runner_factory=lambda t: None
    )


def test_scan_reports_new_problems_once(
    tmp_path: Path, fixtures_dir: Path, fake_transport_factory, monkeypatch
) -> None:
    ctx = _ctx(tmp_path, fixtures_dir, fake_transport_factory, monkeypatch)
    first = scan_target(ctx, ctx.target("testbed"))
    assert sorted(first.new_problem_ids) == [1, 2, 3] and first.problem_count == 3
    second = scan_target(ctx, ctx.target("testbed"))
    assert second.new_problem_ids == []
    scans = ctx.store.list_scans("testbed")
    assert len(scans) == 2 and scans[0].finished_at is not None


def test_scan_all_notifies_and_tolerates_unreachable(
    tmp_path: Path, fixtures_dir: Path, fake_transport_factory, monkeypatch
) -> None:
    log = tmp_path / "notify.txt"
    ctx = _ctx(
        tmp_path,
        fixtures_dir,
        fake_transport_factory,
        monkeypatch,
        AUTODIAG_NOTIFY_COMMAND=f"sh -c 'echo \"$1\" >> {log}' --",
    )
    results = scan_all(ctx)
    assert {r.target for r in results} == {"testbed", "prod-rac"}
    assert log.exists() and "ORA 7445 [kglic0()+1223]" in log.read_text()
    assert (ctx.settings.data_dir / "notifications.log").exists()
    prod = next(r for r in results if r.target == "prod-rac")
    assert prod.error is None or prod.new_problem_ids == []  # the fake answers every target


def test_notify_without_command_only_logs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "none.toml"))
    monkeypatch.setenv("AUTODIAG_DATA_DIR", str(tmp_path / "data"))
    s = load_settings(env_file=None)
    notify(s, "hello")
    assert "hello" in (s.data_dir / "notifications.log").read_text()


def test_retention_purges_old_closed_cases(
    tmp_path: Path, fixtures_dir: Path, fake_transport_factory, monkeypatch
) -> None:
    ctx = _ctx(tmp_path, fixtures_dir, fake_transport_factory, monkeypatch)
    st = ctx.store
    old = st.open_case("testbed", "old")
    art = st.add_artifact(
        old.id, kind="trace", path=fixtures_dir / "23ai/traces/deadlock_ora60.trc", origin={}
    )
    st.close_case(old.id)
    st._conn.execute(
        "UPDATE cases SET updated_at=? WHERE id=?",
        ((datetime.now(UTC) - timedelta(days=400)).isoformat(), old.id),
    )
    keep = st.open_case("testbed", "recent")
    st.close_case(keep.id)
    result = purge(st, days=90)
    assert result.cases_deleted == 1 and result.files_deleted == 1
    assert not Path(art.path).exists()
    assert [c.id for c in st.list_cases()] == [keep.id]

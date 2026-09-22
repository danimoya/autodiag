from pathlib import Path

import pytest

from autodiag.core.models import Target, TargetKind
from autodiag.core.targets import TargetInventory, load_targets


def test_load_targets_from_yaml(fixtures_dir: Path) -> None:
    inv = load_targets(fixtures_dir / "config" / "targets.yaml")
    assert isinstance(inv, TargetInventory)
    assert [t.name for t in inv.targets] == ["testbed", "prod-rac"]
    tb = inv.get("testbed")
    assert tb.kind is TargetKind.SINGLE
    assert tb.nodes[0].ssh_alias == "autodiag-testbed"
    assert tb.nodes[0].ssh_target == "autodiag-testbed"
    assert tb.sqlnet is not None and tb.sqlnet.user == "c##autodiag"
    assert tb.adr_homes == ["diag/rdbms/free/FREE"]
    assert tb.allowed_roots == ["/opt/oracle/diag", "/tmp"]


def test_node_ssh_target_defaults_to_user_at_host(fixtures_dir: Path) -> None:
    inv = load_targets(fixtures_dir / "config" / "targets.yaml")
    rac = inv.get("prod-rac")
    assert rac.kind is TargetKind.RAC
    assert rac.nodes[0].ssh_user == "oracle"
    assert rac.nodes[0].ssh_target == "oracle@dbnode01.example.internal"
    assert rac.node_for_instance("PRODDB2").host == "dbnode02.example.internal"


def test_unknown_target_raises(fixtures_dir: Path) -> None:
    inv = load_targets(fixtures_dir / "config" / "targets.yaml")
    with pytest.raises(KeyError):
        inv.get("nope")


def test_missing_file_gives_empty_inventory(tmp_path: Path) -> None:
    inv = load_targets(tmp_path / "none.yaml")
    assert inv.targets == []


def test_sqlnet_password_comes_from_environment_only(monkeypatch, fixtures_dir: Path) -> None:
    inv = load_targets(fixtures_dir / "config" / "targets.yaml")
    tb = inv.get("testbed")
    monkeypatch.delenv("TESTBED_AUTODIAG_PWD", raising=False)
    assert tb.sqlnet is not None
    assert tb.sqlnet.password() is None
    monkeypatch.setenv("TESTBED_AUTODIAG_PWD", "s3cret")
    assert tb.sqlnet.password() == "s3cret"
    assert "s3cret" not in repr(tb)


def test_target_model_rejects_duplicate_names(tmp_path: Path) -> None:
    f = tmp_path / "t.yaml"
    f.write_text(
        "targets:\n  - name: a\n    nodes: [{host: h}]\n  - name: a\n    nodes: [{host: h}]\n"
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_targets(f)


def test_target_is_pydantic_model() -> None:
    t = Target(name="x", nodes=[{"host": "h"}])
    assert t.redact is True
    assert t.platform.value == "generic"

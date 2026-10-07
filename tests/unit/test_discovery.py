import json
import os
import subprocess
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from autodiag.cli import common
from autodiag.cli.main import app
from autodiag.core.discovery import discover
from autodiag.core.discovery_probe import _process_link, _utility_owner, probe
from autodiag.core.models import Node, Target
from autodiag.core.settings import Settings
from autodiag.core.targets import add_targets, load_targets


def test_discovery_saves_owner_and_crs_home(monkeypatch):
    def run(argv, **kw):
        assert argv[-1] == "sudo -n -- python3 -"
        assert "StrictHostKeyChecking=yes" in argv
        assert "capture_output" in kw
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "hostname": "node1",
                    "instances": [
                        {
                            "component": "crs",
                            "instance": None,
                            "owner": "grid",
                            "oracle_home": "/u01/grid",
                            "adr_base": "/u01/app/grid",
                            "adr_homes": ["diag/crs/node1/crs"],
                            "version": "19.0.0.0.0",
                        }
                    ],
                }
            )
        )

    monkeypatch.setattr(subprocess, "run", run)
    targets, warnings = discover("admin@node1")
    target = targets[0]
    assert target.component == "crs" and not target.diagnostics_pack
    assert target.nodes[0].sudo_user == "grid"
    assert target.nodes[0].ssh_target == "admin@node1"
    assert target.adr_homes == ["diag/crs/node1/crs"]
    assert not warnings


@pytest.mark.parametrize("host", ["-oProxyCommand=id", "node;id", "node\nother", "a b"])
def test_reject_host_injection(host):
    with pytest.raises(ValueError):
        discover(host)


@pytest.mark.parametrize("process_uid,oracle_uid", [(1000, 0), (1000, 1001), (0, 0)])
def test_spoofed_crs_cannot_select_privileged_owner(process_uid, oracle_uid):
    with pytest.raises(ValueError, match="unsafe discovered utility owner"):
        _utility_owner(process_uid, oracle_uid)


def test_root_crs_may_drop_to_grid_owner(monkeypatch):
    import pwd

    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name="grid"))
    assert _utility_owner(0, 1001) == "grid"
    assert _utility_owner(1001, 1001) == "grid"


@pytest.mark.parametrize("output", ["Welcome!\n{}", "broken", "[]", "null"])
def test_invalid_probe_output_fails_cleanly(monkeypatch, output):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=output))
    with pytest.raises(ValueError, match="invalid JSON"):
        discover("node")


def test_probe_ignores_unidentified_process_exit(tmp_path):
    (tmp_path / "self/ns").mkdir(parents=True)
    (tmp_path / "self/ns/mnt").symlink_to("mnt:[1]")
    (tmp_path / "123").mkdir()  # disappeared before cmdline could be read
    result = probe(tmp_path)
    assert result["instances"] == [] and result["warnings"] == []


def test_restricted_process_reports_required_access(monkeypatch):
    def deny_link(path):
        raise PermissionError("denied")

    def deny_owner(argv, **kwargs):
        raise subprocess.CalledProcessError(1, argv)

    monkeypatch.setattr(os, "readlink", deny_link)
    monkeypatch.setattr(subprocess, "run", deny_owner)
    with pytest.raises(PermissionError, match="CAP_SYS_PTRACE"):
        _process_link("/proc/123/exe", "oracle")


def test_add_is_idempotent_and_preserves_configuration(tmp_path):
    path = tmp_path / "targets.yaml"
    original = Target(name="db", nodes=[Node(host="db")], diagnostics_pack=True)
    add_targets(path, [original])
    content = path.read_text()
    assert add_targets(path, [original.model_copy(update={"diagnostics_pack": False})]) == (
        [],
        ["db"],
    )
    assert path.read_text() == content
    assert load_targets(path).get("db").diagnostics_pack
    add_targets(path, [Target(name="crs", component="crs", nodes=[Node(host="db")])])
    assert next(tmp_path.glob("targets.yaml.bak-*")).read_text() == content


@pytest.mark.parametrize("version_failure", [False, True])
@pytest.mark.parametrize("restricted_proc", [False, True])
@pytest.mark.parametrize("sql_failure", [False, True])
def test_probe_running_instances_and_namespace_filter(
    tmp_path, monkeypatch, version_failure, restricted_proc, sql_failure
):
    proc = tmp_path / "proc"
    (proc / "self/ns").mkdir(parents=True)
    (proc / "self/ns/mnt").symlink_to("mnt:[1]")
    home = tmp_path / "home"
    (home / "bin").mkdir(parents=True)
    for binary in ("oracle", "sqlplus", "ohasd.bin"):
        (home / "bin" / binary).touch()
    hostname = os.uname().nodename.split(".")[0]
    for pid, cmd, exe, ns in [
        ("1", "ora_pmon_LONG_INSTANCE_NAME", "oracle", "mnt:[1]"),
        ("2", str(home / "bin/ohasd.bin"), "ohasd.bin", "mnt:[1]"),
        ("3", "ora_pmon_CONTAINER", "oracle", "mnt:[2]"),
        ("4", "asm_pmon_+ASM1", "oracle", "mnt:[1]"),
    ]:
        p = proc / pid
        (p / "ns").mkdir(parents=True)
        (p / "ns/mnt").symlink_to(ns)
        (p / "exe").symlink_to(home / "bin" / exe)
        (p / "cmdline").write_bytes(cmd.encode() + b"\0")

    readlink = os.readlink

    def restricted_readlink(path, **kw):
        if restricted_proc and (str(path).endswith("/exe") or "/ns/" in str(path)):
            if str(path) != str(proc / "self/ns/mnt"):
                raise PermissionError("container root lacks ptrace")
        return readlink(path, **kw)

    monkeypatch.setattr(os, "readlink", restricted_readlink)

    def run(argv, **kw):
        if argv[-2] == "readlink":
            return SimpleNamespace(stdout=readlink(argv[-1]) + "\n")
        if argv[-1].endswith("orabase"):
            output = "/u01/app/oracle"
        elif argv[-1] == "-V":
            if version_failure:
                raise subprocess.CalledProcessError(1, argv)
            output = "Release 19.0.0.0.0\nVersion 19.28.0.0.0"
        elif "-L" in argv:
            if sql_failure:
                raise subprocess.CalledProcessError(1, argv)
            assert "v$diag_info" in kw["input"]
            component = "asm" if argv[-1] == "/ as sysasm" else "rdbms"
            home_path = "asm/+asm/+ASM1" if component == "asm" else "rdbms/db/LONG_INSTANCE_NAME"
            output = f"ADR Base=/custom/diagnostics\nADR Home=/custom/diagnostics/diag/{home_path}"
        else:
            output = (
                f"diag/rdbms/db/LONG_INSTANCE_NAME\ndiag/crs/{hostname}/crs\ndiag/crs/oldnode/crs"
                "\ndiag/asm/+asm/+ASM1\ndiag/asm/+asm/+ASM2"
            )
        return SimpleNamespace(stdout=output)

    monkeypatch.setattr(subprocess, "run", run)
    result = probe(proc)
    assert len(result["warnings"]) == (3 if version_failure else 0) + (2 if sql_failure else 0)
    assert {i["component"] for i in result["instances"]} == {"rdbms", "crs", "asm"}
    assert all(
        i["version"] == (None if version_failure else "19.28.0.0.0") for i in result["instances"]
    )
    assert all("oldnode" not in " ".join(i["adr_homes"]) for i in result["instances"])
    asm = next(i for i in result["instances"] if i["component"] == "asm")
    assert asm["instance"] == "+ASM1" and asm["adr_homes"] == ["diag/asm/+asm/+ASM1"]
    assert asm["adr_base"] == ("/u01/app/oracle" if sql_failure else "/custom/diagnostics")


def test_cli_dry_run_then_add(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "absent"))
    path = tmp_path / "targets.yaml"
    monkeypatch.setattr(common, "settings", lambda: Settings(_env_file=None, targets_file=path))
    from autodiag.core import discovery

    monkeypatch.setattr(
        discovery,
        "discover",
        lambda *a, **kw: ([Target(name="node-db", nodes=[Node(host="node")])], []),
    )
    runner = CliRunner()
    result = runner.invoke(app, ["targets", "discover", "node", "--dry-run", "--json"])
    assert result.exit_code == 0, result.output
    assert not path.exists()
    result = runner.invoke(app, ["targets", "discover", "node", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["added"] == ["node-db"]


@pytest.mark.parametrize("initial", [None, "", "targets:\n# café\n", "targets: []\n"])
def test_add_empty_inventory_and_utf8_backup(tmp_path, initial):
    path = tmp_path / "targets.yaml"
    if initial is not None:
        path.write_text(initial, encoding="utf-8")
    assert load_targets(path).targets == []
    target = Target(name="db", nodes=[Node(host="node")])
    assert add_targets(path, [target]) == (["db"], [])
    assert load_targets(path).names() == ["db"]
    if initial is not None:
        assert next(tmp_path.glob("*.bak-*")).read_text(encoding="utf-8") == initial

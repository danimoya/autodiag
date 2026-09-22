import io
import subprocess
from pathlib import Path

import pytest

from autodiag.core.models import Node
from autodiag.transport.allowlist import AllowlistError
from autodiag.transport.ssh import CommandResult, SshTransport


class FakeRunner:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", rc: int = 0) -> None:
        self.calls: list[dict] = []
        self.stdout, self.stderr, self.rc = stdout, stderr, rc

    def __call__(self, argv, **kw):
        self.calls.append({"argv": argv, **kw})
        return subprocess.CompletedProcess(argv, self.rc, self.stdout, self.stderr)


@pytest.fixture
def node() -> Node:
    return Node(
        host="dbnode01.example.internal",
        instance="PRODDB1",
        oracle_home="/u01/app/oracle/product/19/dbhome_1",
    )


def test_run_builds_ssh_and_login_shell_command(node: Node) -> None:
    runner = FakeRunner(stdout=b"ADR Homes: \ndiag/rdbms/x/X\n")
    t = SshTransport(node, allowed_roots=["/u02/app/oracle/diag"], runner=runner)
    res = t.run("adrci_show_homes", {})
    assert isinstance(res, CommandResult)
    assert res.returncode == 0 and "diag/rdbms/x/X" in res.stdout
    argv = runner.calls[0]["argv"]
    assert argv[0] == "ssh"
    assert "BatchMode=yes" in argv
    assert "oracle@dbnode01.example.internal" in argv
    remote = argv[-1]
    assert remote.startswith("bash -lc ")
    assert "export ORACLE_HOME=/u01/app/oracle/product/19/dbhome_1" in remote
    assert "export ORACLE_SID=PRODDB1" in remote
    assert "adrci" in remote and "exec=show homes" in remote
    assert runner.calls[0]["timeout"] == 60  # spec timeout


def test_alias_and_port_and_config(tmp_path: Path) -> None:
    n = Node(host="127.0.0.1", ssh_alias="autodiag-testbed", ssh_port=2222)
    runner = FakeRunner()
    t = SshTransport(n, allowed_roots=[], ssh_config=tmp_path / "ssh_config", runner=runner)
    t.run("hostname", {})
    argv = runner.calls[0]["argv"]
    assert "-F" in argv and str(tmp_path / "ssh_config") in argv
    assert argv[-2] == "autodiag-testbed"
    assert "-p" not in argv  # alias carries the port


def test_port_used_without_alias() -> None:
    n = Node(host="h.example.internal", ssh_port=2222)
    runner = FakeRunner()
    SshTransport(n, allowed_roots=[], runner=runner).run("uptime", {})
    argv = runner.calls[0]["argv"]
    assert argv[argv.index("-p") + 1] == "2222"


def test_disallowed_command_never_reaches_ssh(node: Node) -> None:
    runner = FakeRunner()
    t = SshTransport(node, allowed_roots=["/u02/app/oracle/diag"], runner=runner)
    with pytest.raises(AllowlistError):
        t.run("read_range", {"path": "/etc/shadow", "offset": 0, "length": 10})
    assert runner.calls == []


def test_output_is_capped_and_marked_truncated(node: Node) -> None:
    runner = FakeRunner(stdout=b"x" * 10_000)
    t = SshTransport(node, allowed_roots=[], runner=runner)
    res = t.run("hostname", {}, max_bytes=100)
    assert res.truncated is True and len(res.stdout) == 100


def test_timeout_is_reported_not_raised(node: Node) -> None:
    def runner(argv, **kw):
        raise subprocess.TimeoutExpired(argv, kw["timeout"])

    t = SshTransport(node, allowed_roots=[], runner=runner)
    res = t.run("hostname", {}, timeout=1)
    assert res.returncode == 124 and res.timed_out is True


def test_fetch_streams_file_to_destination(node: Node, tmp_path: Path) -> None:
    class FakePopen:
        def __init__(self, argv, **kw):
            self.argv = argv
            self.stdout = io.BytesIO(b"line1\nline2\n" * 1000)
            self.stderr = io.BytesIO(b"")
            self.returncode = 0

        def wait(self, timeout=None):
            return 0

        def kill(self):
            pass

    t = SshTransport(node, allowed_roots=["/u02/app/oracle/diag"], popen=FakePopen)
    dest = tmp_path / "alert.log"
    res = t.fetch("/u02/app/oracle/diag/rdbms/x/X/trace/alert_X.log", dest, max_bytes=5000)
    assert dest.exists() and dest.stat().st_size == 5000
    assert res.truncated is True
    with pytest.raises(AllowlistError):
        t.fetch("/etc/passwd", tmp_path / "p")

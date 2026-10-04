import subprocess
from datetime import UTC, datetime

import pytest

from autodiag.adr.source import AdrSource, AdrSourceError
from autodiag.core.models import Node, Target
from autodiag.transport.ssh import CommandResult, SshTransport


def test_large_log_keeps_recent_error_and_reports_omitted_history(tmp_path):
    path = tmp_path / "alert_DB.log"
    with path.open("wb") as fh:
        fh.write(b"2026-01-01T00:00:00.000000+00:00\nold message\n")
        fh.seek(65 * 1024 * 1024)
        fh.write(b"\n2026-10-04T12:00:00.000000+00:00\nORA-00600: [recent_marker]\n")
    node = Node(host="synthetic", instance="DB")

    def runner(argv, **kw):
        # Exercise the real tail executable on a sparse >64 MiB file, without SSH.
        return subprocess.run(["tail", "-c", "4097", "--", str(path)], **kw)

    transport = SshTransport(node, [str(tmp_path)], runner=runner)
    dest = tmp_path / "tail.log"
    result = transport.fetch_tail(str(path), dest, max_bytes=4096)
    assert result.ok and result.truncated
    assert "recent_marker" in dest.read_text() and "old message" not in dest.read_text()
    assert dest.stat().st_size <= 4096


def test_reader_discards_partial_first_record_and_exposes_coverage(tmp_path):
    class Transport:
        def fetch_tail(self, path, dest, **kw):
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(
                "old partial line\n2026-10-04T12:00:00.000000+00:00\nORA-00600: [latest]\n"
            )
            return CommandResult(
                name="tail_file", argv=[], returncode=0, stdout=str(dest), truncated=True
            )

    target = Target(
        name="test",
        nodes=[Node(host="a", instance="DB")],
        adr_base="/diag",
        adr_homes=["diag/rdbms/db/DB"],
    )
    source = AdrSource(target, transport_factory=lambda node: Transport())
    read = source.read_alert(target.nodes[0], target.adr_homes[0], tmp_path)
    assert len(read.records) == 1 and read.records[0].ts == datetime(2026, 10, 4, 12, tzinfo=UTC)
    assert read.coverage["truncated"] and read.coverage["warning"]
    assert read.coverage["line_numbers"] == "tail-relative"


def test_truncated_artifacts_are_rejected(tmp_path):
    class Transport:
        def fetch(self, path, dest, **kw):
            return CommandResult(
                name="cat_file", argv=[], returncode=0, stdout=str(dest), truncated=True
            )

    target = Target(name="test", nodes=[Node(host="a")])
    source = AdrSource(target, transport_factory=lambda node: Transport())
    with pytest.raises(AdrSourceError, match="truncated"):
        source.fetch_file(target.nodes[0], "/diag/trace.trc", tmp_path / "partial")


def test_tail_ssh_failure_does_not_write_a_successful_result(tmp_path):
    def runner(argv, **kw):
        return subprocess.CompletedProcess(argv, 255, b"", b"unreachable")

    transport = SshTransport(Node(host="a"), [str(tmp_path)], runner=runner)
    dest = tmp_path / "tail.log"
    res = transport.fetch_tail(str(tmp_path / "remote.log"), dest, max_bytes=200)
    assert not res.ok and not dest.exists()

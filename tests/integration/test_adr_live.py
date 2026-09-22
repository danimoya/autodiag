import pytest

from autodiag.trace.incident import parse_incident
from autodiag.trace.models import TraceKind
from autodiag.trace.registry import parse_trace, sniff_kind

pytestmark = pytest.mark.integration


def test_homes_and_problems(testbed_source) -> None:
    node = testbed_source.target.nodes[0]
    assert "diag/rdbms/free/FREE" in testbed_source.list_homes(node)
    problems = testbed_source.list_problems(days=30)
    keys = [p.problem_key for p in problems]
    assert any(k.startswith("ORA 7445") for k in keys), keys


def test_incident_detail_and_trace_roundtrip(testbed_source, tmp_path) -> None:
    problems = testbed_source.list_problems(days=30)
    p = next(p for p in problems if p.problem_key.startswith("ORA 7445"))
    incs = testbed_source.list_incidents(problem_key=p.problem_key)
    assert incs and incs[0].problem_key == p.problem_key
    inc = testbed_source.get_incident(incs[0].incident_id)
    assert inc is not None and inc.trace_file and "/incident/incdir_" in inc.trace_file
    dest = testbed_source.fetch_file(
        testbed_source.target.nodes[0], inc.trace_file, tmp_path / "i.trc"
    )
    text = dest.read_text(errors="replace")
    assert sniff_kind(text) is TraceKind.INCIDENT
    doc = parse_incident(text)
    assert doc.incident_id == inc.incident_id and doc.problem_key == p.problem_key
    assert doc.call_stack is not None and len(doc.call_stack.frames) > 10
    assert doc.first_app_frame == p.problem_key.split("[")[1].rstrip("]")


def test_alert_log_grep_and_fetch(testbed_source, tmp_path) -> None:
    node, home = testbed_source.primary_ref()
    path = testbed_source.alert_log_path(node, home)
    out = testbed_source.grep_file(node, path, "ORA-00060", context=1, max_lines=20)
    assert "ORA-00060" in out
    dest = testbed_source.fetch_file(node, path, tmp_path / "alert.log", max_bytes=4 * 1024 * 1024)
    assert dest.stat().st_size > 1000
    doc = parse_trace(dest.read_text(errors="replace"))
    assert doc.kind is TraceKind.GENERIC  # alert log is not a trace, but must not crash


def test_allowlist_blocks_paths_outside_adr(testbed_source) -> None:
    from autodiag.transport.allowlist import AllowlistError

    node = testbed_source.target.nodes[0]
    with pytest.raises(AllowlistError):
        testbed_source.grep_file(node, "/etc/passwd", "root")

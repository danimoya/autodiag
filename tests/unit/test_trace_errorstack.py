from pathlib import Path

from autodiag.trace.errorstack import parse_errorstack
from autodiag.trace.models import TraceKind


def test_parse_errorstack(fixtures_dir: Path) -> None:
    es = parse_errorstack((fixtures_dir / "23ai/traces/errorstack_level3.trc").read_text())
    assert es.kind is TraceKind.ERRORSTACK
    assert es.sql_id == "cs3hxfwqjkhnh"
    assert es.current_sql and "errorstack" in es.current_sql.lower()
    assert es.call_stack is not None and es.call_stack.frames[0].func == "ksedst1"
    assert es.header.session_id == 70

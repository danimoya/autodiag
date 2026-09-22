from pathlib import Path

import pytest

from autodiag.trace.models import TraceKind
from autodiag.trace.registry import parse_trace, sniff_kind


@pytest.mark.parametrize(
    "name,kind",
    [
        ("incident_ora7445.trc", TraceKind.INCIDENT),
        ("deadlock_ora60.trc", TraceKind.DEADLOCK),
        ("hanganalyze_systemstate.trc", TraceKind.HANG),
        ("errorstack_level3.trc", TraceKind.ERRORSTACK),
        ("AUTODIAG_NORMAL.trc", TraceKind.SQLTRACE),
        ("AUTODIAG_10053.trc", TraceKind.OPTIMIZER),
    ],
)
def test_sniff_and_parse(fixtures_dir: Path, name: str, kind: TraceKind) -> None:
    text = (fixtures_dir / "23ai/traces" / name).read_text()
    assert sniff_kind(text) is kind
    doc = parse_trace(text)
    assert doc.kind is kind
    assert doc.header.oracle_version == "23.26.3.0.0"
    assert doc.line_count > 0


def test_generic_fallback() -> None:
    doc = parse_trace(
        "Trace file /x/y.trc\nVersion 19.0.0.0.0\n*** 2026-01-01T00:00:00.000000+00:00\nORA-01555: snapshot too old\n"
    )
    assert doc.kind is TraceKind.GENERIC
    assert doc.ora_lines == ["ORA-01555: snapshot too old"]
    assert doc.header.oracle_version == "19.0.0.0.0"

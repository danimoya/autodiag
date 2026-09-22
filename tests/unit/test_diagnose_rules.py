from datetime import UTC, datetime, timedelta
from pathlib import Path

from autodiag.alertlog.models import AlertRecord
from autodiag.alertlog.text import parse_alert_text
from autodiag.diagnose.models import Severity
from autodiag.diagnose.rules import classify, sweep

FX = Path("tests/fixtures/23ai/alertlog/alert_excerpt.log")


def _rec(line: str, ts: datetime, n: int = 1, ora: list[int] | None = None) -> AlertRecord:
    from autodiag.alertlog.signatures import signature_key

    return AlertRecord(
        ts=ts, lines=[line], source_line=n, ora_codes=ora or [], signature=signature_key(line)
    )


def test_classify_rules_and_defaults() -> None:
    t = datetime(2026, 9, 22, tzinfo=UTC)
    assert (
        classify(_rec("ORA-00600: internal error code, arguments: [x]", t, ora=[600])).severity
        is Severity.CRITICAL
    )
    assert (
        classify(_rec("Thread 1 advanced to log sequence 42 (LGWR switch)", t)).severity
        is Severity.NOISE
    )
    assert classify(_rec("ORA-00060: Deadlock detected.", t, ora=[60])).category == "locking"
    unknown = classify(_rec("Something nobody has a rule for", t))
    assert unknown.severity is Severity.INFO and unknown.rule == "default"
    # an unknown message that carries an ORA code is at least a warning
    assert classify(_rec("Weird: ORA-99999 happened", t, ora=[99999])).severity is Severity.WARNING


def test_sweep_keeps_errors_and_suppresses_noise() -> None:
    recs = parse_alert_text(FX.read_text())
    res = sweep(recs)
    kept_first_lines = [k.record.lines[0] for k in res.kept]
    assert any("ORA-00600" in k.record.text for k in res.kept)
    assert any("SIGSEGV" in ln for ln in kept_first_lines)
    assert any("Corrupt block" in k.record.text for k in res.kept)
    assert all("advanced to log sequence" not in ln for ln in kept_first_lines)
    assert any("advanced to log sequence" in g.signature for g in res.noise)
    assert res.suppressed >= 1 and res.records_seen == len(recs)


def test_sweep_folds_duplicates_and_detects_bursts() -> None:
    t0 = datetime(2026, 9, 22, 10, 0, tzinfo=UTC)
    cur = [
        _rec("ORA-03136: inbound connection timed out", t0 + timedelta(seconds=i), i, [3136])
        for i in range(60)
    ]
    prev = [_rec("ORA-03136: inbound connection timed out", t0 - timedelta(hours=1), 1, [3136])]
    res = sweep(cur, previous=prev)
    assert res.records_kept == 1  # info entries fold to one per signature
    assert res.kept[0].duplicates == 59
    assert len(res.bursts) == 1
    b = res.bursts[0]
    assert b.count == 60 and b.previous_count == 1 and b.severity is Severity.WARNING
    # critical entries keep up to three per signature
    crit = [
        _rec("ORA-00600: internal error code, arguments: [kk]", t0 + timedelta(seconds=i), i, [600])
        for i in range(5)
    ]
    res2 = sweep(crit)
    assert res2.records_kept == 3 and res2.kept[0].duplicates == 2

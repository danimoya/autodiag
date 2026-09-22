from datetime import UTC, datetime
from pathlib import Path

from autodiag.alertlog.text import parse_alert_text
from autodiag.alertlog.window import window
from autodiag.diff.alertrate import compare_alert_rates


def test_alert_rate_compare(fixtures_dir: Path) -> None:
    recs = parse_alert_text((fixtures_dir / "23ai/alertlog/alert_excerpt.log").read_text())
    utc = UTC
    a = window(recs, datetime(2026, 9, 22, 11, tzinfo=utc), datetime(2026, 9, 22, 12, tzinfo=utc))
    b = window(recs, datetime(2026, 9, 22, 12, tzinfo=utc), datetime(2026, 9, 22, 13, tzinfo=utc))
    d = compare_alert_rates(a, b, hours_a=1.0, hours_b=1.0)
    assert d.records_a == 2 and d.records_b == 8
    assert d.ora_counts_a == {} and d.ora_counts_b[60] == 2 and d.ora_counts_b[600] == 1
    new = [i for i in d.items if i.new_in_b]
    assert any("ORA-00060" in i.signature for i in new)
    top = d.items[0]
    assert top.count_b >= 1 and top.score > 0
    assert all(d.items[i].score >= d.items[i + 1].score for i in range(len(d.items) - 1))
    assert d.incidents_a == 0 and d.incidents_b == 2
    assert any("ORA-00060" in s for s in d.summary_lines())


def test_gone_and_ratio() -> None:
    from autodiag.alertlog.models import AlertRecord

    utc = UTC

    def mk(ts, text):
        return AlertRecord(
            ts=datetime(2026, 1, 1, ts, tzinfo=utc), lines=[text], source_line=1, signature=text
        )

    a = [mk(1, "checkpoint not complete")] * 10
    b = [mk(2, "checkpoint not complete")]
    d = compare_alert_rates(a, b, hours_a=1.0, hours_b=1.0)
    item = d.items[0]
    assert item.count_a == 10 and item.count_b == 1 and item.ratio < 1 and not item.gone_in_b
    d2 = compare_alert_rates(a, [], hours_a=1.0, hours_b=1.0)
    assert d2.items[0].gone_in_b is True

from datetime import UTC, datetime
from pathlib import Path

import pytest

from autodiag.alertlog.models import AlertRecord
from autodiag.alertlog.signatures import (
    extract_incident_id,
    extract_ora_codes,
    extract_trace_file,
    signature_key,
)
from autodiag.alertlog.stats import alert_stats
from autodiag.alertlog.text import parse_alert_text
from autodiag.alertlog.window import grep_records, window
from autodiag.alertlog.xml import parse_alert_xml


@pytest.fixture
def text_records(fixtures_dir: Path) -> list[AlertRecord]:
    return parse_alert_text((fixtures_dir / "23ai/alertlog/alert_excerpt.log").read_text())


@pytest.fixture
def xml_records(fixtures_dir: Path) -> list[AlertRecord]:
    return parse_alert_xml((fixtures_dir / "23ai/alertlog/log_excerpt.xml").read_text())


def test_text_records_are_split_on_timestamps(text_records: list[AlertRecord]) -> None:
    assert len(text_records) == 10
    first = text_records[0]
    assert first.ts == datetime(2026, 9, 22, 11, 44, 57, 708298, tzinfo=UTC)
    assert first.lines[0].startswith("FREEPDB1(3):Opening pdb")
    assert first.con_name == "FREEPDB1"
    assert first.source_line == 2  # line 1 is the timestamp
    assert "Completed: ALTER DATABASE OPEN" in first.text


def test_text_ora600_record(text_records: list[AlertRecord]) -> None:
    rec = next(r for r in text_records if 600 in r.ora_codes)
    assert rec.incident_id == 8873
    assert rec.trace_file == "/opt/oracle/diag/rdbms/free/FREE/trace/FREE_ora_4021.trc"
    assert rec.incident_file == (
        "/opt/oracle/diag/rdbms/free/FREE/incident/incdir_8873/FREE_ora_4021_i8873.trc"
    )
    assert rec.con_name == "CDB$ROOT"
    assert rec.error_args == ["autodiag_test", "0", "0"]


def test_text_ora7445_and_pdb_prefix(text_records: list[AlertRecord]) -> None:
    rec = next(r for r in text_records if 7445 in r.ora_codes)
    assert rec.incident_id == 9041
    assert rec.con_name == "FREEPDB1"
    assert rec.error_args[:2] == ["kglic0()+1223", "SIGSEGV"]


def test_text_deadlock_trace_file(text_records: list[AlertRecord]) -> None:
    dl = [r for r in text_records if 60 in r.ora_codes]
    assert len(dl) == 2
    assert dl[0].trace_file == "/opt/oracle/diag/rdbms/free/FREE/trace/FREE_ora_5301.trc"


def test_xml_records(xml_records: list[AlertRecord]) -> None:
    assert len(xml_records) == 4
    inc = xml_records[1]
    assert inc.ora_codes == [600]
    assert inc.incident_id == 8873
    assert inc.problem_key == "ORA 600 [autodiag_test]"
    assert inc.msg_type == "INCIDENT_ERROR"
    assert inc.con_name == "CDB$ROOT"
    assert inc.pid == 4021
    assert inc.args == {"PDBNAME": "CDB$ROOT"}
    assert xml_records[2].group == "deadlock"
    assert xml_records[0].text.startswith("Opening pdb")


def test_signature_key_normalises_variable_parts() -> None:
    a = "ORA-00060: Deadlock detected. More info in file /x/FREE_ora_5301.trc."
    b = "ORA-00060: Deadlock detected. More info in file /x/FREE_ora_9999.trc."
    assert signature_key(a) == signature_key(b)
    assert signature_key("Thread 1 advanced to log sequence 42 (LGWR switch),  current SCN: 3") == (
        signature_key("Thread 1 advanced to log sequence 43 (LGWR switch),  current SCN: 99")
    )
    corrupt_a = "FREEPDB1(3):Corrupt block relative dba: 0x04400083 (file 17, block 131)"
    corrupt_b = "Corrupt block relative dba: 0x0aa00001 (file 3, block 9)"
    assert signature_key(corrupt_a) == signature_key(corrupt_b)
    assert signature_key("ORA-00600: internal error code, arguments: [a], [1]") != signature_key(
        "ORA-07445: exception encountered: core dump [b]"
    )


def test_extractors() -> None:
    assert extract_ora_codes("ORA-00600: x\nORA-07445: y ORA-27300") == [600, 7445, 27300]
    assert extract_incident_id("Errors in file /a.trc  (incident=41) (PDBNAME=X):") == 41
    assert extract_trace_file("More info in file /opt/x/FREE_ora_1.trc.") == "/opt/x/FREE_ora_1.trc"
    assert extract_trace_file("nothing here") is None


def test_window_and_grep(text_records: list[AlertRecord]) -> None:
    sel = window(
        text_records,
        datetime(2026, 9, 22, 12, 0, tzinfo=UTC),
        datetime(2026, 9, 22, 12, 11, tzinfo=UTC),
    )
    assert [r.incident_id for r in sel if r.incident_id] == [8873, 9041]
    assert len(sel) == 5
    hits = grep_records(text_records, "ORA-00060", context=1)
    assert len(hits) == 2
    assert hits[0].line_no > 0 and "ORA-00060" in hits[0].line
    assert len(hits[0].before) == 1 and len(hits[0].after) <= 1


def test_stats(text_records: list[AlertRecord]) -> None:
    s = alert_stats(text_records)
    assert s.record_count == 10
    assert s.ora_counts[60] == 2 and s.ora_counts[600] == 1 and s.ora_counts[7445] == 1
    assert s.incident_count == 2
    top_keys = [sig for sig, _ in s.top_signatures]
    assert any("ORA-00060" in k for k in top_keys)
    assert s.first_ts is not None and s.last_ts is not None and s.first_ts < s.last_ts
    assert s.per_hour[datetime(2026, 9, 22, 12, tzinfo=UTC)]["ora"] == 5
    assert any("Completed: ALTER DATABASE OPEN" in e.text for e in s.lifecycle_events)

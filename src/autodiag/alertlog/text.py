"""Parser for the text alert log (``alert_<SID>.log``)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime

from autodiag.alertlog.models import AlertRecord
from autodiag.alertlog.signatures import (
    extract_con_name,
    extract_error_args,
    extract_incident_file,
    extract_incident_id,
    extract_ora_codes,
    extract_trace_file,
    signature_key,
)

_ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})\s*$")
_OLD_TS = re.compile(
    r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"(\d{2}) (\d{2}:\d{2}:\d{2}) (\d{4})\s*$"
)


def _parse_ts(line: str) -> datetime | None:
    m = _ISO_TS.match(line)
    if m:
        return datetime.fromisoformat(m.group(1))
    m = _OLD_TS.match(line)
    if m:
        return datetime.strptime(line.strip(), "%a %b %d %H:%M:%S %Y")
    return None


def iter_alert_text(lines: Iterable[str]) -> Iterable[AlertRecord]:
    """Yield one record per timestamp block. Lines before the first timestamp form a record
    with ``ts=None``."""
    ts: datetime | None = None
    buf: list[str] = []
    start = 1
    for no, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        new_ts = _parse_ts(line)
        if new_ts is not None:
            if buf:
                yield _record(ts, buf, start)
            ts, buf, start = new_ts, [], no + 1
            continue
        buf.append(line)
    if buf:
        yield _record(ts, buf, start)


def parse_alert_text(text: str) -> list[AlertRecord]:
    return list(iter_alert_text(text.splitlines()))


def _record(ts: datetime | None, lines: list[str], start: int) -> AlertRecord:
    text = "\n".join(lines)
    con = next((c for c in (extract_con_name(ln) for ln in lines) if c), None)
    pdb_tag = re.search(r"\(PDBNAME=([^)]+)\)", text)
    if pdb_tag:
        con = pdb_tag.group(1)
    return AlertRecord(
        ts=ts,
        lines=lines,
        source_line=start,
        con_name=con,
        ora_codes=extract_ora_codes(text),
        error_args=extract_error_args(text),
        incident_id=extract_incident_id(text),
        trace_file=extract_trace_file(text),
        incident_file=extract_incident_file(text),
        signature=signature_key(text),
    )

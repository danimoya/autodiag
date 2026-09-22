"""Parser for the XML alert log (``alert/log.xml``): a stream of ``<msg>`` fragments
without a document root, so it is parsed per fragment."""

from __future__ import annotations

import html
import re
from datetime import datetime

from autodiag.alertlog.models import AlertRecord
from autodiag.alertlog.signatures import (
    extract_error_args,
    extract_incident_file,
    extract_incident_id,
    extract_ora_codes,
    extract_trace_file,
    signature_key,
)

_MSG = re.compile(r"<msg\b(.*?)>(.*?)</msg>", re.DOTALL)
_ATTR = re.compile(r"([A-Za-z_][\w]*)='([^']*)'")
_TXT = re.compile(r"<txt>(.*?)</txt>", re.DOTALL)
_ARG = re.compile(r"<arg name='([^']*)' value='([^']*)'\s*/>")


def parse_alert_xml(text: str) -> list[AlertRecord]:
    records: list[AlertRecord] = []
    for m in _MSG.finditer(text):
        attrs = dict(_ATTR.findall(m.group(1)))
        body = m.group(2)
        txt_m = _TXT.search(body)
        txt = html.unescape(txt_m.group(1)) if txt_m else ""
        lines = [ln.rstrip() for ln in txt.strip("\n").splitlines()]
        lines = [ln[1:] if ln.startswith(" ") else ln for ln in lines]  # leading pad in <txt>
        joined = "\n".join(lines)
        ts = _ts(attrs.get("time"))
        line_no = text.count("\n", 0, m.start()) + 1
        records.append(
            AlertRecord(
                ts=ts,
                lines=lines,
                source_line=line_no,
                con_name=attrs.get("con_name"),
                ora_codes=extract_ora_codes(joined),
                error_args=extract_error_args(joined),
                incident_id=_int(attrs.get("errid")) or extract_incident_id(joined),
                problem_key=attrs.get("prob_key"),
                trace_file=attrs.get("detail_path") or extract_trace_file(joined),
                incident_file=extract_incident_file(joined),
                msg_type=attrs.get("type"),
                group=attrs.get("group"),
                level=_int(attrs.get("level")),
                pid=_int(attrs.get("pid")),
                args=dict(_ARG.findall(body)),
                signature=signature_key(joined),
            )
        )
    return records


def _ts(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None


def _int(v: str | None) -> int | None:
    try:
        return int(v) if v else None
    except ValueError:
        return None

"""Common trace-file header (first ~40 lines) and ``***`` session markers."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime

from autodiag.trace.models import TraceHeader

_TS = re.compile(r"^\*\*\* .*?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})")
_MARK = re.compile(r"^\*\*\* ([A-Z ]+?):\((.*?)\)")
_VERSION = re.compile(r"^Version (\d+(?:\.\d+)+)")
_KV = {
    "Build label:": "build_label",
    "ORACLE_HOME:": "oracle_home",
    "Node name:": "node_name",
    "Release:": "os_release",
    "Instance name:": "instance_name",
    "Database name:": "db_name",
    "Database unique name:": "db_unique_name",
    "Oracle process number:": "oracle_pid",
    "Unix process pid:": "ospid",
    "image:": "image",
}
_INTS = {"oracle_pid", "ospid"}


def parse_timestamp_marker(line: str) -> datetime | None:
    """Timestamp of a ``*** ...`` marker line (bare, or trailing a SESSION ID/MODULE marker)."""
    m = _TS.match(line)
    if not m:
        return None
    try:
        return datetime.fromisoformat(m.group(1))
    except ValueError:
        return None


def parse_header(lines: Sequence[str], *, limit: int = 120) -> TraceHeader:
    h = TraceHeader()
    for idx, raw in enumerate(lines[:limit]):
        line = raw.strip()
        if idx == 0 and (line.startswith("Trace file ") or line.startswith("Dump file ")):
            h.trace_file = line.split(" ", 2)[2].strip()
            continue
        m = _VERSION.match(line)
        if m and h.oracle_version is None:
            h.oracle_version = m.group(1)
            continue
        for key, attr in _KV.items():
            if line.startswith(key):
                value = line[len(key) :].strip()
                if attr in _INTS:
                    try:
                        setattr(h, attr, int(value.split()[0]))
                    except (ValueError, IndexError):
                        pass
                elif getattr(h, attr) is None:
                    setattr(h, attr, value)
                break
        ts = parse_timestamp_marker(line)
        if ts is not None:
            if h.first_ts is None:
                h.first_ts = ts
            cm = re.search(r"\(([A-Za-z0-9_$#]+)\((\d+)\)\)\s*$", line)
            if cm and h.container_name is None:
                h.container_name = cm.group(1)
            mm = _MARK.match(line)
            if mm:
                _apply_marker(h, mm.group(1), mm.group(2))
            h.header_lines = idx + 1
    return h


def _apply_marker(h: TraceHeader, name: str, value: str) -> None:
    if name == "SESSION ID":
        m = re.match(r"(\d+)\.(\d+)", value)
        if m:
            h.session_id, h.session_serial = int(m.group(1)), int(m.group(2))
    elif name == "CLIENT ID":
        h.client_id = value or None
    elif name == "SERVICE NAME":
        h.service_name = value or None
    elif name == "MODULE NAME":
        h.module = value or None
    elif name == "ACTION NAME":
        h.action = value or None
    elif name == "CLIENT DRIVER":
        h.client_driver = value or None
    elif name == "CONTAINER ID":
        h.container_id = int(value) if value.isdigit() else None
    elif name == "CLIENT IP":
        h.client_ip = value if value and value != "N/A" else None

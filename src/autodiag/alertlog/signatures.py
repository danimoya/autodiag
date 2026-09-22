"""Extractors and the signature normaliser shared by both alert-log parsers."""

from __future__ import annotations

import re

_ORA = re.compile(r"\bORA-(\d{1,5})\b")
_INCIDENT = re.compile(r"\(incident=(\d+)\)")
_TRACE = re.compile(r"(/\S+?\.trc)\b")
_INCIDENT_FILE = re.compile(r"Incident details in: (/\S+\.trc)")
_PDB_PREFIX = re.compile(r"^([A-Za-z0-9_$#]+)\(\d+\):")
_ORA600_ARGS = re.compile(r"ORA-00600: internal error code, arguments: (.*)$")
_ORA7445_ARGS = re.compile(r"ORA-07445: exception encountered: core dump (.*)$")
_BRACKET = re.compile(r"\[([^\]]*)\]")

_NORM_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^[A-Za-z0-9_$#]+\(\d+\):"), ""),  # PDB prefix
    (re.compile(r"/\S+"), "<path>"),
    (re.compile(r"0x[0-9A-Fa-f]+"), "<hex>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*"), "<ts>"),
    (re.compile(r"\b\d+\b"), "<n>"),
    (re.compile(r"\s+"), " "),
]


def extract_ora_codes(text: str) -> list[int]:
    """Distinct ORA codes in order of first appearance (ORA-00060 and ORA-60 are one code)."""
    seen: list[int] = []
    for m in _ORA.findall(text):
        code = int(m)
        if code not in seen:
            seen.append(code)
    return seen


def extract_incident_id(text: str) -> int | None:
    m = _INCIDENT.search(text)
    return int(m.group(1)) if m else None


def extract_trace_file(text: str) -> str | None:
    m = _TRACE.search(text)
    return m.group(1) if m else None


def extract_incident_file(text: str) -> str | None:
    m = _INCIDENT_FILE.search(text)
    return m.group(1) if m else None


def extract_con_name(line: str) -> str | None:
    m = _PDB_PREFIX.match(line)
    return m.group(1) if m else None


def extract_error_args(text: str) -> list[str]:
    """Bracketed arguments of an ORA-600 / ORA-7445 line, empty ones dropped."""
    for rx in (_ORA600_ARGS, _ORA7445_ARGS):
        for line in text.splitlines():
            m = rx.search(line)
            if m:
                return [a for a in _BRACKET.findall(m.group(1)) if a.strip()]
    return []


def strip_pdb_prefix(line: str) -> str:
    return _PDB_PREFIX.sub("", line, count=1)


_ERR_CODE = re.compile(r"\b([A-Z]{2,5})-(\d{1,5})\b")


def signature_key(text: str) -> str:
    """Collapse variable parts (numbers, paths, hex, timestamps) of the first line while
    keeping error codes such as ORA-00600 or TNS-12541 intact."""
    first = text.strip().splitlines()[0] if text.strip() else ""
    first = _ERR_CODE.sub(lambda m: f"{m.group(1)}_{m.group(2)}", first)
    for rx, repl in _NORM_RULES:
        first = rx.sub(repl, first)
    first = re.sub(r"\b([A-Z]{2,5})_(\d{1,5})\b", r"\1-\2", first)
    return first.strip()[:200]

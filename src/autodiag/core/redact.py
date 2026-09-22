"""Redaction applied at the model boundary (never to stored artifacts).

Masks bind values, string literals, IP addresses, e-mail addresses and host names so
that trace/alert excerpts can be shown to a language model without leaking data.
File paths and ORA-xxxxx lines are kept because they carry diagnostic meaning.
"""

from __future__ import annotations

import re

_BIND_VALUE = re.compile(r"(^|[\s:])(value=)\S*", re.MULTILINE)
_STR_LITERAL = re.compile(r"'(?:[^'\\]|\\.|'')*'")
# four dotted octets not embedded in a longer dotted number (23.26.3.0.0 is a version)
_IPV4 = re.compile(r"(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_HOST = re.compile(r"\b(?<![/\w.-])([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b(?![/\w])")
_KEEP_SUFFIXES = (".trc", ".trm", ".log", ".xml", ".sql", ".ora", ".dbf")
_LINE_KEEP = re.compile(r"^(ORA|TNS|PLS|DBT|RMAN)-\d{1,5}:")


def redact_for_llm(text: str, *, enabled: bool = True) -> str:
    if not enabled:
        return text
    out_lines: list[str] = []
    for line in text.splitlines(keepends=True):
        if _LINE_KEEP.match(line):
            out_lines.append(line)
            continue
        line = _BIND_VALUE.sub(r"\1\2<redacted>", line)
        line = _STR_LITERAL.sub("'<str>'", line)
        line = _EMAIL.sub("<email>", line)
        line = _IPV4.sub("<ip>", line)
        line = _HOST.sub(_host_repl, line)
        out_lines.append(line)
    return "".join(out_lines)


def _host_repl(m: re.Match[str]) -> str:
    token = m.group(1)
    if token.lower().endswith(_KEEP_SUFFIXES):
        return token
    if re.fullmatch(r"[\d.]+", token):  # version numbers like 23.26.3.0.0
        return token
    return "<host>"

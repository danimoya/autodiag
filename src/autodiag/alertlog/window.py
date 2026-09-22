"""Time-window selection and grep-with-context over alert records."""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel

from autodiag.alertlog.models import AlertRecord


class GrepHit(BaseModel):
    line_no: int
    line: str
    ts: datetime | None
    before: list[str]
    after: list[str]


def window(
    records: list[AlertRecord], from_ts: datetime | None, to_ts: datetime | None
) -> list[AlertRecord]:
    out = []
    for r in records:
        if r.ts is None:
            continue
        if from_ts is not None and r.ts < from_ts:
            continue
        if to_ts is not None and r.ts > to_ts:
            continue
        out.append(r)
    return out


def grep_records(
    records: list[AlertRecord],
    pattern: str,
    *,
    context: int = 3,
    regex: bool = False,
    max_hits: int = 200,
) -> list[GrepHit]:
    rx = re.compile(pattern if regex else re.escape(pattern), re.IGNORECASE)
    flat: list[tuple[int, str, datetime | None]] = []
    for r in records:
        for i, ln in enumerate(r.lines):
            flat.append((r.source_line + i, ln, r.ts))
    hits: list[GrepHit] = []
    for idx, (no, ln, ts) in enumerate(flat):
        if rx.search(ln):
            hits.append(
                GrepHit(
                    line_no=no,
                    line=ln,
                    ts=ts,
                    before=[x[1] for x in flat[max(0, idx - context) : idx]],
                    after=[x[1] for x in flat[idx + 1 : idx + 1 + context]],
                )
            )
            if len(hits) >= max_hits:
                break
    return hits

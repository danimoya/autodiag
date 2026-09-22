"""Summary statistics over alert records: ORA histogram, signatures, lifecycle events."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime

from pydantic import BaseModel, Field

from autodiag.alertlog.models import AlertRecord

_LIFECYCLE = re.compile(
    r"Starting ORACLE instance|Shutting down instance|Instance terminated|"
    r"Completed: ALTER DATABASE OPEN|ALTER DATABASE CLOSE|Reconfiguration started|"
    r"Reconfiguration complete|PMON .*terminating|opened read write|ALTER SYSTEM SET",
    re.IGNORECASE,
)


class LifecycleEvent(BaseModel):
    ts: datetime | None
    text: str
    source_line: int


class AlertStats(BaseModel):
    record_count: int
    first_ts: datetime | None
    last_ts: datetime | None
    ora_counts: dict[int, int]
    incident_count: int
    top_signatures: list[tuple[str, int]]
    per_hour: dict[datetime, dict[str, int]] = Field(
        description="hour -> {records, ora, incidents}"
    )
    lifecycle_events: list[LifecycleEvent]


def alert_stats(records: list[AlertRecord], *, top: int = 30) -> AlertStats:
    ora: Counter[int] = Counter()
    sigs: Counter[str] = Counter()
    per_hour: dict[datetime, dict[str, int]] = defaultdict(
        lambda: {"records": 0, "ora": 0, "incidents": 0}
    )
    incidents = 0
    events: list[LifecycleEvent] = []
    stamped = [r.ts for r in records if r.ts is not None]
    for r in records:
        ora.update(r.ora_codes)
        if r.is_error and r.signature:
            sigs[r.signature] += 1
        if r.incident_id is not None:
            incidents += 1
        if r.ts is not None:
            h = r.ts.replace(minute=0, second=0, microsecond=0)
            bucket = per_hour[h]
            bucket["records"] += 1
            bucket["ora"] += len(r.ora_codes)
            bucket["incidents"] += 1 if r.incident_id is not None else 0
        for i, ln in enumerate(r.lines):
            if _LIFECYCLE.search(ln):
                events.append(
                    LifecycleEvent(ts=r.ts, text=ln.strip(), source_line=r.source_line + i)
                )
    return AlertStats(
        record_count=len(records),
        first_ts=min(stamped) if stamped else None,
        last_ts=max(stamped) if stamped else None,
        ora_counts=dict(ora),
        incident_count=incidents,
        top_signatures=sigs.most_common(top),
        per_hour=dict(per_hour),
        lifecycle_events=events,
    )

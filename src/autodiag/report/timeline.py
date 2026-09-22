"""Merge alert-log entries, incidents and ASH samples into one ordered timeline."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from autodiag.alertlog.models import AlertRecord


class TimelineEvent(BaseModel):
    ts: datetime
    source: str  # alert | incident | ash | lifecycle | note
    text: str
    ref: str | None = None
    is_error: bool = False


def build_timeline(
    *,
    alert_records: list[AlertRecord] | None = None,
    incidents: list[dict[str, Any]] | None = None,
    ash_rows: list[dict[str, Any]] | None = None,
    notes: list[TimelineEvent] | None = None,
    only_errors: bool = False,
    max_items: int = 200,
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for r in alert_records or []:
        if r.ts is None:
            continue
        if only_errors and not r.is_error:
            continue
        events.append(
            TimelineEvent(
                ts=r.ts,
                source="alert",
                text=r.lines[0][:200] if r.lines else "",
                ref=str(r.source_line),
                is_error=r.is_error,
            )
        )
    for i in incidents or []:
        ts = i.get("create_time")
        if ts:
            events.append(
                TimelineEvent(
                    ts=ts,
                    source="incident",
                    text=f"{i.get('problem_key', '')} incident {i.get('incident_id')}",
                    ref=str(i.get("incident_id")),
                    is_error=True,
                )
            )
    for a in ash_rows or []:
        ts = a.get("sample_time")
        if ts:
            events.append(
                TimelineEvent(
                    ts=ts,
                    source="ash",
                    text=f"ASH: {a.get('event') or 'ON CPU'} x{a.get('samples', '?')}",
                    ref=a.get("sql_id"),
                )
            )
    events += notes or []
    events.sort(key=lambda e: e.ts)
    if len(events) > max_items:
        # keep errors preferentially, then trim from the middle
        errors = [e for e in events if e.is_error]
        others = [e for e in events if not e.is_error]
        keep = errors[:max_items]
        room = max_items - len(keep)
        if room > 0:
            step = max(1, len(others) // room)
            keep += others[::step][:room]
        events = sorted(keep, key=lambda e: e.ts)
    return events

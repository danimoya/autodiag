"""Alert-log message-rate comparison between two windows (baseline vs anomaly)."""

from __future__ import annotations

import math
from collections import Counter

from pydantic import BaseModel, Field

from autodiag.alertlog.models import AlertRecord


class RateItem(BaseModel):
    signature: str
    count_a: int
    count_b: int
    rate_a: float
    rate_b: float
    ratio: float
    new_in_b: bool
    gone_in_b: bool
    score: float
    example: str


class AlertRateDiff(BaseModel):
    hours_a: float
    hours_b: float
    records_a: int
    records_b: int
    incidents_a: int
    incidents_b: int
    ora_counts_a: dict[int, int]
    ora_counts_b: dict[int, int]
    items: list[RateItem] = Field(default_factory=list)

    def summary_lines(self, top: int = 8) -> list[str]:
        out = [
            f"records {self.records_a} -> {self.records_b}, "
            f"incidents {self.incidents_a} -> {self.incidents_b}",
        ]
        for it in self.items[:top]:
            flag = "NEW" if it.new_in_b else ("GONE" if it.gone_in_b else f"x{it.ratio}")
            out.append(f"[{flag}] {it.count_a} -> {it.count_b}  {it.signature[:110]}")
        return out


def compare_alert_rates(
    records_a: list[AlertRecord],
    records_b: list[AlertRecord],
    *,
    hours_a: float,
    hours_b: float,
    top: int = 30,
) -> AlertRateDiff:
    ca: Counter[str] = Counter(r.signature for r in records_a if r.signature)
    cb: Counter[str] = Counter(r.signature for r in records_b if r.signature)
    examples = {r.signature: r.lines[0] for r in [*records_a, *records_b] if r.lines}
    items: list[RateItem] = []
    for sig in dict.fromkeys([*cb, *ca]):
        a, b = ca.get(sig, 0), cb.get(sig, 0)
        ra, rb = a / max(hours_a, 1e-9), b / max(hours_b, 1e-9)
        ratio = round((rb + 0.5) / (ra + 0.5), 3)
        score = abs(math.log2(ratio)) * math.sqrt(a + b)
        items.append(
            RateItem(
                signature=sig,
                count_a=a,
                count_b=b,
                rate_a=round(ra, 3),
                rate_b=round(rb, 3),
                ratio=ratio,
                new_in_b=a == 0 and b > 0,
                gone_in_b=b == 0 and a > 0,
                score=round(score, 3),
                example=examples.get(sig, "")[:200],
            )
        )
    items.sort(key=lambda i: i.score, reverse=True)
    return AlertRateDiff(
        hours_a=hours_a,
        hours_b=hours_b,
        records_a=len(records_a),
        records_b=len(records_b),
        incidents_a=sum(1 for r in records_a if r.incident_id is not None),
        incidents_b=sum(1 for r in records_b if r.incident_id is not None),
        ora_counts_a=dict(Counter(c for r in records_a for c in r.ora_codes)),
        ora_counts_b=dict(Counter(c for r in records_b for c in r.ora_codes)),
        items=items[:top],
    )

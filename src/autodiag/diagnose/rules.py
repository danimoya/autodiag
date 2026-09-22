"""Alert-log classification and sweep: keep what may matter, count the rest."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime
from functools import lru_cache

from pydantic import BaseModel, Field

from autodiag.alertlog.models import AlertRecord
from autodiag.diagnose.models import NoiseGroup, Severity
from autodiag.kb.loader import load_yaml


class Rule(BaseModel):
    pattern: str
    severity: Severity
    category: str

    _rx: re.Pattern[str] | None = None

    def regex(self) -> re.Pattern[str]:
        if self._rx is None:
            self._rx = re.compile(self.pattern, re.IGNORECASE)
        return self._rx


class Classification(BaseModel):
    severity: Severity
    category: str
    rule: str


@lru_cache
def load_rules() -> list[Rule]:
    return [Rule(**r) for r in load_yaml("severity_rules.yaml").get("rules", [])]


def classify(record: AlertRecord) -> Classification:
    """First matching rule wins; unmatched entries stay visible as info, or warning when
    they carry an ORA code or an incident."""
    head = record.lines[0] if record.lines else ""
    body = record.text
    for rule in load_rules():
        if rule.regex().search(head) or (
            rule.severity in (Severity.CRITICAL, Severity.WARNING) and rule.regex().search(body)
        ):
            sev = rule.severity
            if sev is Severity.NOISE and (record.ora_codes or record.incident_id):
                sev = Severity.WARNING
            return Classification(severity=sev, category=rule.category, rule=rule.pattern)
    if record.incident_id is not None or record.ora_codes:
        return Classification(severity=Severity.WARNING, category="error", rule="ora_code")
    return Classification(severity=Severity.INFO, category="other", rule="default")


class KeptRecord(BaseModel):
    record: AlertRecord
    cls: Classification
    duplicates: int = 0  # further records with the same signature folded into this one


class Burst(BaseModel):
    signature: str
    count: int
    previous_count: int
    ratio: float
    severity: Severity
    example: str
    first_ts: datetime | None = None
    last_ts: datetime | None = None


class SweepResult(BaseModel):
    kept: list[KeptRecord] = Field(default_factory=list)
    noise: list[NoiseGroup] = Field(default_factory=list)
    bursts: list[Burst] = Field(default_factory=list)
    records_seen: int = 0
    records_kept: int = 0
    suppressed: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)


def sweep(
    records: list[AlertRecord],
    *,
    previous: list[AlertRecord] | None = None,
    per_signature: int = 3,
    burst_ratio: float = 10.0,
    burst_min: int = 10,
    node: str | None = None,
) -> SweepResult:
    """Classify every record. Critical and warning entries are kept (at most
    ``per_signature`` per signature, the rest folded into a duplicate count); info entries
    are folded to one per signature; noise is counted only. A signature whose count is
    ``burst_ratio`` times the previous window (and at least ``burst_min``) is a burst."""
    res = SweepResult(records_seen=len(records))
    per_sig: dict[str, int] = Counter()
    kept_by_sig: dict[str, KeptRecord] = {}
    noise: dict[str, NoiseGroup] = {}
    sev_counts: Counter[str] = Counter()
    for r in records:
        cls = classify(r)
        sev_counts[cls.severity.value] += 1
        sig = r.signature or (r.lines[0][:120] if r.lines else "")
        if cls.severity is Severity.NOISE:
            g = noise.get(sig)
            if g is None:
                noise[sig] = NoiseGroup(
                    signature=sig,
                    count=1,
                    first_ts=r.ts,
                    last_ts=r.ts,
                    example=(r.lines[0] if r.lines else "")[:160],
                    category=cls.category,
                    node=node,
                )
            else:
                g.count += 1
                g.last_ts = r.ts or g.last_ts
            res.suppressed += 1
            continue
        limit = 1 if cls.severity is Severity.INFO else per_signature
        per_sig[sig] += 1
        if per_sig[sig] <= limit:
            k = KeptRecord(record=r, cls=cls)
            res.kept.append(k)
            kept_by_sig.setdefault(sig, k)
        else:
            kept_by_sig[sig].duplicates += 1
    res.records_kept = len(res.kept)
    res.noise = sorted(noise.values(), key=lambda g: -g.count)
    res.by_severity = dict(sev_counts)
    # bursts: any non-noise signature that exploded compared with the previous window
    prev_counts: Counter[str] = Counter(p.signature for p in (previous or []) if p.signature)
    cur_counts: Counter[str] = Counter(
        r.signature for r in records if r.signature and classify(r).severity is not Severity.NOISE
    )
    first_last: dict[str, list[datetime | None]] = defaultdict(lambda: [None, None])
    for r in records:
        fl = first_last[r.signature]
        if fl[0] is None:
            fl[0] = r.ts
        fl[1] = r.ts or fl[1]
    for sig, n in cur_counts.items():
        prev = prev_counts.get(sig, 0)
        ratio = (n + 0.5) / (prev + 0.5)
        if n >= burst_min and (ratio >= burst_ratio or (prev == 0 and n >= burst_min * 5)):
            k = kept_by_sig.get(sig)
            example = k.record.lines[0][:160] if k and k.record.lines else sig
            sev = k.cls.severity if k else Severity.INFO
            res.bursts.append(
                Burst(
                    signature=sig,
                    count=n,
                    previous_count=prev,
                    ratio=round(ratio, 1),
                    severity=Severity.WARNING if sev is Severity.INFO else sev,
                    example=example,
                    first_ts=first_last[sig][0],
                    last_ts=first_last[sig][1],
                )
            )
    res.bursts.sort(key=lambda b: -b.count)
    return res

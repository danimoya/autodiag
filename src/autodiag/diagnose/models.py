"""Dossier (what the assessor reads) and Assessment (what it returns, after verification)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    NOISE = "noise"


SEVERITY_ORDER: dict[str, int] = {
    Severity.CRITICAL: 0,
    Severity.WARNING: 1,
    Severity.INFO: 2,
    Severity.NOISE: 3,
}


def worst(severities: list[Severity]) -> Severity:
    return min(severities, key=lambda s: SEVERITY_ORDER[s]) if severities else Severity.INFO


class DossierItem(BaseModel):
    """One piece of evidence. ``id`` is the evidence id recorded in the case store, so a
    proof that cites it can be audited later."""

    id: str
    kind: str = Field(
        description="incident | problem | alert | alert_group | alert_burst | alert_rate | "
        "lifecycle | stack_frequency | stack_diff | kb | query | env | correlation"
    )
    severity_hint: Severity = Severity.INFO
    category: str = ""
    ts: datetime | None = None
    node: str | None = None
    title: str
    text: str = Field(description="Bounded text the assessor reads; proofs quote from it")
    refs: dict[str, Any] = Field(default_factory=dict)
    count: int = 1


class NoiseGroup(BaseModel):
    signature: str
    count: int
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    example: str = ""
    category: str = ""
    node: str | None = None


class Dossier(BaseModel):
    mode: str  # problem | alert | instance
    target: str
    target_kind: str = "single"
    platform: str = "generic"
    oracle_version: str | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime
    nodes: list[str] = Field(default_factory=list)
    items: list[DossierItem] = Field(default_factory=list)
    noise: list[NoiseGroup] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    case_id: str | None = None

    def item(self, item_id: str) -> DossierItem | None:
        return next((i for i in self.items if i.id == item_id), None)

    def sorted_items(self) -> list[DossierItem]:
        return sorted(
            self.items,
            key=lambda i: (SEVERITY_ORDER[i.severity_hint], -(i.ts.timestamp() if i.ts else 0)),
        )

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for i in self.items:
            out[i.severity_hint.value] += 1
        out["noise_records"] = sum(n.count for n in self.noise)
        out["noise_signatures"] = len(self.noise)
        return out


class Proof(BaseModel):
    evidence_id: str
    quote: str
    verified: bool = False


class Concern(BaseModel):
    severity: Severity = Severity.WARNING
    kind: str = Field(default="observation", description="root_cause | contributing | observation")
    title: str
    assessment: str = ""
    proofs: list[Proof] = Field(default_factory=list)
    next_checks: list[str] = Field(default_factory=list)
    proven: bool = False


class Dismissed(BaseModel):
    what: str
    reason: str


class Assessment(BaseModel):
    headline: str
    severity: Severity = Severity.INFO
    concerns: list[Concern] = Field(default_factory=list)
    dismissed: list[Dismissed] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    model: str = "rules"
    grounded: bool = True
    proofs_total: int = 0
    proofs_verified: int = 0
    notes: list[str] = Field(default_factory=list)
    elapsed_ms: int = 0


# ---- what the model is asked to return (verified into an Assessment afterwards) ----


class ProofDraft(BaseModel):
    evidence_id: str
    quote: str


class ConcernDraft(BaseModel):
    severity: str
    kind: str
    title: str
    assessment: str
    proofs: list[ProofDraft]
    next_checks: list[str]


class DismissedDraft(BaseModel):
    what: str
    reason: str


class AssessmentDraft(BaseModel):
    headline: str
    severity: str
    concerns: list[ConcernDraft]
    dismissed: list[DismissedDraft]
    actions: list[str]
    open_questions: list[str]
    confidence: float


class Diagnosis(BaseModel):
    dossier: Dossier
    assessment: Assessment
    case_id: str | None = None
    evidence_id: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    prompt_bytes: int = 0

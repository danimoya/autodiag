"""Assessor: turns a dossier into a verified Assessment through the LLM, or through rules
when no model is available. Every concern must be proven by quotes that really occur in
the dossier items the model cites; unproven concerns are demoted to open questions."""

from __future__ import annotations

import re
from importlib import resources
from typing import Any

from autodiag.core.redact import redact_for_llm
from autodiag.diagnose.models import (
    SEVERITY_ORDER,
    Assessment,
    AssessmentDraft,
    Concern,
    Dismissed,
    Dossier,
    DossierItem,
    Proof,
    Severity,
    worst,
)
from autodiag.llm.ollama import OllamaClient, OllamaError

SYSTEM_PROMPT = (
    resources.files("autodiag.llm.prompts").joinpath("assess_system.md").read_text("utf-8")
)
MAX_CONCERNS = 8
MIN_QUOTE = 8


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().strip("\"'“”‘’…").lower()


# --------------------------------------------------------------------------- prompt


def dossier_text(
    dossier: Dossier, *, redact: bool = True, max_bytes: int = 48_000, item_max_chars: int = 1500
) -> tuple[str, dict[str, str]]:
    """Render the dossier for the model (highest severity first, within a byte budget) and
    return the exact per-item text the model saw, which proofs are verified against."""
    head = [
        "AUTODIAG DOSSIER",
        f"target: {dossier.target} ({dossier.target_kind}, {dossier.platform}, "
        f"Oracle {dossier.oracle_version or 'unknown'}) | mode: {dossier.mode} | scope: "
        + ", ".join(f"{k}={v}" for k, v in dossier.scope.items()),
        f"nodes: {', '.join(dossier.nodes) or '-'} | "
        f"generated: {dossier.generated_at:%Y-%m-%d %H:%M:%S %Z}",
    ]
    if dossier.errors:
        head.append("collector errors: " + " | ".join(e[:200] for e in dossier.errors[:10]))
    if redact:
        head = [redact_for_llm(h) for h in head]
    head.append("")
    head.append(
        "ITEMS (id | kind | severity hint | time | node). Quote proofs verbatim from item text."
    )
    parts: list[str] = []
    seen: dict[str, str] = {}
    used = sum(len(h) + 1 for h in head)
    skipped: list[DossierItem] = []
    for it in dossier.sorted_items():
        text = (
            it.text
            if len(it.text) <= item_max_chars
            else it.text[:item_max_chars] + " …[truncated]"
        )
        if redact:
            text = redact_for_llm(text)
        title = redact_for_llm(it.title) if redact else it.title
        ts = it.ts.strftime("%Y-%m-%dT%H:%M:%S") if it.ts else "-"
        block = (
            f"--- [{it.id}] {it.kind} | {it.severity_hint.value} | {ts} | {it.node or '-'}"
            + (f" | x{it.count}" if it.count > 1 else "")
            + f"\ntitle: {title}\n{text}\n"
        )
        if used + len(block) > max_bytes:
            skipped.append(it)
            continue
        parts.append(block)
        seen[it.id] = f"title: {title}\n{text}"
        used += len(block)
    tail: list[str] = []
    if skipped:
        tail.append("")
        tail.append(f"NOT INCLUDED (budget), {len(skipped)} items, titles only:")
        tail += [f"- [{it.id}] {it.severity_hint.value}: {it.title[:120]}" for it in skipped[:40]]
    if dossier.noise:
        tail.append("")
        tail.append("SUPPRESSED NOISE (signature x count, first..last):")
        for g in dossier.noise[:25]:
            f = g.first_ts.strftime("%H:%M") if g.first_ts else "?"
            last = g.last_ts.strftime("%H:%M") if g.last_ts else "?"
            node = f" [{g.node}]" if g.node else ""
            tail.append(f"- {g.signature[:120]} x{g.count} ({f}..{last}){node}")
    return "\n".join(head + parts + tail), seen


def build_messages(prompt_text: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt_text + "\n\nAssess this dossier. JSON only."},
    ]


def draft_schema() -> dict[str, Any]:
    return AssessmentDraft.model_json_schema()


# --------------------------------------------------------------------------- verification


def _severity(value: str) -> Severity:
    v = (value or "").strip().lower()
    return Severity(v) if v in SEVERITY_ORDER and v != "noise" else Severity.WARNING


def verify(
    draft: AssessmentDraft, texts: dict[str, str], *, model: str, elapsed_ms: int = 0
) -> Assessment:
    """Check every proof against the text the model saw. A quote must occur in the cited
    item (or, failing that, in another item, which is then cited instead)."""
    norm_texts = {k: _norm(v) for k, v in texts.items()}
    concerns: list[Concern] = []
    open_questions = [q for q in draft.open_questions if q.strip()][:12]
    notes: list[str] = []
    total = verified = 0
    for c in draft.concerns[:MAX_CONCERNS]:
        proofs: list[Proof] = []
        for p in c.proofs:
            total += 1
            q = _norm(p.quote)
            ev = p.evidence_id.strip()
            ok = len(q) >= MIN_QUOTE and q in norm_texts.get(ev, "")
            if not ok and len(q) >= MIN_QUOTE:
                other = next((k for k, t in norm_texts.items() if q in t), None)
                if other:
                    notes.append(f"proof re-pointed from {ev} to {other}")
                    ev, ok = other, True
            verified += 1 if ok else 0
            proofs.append(Proof(evidence_id=ev, quote=p.quote.strip()[:240], verified=ok))
        proven = any(p.verified for p in proofs)
        concern = Concern(
            severity=_severity(c.severity),
            kind=c.kind
            if c.kind in {"root_cause", "contributing", "observation"}
            else "observation",
            title=c.title.strip()[:200],
            assessment=c.assessment.strip()[:1500],
            proofs=proofs,
            next_checks=[x for x in c.next_checks if x.strip()][:6],
            proven=proven,
        )
        if proven:
            concerns.append(concern)
        else:
            open_questions.append(
                f"Unproven claim (no verifiable quote): {concern.title} - "
                f"{concern.assessment[:200]}"
            )
    concerns.sort(key=lambda c: SEVERITY_ORDER[c.severity])
    severity = worst([c.severity for c in concerns]) if concerns else Severity.INFO
    unproven = len(draft.concerns[:MAX_CONCERNS]) - len(concerns)
    if unproven:
        notes.append(f"{unproven} concern(s) demoted to open questions for lack of proof")
    return Assessment(
        headline=draft.headline.strip()[:600] or "(no headline)",
        severity=severity,
        concerns=concerns,
        dismissed=[
            Dismissed(what=d.what[:200], reason=d.reason[:400]) for d in draft.dismissed[:15]
        ],
        actions=[a for a in draft.actions if a.strip()][:10],
        open_questions=open_questions,
        confidence=max(0.0, min(1.0, float(draft.confidence))),
        model=model,
        grounded=unproven == 0,
        proofs_total=total,
        proofs_verified=verified,
        notes=notes,
        elapsed_ms=elapsed_ms,
    )


# --------------------------------------------------------------------------- fallbacks


def rules_assessment(dossier: Dossier, *, note: str | None = None) -> Assessment:
    """No model: rank the dossier by the rule severities. Every concern is proven by
    construction (its quote is the first line of the item)."""
    items = [
        i
        for i in dossier.sorted_items()
        if i.severity_hint in (Severity.CRITICAL, Severity.WARNING)
    ]
    concerns = [
        Concern(
            severity=i.severity_hint,
            kind="observation",
            title=i.title[:200],
            assessment=f"{i.kind} flagged {i.severity_hint.value} by rule ({i.category or 'n/a'}).",
            proofs=[
                Proof(
                    evidence_id=i.id,
                    quote=i.text.splitlines()[0][:200] if i.text else i.title[:200],
                    verified=True,
                )
            ],
            proven=True,
        )
        for i in items[:MAX_CONCERNS]
    ]
    counts = dossier.counts()
    headline = (
        f"Rules-only ranking for {dossier.target} ({dossier.mode}): {counts['critical']} critical "
        f"and {counts['warning']} warning items; "
        f"{counts['noise_records']} routine entries suppressed."
    )
    if concerns:
        headline += f" Top: {concerns[0].title}."
    return Assessment(
        headline=headline,
        severity=worst([c.severity for c in concerns]) if concerns else Severity.INFO,
        concerns=concerns,
        dismissed=[
            Dismissed(what=f"{g.signature[:100]} x{g.count}", reason=f"routine ({g.category})")
            for g in dossier.noise[:8]
        ],
        actions=[],
        open_questions=["No model assessment: this is the rule ranking only."],
        confidence=0.3,
        model="rules",
        notes=[note] if note else [],
    )


class OllamaAssessor:
    """Callable(dossier) -> Assessment using an Ollama model with structured output."""

    def __init__(
        self,
        client: OllamaClient,
        model: str,
        *,
        redact: bool = True,
        max_bytes: int = 48_000,
        temperature: float = 0.1,
    ) -> None:
        self.client = client
        self.model = model
        self.redact = redact
        self.max_bytes = max_bytes
        self.temperature = temperature
        self.last_prompt: str = ""

    def __call__(self, dossier: Dossier) -> Assessment:
        prompt, texts = dossier_text(dossier, redact=self.redact, max_bytes=self.max_bytes)
        self.last_prompt = prompt
        data, res = self.client.chat_json(
            self.model,
            build_messages(prompt),
            format=draft_schema(),
            temperature=self.temperature,
        )
        try:
            draft = AssessmentDraft.model_validate(data)
        except ValueError as exc:
            raise OllamaError(f"model output did not match the schema: {str(exc)[:300]}") from None
        out = verify(draft, texts, model=res.model, elapsed_ms=res.elapsed_ms)
        if res.prompt_tokens:
            out.notes.append(
                f"prompt {res.prompt_tokens} tokens, completion {res.completion_tokens or 0}"
            )
        return out


__all__ = [
    "OllamaAssessor",
    "OllamaError",
    "build_messages",
    "dossier_text",
    "draft_schema",
    "rules_assessment",
    "verify",
]

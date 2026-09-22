import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from autodiag.diagnose.models import (
    AssessmentDraft,
    ConcernDraft,
    DismissedDraft,
    Dossier,
    DossierItem,
    ProofDraft,
    Severity,
)
from autodiag.llm.assess import OllamaAssessor, dossier_text, rules_assessment, verify
from autodiag.llm.ollama import OllamaClient, OllamaError, parse_json_object


def _dossier() -> Dossier:
    ts = datetime(2026, 9, 22, 13, 25, tzinfo=UTC)
    return Dossier(
        mode="alert",
        target="t1",
        generated_at=ts,
        nodes=["FREE@10.1.2.3"],
        items=[
            DossierItem(
                id="ev_a",
                kind="alert",
                severity_hint=Severity.CRITICAL,
                ts=ts,
                title="ORA-00600 seen",
                text="ORA-00600: internal error code, arguments: [kkslgop1], [3]\n"
                "Incident details in: /x/y.trc",
            ),
            DossierItem(
                id="ev_b",
                kind="alert",
                severity_hint=Severity.WARNING,
                ts=ts,
                title="Deadlock",
                text="ORA-00060: Deadlock detected. More info in file /x/z.trc",
            ),
            DossierItem(
                id="ev_c",
                kind="alert_group",
                severity_hint=Severity.INFO,
                ts=ts,
                title="Info entries",
                text="TNS-12535: operation timed out (x40)",
            ),
        ],
    )


def _draft(**over) -> AssessmentDraft:
    base = dict(
        headline="An internal error recurs.",
        severity="critical",
        concerns=[
            ConcernDraft(
                severity="critical",
                kind="root_cause",
                title="ORA-600 kkslgop1",
                assessment="bug",
                proofs=[ProofDraft(evidence_id="ev_a", quote="arguments: [kkslgop1], [3]")],
                next_checks=["search MOS"],
            ),
            ConcernDraft(
                severity="warning",
                kind="observation",
                title="Made up",
                assessment="hallucinated",
                proofs=[ProofDraft(evidence_id="ev_b", quote="the instance crashed twice")],
                next_checks=[],
            ),
            ConcernDraft(
                severity="warning",
                kind="observation",
                title="Wrong id",
                assessment="quote is real, id is not",
                proofs=[ProofDraft(evidence_id="ev_a", quote="Deadlock detected")],
                next_checks=[],
            ),
        ],
        dismissed=[DismissedDraft(what="TNS-12535", reason="idle client timeouts")],
        actions=["package the incident"],
        open_questions=["patch level?"],
        confidence=0.8,
    )
    base.update(over)
    return AssessmentDraft(**base)


def test_verify_grounds_proofs_and_demotes_unproven() -> None:
    _, texts = dossier_text(_dossier(), redact=False)
    a = verify(_draft(), texts, model="m")
    assert [c.title for c in a.concerns] == ["ORA-600 kkslgop1", "Wrong id"]
    assert a.concerns[0].proven and a.concerns[0].proofs[0].verified
    repointed = a.concerns[1].proofs[0]
    assert repointed.verified and repointed.evidence_id == "ev_b"
    assert any("Unproven claim" in q and "Made up" in q for q in a.open_questions)
    assert a.proofs_total == 3 and a.proofs_verified == 2 and not a.grounded
    assert a.severity is Severity.CRITICAL and a.model == "m"


def test_title_is_quotable_and_short_quotes_fail() -> None:
    _, texts = dossier_text(_dossier(), redact=False)
    d = _draft(
        concerns=[
            ConcernDraft(
                severity="warning",
                kind="observation",
                title="t",
                assessment="a",
                proofs=[
                    ProofDraft(evidence_id="ev_b", quote="Dead"),
                    ProofDraft(evidence_id="ev_a", quote="ORA-00600 seen"),
                ],
                next_checks=[],
            ),
        ]
    )
    a = verify(d, texts, model="m")
    assert a.concerns and [p.verified for p in a.concerns[0].proofs] == [False, True]


def test_dossier_text_budget_and_redaction() -> None:
    d = _dossier()
    text, seen = dossier_text(d, redact=True, max_bytes=600)
    assert "ev_a" in seen and "NOT INCLUDED (budget)" in text
    assert "10.1.2.3" not in text  # node IP redacted at the model boundary


def test_rules_assessment_ranks_by_severity() -> None:
    a = rules_assessment(_dossier(), note="no model")
    assert a.model == "rules" and a.severity is Severity.CRITICAL
    assert [c.severity for c in a.concerns] == [Severity.CRITICAL, Severity.WARNING]
    assert all(c.proven for c in a.concerns) and a.notes == ["no model"]


def test_parse_json_object_tolerates_fences_and_prose() -> None:
    assert parse_json_object('```json\n{"a": 1}\n```')["a"] == 1
    assert parse_json_object('Sure! {"a": {"b": 2}} done')["a"]["b"] == 2
    with pytest.raises(OllamaError):
        parse_json_object("no json here")


@respx.mock
def test_client_falls_back_and_assessor_verifies() -> None:
    respx.get("http://primary/api/tags").mock(side_effect=httpx.ConnectError("down"))
    respx.get("http://fallback/api/tags").mock(
        return_value=httpx.Response(200, json={"models": []})
    )
    draft = _draft().model_dump()
    respx.post("http://fallback/api/chat").mock(
        return_value=httpx.Response(
            200,
            json={
                "model": "qwen",
                "message": {"role": "assistant", "content": json.dumps(draft)},
                "prompt_eval_count": 500,
                "eval_count": 100,
            },
        )
    )
    client = OllamaClient("http://primary", "http://fallback", timeout=5)
    a = OllamaAssessor(client, "qwen", redact=False)(_dossier())
    assert a.model == "qwen" and a.proofs_verified == 2
    assert any("prompt 500 tokens" in n for n in a.notes)
    sent = json.loads(respx.calls.last.request.content)
    assert sent["format"]["title"] == "AssessmentDraft" and sent["options"]["num_ctx"] == 32768
    assert sent["think"] is False


@respx.mock
def test_client_reports_every_endpoint_failure() -> None:
    respx.get("http://a/api/tags").mock(return_value=httpx.Response(200, json={}))
    respx.post("http://a/api/chat").mock(return_value=httpx.Response(404, text="model not found"))
    client = OllamaClient("http://a", timeout=5)
    with pytest.raises(OllamaError, match="404"):
        client.chat("nope", [{"role": "user", "content": "hi"}])

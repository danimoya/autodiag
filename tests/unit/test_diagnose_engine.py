from pathlib import Path

import pytest

from autodiag.core.settings import load_settings
from autodiag.core.targets import load_targets
from autodiag.diagnose.engine import diagnose
from autodiag.diagnose.models import (
    AssessmentDraft,
    ConcernDraft,
    Dossier,
    ProofDraft,
    Severity,
)
from autodiag.llm.assess import dossier_text, verify
from autodiag.llm.ollama import OllamaError
from autodiag.mcp.server import AutoDiagContext
from autodiag.sql.runner import QueryResult


class FakeRunner:
    ROWS = {
        "rac_instances": (
            ["INST_ID", "INSTANCE_NAME", "STATUS"],
            [[1, "PRODDB1", "OPEN"], [2, "PRODDB2", "MOUNTED"]],
        ),
        "pdbs": (
            ["CON_ID", "NAME", "OPEN_MODE"],
            [[2, "PDB$SEED", "READ ONLY"], [3, "APP", "MOUNTED"]],
        ),
        "rac_blocking_now": (
            ["INST_ID", "SID", "EVENT"],
            [[1, 55, "enq: TX - row lock contention"]],
        ),
        "blocking_tree_now": (["SID", "EVENT"], []),
        "db_info": (["DB_NAME", "VERSION_FULL"], [["PRODDB", "19.27.0.0.0"]]),
    }

    def __init__(self) -> None:
        self.calls: list[str] = []

    def run_named(self, name, params=None, *, max_rows=200, container=None):
        from autodiag.sql.catalog import load_catalog
        from autodiag.sql.runner import SqlRunnerError

        if name not in load_catalog():
            raise SqlRunnerError(f"unknown query {name!r}")
        self.calls.append(name)
        cols, rows = self.ROWS.get(name, (["A"], [[1]]))
        return QueryResult(name=name, columns=cols, rows=rows)


@pytest.fixture
def ctx(tmp_path: Path, fixtures_dir: Path, fake_transport_factory, monkeypatch) -> AutoDiagContext:
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "none.toml"))
    monkeypatch.setenv("AUTODIAG_DATA_DIR", str(tmp_path / "data"))
    s = load_settings(env_file=None)
    inv = load_targets(fixtures_dir / "config" / "targets.yaml")
    return AutoDiagContext(
        settings=s,
        inventory=inv,
        transport_factory=lambda t: fake_transport_factory,
        runner_factory=lambda t: FakeRunner(),
    )


def grounded_assessor(dossier: Dossier):
    """Pretends to be the model: cites the first critical item with a real quote."""
    top = dossier.sorted_items()[0]
    _, texts = dossier_text(dossier, redact=True)
    quote = texts[top.id].splitlines()[1][:80]
    draft = AssessmentDraft(
        headline=f"Top concern: {top.title}",
        severity="critical",
        concerns=[
            ConcernDraft(
                severity="critical",
                kind="root_cause",
                title=top.title,
                assessment="because",
                proofs=[ProofDraft(evidence_id=top.id, quote=quote)],
                next_checks=["check"],
            ),
        ],
        dismissed=[],
        actions=["package with IPS"],
        open_questions=[],
        confidence=0.7,
    )
    return verify(draft, texts, model="fake")


def failing_assessor(dossier: Dossier):
    raise OllamaError("no endpoint")


@pytest.mark.parametrize("new_counter", [False, True])
def test_performance_collector_and_assessor(ctx, monkeypatch, new_counter):
    from autodiag.diagnose import performance

    class PerformanceRunner(FakeRunner):
        sample = 0

        ROWS = {
            **FakeRunner.ROWS,
            "performance_sessions": (["INST_ID", "EVENT"], [[1, "db file sequential read"]]),
        }

        def run_named(self, name, params=None, **kw):
            if name == "performance_counters":
                self.sample += 1
                return QueryResult(
                    name=name,
                    columns=["INST_ID", "STARTUP_TIME", "CATEGORY", "METRIC", "VALUE"],
                    rows=[[1, "start", "time_us", "DB time", self.sample * 5000000]]
                    + (
                        [[1, "start", "wait_us", "new wait", 100]]
                        if new_counter and self.sample == 2
                        else []
                    ),
                )
            return super().run_named(name, params, **kw)

    runner = PerformanceRunner()
    ctx.runner_factory = lambda t: runner
    monkeypatch.setattr(performance.time, "sleep", lambda n: None)
    d = diagnose(
        ctx,
        mode="performance",
        target="testbed",
        instance_id=1,
        assessor=grounded_assessor,
        record=True,
    )
    assert d.dossier.mode == "performance"
    assert not d.dossier.errors
    assert d.dossier.stats["new_counters"] == int(new_counter)
    assert len(d.dossier.items) == 6
    assert d.assessment.proofs_verified == 1
    assert d.finding_ids
    assert "performance_sql" in runner.calls and "performance_sessions" in runner.calls
    assert not any("ash" in name or "awr" in name for name in runner.calls)


def test_performance_missing_sql_is_explicit(ctx):
    ctx.runner_factory = lambda t: None
    d = diagnose(ctx, mode="performance", target="testbed", assess=False)
    assert "SQL*Net" in d.dossier.errors[0]


def test_performance_rejects_crs(ctx):
    ctx.inventory.get("testbed").component = "crs"
    with pytest.raises(ValueError, match="database target"):
        diagnose(ctx, mode="performance", target="testbed", assess=False)


def test_problem_mode_builds_dossier_and_records_findings(ctx) -> None:
    d = diagnose(
        ctx,
        mode="problem",
        target="testbed",
        problem_key="ORA 600 [autodiag_test]",
        record=True,
        assessor=grounded_assessor,
    )
    kinds = {i.kind for i in d.dossier.items}
    assert {"problem", "incident", "kb", "stack_frequency", "stack_diff"} <= kinds
    assert (
        d.assessment.model == "fake" and d.assessment.grounded and d.assessment.proofs_verified == 1
    )
    st = ctx.store
    findings = st.list_findings(d.case_id)
    assert {f.kind for f in findings} == {"root_cause", "action"}
    root = next(f for f in findings if f.kind == "root_cause")
    assert root.author == "agent" and root.evidence_ids == [
        d.assessment.concerns[0].proofs[0].evidence_id
    ]
    assert st.get_case(d.case_id).title.startswith("diagnose problem: ORA 600 [autodiag_test]")
    # every dossier item is real evidence in the case
    ev_ids = {e.id for e in st.list_evidence(d.case_id)}
    assert all(i.id in ev_ids for i in d.dossier.items)


def test_problem_mode_by_incident_id(ctx) -> None:
    d = diagnose(ctx, mode="problem", target="testbed", incident_id=8873, assess=False)
    assert d.dossier.scope["problem_key"] == "ORA 600 [autodiag_test]"
    assert d.assessment.model == "rules" and d.assessment.severity is Severity.CRITICAL


def test_alert_mode_suppresses_noise_and_links_problems(ctx) -> None:
    d = diagnose(ctx, mode="alert", target="testbed", hours=24 * 365 * 5, assess=False)
    ds = d.dossier
    titles = [i.title for i in ds.items]
    assert any("SIGSEGV" in t or "ORA-07445" in t for t in titles)
    assert any(i.kind == "problem" for i in ds.items)
    assert any("advanced to log sequence" in g.signature for g in ds.noise)
    assert all("advanced to log sequence" not in t for t in titles)
    assert ds.stats["records_seen"] > ds.stats["records_kept"]


def test_llm_failure_falls_back_to_rules_with_note(ctx) -> None:
    d = diagnose(ctx, mode="alert", target="testbed", hours=24 * 365 * 5, assessor=failing_assessor)
    assert d.assessment.model == "rules"
    assert any("model assessment unavailable" in n for n in d.assessment.notes)
    assert d.assessment.concerns and all(c.proven for c in d.assessment.concerns)


def test_instance_mode_rac_correlates_nodes_and_judges_live_state(ctx) -> None:
    d = diagnose(
        ctx,
        mode="instance",
        target="prod-rac",
        days=3650,
        hours=24 * 365 * 5,
        live=True,
        assess=False,
    )
    ds = d.dossier
    assert len(ds.nodes) == 2
    corr = [i for i in ds.items if i.kind == "correlation"]
    assert corr and any("2 nodes within" in i.title for i in corr)
    q = {i.title: i for i in ds.items if i.kind == "query"}
    assert q["Instances and status (GV$INSTANCE)"].severity_hint is Severity.CRITICAL
    assert q["Pluggable databases and open mode"].severity_hint is Severity.WARNING
    assert q["Blocked sessions right now"].severity_hint is Severity.WARNING
    assert (
        "Global cache / cluster waits per instance" in q
        and "Exadata cell and smart-scan waits" in q
    )
    assert any(i.kind == "env" for i in ds.items)
    assert ds.scope["live"] is True


def test_instance_mode_without_live(ctx) -> None:
    d = diagnose(ctx, mode="instance", target="testbed", live=False, assess=False)
    assert not any(i.kind == "query" for i in d.dossier.items) and d.dossier.scope["live"] is False


def test_markdown_empty_dismissed_has_explicit_none(ctx):
    from autodiag.diagnose.render import diagnosis_markdown

    d = diagnose(ctx, mode="instance", target="testbed", live=False, assess=False)
    d.assessment.dismissed = []
    assert "## Dismissed\n- none" in diagnosis_markdown(d)


def test_bad_mode_and_missing_key(ctx) -> None:
    with pytest.raises(ValueError):
        diagnose(ctx, mode="nope", target="testbed", assess=False)
    from autodiag.adr.source import AdrSourceError

    with pytest.raises(AdrSourceError):
        diagnose(ctx, mode="problem", target="testbed", assess=False)


def test_truncated_alert_history_is_visible_in_diagnosis(ctx, monkeypatch):
    from autodiag.adr.source import AdrSource

    original = AdrSource.read_alert

    def limited(self, *args, **kw):
        return original(self, *args, **kw).model_copy(update={"truncated": True})

    monkeypatch.setattr(AdrSource, "read_alert", limited)
    d = diagnose(ctx, mode="alert", target="testbed", assess=False)
    assert any(
        i.kind == "coverage" and i.severity_hint == Severity.WARNING for i in d.dossier.items
    )
    assert any("omitted" in e for e in d.dossier.errors)

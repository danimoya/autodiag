"""Diagnosis collectors against the live testbed (no model): the injected faults must
surface as concerns and routine entries must be suppressed."""

import pytest

from autodiag.cli import common
from autodiag.diagnose.engine import diagnose

pytestmark = pytest.mark.integration


def test_problem_mode_on_repeated_ora600() -> None:
    ctx = common.context()
    d = diagnose(
        ctx, mode="problem", target="testbed", problem_key="ORA 600 [autodiag_repeat]", assess=False
    )
    freq = next(i for i in d.dossier.items if i.kind == "stack_frequency")
    assert "identical code path" in freq.text and "dbkeTestFlowKGE_ORA" in freq.text
    assert d.dossier.stats["incidents"] >= 3
    assert d.assessment.severity.value == "critical"


def test_alert_mode_ranks_faults_over_noise() -> None:
    ctx = common.context()
    d = diagnose(ctx, mode="alert", target="testbed", hours=24 * 30, assess=False)
    crit = [i for i in d.dossier.items if i.severity_hint.value == "critical"]
    assert any("ORA-07445" in i.text or "ORA-00600" in i.text for i in crit)
    assert d.dossier.stats["suppressed"] >= 1
    assert all("advanced to log sequence" not in i.title for i in d.dossier.items)


def test_instance_mode_live_queries_run() -> None:
    ctx = common.context()
    d = diagnose(ctx, mode="instance", target="testbed", live=True, assess=False)
    q = [i for i in d.dossier.items if i.kind == "query"]
    assert {i.refs["query"] for i in q} >= {
        "rac_instances",
        "pdbs",
        "blocking_tree_now",
        "system_events_top",
    }
    assert not [e for e in d.dossier.errors if e.startswith("query ")], d.dossier.errors
